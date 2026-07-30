"""The `fieldkit` command tree.

Deliberately thin: parse arguments, call into ``state``/``config``/``creds``/
``scope``, print. All logic lives in those modules so it can be tested without a
subprocess, and nothing here runs at import time.

Phase 0 surface:

    fieldkit init [name]
    fieldkit config show | get KEY | set k=v … | unset KEY
    fieldkit add cred 'CORP/jdoe:Winter2025!' | --from-file creds.txt
    fieldkit add hosts 10.0.0.0/24 | scope.txt
    fieldkit status
"""
import argparse
import functools
import os
import sqlite3
import sys

from datetime import datetime, timezone

from . import (__version__, adcs as adcs_mod, arsenal as arsenal_mod,
               bloodhound as bloodhound_mod, bridge as bridge_mod,
               classify as classify_mod, config as config_mod, creds as creds_mod,
               delegation as delegation_mod, escalate as escalate_mod,
               evasion as evasion_mod,
               executor as executor_mod, fs_scrub as fs_scrub_mod,
               hostenum as hostenum_mod, ingest as ingest_mod,
               kb as kb_mod, kerberos as kerberos_mod, lab as lab_mod,
               mongodb as mongodb_mod, mssql as mssql_mod, poc as poc_mod,
               postgres as postgres_mod, preflight as preflight_mod,
               privesc as privesc_mod, provision as provision_mod,
               report as report_mod, scope as scope_mod,
               sharespider as sharespider_mod, spray as spray_mod,
               wordlist as wordlist_mod)
from .errors import ConfirmationError, FieldkitError
from .state import DB_ENV_VAR, Store, default_db_path

PROG = "fieldkit"


# ------------------------------------------------------------------------ plumbing

def _err(msg):
    print(f"{PROG}: error: {msg}", file=sys.stderr)


def _db_path(args):
    return args.db or default_db_path()


def _open_store(args):
    return Store.open(_db_path(args))


def _confirm(question, assume_yes=False):
    """Ask before anything is committed. Non-interactive callers must pass --yes."""
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        raise ConfirmationError(
            "not running interactively and --yes was not given — refusing to guess; "
            "re-run with --yes once you have checked the parse above")
    try:
        answer = input(f"{question} [y/N] ").strip().lower()
    except EOFError:
        return False
    return answer in ("y", "yes")


def needs_engagement(fn):
    """Wrap a ``cmd_`` handler with the standard "open store + require engagement"
    prologue. The wrapped function is called as ``fn(args, store)``.

    Cuts the same three-line boilerplate ("with _open_store … require_engagement …")
    from every handler and consolidates it: one place to change if the setup ever
    grows a step (a preflight probe, a config load, an idle-DB warning)."""
    @functools.wraps(fn)
    def wrapper(args):
        with _open_store(args) as store:
            store.require_engagement()
            return fn(args, store)
    return wrapper


def needs_target(fn):
    """Same as :func:`needs_engagement`, plus resolves ``args.host`` to (host, cred).
    The wrapped function is called as ``fn(args, store, host, cred)``.

    Errors out (with the canonical message from :func:`_resolve_target`) before the
    handler runs — the handler sees only a valid target."""
    @functools.wraps(fn)
    def wrapper(args):
        with _open_store(args) as store:
            store.require_engagement()
            host, cred, err = _resolve_target(store, args.host)
            if err:
                _err(err)
                return 2
            return fn(args, store, host, cred)
    return wrapper


def _word(n, word):
    if n == 1:
        return word
    if word.endswith("y") and word[-2:-1] not in "aeiou":
        return word[:-1] + "ies"  # opportunity -> opportunities
    return word + "s"


def _plural(n, word):
    return f"{n} {_word(n, word)}"


# ------------------------------------------------------------------------ handlers

def cmd_init(args):
    path = _db_path(args)
    if os.path.exists(path):
        _err(f"{path} already exists — remove it or use --db for a second engagement")
        return 2
    name = args.name or os.path.basename(os.path.dirname(os.path.abspath(path))) or "engagement"
    with Store.create(path) as store:
        row = store.init_engagement(name)
        print(f"created {path}")
        print(f"engagement: {row['name']}  (schema v{store.schema_version()})")

    # Inline preflight so a tester learns about a missing required tool RIGHT HERE,
    # not five commands later when spray/enum/loot mysteriously errors out.
    pf_missing = preflight_mod.missing_required(preflight_mod.check())
    if pf_missing:
        print(f"\n⚠ required tools missing: {', '.join(r[0] for r in pf_missing)}")
        print(f"  the credential loop depends on them — install, then re-run "
              f"`{PROG} preflight` to confirm.")

    print(f"\nnext: {PROG} config set lhost=<your ip> lport=443 domain=<ad domain>")
    print(f"      {PROG} add hosts scope.txt")
    return 0


def cmd_config_show(args):
    with _open_store(args) as store:
        cfg = config_mod.load(store)
        data = cfg.as_dict()
        overrides = cfg.overrides()
        width = max((len(k) for k in config_mod.KEYS), default=0)
        for key in sorted(config_mod.KEYS):
            value = data.get(key)
            marker = " " if cfg.is_set(key) else "."  # '.' = default, not set
            shown = value if value is not None else "-"
            print(f"{marker} {key.ljust(width)}  {shown}")
        if overrides:
            print("\nper-subnet lhost overrides:")
            for cidr, lhost in sorted(overrides.items()):
                print(f"    {cidr}  ->  {lhost}")
        print("\n('.' marks a default that is not explicitly set)")
    return 0


def cmd_config_get(args):
    with _open_store(args) as store:
        cfg = config_mod.load(store)
        if args.key not in config_mod.KEYS:
            _err(f"unknown config key {args.key!r} — known keys: "
                 f"{', '.join(sorted(config_mod.KEYS))}")
            return 2
        value = cfg.get(args.key)
        if value is None:
            return 1
        print(value)
    return 0


def cmd_config_set(args):
    with _open_store(args) as store:
        cfg = config_mod.load(store)
        pairs = [config_mod.parse_assignment(a) for a in args.assignments]
        stored = cfg.set_many(pairs, subnet=args.subnet)
        scope_note = f" (for {args.subnet})" if args.subnet else ""
        for key, value in stored.items():
            print(f"{key} = {value}{scope_note}")
    return 0


def cmd_config_unset(args):
    if not args.key and not args.subnet:
        _err("give a key to unset, or --subnet to drop an lhost override")
        return 2
    with _open_store(args) as store:
        cfg = config_mod.load(store)
        cfg.unset(args.key, subnet=args.subnet)
        print(f"unset {args.key}" + (f" for {args.subnet}" if args.subnet else ""))
    return 0


def cmd_add_cred(args):
    kwargs = dict(domain=args.domain, username=args.user, password=args.password,
                  nt_hash=args.hash, aes_key=args.aes, ccache=args.ccache,
                  ssh_key=args.ssh_key, local_auth=True if args.local else None)

    if args.from_file:
        with open(args.from_file, "r", errors="replace") as fh:
            parsed, errors = creds_mod.parse_credential_lines(fh.read(), **kwargs)
        for lineno, line, message in errors:
            _err(f"{args.from_file}:{lineno}: {message}  ({line})")
        if not parsed:
            _err("no usable credentials in the file")
            return 2
    else:
        if not args.spec and not any([args.password, args.hash, args.aes, args.ccache,
                                      args.ssh_key]):
            _err("give a credential — quote the whole thing:\n"
                 "  fieldkit add cred 'jdoe:Winter2025!'\n"
                 "  fieldkit add cred 'CORP/jdoe:Winter2025!'\n"
                 "  fieldkit add cred 'jdoe:<NT-hash>'\n"
                 "  (or --from-file <path> for one credential per line; see `add cred -h`)")
            return 2
        parsed = [creds_mod.parse_credential(args.spec, **kwargs)]

    for item in parsed:
        print(creds_mod.describe(item.credential))
        for note in item.notes:
            print(f"  note: {note}")
    if not _confirm(f"add {_plural(len(parsed), 'credential')}?", args.yes):
        print("aborted — nothing was stored")
        return 1

    with _open_store(args) as store:
        store.require_engagement()
        added = reused = 0
        with store.transaction():
            for item in parsed:
                _, created = store.add_credential(item.credential, source=args.source)
                added += created
                reused += not created
    print(f"stored {_plural(added, 'credential')}"
          + (f", {reused} already known" if reused else ""))
    return 0


def cmd_add_hosts(args):
    if not args.targets and not args.file:
        _err("nothing to add — give IPs/CIDRs or a scope file")
        return 2

    targets, errors = scope_mod.read_targets(
        args.targets, file=args.file, max_expand=args.max_expand)
    for origin, lineno, line, message in errors:
        _err(f"{origin}:{lineno}: {message}  ({line})")
    if not targets:
        _err("no usable targets found")
        return 2

    with _open_store(args) as store:
        store.require_engagement()
        added = enriched = out_of_scope = 0
        rejected = []
        with store.transaction():  # one commit for the whole scope file
            for ip, hostname in targets:
                if not store.in_scope(ip):
                    out_of_scope += 1
                    if len(rejected) < 5:
                        rejected.append(ip)
                    continue
                _, created = store.add_host(
                    ip, hostname=hostname or None, os_name=args.os,
                    is_dc=True if args.dc else None, subnet=args.subnet)
                added += created
                enriched += not created
        total = store.counts()["hosts"]
    print(f"added {_plural(added, 'host')}"
          + (f", {enriched} already in the engagement" if enriched else "")
          + f" — {total} host(s) in the engagement")
    if out_of_scope:
        preview = ", ".join(rejected) + (f" (+{out_of_scope - len(rejected)} more)"
                                          if out_of_scope > len(rejected) else "")
        _err(f"{out_of_scope} rejected as outside the engagement scope: {preview}. "
             "See `fieldkit scope show`.")
    return 0 if not errors and not out_of_scope else 1


def cmd_scope_show(args):
    with _open_store(args) as store:
        store.require_engagement()
        rows = store.scope_rules()
    if not rows:
        print("no scope rules — every IP is allowed (no enforcement)")
        print(f"tighten with: `{PROG} scope allow 10.0.0.0/24`")
        return 0
    print(f"engagement scope ({len(rows)} rule(s)):")
    for r in rows:
        added = (r["added"] or "").split("T")[0]
        notes = f"  # {r['notes']}" if r["notes"] else ""
        print(f"  {r['kind']:<5}  {r['cidr']:<20}  ({added}){notes}")
    return 0


def cmd_scope_add(args):
    kind = "deny" if args.deny else "allow"
    with _open_store(args) as store:
        store.require_engagement()
        cidrs = []
        for target in args.cidrs:
            try:
                cid, created = store.scope_add(target, kind=kind, notes=args.notes)
            except ValueError as exc:
                _err(f"{target!r}: {exc}")
                return 2
            cidrs.append((target, created))
    for cidr, created in cidrs:
        print(f"{kind:<5}  {cidr}   ({'added' if created else 'already present'})")
    return 0


def cmd_scope_clear(args):
    with _open_store(args) as store:
        store.require_engagement()
        n = len(store.scope_rules())
        if not n:
            print("no scope rules to clear")
            return 0
        prompt = (f"drop {_plural(n, 'scope rule')} — enforcement will be OFF and "
                  "every IP will be allowed?")
        if not _confirm(prompt, args.yes):
            print("aborted — nothing changed")
            return 1
        store.scope_clear()
    print(f"cleared {_plural(n, 'scope rule')} — enforcement OFF")
    return 0


def cmd_ingest_nxc(args):
    if args.file and args.file != "-":
        with open(args.file, "r", errors="replace") as fh:
            text = fh.read()
    elif sys.stdin.isatty():
        _err("no capture given — pass a file or pipe nxc output on stdin")
        return 2
    else:
        text = sys.stdin.read()

    intent = ingest_mod.classify_nxc(text)
    if not intent.hosts and not intent.creds:
        _err("nothing recognizable in that capture — no [+] auth lines or [*] banners")
        return 2

    admin = intent.admin
    print(f"read {_plural(len(intent.hosts), 'host banner')}, "
          f"{_plural(len(intent.creds), 'valid credential')}"
          + (f" ({len(admin)} admin)" if admin else ""))
    for cred, result in intent.creds:
        tag = "  (Pwn3d!)" if result.admin else ""
        print(f"  {result.proto.lower():<5} {result.ip:<15} "
              f"{cred.principal} → {creds_mod.secret_display(cred)}{tag}")

    if not _confirm("record these into the engagement?", args.yes):
        print("aborted — nothing was stored")
        return 1

    with _open_store(args) as store:
        store.require_engagement()
        rep = ingest_mod.apply_nxc(store, intent, source=args.source)
    print(f"stored {_plural(rep.creds_added, 'credential')}"
          + (f", {rep.creds_reused} already known" if rep.creds_reused else "")
          + f"; {rep.access_added} new access {_word(rep.access_added, 'record')}"
          + (f" ({rep.admin_added} admin)" if rep.admin_added else "")
          + f"; {rep.hosts_added} hosts added, {rep.hosts_enriched} enriched")
    return 0


def cmd_spray(args):
    if args.proto not in spray_mod.PROTOCOLS:
        _err(f"unknown proto {args.proto!r} — one of {', '.join(spray_mod.PROTOCOLS)}")
        return 2
    with _open_store(args) as store:
        store.require_engagement()
        cfg = config_mod.load(store)
        # wordlist mode: --userlist / --passlist (or the same config keys) present
        userlist = args.userlist or cfg.get("userlist")
        passlist = args.passlist or cfg.get("passlist")
        if args.wordlist or (userlist and passlist and not store.credentials()):
            return _cmd_spray_wordlist(args, store, cfg, userlist, passlist)

        hosts = store.hosts(subnet=args.subnet)
        creds = store.credentials()
        if not hosts:
            _err("no hosts in the engagement"
                 + (f" for {args.subnet}" if args.subnet else "")
                 + " — run `fieldkit add hosts` first")
            return 2
        if not creds:
            _err("no credentials to spray — run `fieldkit add cred` first, or run "
                 "`fieldkit spray --wordlist` with a userlist + passlist")
            return 2

        question = (f"validate {_plural(len(creds), 'credential')} across "
                    f"{_plural(len(hosts), 'host')} on {args.proto}? this runs nxc "
                    "against the client")
        if not _confirm(question, args.yes):
            print("aborted — nothing ran")
            return 1

        report = spray_mod.spray_loop(
            store, cfg, proto=args.proto, subnet=args.subnet, loot=not args.no_loot,
            with_policy=not args.no_policy, dc_ip=args.dc, timeout=args.timeout,
            on_event=lambda m: print(m))

    if report.aborted:
        _err(report.aborted)
        return 2
    print(f"\ndone in {report.rounds} round(s): "
          f"{report.valid} valid, {report.admin} admin; "
          f"looted {_plural(report.hosts_looted, 'host')}, "
          f"recovered {_plural(report.creds_recovered, 'credential')}")
    if report.creds_recovered:
        print("re-run `fieldkit spray` to chase the recovered credentials further")
    return 0


def _cmd_spray_wordlist(args, store, cfg, userlist, passlist):
    """Wordlist × password spray. Callable only from cmd_spray (the store is open)."""
    if not userlist or not passlist:
        _err("wordlist spray needs --userlist and --passlist (or `config set "
             "userlist=<path> passlist=<path>`)")
        return 2
    hosts = store.hosts(subnet=args.subnet)
    if not hosts:
        _err("no hosts in the engagement"
             + (f" for {args.subnet}" if args.subnet else "")
             + " — run `fieldkit add hosts` first")
        return 2

    def _count(p):
        return sum(1 for line in open(p, "r", errors="replace")
                   if line.strip() and not line.startswith("#"))

    try:
        users, passwords = _count(userlist), _count(passlist)
    except OSError as exc:
        _err(f"wordlist read error: {exc}")
        return 2
    combos = users * passwords
    question = (f"WORDLIST SPRAY on {args.proto}: {users} users × {passwords} "
                f"passwords = {combos} combinations across "
                f"{_plural(len(hosts), 'host')}. This CAN lock accounts if the "
                "domain has a lockout policy. Continue?")
    if not _confirm(question, args.yes):
        print("aborted — nothing ran")
        return 1
    rep = spray_mod.wordlist_spray(
        store, cfg, proto=args.proto, subnet=args.subnet,
        userlist=userlist, passlist=passlist, dc_ip=args.dc,
        allow_lockout_risk=args.allow_lockout_risk, timeout=args.timeout,
        on_event=lambda m: print(m))
    if rep.aborted:
        _err(rep.aborted)
        return 2
    print(f"\nwordlist spray: {rep.valid} valid, {rep.admin} admin, "
          f"{rep.creds_added} new credentials stored")
    if rep.creds_added:
        print("re-run `fieldkit spray` (stored mode) to chase the recovered credentials")
    return 0


def _first_dir(v):
    return v.split(",")[0].strip() if v else v


def _stage_dirs(cfg):
    # a comma-separated stage_win/stage_lin means "try these dirs"; single-dir rendering
    # (find_vector, run) uses the first.
    return dict(stage_win=_first_dir(cfg.get("stage_win")),
                stage_lin=_first_dir(cfg.get("stage_lin")))


def _stage_dir_list(cfg, key):
    v = cfg.get(key)
    return [d.strip() for d in v.split(",") if d.strip()] if v else []


def _expand_stage_dirs(store, host_ip, host_os, cfg, vectors, dirs):
    """For each provisioned (stages/builds) vector, one copy per stage dir — so an
    'artifact didn't land' (delivery) miss advances the loop to the SAME tool in the next
    writable dir. Set e.g. `config set stage_win='C:\\Windows\\Temp,C:\\Users\\Public'`."""
    import dataclasses
    win = host_os == "windows"
    other = _first_dir(cfg.get("stage_lin" if win else "stage_win"))
    out = []
    for v in vectors:
        if not (getattr(v, "stages", ()) or getattr(v, "builds", ())):
            out.append(v)
            continue
        for d in dirs:
            kw = {"stage_win": d, "stage_lin": other} if win else \
                 {"stage_win": other, "stage_lin": d}
            v2 = privesc_mod.find_vector(store, host_ip, v.key, **kw)
            if v2:
                leaf = d.rstrip("\\/").replace("/", "\\").rsplit("\\", 1)[-1] or "dir"
                slug = "".join(c for c in leaf if c.isalnum()) or "dir"
                out.append(dataclasses.replace(v2, key=f"{v2.key}@{slug}"))
    return out


@needs_target
def cmd_spider(args, store, host, cred):
    """SMB share spider + scrub → loot → creds. Uses nxc's spider_plus module."""
    if host["os"] and host["os"] != "windows":
        _err(f"{args.host} is {host['os']} — SMB spidering is Windows-only")
        return 2

    out = args.out or os.path.join(_build_dir(), f"spider-{host['ip']}")
    os.makedirs(out, exist_ok=True)
    question = (f"spider readable SMB shares on {args.host}, download all files "
                f"under 50KB to {out}, and scrub them for secrets? this pulls a "
                "copy of the client's files")
    if not _confirm(question, args.yes):
        print("aborted — nothing ran")
        return 1

    rep = sharespider_mod.spider_and_scrub(
        store, host, cred, output_folder=out, on_event=lambda m: print(m),
        allow_promotion=not args.no_promote)

    if rep.error:
        _err(f"nxc did not run: {rep.error}")
        return 1
    kinds = {}
    for h in rep.hits:
        kinds[h.kind] = kinds.get(h.kind, 0) + 1
    print(f"\nspider {args.host}: {rep.shares_readable} share(s), "
          f"{rep.files_inventoried} file(s) inventoried, "
          f"{_plural(len(rep.hits), 'hit')}")
    for kind, n in sorted(kinds.items(), key=lambda p: (-p[1], p[0])):
        print(f"  {kind:<20} {n}")
    if rep.creds_promoted:
        print(f"\n{_plural(rep.creds_promoted, 'credential')} promoted to the loop — "
              "re-run `fieldkit spray` to chase them")
    print(f"\nclient-data corpus at {out} — recorded as a deletion obligation; "
          "`fieldkit report` will surface it")
    return 0


@needs_target
def cmd_scrub(args, store, host, cred):
    """On-box filesystem scrub: sweep /etc, /opt, $HOME, /var/www for cleartext
    secrets on a Linux foothold. Uses the same scrubbers as `spider`."""
    paths = args.paths or None      # None -> DEFAULT_LINUX_PATHS
    question = (f"scrub {host['ip']} for on-box secrets in "
                f"{', '.join(paths or fs_scrub_mod.DEFAULT_LINUX_PATHS)}? "
                "(read-only; runs one find | cat pipeline on the target)")
    if not _confirm(question, args.yes):
        print("aborted — nothing ran")
        return 1
    rep = fs_scrub_mod.fs_scrub(store, host, cred, paths=paths,
                                on_event=lambda m: print(m))
    if rep.aborted:
        _err(rep.aborted)
        return 2
    kinds = {}
    for h in rep.hits:
        kinds[h.kind] = kinds.get(h.kind, 0) + 1
    print(f"\nfs-scrub {host['ip']}: {_plural(len(rep.hits), 'hit')}")
    for kind, n in sorted(kinds.items(), key=lambda p: (-p[1], p[0])):
        print(f"  {kind:<20} {n}")
    if rep.creds_promoted:
        print(f"\n{_plural(rep.creds_promoted, 'credential')} promoted — "
              "re-run `fieldkit spray` to chase them")
    return 0


@needs_engagement
def cmd_analyze(args, store):
    cfg = config_mod.load(store)
    items = list(kb_mod.analyze(store))
    items += privesc_mod.vectors_from_state(store, **_stage_dirs(cfg))
    counts = store.counts()
    items.sort(key=lambda x: -x.score)

    if not items:
        if not counts["access"]:
            print("nothing to analyze yet — no access proven. Run `fieldkit spray` first.")
        else:
            print("no ranked opportunities from the current state — "
                  "`fieldkit enum <host>` to unlock privesc vectors.")
        return 0

    print(f"{_plural(len(items), 'move')}, best first "
          "(exploitability/safety/detection):\n")
    for i, item in enumerate(items, 1):
        where = f"  [{item.host}]" if item.host else ""
        print(f"{i}. {item.title}{where}")
        print(f"     rank: {item.axes}")
        print(f"     {item.detail}")
        if isinstance(item, privesc_mod.Vector):
            print(f"     command: {item.command}")
            if item.manual:   # prepared route — escalate won't fire it; prep renders the steps
                if item.evidence:
                    print(f"     why: {item.evidence}")
                print(f"     prep: {PROG} prep {item.host} {item.key}   (manual route)")
            else:
                print(f"     run: {PROG} run {item.host} {item.key}")
            if item.cleanup:
                print(f"     cleanup: {item.cleanup}")
        else:
            print(f"     next: {item.next_step}")
        if args.proof and item.safe_proof:
            print(f"     safe proof: {item.safe_proof}")
        print()
    return 0


def _resolve_target(store, ip):
    """(host_row, cred_row) for a target, or an error string. Shared by enum/run.

    Distinct failures the error message MUST NOT conflate:
      * ``ip`` looks like a CIDR (this command takes one IP);
      * ``ip`` is outside :meth:`Store.scope_rules` allow/deny (scope violation);
      * ``ip`` is not in the engagement database (needs ``add hosts``);
      * the engagement has NO credentials at all (needs ``add cred``);
      * credentials exist but none is proven to work on THIS host (needs a spray
        or an ingest of a prior nxc result to prove one).

    The last two are the ones testers most commonly confuse — the old message
    said "no credential is proven on X" for both, which read as "no cred exists"
    when the tester had just added one.
    """
    if "/" in ip:
        return None, None, (f"{ip} looks like a CIDR — this command takes a single "
                            "host. Use `add hosts <cidr>` to register the range, then "
                            "`spray` to sweep it, then run this on a specific IP.")
    if not store.in_scope(ip):
        return None, None, (f"{ip} is outside the engagement scope — see "
                            "`fieldkit scope show` for the current rules")
    host = store.host_by_ip(ip)
    if host is None:
        return None, None, (f"{ip} is not in the engagement — add it with "
                            "`fieldkit add hosts` (accepts single IPs, CIDR, or a "
                            "scope file)")
    cred = store.credential_with_access_on(host["id"])
    if cred is None:
        n_creds = store.counts()["credentials"]
        if n_creds == 0:
            note = ("no credentials in the engagement — add one with `fieldkit "
                    "add cred 'jdoe:Winter2025!'`, or spray a wordlist with "
                    "`fieldkit spray --wordlist --userlist … --passlist …`")
        else:
            note = (f"{_plural(n_creds, 'credential')} stored, but none is proven "
                    f"to work on {ip} yet — run `fieldkit spray` to validate them "
                    f"there (this command runs as a credential that ALREADY works)")
        return host, None, note
    return host, cred, None


def _facts_summary(facts):
    """One-line-per-signal digest of what enum found, for the operator."""
    lines = []
    if facts.os == hostenum_mod.LINUX:
        lines.append(f"  user: {facts.user or '?'} (uid {facts.uid})"
                     + (" — ROOT" if facts.is_root else "")
                     + (f"  groups: {', '.join(sorted(facts.groups))}" if facts.groups else ""))
        if facts.sudo_all:
            lines.append("  sudo: FULL root (ALL)")
        elif facts.sudo_binaries:
            lines.append(f"  sudo: {', '.join(sorted(facts.sudo_binaries))}"
                         + ("  NOPASSWD" if facts.sudo_nopasswd else "")
                         + (f"  env_keep={','.join(sorted(facts.sudo_env_keep))}"
                            if facts.sudo_env_keep else ""))
        if facts.suid:
            lines.append(f"  suid: {', '.join(sorted(facts.suid))}")
        if facts.caps:
            lines.append(f"  caps: {', '.join(f'{k}={v}' for k, v in sorted(facts.caps.items()))}")
        if facts.kernel:
            lines.append(f"  kernel: {facts.kernel}")
    else:
        if facts.privs:
            lines.append(f"  privileges: {', '.join(sorted(facts.privs))}")
        if facts.win_groups:
            lines.append(f"  groups: {', '.join(sorted(facts.win_groups))}")
        if facts.always_install_elevated:
            lines.append("  AlwaysInstallElevated: ON (both keys)")
        if facts.unquoted_services:
            lines.append(f"  unquoted services: {len(facts.unquoted_services)}")
    return lines


@needs_target
def cmd_enum(args, store, host, cred):
    principal = creds_mod.Credential.from_row(cred).principal
    if not _confirm(f"enumerate {args.host} as {principal}? (read-only, runs commands "
                    "on the target)", args.yes):
        print("aborted — nothing ran")
        return 1
    report = hostenum_mod.run_enum(store, host, cred, on_event=lambda m: print(m))
    if report.blocked:
        _err(report.blocked)
        return 2
    facts = hostenum_mod.facts_for(store, host["id"])

    print(f"\nenumerated {args.host}: {_plural(len(report.ran), 'check')} captured"
          + (f", {len(report.failed)} failed" if report.failed else ""))
    summary = _facts_summary(facts)
    if summary:
        print("\n".join(summary))
    print(f"\nnext: {PROG} analyze   (ranks the privesc vectors this enum unlocked)")
    return 0


@needs_target
def cmd_run(args, store, host, cred):
    cfg = config_mod.load(store)
    vector = privesc_mod.find_vector(store, args.host, args.vector, **_stage_dirs(cfg))
    if vector is None:
        available = [v.key for v in privesc_mod.vectors_from_state(store, **_stage_dirs(cfg))
                     if v.host == args.host]
        _err(f"no vector {args.vector!r} on {args.host}"
             + (f" — available: {', '.join(available)}" if available
                else " — run `fieldkit enum` then `fieldkit analyze` first"))
        return 2

    allow = ["read-only"] + list(args.allow or [])
    gated = not executor_mod.gate(vector.safety, allow)
    print(f"vector: {vector.title}")
    print(f"  host {args.host}  rank {vector.axes}  safety {vector.safety}")
    print(f"  command: {vector.command}")
    if vector.cleanup:
        print(f"  cleanup: {vector.cleanup}")
    if gated:
        _err(f"{vector.safety} action blocked by the safety gate — re-run with "
             f"--allow {vector.safety}")
        return 2
    if not _confirm(f"run this on {args.host}? (executes on the target)", args.yes):
        print("aborted — nothing ran")
        return 1

    vtype = vector.report_type or vector.key.split(":", 1)[0]
    finding_id, _ = store.add_finding(
        vtype, vector.title, host_id=host["id"], risk=vector.detection)
    creates = [(f"{vector.title} (artifact)", vector.cleanup)] if vector.cleanup else ()
    action = executor_mod.Action(
        host=host, cred=cred, command=vector.command, label=f"vector:{vector.key}",
        safety=vector.safety, shell=vector.shell, finding_id=finding_id, creates=creates)
    res = executor_mod.execute(store, action, allow=allow, on_event=lambda m: print(m))

    if res.blocked:
        _err(res.blocked)
        return 2
    verdict = classify_mod.classify(res.run, os_name=host["os"])
    if verdict.ok:
        store.add_finding(vtype, vector.title, host_id=host["id"], proven=True,
                          evidence=(res.output or "").strip()[:500])

    print("\n--- output ---")
    print((res.output or "").rstrip() or "(no output)")
    print("---")
    if verdict.ok:
        print("PROVEN: the command returned an elevated context. Captured as a finding.")
    else:
        print(f"verdict: {verdict.outcome} ({verdict.confidence} confidence) — {verdict.detail}")
        print(f"  → {verdict.guidance}")
    if vector.cleanup:
        print(f"cleanup recorded: {vector.cleanup}")
    return 0


def _host_vectors(store, cfg, host_ip):
    """The ranked privesc vectors for one host from current enum facts."""
    return [v for v in privesc_mod.vectors_from_state(store, **_stage_dirs(cfg))
            if v.host == host_ip]


def _provision_to_target(store, host, cred, local, remote, label, allow, cfg):
    """Get ``local`` onto the target at ``remote`` — see :func:`fieldkit.provision.put`."""
    return provision_mod.put(store, host, cred, local, remote, label, allow, cfg,
                             on_event=print)


def _build_dir():
    """A scratch dir for artifacts fieldkit builds mid-loop (attacker-side)."""
    d = os.path.join(os.environ.get("FIELDKIT_BUILD", os.path.join(
        os.path.expanduser("~"), ".fieldkit", "build")))
    os.makedirs(d, exist_ok=True)
    return d


def cmd_escalate(args):
    if args.rules:
        print(escalate_mod.describe_policy())
        return 0
    if not args.host:
        _err("an IP is required (or pass --rules to see the policy)")
        return 2
    with _open_store(args) as store:
        store.require_engagement()
        cfg = config_mod.load(store)
        host, cred, err = _resolve_target(store, args.host)
        # --dry-run is plan-only: proceed even when no credential is yet proven
        # on this host, as long as the host itself is resolvable. The plan is
        # what the operator wanted to see before committing.
        if err and not (args.dry_run and host is not None):
            _err(err)
            return 2
        if args.dry_run and cred is None:
            print(f"(dry-run: {err}) — showing the plan anyway\n")
        vectors = _host_vectors(store, cfg, args.host)
        if not vectors:
            _err(f"no privesc vectors on {args.host} — run `fieldkit enum {args.host}` "
                 "then `fieldkit analyze` first")
            return 2
        # a comma-separated stage_win/stage_lin → try each dir for provisioned vectors,
        # so a "didn't land" miss rolls to the same tool in the next writable dir.
        dir_key = "stage_win" if host["os"] == "windows" else "stage_lin"
        dirs = _stage_dir_list(cfg, dir_key)
        if len(dirs) > 1:
            vectors = _expand_stage_dirs(store, args.host, host["os"], cfg, vectors, dirs)
        allow = ["read-only"] + list(args.allow or [])

        # evasion posture: order delivery alternates + know which are already caught.
        now = datetime.now(timezone.utc)
        delivery_order, caught = evasion_mod.posture(store.evasion_result, host["os"], now=now)
        vectors = escalate_mod.order_deliveries(vectors, delivery_order)

        # the plan, before anything runs: what the loop would try, in order. Manual
        # routes (prep-only) are shown but never auto-fired, so they aren't "runnable".
        gated = [v for v in vectors if not executor_mod.gate(v.safety, allow)]
        runnable = [v for v in vectors
                    if executor_mod.gate(v.safety, allow) and not getattr(v, "manual", False)]
        print(f"escalation plan for {args.host} — {_plural(len(vectors), 'vector')} ranked, "
              f"blast radius {'/'.join(allow)}:")
        for v in vectors:
            if getattr(v, "manual", False):
                print(f"  {v.key:<26} {v.axes:<18} {v.safety}"
                      f"  (manual — {PROG} prep {args.host} {v.key})")
                continue
            marks = []
            if v in gated:
                marks.append(f"gated — needs --allow {v.safety}")
            if v.delivery:
                marks.append(f"delivery {v.delivery}"
                             + (" — KNOWN CAUGHT, will skip" if v.delivery in caught else ""))
            for name, _ in v.stages:
                have = "in arsenal" if arsenal_mod.find(name) else "NOT staged"
                marks.append(f"auto-stage {name} ({have})")
            for fmt, _, _ in v.builds:
                have = f"{poc_mod.BUILDER.get(fmt, '?')} ready" if poc_mod.have(fmt) \
                    else f"needs {poc_mod.BUILDER.get(fmt, 'a builder')}"
                marks.append(f"auto-build {fmt} ({have})")
            mark = ("  (" + "; ".join(marks) + ")") if marks else ""
            print(f"  {v.key:<26} {v.axes:<18} {v.safety}{mark}")
        manual = [v for v in vectors if getattr(v, "manual", False)]
        if not runnable:
            if manual:
                print(f"\n{_plural(len(manual), 'route')} here can't be auto-fired "
                      "(operator hands needed) — prepare the artifact + steps:")
                for v in manual:
                    print(f"  {PROG} prep {args.host} {v.key}")
                return 0
            _err("every vector is above the current --allow — re-run with --allow "
                 "config-change (and/or crash-risk) once you accept the blast radius")
            return 2
        if args.dry_run:
            print(f"\ndry run — nothing fired. {_plural(len(runnable), 'vector')} would run"
                  + (f"; {_plural(len(manual), 'manual route')} need `{PROG} prep`." if manual
                     else "."))
            return 0

        budget = args.max if args.max is not None else escalate_mod.DEFAULT_BUDGET
        if not _confirm(
                f"walk the escalation loop on {args.host}? fires up to "
                f"{min(budget, len(runnable))} vector(s) on the target, stopping at the "
                "first proof", args.yes):
            print("aborted — nothing ran")
            return 1

        prov = provision_mod.Provisioner(store, host, cred, cfg, allow,
                                         build_dir=_build_dir(), on_event=print)

        def mark_caught(technique):
            store.record_evasion(technique, "caught",
                                 detail=f"caught live during escalation on {args.host} "
                                        f"({now.date().isoformat()})")

        print("\n--- escalating ---")
        outcome = escalate_mod.escalate(
            vectors, fire=prov.fire, allow=allow, os_name=host["os"], budget=budget,
            delivery_order=delivery_order, caught=caught, mark_caught=mark_caught,
            stage=None if args.no_stage else prov.stage,
            build=None if args.no_stage else prov.build, on_event=lambda m: print(m))

        provision_mod.record_proof(store, outcome, prov.results, host)

    _print_escalation_outcome(outcome)
    return 0 if outcome.ok else 1


def _print_escalation_outcome(outcome):
    print("\n--- trail ---")
    for a in outcome.attempts:
        if a.verdict is not None:
            print(f"  {a.action:<8} {a.vector.key:<24} {a.verdict.outcome} — {a.note}")
        else:
            print(f"  {a.action:<8} {a.vector.key:<24} {a.note}")
    print("---")
    if outcome.ok:
        v = outcome.proven
        print(f"PROVEN: {v.title} elevated on {v.host}. Recorded as a finding"
              + (f"; cleanup: {v.cleanup}" if v.cleanup else "") + ".")
    elif outcome.stopped == "surfaced":
        print("STOPPED: a result the classifier does not recognise — shown above. "
              "Inspect it before continuing (`fieldkit arsenal rules`).")
    elif outcome.stopped == "budget":
        print("STOPPED: attempt budget reached before proof — raise it with --max or "
              "narrow the plan.")
    else:
        print("no vector proved elevation — every ranked move was tried. See the trail "
              "for the per-vector verdict and its recommended manual step.")
    if not outcome.ok and any(a.verdict and a.verdict.axis == "delivery"
                              for a in outcome.attempts):
        print("\nan artifact didn't land at the stage dir. Try more writable dirs — the loop "
              "walks each one:\n  fieldkit config set "
              "stage_win='C:\\Windows\\Temp,C:\\Users\\Public,C:\\ProgramData'\n"
              "then re-run. If it's AV eating the payload (common with Potatoes), that's an "
              "evasion problem, not a dir problem — see `fieldkit poc` / posture.")
    manual = [a for a in outcome.attempts if a.action == escalate_mod.MANUAL]
    if manual:
        print(f"\n{_plural(len(manual), 'manual route')} can't be auto-fired — prepare "
              "the artifact + steps with:")
        for a in manual:
            print(f"  {PROG} prep {a.vector.host} {a.vector.key}")


def cmd_prep(args):
    with _open_store(args) as store:
        store.require_engagement()
        cfg = config_mod.load(store)
        host, cred, err = _resolve_target(store, args.host)
        if host is None:
            _err(err)
            return 2
        if args.stage and err:            # staging needs proven access; building doesn't
            _err(err)
            return 2
        vector = privesc_mod.find_vector(store, args.host, args.vector, **_stage_dirs(cfg))
        if vector is None:
            available = [v.key for v in _host_vectors(store, cfg, args.host)
                         if v.builds or v.manual]
            _err(f"no vector {args.vector!r} on {args.host}"
                 + (f" — preparable: {', '.join(available)}" if available
                    else " — run `fieldkit enum` then `fieldkit analyze` first"))
            return 2
        # preparable = fieldkit builds the artifact, or the route needs operator hands
        # (a manual route's artifact comes from the arsenal instead of a build).
        if not vector.builds and not vector.manual:
            _err(f"{vector.key} has nothing to prepare — it's auto-fireable "
                 f"(`{PROG} run {args.host} {vector.key}` or `{PROG} escalate`)")
            return 2

        arch = "x86" if cfg.get("arch") == "x86" else "x64"
        built = []
        for fmt, remote, bcmd in vector.builds:
            out = os.path.join(_build_dir(), f"{vector.key.replace(':', '_')}.{fmt}")
            bres = poc_mod.build(fmt, out, arch=arch, command=bcmd,
                                 lhost=cfg.get("lhost"), lport=cfg.get("lport"))
            if not bres.ok:
                _err(f"build failed ({bres.tool}): {bres.detail}")
                return 1
            built.append([fmt, out, remote, bres.tool, None])
        # arsenal-sourced artifacts (a staged PoC, e.g. a lin-kernel exploit): resolve the
        # local copy so prep can name it and optionally push it. Not fetched = say so.
        for name, remote in vector.stages:
            local = arsenal_mod.find(name)
            built.append([name, local or f"<not in arsenal: exploits/fetch.sh --only {name}>",
                          remote, "arsenal", None])

        if args.stage:
            if not _confirm(f"upload {_plural(len(built), 'artifact')} to {args.host} "
                            "(writes to the target)?", args.yes):
                print("built locally; not staged (declined)")
                args.stage = False
            else:
                for entry in built:
                    fmt, out, remote = entry[0], entry[1], entry[2]
                    if not os.path.exists(out):     # unresolved arsenal artifact
                        entry[4] = None
                        continue
                    # put-file, or download-stage over the exec transport (e.g. MSSQL-only).
                    ok, how = _provision_to_target(
                        store, host, cred, out, remote, f"prep:{fmt}",
                        ["read-only", "config-change"], cfg)
                    if not ok:
                        _err(f"stage failed: {how}")
                        return 1
                    entry[4] = f"{remote} ({how})"

    _render_prep(vector, built)
    return 0


def _render_prep(vector, built):
    pb = vector.playbook
    print(f"\n=== prep: {vector.title} ===")
    if pb:
        print(pb.summary)
    print("\nartifacts (attacker-side):")
    for fmt, out, remote, tool, staged in built:
        print(f"  {fmt:<4} {out}   (via {tool})")
        if staged:
            print(f"       staged on target → {staged}")
        else:
            print(f"       copy it to the target yourself → {remote}")
    if not pb:
        return
    print(f"\nplace at: {pb.place}")
    print("steps:")
    for i, step in enumerate(pb.steps, 1):
        print(f"  {i}. {step}")
    if pb.restore:
        print(f"\nrestore/cleanup: {pb.restore}")


def cmd_preflight(args):
    rows = preflight_mod.check()
    print("preflight — external tools fieldkit drives:\n")
    for name, purpose, found, alts, required in rows:
        if found:
            mark, val = "OK ", found
        elif required:
            mark, val = "!! ", "MISSING — required"
        else:
            mark, val = "-- ", "not installed"
        alt = f"   (any of: {', '.join(alts)})" if not found and len(alts) > 1 else ""
        label = f"{name} ({purpose})"
        print(f"  {mark} {label:<42} {val}{alt}")
    missing = preflight_mod.missing_required(rows)
    print("\nbuild toolchain detail: `fieldkit poc --check`   ·   "
          "staged exploits: `fieldkit arsenal check`")
    if missing:
        print(f"\n{_plural(len(missing), 'required tool')} missing — the credential loop "
              "needs netexec + impacket.")
        return 1
    return 0


def cmd_poc(args):
    if args.check:
        print("build toolchain — which builders are installed:\n")
        for tool, path in poc_mod.toolchain():
            print(f"  {'OK ' if path else '-- '} {tool:<28} {path or 'not on PATH'}")
        conf = poc_mod.confuser(args.confuser)
        print(f"  {'OK ' if conf else '-- '} {'ConfuserEx (obfuscate)':<28} "
              f"{conf or 'not found — set confuser_cli / --confuser (+ mono for a .exe)'}")
        print("\nformats: " + ", ".join(f"{f} ({b})" for f, b in sorted(poc_mod.BUILDER.items())))
        return 0
    if args.obfuscate:  # ConfuserEx: obfuscate a compiled .NET assembly (e.g. a Potato .exe)
        src = args.obfuscate
        if not os.path.exists(src):  # allow naming an arsenal artifact instead of a path
            resolved = arsenal_mod.find(src)
            if resolved:
                src = resolved
        out = args.out or os.path.join(_build_dir(),
                                       f"{os.path.splitext(os.path.basename(src))[0]}-obf.exe")
        cfg = {}
        if os.path.exists(_db_path(args)):
            try:
                with _open_store(args) as store:
                    cfg = config_mod.load(store)
            except FieldkitError:
                pass
        res = poc_mod.obfuscate(src, out, cli=args.confuser or cfg.get("confuser_cli"))
        if not res.ok:
            _err(f"obfuscate failed ({res.tool or 'ConfuserEx'}): {res.detail}")
            return 1
        print(f"obfuscated via {res.tool}: {res.path}")
        print("  stage this in place of the stock .exe for the on-disk native rung; "
              "the in-memory rung already evades on-disk via reflection + `amsi_bypass`.")
        return 0
    if not args.format:
        _err("a format is required (exe|dll|msi|so|ps1), --obfuscate <exe>, or --check")
        return 2
    out = args.out or os.path.join(_build_dir(), f"payload.{args.format}")
    if not poc_mod.have(args.format) and not args.source:
        _err(f"{poc_mod.BUILDER.get(args.format, 'the builder')} for {args.format} is not "
             "installed — `fieldkit poc --check`")
        return 2
    cfg = {}
    if os.path.exists(_db_path(args)):  # poc works standalone; use lhost/lport if a db exists
        try:
            with _open_store(args) as store:
                cfg = config_mod.load(store)
        except FieldkitError:
            pass
    lhost = args.lhost or cfg.get("lhost")
    lport = args.lport or cfg.get("lport")
    res = poc_mod.build(args.format, out, arch=args.arch, command=args.command,
                        lhost=lhost, lport=lport, source=args.source)
    if not res.ok:
        _err(f"build failed ({res.tool}): {res.detail}")
        return 1
    kind = "reverse shell" if (lhost and lport) else f"proof ({args.command or 'whoami/id'})"
    print(f"built {res.fmt} via {res.tool}: {res.path}")
    print(f"  payload: {kind}" + (f"  (arch {args.arch})" if args.format in ("exe", "dll") else ""))
    return 0


@needs_target
def cmd_mssql_escalate(args, store, host, cred):
    allow_cc = "config-change" in (args.allow or [])
    prompt = ("enumerate + escalate MSSQL privileges on "
              + args.host + (" (may add your login to the sysadmin role — reversible)?"
                             if allow_cc else
                             " (read-only enum; add --allow config-change to escalate)?"))
    if not _confirm(prompt, args.yes):
        print("aborted — nothing ran")
        return 1
    rep = mssql_mod.escalate_privs(store, host, cred, allow_config_change=allow_cc,
                                   on_event=lambda m: print(m))
    if rep.aborted:
        _err(rep.aborted)
        return 2

    print()
    nxt = (f"next: `{PROG} enum {args.host}` → "
           f"`{PROG} escalate {args.host} --allow config-change` → SYSTEM (over xp_cmdshell).")
    if rep.status == "xpcmd":
        print("GOT EXEC: xp_cmdshell runs OS commands as the SQL service account (enabled + "
              "verified). Recorded as a finding; your MSSQL access is upgraded to admin, and "
              "disabling xp_cmdshell is on the cleanup manifest.")
        print(nxt)
    elif rep.status == "escalated":
        print(f"ESCALATED: impersonated {rep.via} → added your login to sysadmin → enabled "
              "xp_cmdshell (verified). Recorded as a finding; cleanup (drop the role member, "
              "disable xp_cmdshell) is on the manifest.")
        print(nxt)
    elif rep.status == "already_sysadmin":
        print("you are sysadmin — re-run with `--allow config-change` to enable + confirm "
              f"xp_cmdshell, then `{PROG} enum`/`escalate` run over it.")
    elif rep.status == "gated":
        print(f"impersonatable sysadmin login(s): {', '.join(rep.impersonatable)} — re-run "
              "with `--allow config-change` to grant yourself sysadmin (reversible).")
    elif rep.status == "linked_only":
        print(f"no impersonation path, but RPC-out linked server(s): {', '.join(rep.linked)} "
              "(recorded as observations). Hop with `EXEC ('…') AT [<server>]`.")
    elif rep.status == "failed":
        print("the impersonation grant did not verify as sysadmin — inspect manually.")
    else:
        print("no SQL-layer escalation path found (no impersonatable sysadmin login, no "
              "RPC-out linked servers).")
    return 0


@needs_target
def cmd_postgres_escalate(args, store, host, cred):
    allow_cc = "config-change" in (args.allow or [])
    prompt = (f"enumerate + escalate PostgreSQL privileges on {args.host}:{args.port}"
              + (" (may run `id` on the target via COPY FROM PROGRAM — reversible)?"
                 if allow_cc else
                 " (read-only enum; add --allow config-change to run COPY FROM PROGRAM)?"))
    if not _confirm(prompt, args.yes):
        print("aborted — nothing ran")
        return 1
    rep = postgres_mod.escalate_privs(
        store, host, cred, allow_config_change=allow_cc,
        port=args.port, database=args.database,
        on_event=lambda m: print(m))
    if rep.aborted:
        _err(rep.aborted)
        return 2

    print()
    if rep.status == "exec":
        why = "superuser" if rep.is_superuser else "pg_execute_server_program"
        print(f"GOT EXEC: COPY FROM PROGRAM runs OS commands as the postgres user "
              f"(via {why}). Recorded as a finding; your postgres access is upgraded to admin.")
    elif rep.status == "escalated":
        print(f"ESCALATED: SET ROLE {rep.via} → superuser → COPY FROM PROGRAM (verified).")
    elif rep.status == "already_superuser":
        print("you are superuser — re-run with `--allow config-change` to run + capture "
              "`id` via COPY FROM PROGRAM.")
    elif rep.status == "gated":
        which = rep.escalatable_via or (
            ["pg_execute_server_program"] if rep.exec_role_member else [])
        print(f"escalatable via: {', '.join(which)} — re-run with `--allow config-change`.")
    elif rep.status == "failed":
        print("the escalation attempt did not produce output — inspect manually.")
    else:
        print("no PG-layer escalation path found (not superuser, no superuser role "
              "membership, not a member of pg_execute_server_program).")
    if rep.databases:
        print(f"databases: {', '.join(rep.databases)}")
    return 0


@needs_target
def cmd_mongodb_escalate(args, store, host, cred):
    allow_cc = "config-change" in (args.allow or [])
    prompt = (f"enumerate MongoDB on {args.host}:{args.port}"
              + (" (will dump admin.system.users + count credential-fields — "
                 "read-only against DB state, writes to the audit log)?"
                 if allow_cc else
                 " (surface only; add --allow config-change to dump users/scan data)?"))
    if not _confirm(prompt, args.yes):
        print("aborted — nothing ran")
        return 1
    rep = mongodb_mod.enumerate_privs(
        store, host, cred, allow_config_change=allow_cc,
        port=args.port, database=args.database, scan_data=args.scan_data,
        on_event=lambda m: print(m))
    if rep.aborted:
        _err(rep.aborted)
        return 2

    print()
    if rep.is_unauth:
        print("UNAUTH: MongoDB accepts connections without credentials. Recorded as a "
              "Critical finding; enumerated the surface anonymously.")
    elif rep.privileged_roles:
        print(f"ADMIN: role(s) {', '.join(sorted(set(rep.privileged_roles)))} — full "
              "user + data administration. Recorded as a finding; your mongodb access is "
              "upgraded to admin.")
    elif rep.identity:
        print(f"authenticated as {rep.identity} (no privileged role) — enumerated the "
              "visible databases only.")
    else:
        print("no MongoDB-layer escalation path found.")
    if rep.databases:
        print(f"databases: {', '.join(rep.databases)}")
    if rep.users_dumped:
        print(f"users dumped: {rep.users_dumped} (recorded as loot)")
    if rep.cred_candidates:
        print(f"credential-field candidates: {_plural(len(rep.cred_candidates), 'hit')}")
        for db, coll, field, count in rep.cred_candidates[:8]:
            print(f"  {db}.{coll}.{field}: {count} document(s)")
    return 0


def cmd_lab_test(args):
    with _open_store(args) as store:
        store.require_engagement()
        cfg = config_mod.load(store)
        lab_host = args.host or cfg.get("lab_host")
        if not lab_host:
            _err("no lab host — set one with `fieldkit config set lab_host=<ip>` or pass --host")
            return 2
        host, cred, err = _resolve_target(store, lab_host)
        if err:
            _err(err)
            return 2
        if host["os"] and host["os"] != evasion_mod.WINDOWS:
            _err(f"the lab host {lab_host} is not Windows — the Defender harness is Windows-only")
            return 2
        if not _confirm(f"run the Defender lab probes against {lab_host}? (drops the EICAR "
                        "control + benign probes on the lab)", args.yes):
            print("aborted — nothing ran")
            return 1
        report = lab_mod.run_tests(store, host, cred, allow=("read-only", "config-change"),
                                   on_event=lambda m: print(m))

    if report.aborted:
        _err(report.aborted)
        return 2
    greens = report.green
    print(f"\nlab {lab_host} (signature {report.signature or '?'}): "
          f"{len(greens)} green, {len(report.results) - len(greens)} red")
    if report.skipped:
        print(f"skipped (need a staged benign probe): {', '.join(report.skipped)}")
    print(f"\nsee the full matrix: {PROG} posture")
    return 0


def cmd_posture(args):
    now = datetime.now(timezone.utc)
    with _open_store(args) as store:
        store.require_engagement()
        cfg = config_mod.load(store)
        lab_host = cfg.get("lab_host")
        statuses = [evasion_mod.resolve(t, store.evasion_result(t.key), now=now)
                    for t in evasion_mod.TECHNIQUES]

    label = {evasion_mod.GREEN: "GREEN", evasion_mod.CAUGHT: "RED  caught",
             evasion_mod.STALE: "RED  stale", evasion_mod.UNTESTED: "RED  untested"}
    print("evasion posture — assume-caught: every path is red until the lab proves it clean\n")
    print(f"  lab host: {lab_host or '(unset — `fieldkit config set lab_host=<ip>`)'}")
    proven = [s for s in statuses if s.usable]
    print(f"  {_plural(len(proven), 'technique')} lab-proven green; "
          "the rest are treated as caught.\n")

    for os_name in (evasion_mod.WINDOWS, evasion_mod.LINUX):
        group = evasion_mod.recommend([s for s in statuses if s.technique.os == os_name])
        if not group:
            continue
        print(f"  {os_name}:")
        for s in group:
            t = s.technique
            amsi = "AMSI" if t.amsi_surface else "no-AMSI"
            print(f"    {label[s.verdict]:<13} {t.title:<34} [{amsi}]  {s.reason}")
        print()

    win = evasion_mod.recommend([s for s in statuses if s.technique.os == evasion_mod.WINDOWS])
    order = ", ".join(s.technique.key for s in win)
    print(f"recommended delivery order (Windows, current knowledge):\n  {order}")
    if not proven:
        print(f"\nnothing is lab-proven — run `{PROG} lab test` against a Defender host to earn a green.")
    return 0


def _domain_credential(store):
    for row in store.credentials():
        if row["domain"] and not row["local_auth"]:
            return row
    return None


@needs_engagement
def cmd_roast(args, store):
    dcs = [h for h in store.hosts() if h["is_dc"]]
    dc_ip = args.dc or (dcs[0]["ip"] if dcs else None)
    if not dc_ip:
        _err("no DC known — mark one with `add hosts --dc`, or pass --dc <ip>")
        return 2
    dc_host = store.host_by_ip(dc_ip)
    if dc_host is None:
        _err(f"{dc_ip} is not in the engagement — add it with `fieldkit add hosts <ip>`")
        return 2
    cred = _domain_credential(store)
    if cred is None:
        _err("roasting needs a domain credential — add one with `fieldkit add cred`")
        return 2
    kinds = {"both": ("kerberoast", "asrep_roast"), "kerberoast": ("kerberoast",),
             "asrep": ("asrep_roast",)}[args.kind]
    principal = creds_mod.Credential.from_row(cred).principal
    if not _confirm(f"roast {', '.join(kinds)} against {dc_ip} as {principal}? "
                    "(read-only Kerberos requests)", args.yes):
        print("aborted — nothing ran")
        return 1
    report = kerberos_mod.run_roast(store, dc_host, cred, kinds=kinds,
                                    on_event=lambda m: print(m))
    if report.aborted:
        _err(report.aborted)
        return 2
    print(f"\nrecovered {_plural(report.recovered, 'roast hash')} into loot"
          + (" — crack offline, then `fieldkit add cred` to re-spray"
             if report.recovered else ""))
    return 0


@needs_engagement
def cmd_bloodhound_import(args, store):
    if not os.path.exists(args.path):
        _err(f"{args.path}: no such file or directory")
        return 2
    try:
        counts = bloodhound_mod.import_graph(store, args.path)
    except ValueError as exc:
        _err(str(exc))
        return 2
    paths = bloodhound_mod.owned_paths(store)
    print(f"imported {counts['nodes']} nodes, {counts['edges']} edges "
          f"({counts['high_value']} high-value)")
    if paths:
        print(f"\n{_plural(len(paths), 'owned principal')} reach a high-value target:")
        for p in paths[:10]:
            print(f"  {p['path']}")
        print("\n`fieldkit analyze` ranks these among the next moves.")
    else:
        print("no owned principal reaches a high-value target yet — "
              "own more credentials (spray/roast) and re-check with `fieldkit analyze`.")
    return 0


@needs_engagement
def cmd_delegation(args, store):
    dcs = [h for h in store.hosts() if h["is_dc"]]
    dc_ip = args.dc or (dcs[0]["ip"] if dcs else None)
    if not dc_ip:
        _err("no DC known — mark one with `add hosts --dc`, or pass --dc <ip>")
        return 2
    dc_host = store.host_by_ip(dc_ip)
    if dc_host is None:
        _err(f"{dc_ip} is not in the engagement — add it with `fieldkit add hosts <ip>`")
        return 2
    cred = _domain_credential(store)
    if cred is None:
        _err("finding delegation needs a domain credential — add one with `add cred`")
        return 2
    principal = creds_mod.Credential.from_row(cred).principal
    if not _confirm(f"enumerate Kerberos delegation on {dc_ip} as {principal}? "
                    "(nxc --find-delegation, read-only)", args.yes):
        print("aborted — nothing ran")
        return 1
    report = delegation_mod.run_find(store, dc_host, cred, on_event=lambda m: print(m))
    if report.aborted:
        _err(report.aborted)
        return 2
    print(f"\nfound {_plural(report.found, 'delegation')} — "
          "`fieldkit analyze` ranks them, `fieldkit report` writes them up")
    return 0


@needs_engagement
def cmd_adcs_find(args, store):
    dcs = [h for h in store.hosts() if h["is_dc"]]
    dc_ip = args.dc or (dcs[0]["ip"] if dcs else None)
    if not dc_ip:
        _err("no DC/CA known — mark one with `add hosts --dc`, or pass --dc <ip>")
        return 2
    dc_host = store.host_by_ip(dc_ip)
    if dc_host is None:
        _err(f"{dc_ip} is not in the engagement — add it with `fieldkit add hosts <ip>`")
        return 2
    cred = _domain_credential(store)
    if cred is None:
        _err("certipy needs a domain credential — add one with `fieldkit add cred`")
        return 2
    principal = creds_mod.Credential.from_row(cred).principal
    if not _confirm(f"enumerate vulnerable certificate templates on {dc_ip} as "
                    f"{principal}? (certipy find, read-only)", args.yes):
        print("aborted — nothing ran")
        return 1
    report = adcs_mod.run_find(store, dc_host, cred, on_event=lambda m: print(m))
    if report.aborted:
        _err(report.aborted)
        return 2
    print(f"\nfound {_plural(report.found, 'vulnerable template')} — "
          "`fieldkit analyze` ranks them, `fieldkit report` writes them up")
    return 0


@needs_engagement
def cmd_report(args, store):
    # Observations are in the report by default now; --proven-only drops them. (--all is a
    # retired no-op alias — it used to be the way to include observations.)
    cfg = config_mod.load(store)
    engagement, findings = report_mod.build(store, cfg, proven_only=args.proven_only)

    proven = [f for f in findings if f.get("proven", True)]
    errors, warns = report_mod.check(findings)
    if args.check:
        # A --check with zero findings is not a real OK — it's a nothing-to-check.
        # The old "CHECK OK: 0 proven findings" read as green even though nothing
        # had been proven; a tester ran --check before doing any work and got
        # false confidence. Say what actually happened.
        if not findings:
            print("nothing to check — no findings recorded yet. Run "
                  "`fieldkit escalate` / `fieldkit run` to prove a vector first, "
                  "then re-run `fieldkit report --check`.")
            return 1
        for tag, m in errors:
            print(f"  ERROR  [{tag}] {m}")
        for tag, m in warns:
            print(f"  warn   [{tag}] {m}")
        if errors:
            print(f"CHECK FAILED: {len(errors)} error(s), {len(warns)} warning(s).")
            return 2
        print(f"CHECK OK: {_plural(len(proven), 'proven finding')}, "
              f"{len(warns)} warning(s) — every proven finding carries its captured proof.")
        return 0

    if args.cleanup:
        # only proven findings made changes to a target — observations weren't exploited.
        path = f"{args.out}.cleanup.md"
        with open(path, "w") as fh:
            fh.write(report_mod.cleanup_manifest(engagement, proven))
        print(f"wrote {path}  (INTERNAL cleanup manifest — do not send to the client)")
        return 0

    if errors and not args.force:
        for tag, m in errors:
            print(f"  ERROR  [{tag}] {m}")
        _err(f"refusing to render: {_plural(len(errors), 'anti-fabrication error')} "
             "(a proven finding without captured proof). Fix them, or pass --force.")
        return 2

    # Refuse to write empty deliverables. Producing three near-empty files
    # (report.md, report.docx, report.pdf) in CWD before the engagement has any
    # findings just clutters the tester's workspace. --force is the operator
    # opt-in for "yes, write it anyway (I'm checking a template render)".
    if not findings and not args.force:
        _err("nothing to report yet — no findings recorded. Run `fieldkit escalate` "
             "or `fieldkit run` to prove a vector first, or pass --force to write "
             "an empty template.")
        return 1

    formats = [x.strip() for x in args.formats.split(",") if x.strip()]
    md = report_mod.render_markdown(engagement, findings)
    md_path = f"{args.out}.md"
    with open(md_path, "w") as fh:
        fh.write(md)
    obs = len(findings) - len(proven)
    tally = _plural(len(proven), "finding") + (f" + {_plural(obs, 'observation')}" if obs else "")
    print(f"wrote {md_path}  ({tally})")
    for line in report_mod.export(md_path, args.out, formats):
        print(line)
    if not proven:
        print("note: no proven findings yet — run `fieldkit run`/`escalate` to prove vectors "
              "(the report currently holds only observations).")
    return 0


@needs_engagement
def cmd_export_recce(args, store):
    import json
    cfg = config_mod.load(store)
    engagement, findings = report_mod.build(store, cfg, proven_only=not args.all)
    if not findings:
        _err("no proven findings to export — run `fieldkit run` to prove vectors first "
             "(or --all to include unproven)")
        return 2
    payload = bridge_mod.export_payload(engagement, findings)
    dest = args.out or "recce_findings.json"
    with open(dest, "w") as fh:
        json.dump(payload, fh, indent=2)
    print(f"wrote {dest}  ({_plural(len(findings), 'finding')}, KB-enriched for recce)")
    print(f"  fold into the recce workbook + report:  recce fieldkit-import {dest} -o <engagement>")
    return 0


def cmd_wordlist(args):
    """Generate a targeted wordlist from seed words + inspectable mutation rules."""
    if getattr(args, "rules", False):
        print("wordlist mutation rules (all pure, inspectable):\n")
        for r in wordlist_mod.RULES:
            print(f"  {r.name:<10} {r.description}")
        print("\nseed input:")
        print("  positional args, --from-file <path>, --from-text <text> (any/all)")
        print("\ndefaults:  cases + leet + suffix ON; "
              "prefix/combine/season/walks/wrapped OFF")
        print("presets:   --long  →  min-len 12, max-len 16, walks+wrapped ON "
              "(modern ≥12-char engagement shape)")
        return 0

    seeds = list(args.seeds or [])
    if args.from_file:
        try:
            with open(args.from_file, "r", errors="replace") as fh:
                for line in fh:
                    w = line.strip()
                    if w and not w.startswith("#"):
                        seeds.append(w)
        except OSError as exc:
            _err(f"--from-file {args.from_file}: {exc}")
            return 2
    if args.from_text:
        seeds.extend(wordlist_mod.seeds_from_text(args.from_text))
    # --walks alone produces a standalone list; no seeds required. Same for --long
    # when the operator wants just keyboard walks in the 12-16 band.
    if not seeds and not args.walks and not args.long:
        _err("no seeds — give words as positional args, `--from-file <path>`, "
             "`--from-text \"<about-page copy>\"`, or use `--walks` for a "
             "seedless keyboard-walk list. `fieldkit wordlist --rules` shows "
             "how each seed will be expanded.")
        return 2

    years = args.years or ()
    # --long is a preset for the modern ≥12-char engagement shape the operator
    # described: keyboard walks + phrase wrapped by symbols/numbers, in the
    # 12–16 char band. It layers on top; explicit --min-len/--max-len still win.
    if args.long:
        if not args.walks and not args.wrapped:
            args.walks = args.wrapped = True
        if args.min_len == 6:            # only if operator didn't override
            args.min_len = 12
        if args.max_len == 32:
            args.max_len = 16
    rep = wordlist_mod.generate(
        seeds, years=years, seasons=args.seasons, combine=args.combine,
        walks=args.walks, wrapped=args.wrapped,
        cases=not args.no_cases, leet=not args.no_leet, suffixes=not args.no_suffixes,
        prefixes=args.prefixes, extra_suffixes=args.suffix or (),
        extra_prefixes=args.prefix or (),
        min_len=args.min_len, max_len=args.max_len, max_output=args.max)

    if args.out:
        try:
            with open(args.out, "w") as fh:
                fh.write("\n".join(rep.words) + "\n")
        except OSError as exc:
            _err(f"--out {args.out}: {exc}")
            return 2
        note = " (truncated at --max)" if rep.truncated else ""
        print(f"wrote {args.out}  ({rep.total} words from "
              f"{_plural(len(seeds), 'seed')}; rules: {', '.join(rep.rules)}){note}")
        print(f"  use it: `{PROG} spray --wordlist --passlist {args.out}`")
    else:
        for w in rep.words:
            print(w)
    return 0


def cmd_arsenal_list(args):
    st = arsenal_mod.staged()
    root = arsenal_mod.arsenal_dir()
    if not st:
        print(f"nothing staged in {root} — run `sh exploits/fetch.sh` on a connected box.")
        return 0
    total = sum(len(v) for v in st.values())
    print(f"staged arsenal ({total} artifacts in {root}):\n")
    for cat, names in st.items():
        print(f"  {cat} ({len(names)})")
        print("    " + ", ".join(names))
    return 0


def cmd_arsenal_find(args):
    p = arsenal_mod.find(args.name)
    if p:
        print(p)
        return 0
    _err(f"{args.name!r} is not staged (checked {arsenal_mod.arsenal_dir()})")
    return 1


def _resolutions():
    out = []
    for key, need in sorted(arsenal_mod.PRIVESC_NEEDS.items()):
        out.append(("privesc", arsenal_mod.resolve(key, need)))
    for key, need in sorted(arsenal_mod.EVASION_NEEDS.items()):
        out.append(("evasion", arsenal_mod.resolve(key, need)))
    return out


def cmd_arsenal_check(args):
    res = _resolutions()
    marks = {arsenal_mod.BUILTIN: "native", arsenal_mod.BUILD: "build",
             arsenal_mod.STAGED: "staged", arsenal_mod.SUPPLIED: "supply"}
    gaps = [(g, r) for g, r in res if not r.ready]
    print("arsenal readiness — what each route needs to fire:\n")
    if args.all:
        for group, r in res:
            flag = "OK " if r.ready else "!! "
            print(f"  {flag}[{marks[r.need.kind]:<6}] {group}:{r.key:<24} {r.detail}")
        print()
    print(f"{_plural(len(gaps), 'gap')} — routes that need an artifact you must stage/supply:")
    if not gaps:
        print("  (none — every mapped route is native, buildable, or already staged)")
    for _, r in gaps:
        print(f"  !! {r.key:<24} {r.need.hint}")
        print(f"       {r.detail}")
    print("\n(build-kind routes are produced by `fieldkit poc`; run with --all for the full map)")
    return 0


def _current_phase(counts):
    """Where in the engagement workflow the state says we are."""
    if not counts["hosts"] and not counts["credentials"]:
        return "setup", f"`{PROG} add hosts <scope>` and `{PROG} add cred <cred>`"
    if not counts["hosts"]:
        return "setup", f"`{PROG} add hosts <scope>`"
    if not counts["credentials"]:
        return "setup", f"`{PROG} add cred <cred>` (or `{PROG} spray --wordlist`)"
    if not counts["access"]:
        return "spraying", f"`{PROG} spray` to validate stored credentials"
    if not counts["findings"]:
        return "enumeration", (
            f"`{PROG} enum <host>` on a Pwn3d host, then `{PROG} analyze`")
    if not counts["proven_findings"]:
        return "exploitation", (
            f"`{PROG} escalate <host> --allow config-change` to prove a vector")
    return "reporting", f"`{PROG} report` and `{PROG} export-recce`"


def _next_moves(store, cfg, limit=3):
    """The top-``limit`` opportunities from analyze, ranked."""
    items = list(kb_mod.analyze(store))
    items += privesc_mod.vectors_from_state(store, **_stage_dirs(cfg))
    items.sort(key=lambda x: -x.score)
    return items[:limit]


@needs_engagement
def cmd_status(args, store):
    row = store.require_engagement()
    cfg = config_mod.load(store)
    counts = store.counts()

    print(f"engagement:  {row['name']}   created {row['created']}")
    print(f"database:    {store.path}")
    summary = "  ".join(
        f"{k}={cfg.get(k)}" for k in config_mod.HEADLINE_KEYS if cfg.get(k))
    overrides = cfg.overrides()
    print(f"config:      {summary or '(unset — run `fieldkit config set lhost=…`)'}"
          + (f"   (+{_plural(len(overrides), 'subnet override')})" if overrides else ""))
    scope_rules = store.scope_rules()
    if scope_rules:
        by_kind = {}
        for r in scope_rules:
            by_kind.setdefault(r["kind"], []).append(r["cidr"])
        parts = [f"{k}={','.join(v)}" for k, v in sorted(by_kind.items())]
        print(f"scope:       {' · '.join(parts)}")
    print()

    os_mix = "  ".join(f"{r['os'] or 'unfingerprinted'} {r['n']}"
                       for r in store.host_os_breakdown())
    cred_mix = "  ".join(f"{r['secret_type']} {r['n']}"
                         for r in store.credential_type_breakdown())
    print(f"hosts        {counts['hosts']:>5}   {os_mix}")
    print(f"services     {counts['services']:>5}")
    print(f"credentials  {counts['credentials']:>5}   {cred_mix}")
    print(f"access       {counts['access']:>5}   "
          f"{counts['admin_access']} admin on {_plural(counts['admin_hosts'], 'host')}")
    print(f"findings     {counts['findings']:>5}   {counts['proven_findings']} proven")
    print(f"loot         {counts['loot']:>5}")

    # --- situational board: phase, top-3 next moves, preflight, blockers -----
    phase, phase_hint = _current_phase(counts)
    print(f"\nphase:       {phase}")
    print(f"next:        {phase_hint}")

    # Where am I hot? A tester coming back after a break wants to know THE IPS,
    # not just the count. "3 admin on 3 hosts" hides which ones — this line
    # names them so `enum <ip>` / `escalate <ip>` are one glance away.
    if counts["admin_hosts"]:
        pwned = store.admin_hosts()
        labels = [(f"{h['ip']} ({h['hostname']})" if h["hostname"] else h["ip"])
                  + (" — DC" if h["is_dc"] else "")
                  for h in pwned[:8]]
        more = f" (+{len(pwned) - 8} more)" if len(pwned) > 8 else ""
        print(f"pwned:       {', '.join(labels)}{more}")

    # Show top-3 ranked opportunities when there ARE any (skipped in setup phase
    # to keep the empty-engagement output short).
    if counts["access"]:
        moves = _next_moves(store, cfg)
        if moves:
            print("\ntop moves (ranked):")
            for m in moves:
                where = f" [{m.host}]" if getattr(m, "host", None) else ""
                mark = "manual" if getattr(m, "manual", False) else "run"
                print(f"  {m.axes:<22} {m.title[:56]:<56}{where}  ({mark})")

    # Preflight — surface missing required tools once here so the operator
    # doesn't discover nxc is missing mid-run.
    pf_missing = preflight_mod.missing_required(preflight_mod.check())
    if pf_missing:
        labels = ", ".join(r[0] for r in pf_missing)
        print(f"\n⚠ required tools missing: {labels} — "
              f"`{PROG} preflight` for the full list")

    if args.hosts:
        print("\nhosts:")
        for host in store.hosts():
            print(f"  {host['ip']:<39} {host['hostname'] or '':<20} "
                  f"{host['os'] or '':<8} {host['subnet'] or ''}"
                  + ("  DC" if host["is_dc"] else ""))
    if args.creds:
        print("\ncredentials:")
        for row in store.credentials():
            cred = creds_mod.Credential.from_row(row)
            print(f"  {cred.principal:<32} {cred.secret_type:<9} source={row['source']}")
    return 0


# -------------------------------------------------------------------------- parser

def build_parser():
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Stateful internal-AD execution engine. Authorized engagements only.")
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    parser.add_argument("--db", metavar="PATH",
                        help=f"engagement database (default: ${DB_ENV_VAR} or ./engagement.db)")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    p_init = sub.add_parser("init", help="create ./engagement.db")
    p_init.add_argument("name", nargs="?", help="engagement name (default: directory name)")
    p_init.set_defaults(func=cmd_init)

    p_config = sub.add_parser("config", help="engagement config (lhost/lport/domain/…)")
    config_sub = p_config.add_subparsers(dest="config_command", metavar="<action>")

    c_show = config_sub.add_parser("show", help="print every key")
    c_show.set_defaults(func=cmd_config_show)

    c_get = config_sub.add_parser("get", help="print one key")
    c_get.add_argument("key")
    c_get.set_defaults(func=cmd_config_get)

    c_set = config_sub.add_parser("set", help="set keys, e.g. lhost=10.10.14.7 lport=443")
    c_set.add_argument("assignments", nargs="+", metavar="key=value")
    c_set.add_argument("--subnet", metavar="CIDR",
                       help="scope this lhost to one segment (per-subnet override)")
    c_set.set_defaults(func=cmd_config_set)

    c_unset = config_sub.add_parser("unset", help="remove a key or a subnet override")
    c_unset.add_argument("key", nargs="?")
    c_unset.add_argument("--subnet", metavar="CIDR")
    c_unset.set_defaults(func=cmd_config_unset)
    p_config.set_defaults(func=cmd_config_show)  # bare `config` shows everything

    p_add = sub.add_parser("add", help="add credentials or hosts")
    add_sub = p_add.add_subparsers(dest="add_command", metavar="<what>")

    a_cred = add_sub.add_parser(
        "cred", help="add a credential in whatever form you have it",
        description="""Pass the credential the way you already have it — the parser
autodetects the shape and picks the right auth flow.

Examples (just quote the whole thing):

  fieldkit add cred 'jdoe:Winter2025!'                    (plain user + password)
  fieldkit add cred 'CORP/jdoe:Winter2025!'               (domain user + password)
  fieldkit add cred 'CORP\\jdoe:Winter2025!'                 (Windows-style domain)
  fieldkit add cred 'jdoe@corp.local:Winter2025!'         (UPN)
  fieldkit add cred '.\\Administrator:P@ss'                  (local account, -> --local-auth)
  fieldkit add cred 'jdoe:31d6cfe0d16ae931b73c59d7e0c089c0' (NT hash — autodetected)
  fieldkit add cred 'jdoe:aad3b435...ee:31d6cfe...c0'     (LM:NT hash pair)
  fieldkit add cred ':31d6cfe0d16ae931b73c59d7e0c089c0' --user Administrator --local

The individual flags below (--user, --hash, --password, ...) are only needed when
the spec is missing that field. `--from-file` reads one credential per line.
`--source` tags the audit trail on the report (default: manual).""",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    a_cred.add_argument("spec", nargs="?", metavar="CREDENTIAL",
                        help="the credential as you have it — see examples above")
    a_cred.add_argument("--user", help="username, when the spec has none")
    a_cred.add_argument("--domain", help="AD domain (overrides the spec)")
    a_cred.add_argument("--password", help="password, when the spec has none")
    a_cred.add_argument("--hash", help="NT hash (or LM:NT)")
    a_cred.add_argument("--aes", help="Kerberos AES128/256 key (hex)")
    a_cred.add_argument("--ccache", help="path to a Kerberos ccache")
    a_cred.add_argument("--ssh-key", dest="ssh_key", help="path to an SSH private key")
    a_cred.add_argument("--local", action="store_true",
                        help="local account (tools get --local-auth, not -d)")
    a_cred.add_argument("--source", default="manual",
                        help="where it came from: manual/spray/sam/lsa/gpp/ntds/… (default: manual)")
    a_cred.add_argument("--from-file", metavar="FILE", help="one credential per line")
    a_cred.add_argument("-y", "--yes", action="store_true", help="skip the confirm-back")
    a_cred.set_defaults(func=cmd_add_cred)

    a_hosts = add_sub.add_parser("hosts", help="add scope: IPs, CIDRs, or a scope file")
    a_hosts.add_argument("targets", nargs="*", help="IP, CIDR, or a path to a scope file")
    a_hosts.add_argument("--file", help="scope file (one entry per line)")
    a_hosts.add_argument("--os", choices=["windows", "linux", "other"], help="record the OS")
    a_hosts.add_argument("--dc", action="store_true", help="mark these as domain controllers")
    a_hosts.add_argument("--subnet", help="override the derived subnet label")
    a_hosts.add_argument("--max-expand", type=int, default=scope_mod.DEFAULT_MAX_EXPAND,
                         help="max hosts one CIDR may expand to (default: %(default)s)")
    a_hosts.set_defaults(func=cmd_add_hosts)
    p_add.set_defaults(func=lambda a: _missing(p_add))

    p_scope = sub.add_parser(
        "scope", help="engagement scope rules (allow/deny CIDRs)",
        description="Optional engagement-scope enforcement. With no rules, every "
                    "IP is allowed (backward-compat: an engagement that never sets "
                    "up scope rules works as it always did). Add allow rules to "
                    "narrow the engagement to specific CIDRs; add deny rules to "
                    "carve exceptions. Deny always wins. `add hosts` refuses IPs "
                    "outside scope; commands taking a single IP report the exact "
                    "scope violation rather than 'not in scope' being confused "
                    "with 'not in the engagement database'.")
    scope_sub = p_scope.add_subparsers(dest="scope_command", metavar="<action>")
    s_show = scope_sub.add_parser("show", help="list the current rules")
    s_show.set_defaults(func=cmd_scope_show)
    s_allow = scope_sub.add_parser(
        "allow", help="add one or more allow CIDRs (narrows the scope)",
        description="Everything OUTSIDE these CIDRs is rejected. Add several by "
                    "listing them; each is normalized (10.0.0.5/24 -> 10.0.0.0/24).")
    s_allow.add_argument("cidrs", nargs="+", metavar="CIDR", help="CIDR to allow")
    s_allow.add_argument("--notes", metavar="TEXT", help="engagement notes for this rule")
    s_allow.set_defaults(func=cmd_scope_add, deny=False)
    s_deny = scope_sub.add_parser(
        "deny", help="add one or more deny CIDRs (carve exceptions)",
        description="Carve an exception out of a broader allow. E.g. 10.0.0.0/16 "
                    "allowed + 10.0.10.0/24 denied = the /16 minus the /24.")
    s_deny.add_argument("cidrs", nargs="+", metavar="CIDR", help="CIDR to deny")
    s_deny.add_argument("--notes", metavar="TEXT", help="engagement notes for this rule")
    s_deny.set_defaults(func=cmd_scope_add, deny=True)
    s_clear = scope_sub.add_parser("clear", help="drop every scope rule (enforcement OFF)")
    s_clear.add_argument("-y", "--yes", action="store_true", help="skip the confirm-back")
    s_clear.set_defaults(func=cmd_scope_clear)
    p_scope.set_defaults(func=lambda a: _missing(p_scope))

    p_ingest = sub.add_parser("ingest", help="fold captured tool output into state")
    ingest_sub = p_ingest.add_subparsers(dest="ingest_command", metavar="<tool>")
    i_nxc = ingest_sub.add_parser(
        "nxc", help="record a saved netexec capture (valid creds + (Pwn3d!) access)",
        description="Reads nxc output from a file or stdin, records every [+] "
                    "credential and (Pwn3d!) admin result, and enriches scope from "
                    "the [*] banners. The offline twin of `fieldkit spray`.")
    i_nxc.add_argument("file", nargs="?", help="capture file (default: stdin)")
    i_nxc.add_argument("--source", default="spray",
                       help="where these results came from (default: spray)")
    i_nxc.add_argument("-y", "--yes", action="store_true", help="skip the confirm-back")
    i_nxc.set_defaults(func=cmd_ingest_nxc)
    p_ingest.set_defaults(func=lambda a: _missing(p_ingest))

    p_spray = sub.add_parser(
        "spray", help="validate stored creds across scope and run the credential loop",
        description="Sprays every stored credential across the scope on one protocol, "
                    "records who is valid and who is admin ((Pwn3d!)), dumps SAM+LSA on "
                    "owned hosts, promotes recovered secrets to credentials, and repeats "
                    "until dry. Reuses each account's own proven secret, so it cannot "
                    "lock a domain account.")
    p_spray.add_argument("proto", nargs="?", default="smb",
                         help=f"protocol: {', '.join(spray_mod.PROTOCOLS)} (default: smb)")
    p_spray.add_argument("--subnet", metavar="CIDR", help="limit to one segment")
    p_spray.add_argument("--dc", metavar="IP", help="read the lockout policy from this DC")
    p_spray.add_argument("--no-loot", action="store_true",
                         help="do not dump SAM/LSA on owned hosts")
    p_spray.add_argument("--no-policy", action="store_true",
                         help="skip reading the domain password policy first")
    p_spray.add_argument("--timeout", type=int, default=600,
                         help="per-command timeout in seconds (default: %(default)s)")
    p_spray.add_argument("-y", "--yes", action="store_true",
                         help="run without the confirm-back")
    # wordlist-spray mode: switches from "stored creds, safe by construction" to
    # "user × password combos, CAN lock accounts if the lockout policy is respected."
    p_spray.add_argument("--wordlist", action="store_true",
                         help="run wordlist × password spray instead of stored-cred spray "
                              "(uses --userlist / --passlist, or the config keys)")
    p_spray.add_argument("--userlist", metavar="FILE",
                         help="path to a userlist for --wordlist (overrides config userlist)")
    p_spray.add_argument("--passlist", metavar="FILE",
                         help="path to a passlist for --wordlist (overrides config passlist)")
    p_spray.add_argument("--allow-lockout-risk", action="store_true",
                         help="proceed with --wordlist even when the passlist exceeds the "
                              "lockout policy's safe attempts per window (accepts the risk)")
    p_spray.set_defaults(func=cmd_spray)

    p_spider = sub.add_parser(
        "spider", help="spider readable SMB shares, scrub files for secrets, promote creds",
        description="Drives `nxc smb -M spider_plus` against one host: downloads every "
                    "file under 50KB from every readable share and scrubs the corpus "
                    "against an inspectable ruleset (GPP cpassword, unattend.xml, "
                    "web.config, key=value scripts, sensitive filenames). Every hit is "
                    "loot; a plaintext user+password (GPP, unattend, .ps1 -Password) is "
                    "promoted straight into the credential loop. Holding a bulk copy of "
                    "the client's files is recorded as a deletion obligation in the "
                    "cleanup manifest so the report says so.")
    p_spider.add_argument("host", metavar="HOST",
                          help="target IP/hostname (must be a Windows SMB service)")
    p_spider.add_argument("--out", metavar="DIR",
                          help="local download folder (default: build/spider-<host>/)")
    p_spider.add_argument("--no-promote", action="store_true",
                          help="record hits as loot only, do not promote to credentials")
    p_spider.add_argument("-y", "--yes", action="store_true",
                          help="run without the confirm-back")
    p_spider.set_defaults(func=cmd_spider)

    p_scrub = sub.add_parser(
        "scrub", help="on-box filesystem scrub of a Linux foothold for cleartext secrets",
        description="Same scrubbers as `spider`, but against the local filesystem of a "
                    "Linux foothold you already own. One `find | cat` pipeline sweeps "
                    "/etc, /opt, $HOME, /var/www (or the paths you pass) for config "
                    "files that carry credentials (kv-secret, dotenv, YAML), sensitive "
                    "filenames (id_rsa, .env, .git-credentials, .pfx), and web.config "
                    "connection strings. Recovered credentials are promoted; the rest "
                    "become loot. Read-only against the target.")
    p_scrub.add_argument("host", metavar="HOST",
                         help="target IP/hostname (must be a Linux foothold with proven access)")
    p_scrub.add_argument("paths", nargs="*", metavar="PATH",
                         help="paths to scrub (default: /etc /opt /root /home /var/www /srv)")
    p_scrub.add_argument("-y", "--yes", action="store_true",
                         help="run without the confirm-back")
    p_scrub.set_defaults(func=cmd_scrub)

    p_analyze = sub.add_parser(
        "analyze", help="rank the next moves from what the loop has proved",
        description="Reads state and ranks privesc/lateral opportunities by "
                    "exploitability x safety x detection. Read-only — it names the "
                    "next move, it does not run it.")
    p_analyze.add_argument("--proof", action="store_true",
                           help="show each opportunity's safe-proof (report evidence)")
    p_analyze.set_defaults(func=cmd_analyze)

    p_enum = sub.add_parser(
        "enum", help="enumerate a host you have a foothold on (read-only, captured)",
        description="Runs the OS-appropriate privesc enumeration on a host through the "
                    "read-only executor, captures every check as evidence, and prints "
                    "the signals that feed `analyze`.")
    p_enum.add_argument("host", metavar="IP", help="a host you already have access on")
    p_enum.add_argument("-y", "--yes", action="store_true", help="skip the confirm-back")
    p_enum.set_defaults(func=cmd_enum)

    p_run = sub.add_parser(
        "run", help="fire a privesc vector on a host, captured, through the safety gate",
        description="Runs one vector from `analyze` on a host. read-only vectors run "
                    "after a confirm; config-change/crash-risk vectors need an explicit "
                    "--allow. Output, the finding and any cleanup artifact are recorded.")
    p_run.add_argument("host", metavar="IP", help="the host to escalate on")
    p_run.add_argument("vector", help="the vector key from `analyze` (e.g. sudo:find)")
    p_run.add_argument("--allow", action="append",
                       choices=["config-change", "crash-risk"], metavar="LEVEL",
                       help="permit a riskier vector (repeatable)")
    p_run.add_argument("-y", "--yes", action="store_true", help="skip the confirm-back")
    p_run.set_defaults(func=cmd_run)

    p_esc = sub.add_parser(
        "escalate", help="walk the ranked vectors automatically, stopping at first proof",
        description="The orchestrator: fires the best-ranked vector on a host, classifies "
                    "the result, and follows the fallback axis — advance to the next "
                    "vector, retry a timeout, stop on proof, or halt on anything it does "
                    "not recognise. Vectors above --allow are skipped, never fired. Every "
                    "step is captured and the winning vector is recorded as a finding.")
    p_esc.add_argument("host", metavar="IP", nargs="?", help="the host to escalate on")
    p_esc.add_argument("--allow", action="append",
                       choices=["config-change", "crash-risk"], metavar="LEVEL",
                       help="permit riskier vectors in the loop (repeatable)")
    p_esc.add_argument("--max", type=int, metavar="N",
                       help=f"cap vectors fired (default {escalate_mod.DEFAULT_BUDGET})")
    p_esc.add_argument("--no-stage", action="store_true",
                       help="don't auto-stage/build a missing artifact on a miss")
    p_esc.add_argument("--dry-run", action="store_true",
                       help="print the ranked plan and exit without firing")
    p_esc.add_argument("--rules", action="store_true",
                       help="print the axis→action policy table and exit")
    p_esc.add_argument("-y", "--yes", action="store_true", help="skip the confirm-back")
    p_esc.set_defaults(func=cmd_escalate)

    p_poc = sub.add_parser(
        "poc", help="build a payload artifact (msi/exe/dll/so/ps1) by driving the toolchain",
        description="Drives the operator's builders (msfvenom/wixl/gcc/mingw) to produce "
                    "an artifact a vector needs. Orchestration only — the bytes come from "
                    "msfvenom or your --source; fieldkit templates benign scaffolding and "
                    "builds a whoami/id proof by default (--lhost/--lport for a revshell). "
                    "The escalate loop calls this automatically on a build-kind miss.")
    p_poc.add_argument("format", nargs="?", choices=sorted(poc_mod.RECIPES),
                       help="artifact format to build")
    p_poc.add_argument("-o", "--out", metavar="PATH", help="output path (default: ~/.fieldkit/build)")
    p_poc.add_argument("--arch", choices=["x64", "x86"], default="x64",
                       help="target arch for exe/dll (default x64)")
    p_poc.add_argument("--command", metavar="CMD",
                       help="command the artifact runs (default: a whoami/id proof)")
    p_poc.add_argument("--lhost", help="reverse-shell LHOST (msfvenom payload instead of a proof)")
    p_poc.add_argument("--lport", help="reverse-shell LPORT")
    p_poc.add_argument("--source", metavar="FILE", help="compile this .c with mingw (exe/dll)")
    p_poc.add_argument("--obfuscate", metavar="EXE",
                       help="obfuscate a compiled .NET assembly with ConfuserEx (path or arsenal name)")
    p_poc.add_argument("--confuser", metavar="PATH",
                       help="path to the ConfuserEx CLI (else config confuser_cli / PATH)")
    p_poc.add_argument("--check", action="store_true", help="report which builders are installed")
    p_poc.set_defaults(func=cmd_poc)

    p_preflight = sub.add_parser(
        "preflight", help="check which tools fieldkit drives are installed on PATH",
        description="Lists the external tools fieldkit drives (netexec + impacket are the "
                    "spine; certipy/evil-winrm/msfvenom/wixl/gcc/mingw/pandoc are "
                    "per-feature) and whether each is on PATH. Exits non-zero if a required "
                    "tool is missing.")
    p_preflight.set_defaults(func=cmd_preflight)

    p_prep = sub.add_parser(
        "prep", help="build a manual route's artifact + print where to place it and the steps",
        description="Proactive provision for routes the loop can't one-shot (overwrite a "
                    "running service binary, plant a hijack DLL): fieldkit builds the "
                    "artifact and prints the placement path + ordered operator steps. "
                    "--stage also uploads it to the target's stage dir.")
    p_prep.add_argument("host", metavar="IP", help="the host the vector is on")
    p_prep.add_argument("vector", help="the manual vector key (e.g. writablesvc:AppMgmt)")
    p_prep.add_argument("--stage", action="store_true",
                        help="also upload the built artifact to the target (config-change)")
    p_prep.add_argument("-y", "--yes", action="store_true", help="skip the confirm when staging")
    p_prep.set_defaults(func=cmd_prep)

    p_lab = sub.add_parser(
        "lab", help="prove evasion techniques against a Defender lab host")
    lab_sub = p_lab.add_subparsers(dest="lab_command", metavar="<action>")
    l_test = lab_sub.add_parser(
        "test", help="run the benign probes and record Defender's verdict",
        description="Confirms the lab's Defender is live (EICAR control), then runs a "
                    "benign probe per technique and records green/red from Defender's "
                    "own verdict. Refuses to report greens from an unprotected lab.")
    l_test.add_argument("--host", metavar="IP", help="lab host (default: config lab_host)")
    l_test.add_argument("-y", "--yes", action="store_true", help="skip the confirm-back")
    l_test.set_defaults(func=cmd_lab_test)
    p_lab.set_defaults(func=lambda a: _missing(p_lab))

    p_posture = sub.add_parser(
        "posture", help="the evasion green/red matrix + recommended delivery",
        description="Shows every technique's status under assume-caught (red until a "
                    "fresh lab result proves it clean) and the recommended delivery order.")
    p_posture.set_defaults(func=cmd_posture)

    p_roast = sub.add_parser(
        "roast", help="Kerberoast / AS-REP roast a DC into crackable loot",
        description="Drives nxc's Kerberos roasting against a DC with a domain "
                    "credential, stores the $krb5tgs$/$krb5asrep$ hashes as loot, and "
                    "feeds the loop — crack offline, then `add cred` the result.")
    p_roast.add_argument("--dc", metavar="IP", help="DC to roast (default: a host marked --dc)")
    p_roast.add_argument("--kind", choices=["both", "kerberoast", "asrep"], default="both",
                         help="which roast (default: both)")
    p_roast.add_argument("-y", "--yes", action="store_true", help="skip the confirm-back")
    p_roast.set_defaults(func=cmd_roast)

    p_bh = sub.add_parser("bloodhound", help="ingest SharpHound data + find owned→DA paths")
    bh_sub = p_bh.add_subparsers(dest="bloodhound_command", metavar="<action>")
    b_import = bh_sub.add_parser(
        "import", help="load SharpHound JSON (zip/dir) and path-find from owned creds",
        description="Stores the AD control graph (MemberOf/AdminTo/dangerous ACEs) and "
                    "reports which owned principals reach a high-value target.")
    b_import.add_argument("path", help="SharpHound .zip, a directory of JSON, or a .json")
    b_import.set_defaults(func=cmd_bloodhound_import)
    p_bh.set_defaults(func=lambda a: _missing(p_bh))

    p_deleg = sub.add_parser(
        "delegation", help="find Kerberos delegation (unconstrained/constrained/RBCD)",
        description="Drives nxc --find-delegation with a domain credential and records "
                    "each delegated account as a finding for analyze/report.")
    p_deleg.add_argument("--dc", metavar="IP", help="DC to query (default: a host marked --dc)")
    p_deleg.add_argument("-y", "--yes", action="store_true", help="skip the confirm-back")
    p_deleg.set_defaults(func=cmd_delegation)

    p_adcs = sub.add_parser("adcs", help="AD Certificate Services (certipy) enumeration")
    adcs_sub = p_adcs.add_subparsers(dest="adcs_command", metavar="<action>")
    a_find = adcs_sub.add_parser(
        "find", help="enumerate vulnerable certificate templates (ESC1-16)",
        description="Drives `certipy find -vulnerable` with a domain credential and "
                    "records each ESC weakness as a finding for analyze/report.")
    a_find.add_argument("--dc", metavar="IP", help="DC/CA host (default: a host marked --dc)")
    a_find.add_argument("-y", "--yes", action="store_true", help="skip the confirm-back")
    a_find.set_defaults(func=cmd_adcs_find)
    p_adcs.set_defaults(func=lambda a: _missing(p_adcs))

    p_mssql = sub.add_parser(
        "mssql", help="MSSQL privilege escalation (low-priv login → sysadmin → SYSTEM)")
    mssql_sub = p_mssql.add_subparsers(dest="mssql_command", metavar="<action>")
    m_esc = mssql_sub.add_parser(
        "escalate", help="try EXECUTE AS impersonation / linked-server paths to sysadmin",
        description="From a non-sysadmin MSSQL login, enumerates the SQL-layer escalation "
                    "surface (impersonatable sysadmin logins, RPC-out linked servers). With "
                    "--allow config-change it impersonates a sysadmin login and adds your "
                    "login to the sysadmin role (reversible), so `enum`/`escalate` then run "
                    "over xp_cmdshell → SYSTEM. Read-only without --allow.")
    m_esc.add_argument("host", metavar="IP", help="the MSSQL host")
    m_esc.add_argument("--allow", action="append", choices=["config-change"], metavar="LEVEL",
                       help="permit the role grant (config-change) to actually escalate")
    m_esc.add_argument("-y", "--yes", action="store_true", help="skip the confirm-back")
    m_esc.set_defaults(func=cmd_mssql_escalate)
    p_mssql.set_defaults(func=lambda a: _missing(p_mssql))

    p_pg = sub.add_parser(
        "postgres", help="PostgreSQL privilege escalation (login → superuser → OS exec)",
        aliases=["pg", "psql"])
    pg_sub = p_pg.add_subparsers(dest="pg_command", metavar="<action>")
    pg_esc = pg_sub.add_parser(
        "escalate", help="find COPY FROM PROGRAM / SET ROLE paths to OS exec",
        description="From a Postgres login, enumerates the DB-layer escalation surface: "
                    "am I superuser?, roles I'm a member of that grant superuser, and "
                    "whether pg_execute_server_program covers me. With --allow "
                    "config-change it runs `COPY FROM PROGRAM 'id'` (directly if "
                    "superuser or a member of pg_execute_server_program; else via "
                    "SET ROLE to a member superuser). Read-only without --allow.")
    pg_esc.add_argument("host", metavar="IP", help="the Postgres host")
    pg_esc.add_argument("--port", type=int, default=5432, help="port (default 5432)")
    pg_esc.add_argument("-d", "--database", default="postgres",
                        help="database to connect to (default: postgres)")
    pg_esc.add_argument("--allow", action="append", choices=["config-change"],
                        metavar="LEVEL",
                        help="permit COPY FROM PROGRAM to actually run")
    pg_esc.add_argument("-y", "--yes", action="store_true", help="skip the confirm-back")
    pg_esc.set_defaults(func=cmd_postgres_escalate)
    p_pg.set_defaults(func=lambda a: _missing(p_pg))

    p_mongo = sub.add_parser(
        "mongodb", help="MongoDB privilege enumeration + credential extraction",
        aliases=["mongo"])
    mongo_sub = p_mongo.add_subparsers(dest="mongo_command", metavar="<action>")
    mongo_esc = mongo_sub.add_parser(
        "escalate", help="enumerate roles + dump users; flag unauth exposure",
        description="MongoDB (4.0+) has no native OS-exec analog. This enumerates the "
                    "auth surface (identity, roles, databases), records unauth exposure "
                    "as a Critical proven finding, and — with --allow config-change — "
                    "dumps admin.system.users. With --scan-data it also counts "
                    "credential-shaped fields (password/hash/token) across application "
                    "collections; values are not captured — the operator dumps them "
                    "separately if the ROE allow.")
    mongo_esc.add_argument("host", metavar="IP", help="the MongoDB host")
    mongo_esc.add_argument("--port", type=int, default=27017,
                           help="port (default 27017)")
    mongo_esc.add_argument("-d", "--database", default="admin",
                           help="authenticationDatabase (default: admin)")
    mongo_esc.add_argument("--scan-data", action="store_true",
                           help="also count credential-field candidates across app DBs")
    mongo_esc.add_argument("--allow", action="append", choices=["config-change"],
                           metavar="LEVEL",
                           help="permit user dump + data scan (writes to the audit log)")
    mongo_esc.add_argument("-y", "--yes", action="store_true", help="skip the confirm-back")
    mongo_esc.set_defaults(func=cmd_mongodb_escalate)
    p_mongo.set_defaults(func=lambda a: _missing(p_mongo))

    p_report = sub.add_parser(
        "report", help="render the customer report (proven Findings + Observations)",
        description="Projects the engagement database into a report: exec summary + "
                    "proven Findings (with the captured PoC trail) and clearly-labelled "
                    "Observations (seen, not exploited), severity/CWE/remediation from the "
                    "KB. --proven-only drops the Observations; --check gates on "
                    "anti-fabrication; --cleanup writes the internal artifact manifest.")
    p_report.add_argument("-o", "--out", default="report", metavar="BASENAME",
                          help="output basename (default: report)")
    p_report.add_argument("--formats", default="md,docx,pdf",
                          help="which to emit: md,docx,pdf (default: all)")
    p_report.add_argument("--check", action="store_true",
                          help="anti-fabrication gate only (exit 2 on errors)")
    p_report.add_argument("--cleanup", action="store_true",
                          help="write the INTERNAL cleanup manifest instead of the report")
    p_report.add_argument("--proven-only", action="store_true",
                          help="only demonstrated compromises — omit the Observations")
    # retired: --all (observations are now in the report by default). Kept as a hidden,
    # no-op alias so existing scripts don't break — it was the old way to include them.
    p_report.add_argument("--all", action="store_true", help=argparse.SUPPRESS)
    p_report.add_argument("--force", action="store_true",
                          help="render even if the anti-fabrication check has errors")
    p_report.set_defaults(func=cmd_report)

    p_recce = sub.add_parser(
        "export-recce", help="fold proven findings back into recce (fieldkit-import JSON)",
        description="Emits the KB-enriched JSON recce imports with `recce "
                    "fieldkit-import`, so every proven finding lands back in recce's "
                    "workbook + report.")
    p_recce.add_argument("out", nargs="?", help="output file (default: recce_findings.json)")
    p_recce.add_argument("--all", action="store_true",
                         help="include unproven findings (default: proven only)")
    p_recce.set_defaults(func=cmd_export_recce)

    p_wordlist = sub.add_parser(
        "wordlist", help="generate a targeted wordlist from seeds via inspectable mutation rules",
        description="""Build a password wordlist from seed words (company name, product,
common word) by applying an inspectable mutation ruleset — cases + leet + suffixes
by default, prefixes/combine/seasons opt-in. Pipes directly into `fieldkit spray
--wordlist`.

Examples:

  fieldkit wordlist Acme Widget --years 2024 2025 --out passwords.txt
  fieldkit wordlist Acme --seasons --combine --max 10000 --out passwords.txt
  fieldkit wordlist --from-text "$(cat about-page.html)" --years 2024 2025 --out p.txt
  fieldkit wordlist --from-file seeds.txt --out p.txt
  fieldkit wordlist --rules      # print the ruleset""",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p_wordlist.add_argument("seeds", nargs="*", metavar="SEED",
                            help="seed words to mutate (e.g. company name, product)")
    p_wordlist.add_argument("--rules", action="store_true",
                            help="print the mutation ruleset and exit")
    p_wordlist.add_argument("--out", metavar="FILE",
                            help="output file (default: print to stdout)")
    p_wordlist.add_argument("--from-file", metavar="PATH",
                            help="read seed words from a file (one per line, # comments OK)")
    p_wordlist.add_argument("--from-text", metavar="TEXT",
                            help="extract seed words from a text blob (paste in About-page copy)")
    p_wordlist.add_argument("--years", nargs="+", type=int, metavar="YEAR",
                            help="years to append as suffixes (e.g. --years 2024 2025)")
    p_wordlist.add_argument("--suffix", nargs="+", metavar="STR",
                            help="extra suffix(es) to append (adds to the built-in set)")
    p_wordlist.add_argument("--prefix", nargs="+", metavar="STR",
                            help="extra prefix(es) to prepend")
    p_wordlist.add_argument("--seasons", action="store_true",
                            help="add every season + month to the seed pool")
    p_wordlist.add_argument("--combine", action="store_true",
                            help="also concat seed pairs (Acme+Widget → AcmeWidget). "
                                 "Combinatorial — bounded by --max")
    p_wordlist.add_argument("--walks", action="store_true",
                            help="include keyboard walks (qwerty/qazwsx/1qaz2wsx families, "
                                 "shift-mix, common non-walks like Password1) as standalone "
                                 "passwords in the output")
    p_wordlist.add_argument("--wrapped", action="store_true",
                            help="wrap seeds with symbols+numbers before/after: "
                                 "!Password2024!, #Winter@, 2024Password!, etc. Best paired "
                                 "with --min-len 12 for modern policies")
    p_wordlist.add_argument("--long", action="store_true",
                            help="preset for modern ≥12-char engagements: enables --walks + "
                                 "--wrapped, sets --min-len 12 --max-len 16 (both still "
                                 "overridable). One shape among others; keep in mind real "
                                 "policies vary")
    p_wordlist.add_argument("--prefixes", action="store_true",
                            help="apply prefix rule (uses --prefix + --years); off by default "
                                 "because corporate patterns are almost all suffix-heavy")
    p_wordlist.add_argument("--no-cases", action="store_true",
                            help="disable capitalization variants (First, UPPER)")
    p_wordlist.add_argument("--no-leet", action="store_true",
                            help="disable leet substitutions (o→0, e→3, ...)")
    p_wordlist.add_argument("--no-suffixes", action="store_true",
                            help="disable the built-in suffix set (rarely useful)")
    p_wordlist.add_argument("--min-len", type=int, default=6, metavar="N",
                            help="minimum word length (default: 6)")
    p_wordlist.add_argument("--max-len", type=int, default=32, metavar="N",
                            help="maximum word length (default: 32)")
    p_wordlist.add_argument("--max", type=int,
                            default=wordlist_mod.DEFAULT_MAX_OUTPUT, metavar="N",
                            help=f"maximum total words (default: {wordlist_mod.DEFAULT_MAX_OUTPUT})")
    p_wordlist.set_defaults(func=cmd_wordlist)

    p_arsenal = sub.add_parser(
        "arsenal", help="what tools/exploits are staged, and what each route needs")
    ar_sub = p_arsenal.add_subparsers(dest="arsenal_command", metavar="<action>")
    ar_list = ar_sub.add_parser("list", help="list staged artifacts by category")
    ar_list.set_defaults(func=cmd_arsenal_list)
    ar_check = ar_sub.add_parser(
        "check", help="readiness: which privesc/evasion routes are ready vs need staging")
    ar_check.add_argument("--all", action="store_true", help="show every route, not just gaps")
    ar_check.set_defaults(func=cmd_arsenal_check)
    ar_find = ar_sub.add_parser("find", help="print the path to a staged artifact by name")
    ar_find.add_argument("name")
    ar_find.set_defaults(func=cmd_arsenal_find)
    ar_rules = ar_sub.add_parser(
        "rules", help="print the failure-classifier ruleset (how it reads tool output)")
    ar_rules.set_defaults(func=lambda a: (print(classify_mod.describe_rules()) or 0))
    p_arsenal.set_defaults(func=cmd_arsenal_list)  # bare `arsenal` = list

    p_status = sub.add_parser("status", help="the engagement board")
    p_status.add_argument("--hosts", action="store_true", help="list every host")
    p_status.add_argument("--creds", action="store_true", help="list every credential")
    p_status.set_defaults(func=cmd_status)

    return parser


def _missing(parser):
    parser.print_help(sys.stderr)
    return 2


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help(sys.stderr)
        return 2
    try:
        return args.func(args)
    except FieldkitError as exc:
        # Every operator-actionable failure lands here; anything else is a fieldkit bug.
        _err(str(exc))
        return 2
    except FileNotFoundError as exc:
        _err(f"{exc.filename}: no such file")
        return 2
    except sqlite3.Error as exc:
        # A locked/read-only/corrupt database is an operator problem, not a crash.
        _err(f"database error: {exc}")
        return 2
    except BrokenPipeError:  # pragma: no cover - `| head`
        return 0
    except KeyboardInterrupt:  # pragma: no cover - operator hit ^C
        _err("interrupted")
        return 130
