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
import os
import re
import sqlite3
import sys

from . import (__version__, config as config_mod, creds as creds_mod,
               executor as executor_mod, hostenum as hostenum_mod, ingest as ingest_mod,
               kb as kb_mod, privesc as privesc_mod, scope as scope_mod, spray as spray_mod)
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
            _err("give a credential, e.g. 'CORP/jdoe:Winter2025!' or --user jdoe --hash <NT>")
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
        added = enriched = 0
        with store.transaction():  # one commit for the whole scope file
            for ip, hostname in targets:
                _, created = store.add_host(
                    ip, hostname=hostname or None, os_name=args.os,
                    is_dc=True if args.dc else None, subnet=args.subnet)
                added += created
                enriched += not created
        total = store.counts()["hosts"]
    print(f"added {_plural(added, 'host')}"
          + (f", {enriched} already in scope" if enriched else "")
          + f" — {total} in scope now")
    return 0 if not errors else 1


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
        hosts = store.hosts(subnet=args.subnet)
        creds = store.credentials()
        if not hosts:
            _err("no hosts in scope" + (f" for {args.subnet}" if args.subnet else "")
                 + " — run `fieldkit add hosts` first")
            return 2
        if not creds:
            _err("no credentials to spray — run `fieldkit add cred` first")
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


def _stage_dirs(cfg):
    return dict(stage_win=cfg.get("stage_win"), stage_lin=cfg.get("stage_lin"))


def cmd_analyze(args):
    with _open_store(args) as store:
        store.require_engagement()
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
    """(host_row, cred_row) for a target, or an error string. Shared by enum/run."""
    host = store.host_by_ip(ip)
    if host is None:
        return None, None, f"{ip} is not in scope — add it with `fieldkit add hosts`"
    cred = store.credential_with_access_on(host["id"])
    if cred is None:
        return host, None, (f"no credential is proven on {ip} — spray/validate one there "
                            "first (enum runs as a credential that already works)")
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


def cmd_enum(args):
    with _open_store(args) as store:
        store.require_engagement()
        host, cred, err = _resolve_target(store, args.host)
        if err:
            _err(err)
            return 2
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


def _looks_elevated(output, os_name):
    low = (output or "").lower()
    if os_name == hostenum_mod.WINDOWS:
        return "nt authority\\system" in low or "\\administrator" in low
    return "uid=0(" in low or bool(re.search(r"\buid=0\b", low))


def cmd_run(args):
    with _open_store(args) as store:
        store.require_engagement()
        cfg = config_mod.load(store)
        host, cred, err = _resolve_target(store, args.host)
        if err:
            _err(err)
            return 2
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

        finding_id, _ = store.add_finding(
            vector.key.split(":", 1)[0], vector.title, host_id=host["id"],
            risk=vector.detection)
        creates = [(f"{vector.title} (artifact)", vector.cleanup)] if vector.cleanup else ()
        action = executor_mod.Action(
            host=host, cred=cred, command=vector.command, label=f"vector:{vector.key}",
            safety=vector.safety, shell=vector.shell, finding_id=finding_id, creates=creates)
        res = executor_mod.execute(store, action, allow=allow, on_event=lambda m: print(m))

        if res.blocked:
            _err(res.blocked)
            return 2
        if not res.ok:
            _err(f"the vector did not complete: {res.run.error if res.run else 'no output'}")
            return 1
        elevated = _looks_elevated(res.output, host["os"])
        if elevated:
            store.add_finding(vector.key.split(":", 1)[0], vector.title,
                              host_id=host["id"], proven=True,
                              evidence=(res.output or "").strip()[:500])

    print("\n--- output ---")
    print((res.output or "").rstrip() or "(no output)")
    print("---")
    if elevated:
        print("PROVEN: the command returned an elevated context. Captured as a finding.")
    else:
        print("ran, but the output does not clearly show elevation — check it above.")
    if vector.cleanup:
        print(f"cleanup recorded: {vector.cleanup}")
    return 0


def cmd_status(args):
    with _open_store(args) as store:
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

        if not counts["hosts"]:
            print(f"\nnext: {PROG} add hosts scope.txt")
        elif not counts["credentials"]:
            print(f"\nnext: {PROG} add cred 'CORP/jdoe:Winter2025!'")
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

    p_config = sub.add_parser("config", help="engagement config (replaces configure.sh)")
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
        description="Accepts DOMAIN\\user:pass, user@corp.local:pass, corp/user:pass, "
                    "user:LM:NT, :NT, a secretsdump line, or a ccache/key path.")
    a_cred.add_argument("spec", nargs="?", help="the credential as you have it")
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
    p_spray.set_defaults(func=cmd_spray)

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
