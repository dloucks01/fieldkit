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
import sqlite3
import sys

from . import __version__, config as config_mod, creds as creds_mod, scope as scope_mod
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


def _plural(n, word):
    return f"{n} {word}{'' if n == 1 else 's'}"


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
