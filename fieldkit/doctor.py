"""Fieldkit health check — one gate for preflight + chain lint +
engagement sanity + TTP catalog.

Answers "is this fieldkit install + this engagement's state healthy
enough to run a session against a customer target?" in one command,
with one exit code CI can gate on.

Four probe groups (severity is the WORST rung any probe in the
group returns):

  * **tools**       — preflight (required tools on PATH)
  * **chains**      — chainlint over the shipped profile catalog
  * **engagement**  — engagement exists, staging dirs configured
                      + writable, credentials present when hosts
                      are
  * **ttps**        — TTP catalog loads without parse errors

Every probe returns one :class:`Report` with a rung
(``ok`` / ``warning`` / ``error``) + a one-line human message + an
optional list of detail lines. The top-level :func:`run` composes
the group's severity from the worst rung + reports the exit code
the CLI should use.
"""
from dataclasses import dataclass, field
from typing import List


@dataclass
class Report:
    """One probe result. ``rung`` is one of ``ok``/``warning``/``error``.
    ``details`` is optional per-probe supporting evidence
    (missing tools, lint findings, unwritable paths — whatever the
    operator needs to fix the probe)."""
    name: str
    rung: str
    message: str
    details: List[str] = field(default_factory=list)


_RUNGS = ("ok", "warning", "error")


def _worst(reports):
    """Return the worst rung among ``reports``. ``ok`` when the list
    is empty."""
    return max(
        (r.rung for r in reports),
        key=lambda x: _RUNGS.index(x),
        default="ok",
    )


def probe_tools():
    """preflight() over the required-tools list — one Report with
    the missing tools called out. Non-required missing tools show
    as a warning (kit is incomplete but runs); missing required
    tools are an error."""
    from . import preflight
    rows = preflight.check()
    missing_req = [r for r in rows if r[4] and not r[2]]
    missing_opt = [r for r in rows if not r[4] and not r[2]]
    if missing_req:
        return Report(
            name="tools", rung="error",
            message=f"{len(missing_req)} required tool(s) missing on PATH",
            details=[f"{r[0]} — {r[1]}" for r in missing_req])
    if missing_opt:
        return Report(
            name="tools", rung="warning",
            message=(f"{len(missing_opt)} optional tool(s) missing "
                     "— some features unavailable"),
            details=[f"{r[0]} — {r[1]}" for r in missing_opt])
    return Report(name="tools", rung="ok",
                    message="every required + optional tool on PATH")


def probe_chains():
    """chainlint over every registered profile — errors trip the
    doctor gate; warnings surface but pass."""
    from . import chain as chain_mod
    from . import chainlint
    profiles = chain_mod.known_profiles()
    if not profiles:
        return Report(name="chains", rung="warning",
                        message="no chain profiles registered")
    findings = chainlint.audit_all()
    errs = [f for f in findings if f.severity == "error"]
    warns = [f for f in findings if f.severity == "warning"]
    if errs:
        return Report(
            name="chains", rung="error",
            message=f"{len(errs)} chain lint error(s) in shipped catalog",
            details=[f"{f.profile}: [{f.code}] {f.message}"
                     for f in errs])
    if warns:
        return Report(
            name="chains", rung="warning",
            message=f"{len(warns)} chain lint warning(s)",
            details=[f"{f.profile}: [{f.code}] {f.message}"
                     for f in warns])
    return Report(name="chains", rung="ok",
                    message=f"{len(profiles)} profile(s) — no findings")


def probe_engagement(store):
    """Engagement-scoped sanity: is an engagement initialized?
    Are stage_win / stage_lin configured to writable dirs? Are
    hosts present without any credential to spray?"""
    import os
    from . import config as config_mod
    row = store.engagement()
    if row is None:
        return Report(name="engagement", rung="warning",
                        message="no engagement initialized — "
                                "`fieldkit init <name>` to start")
    cfg = config_mod.load(store)
    details = []
    rung = "ok"
    for key in ("stage_win", "stage_lin"):
        path = cfg.get(key)
        if not path:
            details.append(f"{key}: not configured")
            rung = max((rung, "warning"), key=_RUNGS.index)
            continue
        if not os.path.isdir(path):
            details.append(f"{key}: {path} — no such directory")
            rung = max((rung, "warning"), key=_RUNGS.index)
            continue
        if not os.access(path, os.W_OK):
            details.append(f"{key}: {path} — not writable")
            rung = max((rung, "error"), key=_RUNGS.index)
    counts = store.counts()
    if counts["hosts"] and not counts["credentials"]:
        details.append(
            f"{counts['hosts']} host(s) but 0 credentials — "
            "add one (or `spray --wordlist`) to move past setup")
        rung = max((rung, "warning"), key=_RUNGS.index)
    return Report(
        name="engagement", rung=rung,
        message=(f"engagement {row['name']!r} — "
                 f"{counts['hosts']} hosts, "
                 f"{counts['credentials']} creds, "
                 f"{counts['findings']} findings"),
        details=details)


def probe_ttps():
    """TTP catalog loads without parse errors."""
    try:
        from .ttps import load_all, LoaderError
    except Exception as exc:                                # noqa: BLE001
        return Report(name="ttps", rung="error",
                        message=f"TTP module import failed: {exc}")
    try:
        tt = load_all()
    except LoaderError as exc:
        return Report(name="ttps", rung="error",
                        message=f"TTP catalog parse failure: {exc}")
    except Exception as exc:                                # noqa: BLE001
        return Report(name="ttps", rung="error",
                        message=f"TTP catalog raised {type(exc).__name__}: {exc}")
    return Report(name="ttps", rung="ok",
                    message=f"{len(tt)} TTP(s) loaded")


def fix(reports, store=None):
    """Attempt to auto-remediate the actionable warnings from a
    :func:`run` pass. Returns a list of ``(action, outcome)`` tuples
    where ``outcome`` is one of ``"fixed"`` / ``"skipped"`` /
    ``"failed: <reason>"``.

    Fixes are conservative: only issues with an unambiguous safe
    action are attempted (mkdir a missing stage_lin, config-set a
    default when missing). Anything requiring a value judgment
    (chain-lint findings, chain-lint errors from a broken profile,
    unwritable directories the operator owns) is surfaced with a
    concrete command hint but not touched.
    """
    import os
    from . import config as config_mod
    actions = []
    reports_by_name = {r.name: r for r in reports}

    # ----- engagement probe fixes ------------------------------------
    if "engagement" in reports_by_name and store is not None:
        r = reports_by_name["engagement"]
        cfg = None
        for detail in r.details:
            # "stage_win: /path — no such directory" → mkdir
            if " — no such directory" in detail:
                key, path = detail.split(":", 1)[0], \
                    detail.split(": ", 1)[1].split(" — ")[0]
                # Only mkdir Linux-shaped paths; Windows stage on Linux
                # host is a config artifact the operator set intending
                # to run against Windows targets — don't create it.
                if path.startswith("/") and not os.path.isdir(path):
                    try:
                        os.makedirs(path, mode=0o700, exist_ok=True)
                        actions.append((f"mkdir {path}", "fixed"))
                    except OSError as exc:
                        actions.append(
                            (f"mkdir {path}", f"failed: {exc}"))
                else:
                    actions.append(
                        (f"mkdir {path}",
                         "skipped: not a Linux-shaped path; "
                         "windows stage dir must be created on the target"))
            elif ": not configured" in detail:
                key = detail.split(":", 1)[0].strip()
                # Restore the shipped default
                default = config_mod.DEFAULTS.get(key)
                if default:
                    try:
                        cfg = cfg or config_mod.load(store)
                        cfg.set(key, default)
                        actions.append(
                            (f"config set {key}={default}", "fixed"))
                    except Exception as exc:  # noqa: BLE001
                        actions.append(
                            (f"config set {key}={default}",
                             f"failed: {exc}"))
            elif "not writable" in detail:
                path = detail.split(": ", 1)[1].split(" — ")[0]
                actions.append(
                    (f"chmod +w {path}",
                     "skipped: doctor doesn't chmod on the operator's "
                     "behalf — run manually or move stage_dir elsewhere"))
            elif "0 credentials" in detail:
                actions.append(
                    ("add a credential",
                     "skipped: run `fieldkit add cred <spec>` or "
                     "`fieldkit spray --wordlist`"))

    # ----- tools probe: print install hints; can't apt-get --------
    if reports_by_name.get("tools") and reports_by_name["tools"].details:
        for line in reports_by_name["tools"].details:
            tool = line.split(" — ")[0]
            actions.append(
                (f"install {tool}",
                 f"skipped: run `apt install {tool}` or the tool's "
                 "documented install (`fieldkit preflight` names each)"))

    # ----- chains probe: findings need code / YAML edits ---------
    if reports_by_name.get("chains") and reports_by_name["chains"].details:
        for line in reports_by_name["chains"].details:
            actions.append(
                (line, "skipped: chain-lint findings need a code / "
                 "YAML edit — see `fieldkit chain lint --json`"))

    # ----- ttps probe: parse errors need YAML edits --------------
    if (reports_by_name.get("ttps") and
            reports_by_name["ttps"].rung != "ok"):
        actions.append(
            (reports_by_name["ttps"].message,
             "skipped: TTP catalog parse errors need a YAML edit"))

    return actions


def run(store=None):
    """Compose every probe → return ``(reports, exit_code)``.

    ``store`` may be None for a "tools + chains + ttps only" run
    (a fresh box before any engagement exists — the doctor still
    surfaces the missing-tools shape).

    Exit codes:
      * 0 — every probe ``ok``;
      * 1 — one or more warnings, no errors;
      * 2 — one or more errors.
    """
    reports = [probe_tools(), probe_chains(), probe_ttps()]
    if store is not None:
        reports.append(probe_engagement(store))
    worst = _worst(reports)
    return reports, {"ok": 0, "warning": 1, "error": 2}[worst]
