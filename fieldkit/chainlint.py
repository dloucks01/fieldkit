"""Coverage audit for the coerce-chain profile catalog.

Answers one question: for every registered chain profile, is the
plan honest about what it will emit + what it will do? The lint
surfaces gaps that would either mislead the detection-debt
accounting or break the walker's semantic contract.

Load-bearing checks (all read-only — no walker runs):

  * ``preflight-not-first`` — the chain must have a preflight
    step at index 0. Missing it means ``chain run`` can fire
    louder steps against an unreachable target. **error**.
  * ``empty-catalog`` — profile registered but factory returns
    an empty step tuple. **error**.
  * ``factory-fails`` — the factory raises when called with a
    placeholder target. **error**.
  * ``duplicate-step-names`` — two steps in the same profile
    share a name. The walker + trail-persistence use step names
    as opaque identifiers; duplicates break resume-lookup.
    **warning**.
  * ``no-signals`` — a step falls back to :attr:`Step.detection_cost`
    because its ``signals`` catalog is empty. The coarse fallback
    works but the report's per-step signal breakdown is a
    "no signals recorded" gap. **warning**.
  * ``coerce-without-rpc-signal`` — a ``coerce:*`` step has no
    ``rpc-call`` signal in its catalog. Every coerce primitive
    fieldkit ships is an EFSRPC / DRSUAPI RPC; missing that
    signal understates the debt of the loudest step in the plan.
    **warning**.

The lint is deliberately narrow — false-positive-averse rather
than exhaustive. A defender-focused audit belongs elsewhere; the
lint is here to keep the shipped catalog honest with itself.
"""
from dataclasses import dataclass
from typing import Optional


@dataclass
class Finding:
    """One lint finding — always includes the profile it came from
    so ``chain lint --profile X`` can filter cleanly."""
    profile: str
    code: str
    severity: str    # "error" | "warning"
    step_index: Optional[int]
    step_name: Optional[str]
    message: str


def audit_profile(name):
    """Return every :class:`Finding` for one profile.

    Structured so callers can filter (only errors, only one code,
    JSON export, etc.) without re-running the audit. A
    ``factory-fails`` finding short-circuits per-step checks —
    there are no steps to inspect if the factory raised.
    """
    from . import chain as chain_mod
    findings = []
    try:
        factory = chain_mod.profile(name)
    except KeyError:
        # Caller is responsible for handling missing profiles;
        # audit_profile is only called for names in known_profiles().
        return findings
    try:
        ch = factory("<lint-target>")
    except Exception as exc:                                # noqa: BLE001
        findings.append(Finding(
            profile=name, code="factory-fails", severity="error",
            step_index=None, step_name=None,
            message=(f"profile factory raised on placeholder target: "
                     f"{type(exc).__name__}: {exc}")))
        return findings

    if not ch.steps:
        findings.append(Finding(
            profile=name, code="empty-catalog", severity="error",
            step_index=None, step_name=None,
            message="profile has zero steps"))
        return findings

    if ch.steps[0].kind != "preflight":
        findings.append(Finding(
            profile=name, code="preflight-not-first", severity="error",
            step_index=0, step_name=ch.steps[0].name,
            message=(f"first step is {ch.steps[0].name!r} "
                     f"(kind={ch.steps[0].kind!r}); chain semantics "
                     "require a preflight step at index 0")))

    seen_names = {}
    for i, s in enumerate(ch.steps):
        seen_names.setdefault(s.name, []).append(i)
    for step_name, idxs in seen_names.items():
        if len(idxs) > 1:
            findings.append(Finding(
                profile=name, code="duplicate-step-names",
                severity="warning",
                step_index=idxs[0], step_name=step_name,
                message=(f"step name {step_name!r} appears at "
                         f"indices {idxs} — walker resume-lookup "
                         "uses step names as identifiers")))

    for i, s in enumerate(ch.steps):
        if not s.signals:
            findings.append(Finding(
                profile=name, code="no-signals", severity="warning",
                step_index=i, step_name=s.name,
                message=(f"step falls back to detection_cost={s.detection_cost} "
                         "— no per-signal breakdown available for the "
                         "report or the dashboard's debt view")))
        if s.kind.startswith("coerce:") or s.name.startswith("coerce:"):
            has_rpc = any(sig.kind == "rpc-call" for sig in s.signals)
            if not has_rpc:
                findings.append(Finding(
                    profile=name, code="coerce-without-rpc-signal",
                    severity="warning",
                    step_index=i, step_name=s.name,
                    message=("coerce primitive with no rpc-call signal "
                             "— every shipped coerce is an EFSRPC/DRSUAPI "
                             "RPC; missing the signal understates the "
                             "debt of the loudest step")))

    return findings


def audit_all():
    """Audit every registered profile; returns the merged findings
    list in profile-name order. Empty when everything is clean."""
    from . import chain as chain_mod
    out = []
    for name in chain_mod.known_profiles():
        out.extend(audit_profile(name))
    return out


def summarize(findings, profiles):
    """Compact overall count for the CLI's summary line + exit code.

    Returns ``(ok, warn, err)`` where each is the number of profiles
    in that state (a profile with any error counts as ``err``; a
    profile with warnings only counts as ``warn``). ``ok`` is
    profiles with no findings.
    """
    by_profile = {}
    for f in findings:
        by_profile.setdefault(f.profile, []).append(f)
    ok = warn = err = 0
    for p in profiles:
        fs = by_profile.get(p, [])
        if not fs:
            ok += 1
        elif any(f.severity == "error" for f in fs):
            err += 1
        else:
            warn += 1
    return ok, warn, err
