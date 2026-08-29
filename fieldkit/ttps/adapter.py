"""Adapter: TTP + HostFacts → :class:`~fieldkit.privesc.Vector`.

The engine (:mod:`fieldkit.privesc`) already knows how to consume Vectors — this
module bridges the loaded TTP library to that shape. Each TTP's detect predicate
is evaluated against :class:`~fieldkit.hostenum.HostFacts`; when it matches, we
produce a Vector with the TTP's command / ranking / cleanup / report metadata.

Predicate evaluators are named `_p_<kind>` and take (`facts`, `value`) → matched-
bool + extracted-payload (e.g. the binary name that matched, so key construction
can name it). Adding a new predicate = one function here plus the schema/loader
allowlisting it.

Key namespacing: TTP-generated Vectors use the same key shape as the inlined
GTFO/CAPS/PRIVS drivers (``sudo:find``, ``cap:python3``, ``priv:seimpersonate``)
so :func:`fieldkit.privesc.vectors_for`'s dedup collapses duplicates cleanly
during the port window.
"""
from ..privesc import Vector


def _p_always(facts, value):
    _ = facts, value
    return True, None


def _p_sudo_allows(facts, value):
    # `sudo -l` says "ALL" → step aside; the `_d_sudo_all` driver produces
    # the single `sudo:ALL` vector and per-binary TTPs would be redundant
    # noise. Matches the inlined `_d_sudo_gtfo`'s early-return behavior.
    if facts.sudo_all:
        return False, None
    if value in facts.sudo_binaries:
        return True, value
    return False, None


def _p_suid(facts, value):
    if value in facts.suid:
        return True, value
    return False, None


def _p_capability(facts, value):
    for binname, cap in facts.caps.items():
        if cap == value:
            return True, binname
    return False, None


def _p_facts_match(facts, value):
    if not isinstance(value, dict):
        return False, None
    for attr, expected in value.items():
        if getattr(facts, attr, None) != expected:
            return False, None
    return True, None


def _p_privilege(facts, value):
    """Windows: matches when `value` (a privilege token, e.g. `SeBackupPrivilege`)
    is present in facts.privs. Payload is the priv name so the vector's evidence
    can name it."""
    if value in facts.privs:
        return True, value
    return False, None


def _p_group_member(facts, value):
    """Windows: matches when `value` (a group name, e.g. `Backup Operators`)
    is present in facts.win_groups."""
    if value in facts.win_groups:
        return True, value
    return False, None


_PREDICATES = {
    "always":        _p_always,
    "sudo_allows":   _p_sudo_allows,
    "suid":          _p_suid,
    "capability":    _p_capability,
    "facts_match":   _p_facts_match,
    "privilege":     _p_privilege,
    "group_member":  _p_group_member,
}


def _key_for(ttp, matched_payload):
    """Vector key that matches the inlined-driver naming so `vectors_for`'s
    dedup collapses same-target vectors regardless of source."""
    # Explicit override wins — used when the TTP's dedup key differs from
    # the naming default (e.g. SeDebug's key `sedebug` vs vector_type `lsass`).
    if ttp.key:
        return ttp.key
    kind = ttp.detect.kind
    if kind == "sudo_allows" and matched_payload:
        return f"sudo:{matched_payload}"
    if kind == "suid" and matched_payload:
        return f"suid:{matched_payload}"
    if kind == "capability" and matched_payload:
        return f"cap:{matched_payload}"
    # For privilege/group_member predicates, use the report.vector_type as the
    # key — this matches how the inlined WIN_PRIVS/WIN_GROUPS tables set both
    # SeBackupPrivilege and "Backup Operators" to key=`sebackup`, so dedup
    # collapses them to one vector regardless of which fact matched.
    if kind in ("privilege", "group_member"):
        return ttp.report.vector_type
    return f"ttp:{ttp.technique}"


def _substitute(command, payload, ctx):
    """Fill template variables in the command with the matched payload / ctx.

    Supported:
      * ``{{binary}}`` — the binary basename the predicate matched (a
        sudo-allowed binary, a cap-carrying binary, …).
      * ``{{stage}}`` — the platform-appropriate staging dir from ctx
        (Windows: ``ctx.stage_win``; Linux: ``ctx.stage_lin``). Matches the
        inlined `_win_vector`'s ``{stage}`` substitution convention.
    """
    out = command
    if payload and isinstance(payload, str) and "{{binary}}" in out:
        out = out.replace("{{binary}}", payload)
    if "{{stage}}" in out:
        stage = getattr(ctx, "stage_win", None) or getattr(ctx, "stage_lin", None) or ""
        # Pick per-platform when both are set (impersonation TTPs will use win).
        # For now the ctx passes both; the YAML's platform disambiguates via
        # which TTP is running — Windows TTPs read stage_win, Linux stage_lin.
        # The ctx already has the right one loaded for the acting OS.
        out = out.replace("{{stage}}", stage)
    return out


def ttp_to_vector(ttp, facts, ctx):
    """Return a :class:`Vector` if the TTP applies to these facts, else None.

    Platform filter runs first (a Linux TTP never fires against a Windows host,
    even if the predicate happens to be satisfiable). Then the predicate.
    ``{{binary}}`` in the command is substituted with the matched payload so a
    single TTP can generate host-specific commands (e.g. `{{binary}} /etc/shadow`
    where `{{binary}}` is whichever binary carries `cap_dac_read_search`).
    """
    if facts.os not in ttp.platform:
        return None
    predicate = _PREDICATES.get(ttp.detect.kind)
    if predicate is None:
        return None
    matched, payload = predicate(facts, ttp.detect.value)
    if not matched:
        return None
    # Shell selection: honor YAML's `execute.shell` if declared, else default
    # per platform (`cmd` on windows, `sh` on linux). Windows TTPs that use
    # PowerShell explicitly set `execute.shell: powershell`.
    shell = ttp.execute.shell or ("cmd" if facts.os == "windows" else "sh")
    return Vector(
        key=_key_for(ttp, payload),
        title=ttp.name,
        exploitability=ttp.ranking.exploitability,
        safety=ttp.ranking.safety,
        detection=ttp.ranking.detection,
        command=_substitute(ttp.execute.command, payload, ctx),
        shell=shell,
        host=ctx.host,
        detail=ttp.report.description or f"loaded from TTP {ttp.technique}",
        evidence=f"detected via TTP {ttp.technique} ({ttp.detect.kind})",
        safe_proof=_substitute(ttp.verify.proof, payload, ctx) if ttp.verify.proof else None,
        cleanup=_substitute(ttp.cleanup.command, payload, ctx) if ttp.cleanup.command else None,
        report_type=ttp.report.vector_type,
    )
