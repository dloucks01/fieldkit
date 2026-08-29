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


_PREDICATES = {
    "always":       _p_always,
    "sudo_allows":  _p_sudo_allows,
    "suid":         _p_suid,
    "capability":   _p_capability,
    "facts_match":  _p_facts_match,
}


def _key_for(ttp, matched_payload):
    """Vector key that matches the inlined-driver naming so `vectors_for`'s
    dedup collapses same-target vectors regardless of source."""
    kind = ttp.detect.kind
    if kind == "sudo_allows" and matched_payload:
        return f"sudo:{matched_payload}"
    if kind == "suid" and matched_payload:
        return f"suid:{matched_payload}"
    if kind == "capability" and matched_payload:
        return f"cap:{matched_payload}"
    return f"ttp:{ttp.technique}"


def ttp_to_vector(ttp, facts, ctx):
    """Return a :class:`Vector` if the TTP applies to these facts, else None.

    Platform filter runs first (a Linux TTP never fires against a Windows host,
    even if the predicate happens to be satisfiable). Then the predicate. Command
    and metadata flow through unchanged from the YAML file.
    """
    if facts.os not in ttp.platform:
        return None
    predicate = _PREDICATES.get(ttp.detect.kind)
    if predicate is None:
        return None
    matched, payload = predicate(facts, ttp.detect.value)
    if not matched:
        return None
    shell = "cmd" if facts.os == "windows" else "sh"
    return Vector(
        key=_key_for(ttp, payload),
        title=ttp.name,
        exploitability=ttp.ranking.exploitability,
        safety=ttp.ranking.safety,
        detection=ttp.ranking.detection,
        command=ttp.execute.command,
        shell=shell,
        host=ctx.host,
        detail=ttp.report.description or f"loaded from TTP {ttp.technique}",
        evidence=f"detected via TTP {ttp.technique} ({ttp.detect.kind})",
        safe_proof=ttp.verify.proof or None,
        cleanup=ttp.cleanup.command or None,
        report_type=ttp.report.vector_type,
    )
