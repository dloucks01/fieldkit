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
import re

from ..privesc import Playbook, Vector, _canon


# -------- version_range predicate helpers ---------------------------------

#: The comparison operators the `version_range` predicate supports. Order
#: matters — the two-char operators must be tried before the single-char
#: prefixes so ">=" isn't shortened to ">".
_OP_ORDER = ("<=", ">=", "==", "!=", "<", ">")
_OPS = {
    "<":  lambda a, b: a < b,
    "<=": lambda a, b: a <= b,
    ">":  lambda a, b: a > b,
    ">=": lambda a, b: a >= b,
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
}

#: Two capture groups: numeric dotted head, then optional ``p<N>`` sudo-patch
#: suffix. Matches :func:`fieldkit.privesc._vtuple` so ``sudo 1.9.5p1`` and
#: ``sudo 1.9.5p2`` compare distinctly (the difference IS the fix for
#: CVE-2021-3156 baronsamedit — dropping the suffix would collapse them).
_VERSION_RE = re.compile(r"^\s*(\d+(?:\.\d+)*)(?:p(\d+))?")


def _parse_version(s):
    """Turn a version string into a normalized 4-tuple of ints. Ignores
    trailing non-numeric suffixes (`5.15.0-generic` → `(5,15,0,0)`),
    pads short versions with zeros so tuple compare is honest
    (`5.15` == `5.15.0.0` == `(5,15,0,0)`). Preserves a ``p<N>`` sudo-style
    patch suffix as the 4th tuple element so ``1.9.5p1`` = ``(1,9,5,1)``
    and ``1.9.5p2`` = ``(1,9,5,2)``.

    Returns None for unparseable input — the predicate treats that as
    "cannot decide, don't match".
    """
    if not s:
        return None
    m = _VERSION_RE.match(str(s))
    if not m:
        return None
    parts = [int(x) for x in m.group(1).split(".")]
    while len(parts) < 3:
        parts.append(0)
    parts.append(int(m.group(2)) if m.group(2) else 0)
    return tuple(parts[:4])


def _parse_constraint(spec):
    """Parse one constraint like ``'>=5.4'`` → ``(op_fn, target_tuple)``.
    Returns None if the constraint doesn't match the shape."""
    spec = spec.strip()
    for op in _OP_ORDER:
        if spec.startswith(op):
            v = _parse_version(spec[len(op):])
            if v is None:
                return None
            return _OPS[op], v
    return None



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
    """Matches when ``value`` (a GTFO-canonical binary name) is present in
    ``facts.suid``. Direct match first; then _canon-stripped match so a TTP
    that says ``suid: python`` also fires on ``python3.8`` (the inlined
    :func:`fieldkit.privesc._d_suid_gtfo` did the same via ``_canon``).

    Payload is the ACTUAL basename on the host, so ``{{binary}}`` in the
    command renders as the file the user can actually invoke (``python3.8``,
    not the abstract ``python``) and the vector key ends up ``suid:python3.8``.
    """
    if value in facts.suid:
        return True, value
    for present in facts.suid:
        if _canon(present) == value:
            return True, present
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
    """Windows: matches when `value` is present in facts.privs. `value` may
    be a string (single priv) or a list (any-of match, for the compound
    SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege case).

    Payload is the priv name that matched (for the evidence string).
    """
    if isinstance(value, list):
        for priv in value:
            if priv in facts.privs:
                return True, priv
        return False, None
    if value in facts.privs:
        return True, value
    return False, None


def _p_group_member(facts, value):
    """Windows: matches when `value` (a group name, e.g. `Backup Operators`)
    is present in facts.win_groups."""
    if value in facts.win_groups:
        return True, value
    return False, None


def _resolve_field(facts, path):
    """Read a HostFacts attribute by dotted path — ``kernel`` returns
    ``facts.kernel``; ``services.apache`` returns ``facts.services["apache"]``.
    Returns None for any missing hop. One-level dict indexing is enough for
    the shipped fact model; deeper paths land when they're needed."""
    parts = path.split(".", 1)
    root = getattr(facts, parts[0], None)
    if len(parts) == 1:
        return root
    if isinstance(root, dict):
        return root.get(parts[1])
    return None


def _p_version_range(facts, value):
    """Matches when every declared field's version satisfies the given
    constraint spec.

    ``value`` is a dict ``{field: spec}`` where:
      * ``field`` names a HostFacts version attribute (kernel, sudo_version,
        pkexec_version, glibc_version, win_build) OR a dotted path into a
        dict-valued attribute (``services.apache``, ``services.openssh``);
      * ``spec`` is a comma-separated list of constraints, each of the form
        ``<op><version>`` where op is one of ``<``, ``<=``, ``>``, ``>=``,
        ``==``, ``!=``. All constraints on a field are AND-ed; all fields
        in the dict are AND-ed. E.g. ``kernel: ">=2.6.22,<=4.8.3"``.

    Missing / unparseable host versions are treated as "cannot decide → no
    match" so a partially-enumerated host never spuriously fires a version-
    gated exploit.

    Returns ``(matched, payload)`` where ``payload`` (on match) is
    ``{"field": <first-declared-field-name>, "version": <host-version-str>,
    "lo": <derived-lo>, "hi": <derived-hi>}`` — the derived bounds let the
    evidence-template renderer produce
    ``"kernel 5.15.0 in 5.8–5.16.11"`` without walking ``ttp.detect.value``
    (important for compound `all_of` predicates that wrap version_range).
    """
    if not isinstance(value, dict):
        return False, None
    payload = None
    for field_name, spec in value.items():
        raw_host_val = _resolve_field(facts, field_name)
        host_v = _parse_version(raw_host_val)
        if host_v is None:
            return False, None
        for raw in str(spec).split(","):
            parsed = _parse_constraint(raw)
            if parsed is None:
                return False, None
            op_fn, target_v = parsed
            if not op_fn(host_v, target_v):
                return False, None
        if payload is None:
            lo, hi = _derive_lo_hi(spec)
            payload = {"field": field_name, "version": str(raw_host_val),
                       "lo": lo, "hi": hi}
    return True, payload


def _p_no_hotfix_from(facts, value):
    """Matches when NONE of the listed Windows KBs are installed on the target.

    ``value`` is a list of KB IDs (e.g. ``["KB4601319", "KB4601315"]``). The
    predicate returns True when ``facts.hotfixes ∩ value == ∅`` — i.e. the
    target has not received any of the fixes that would close the CVE this
    predicate guards.

    Mirrors the inlined ``win_lpe_candidates``: an empty ``facts.hotfixes``
    (the enumerator didn't capture the KB list) still counts as "no fix
    installed" and lets the rule fire — the analyze report notes this
    caveat. Refusing to fire on missing enum would silently under-report
    on hosts where the operator hasn't run ``wmic qfe get``.
    """
    if not isinstance(value, (list, tuple)):
        return False, None
    installed = set(getattr(facts, "hotfixes", set()) or set())
    if installed & set(value):
        return False, None
    return True, None


def _p_all_of(facts, value):
    """Compound predicate: matches when every sub-predicate in ``value``
    matches. ``value`` is a list of single-entry dicts, each of the shape a
    top-level ``detect:`` block takes (``{"version_range": {...}}``,
    ``{"no_hotfix_from": [...]}``, etc.).

    Propagates the first sub-predicate's non-None payload up, so a TTP that
    combines ``version_range`` (which returns lo/hi/version) with
    ``no_hotfix_from`` (which returns None) can still render an evidence
    template referencing ``{{version}}`` / ``{{lo}}`` / ``{{hi}}``.
    """
    if not isinstance(value, list) or not value:
        return False, None
    propagated = None
    for entry in value:
        if not isinstance(entry, dict) or len(entry) != 1:
            return False, None
        (kind, sub_value), = entry.items()
        sub = _PREDICATES.get(kind)
        if sub is None:
            return False, None
        matched, sub_payload = sub(facts, sub_value)
        if not matched:
            return False, None
        if propagated is None and sub_payload is not None:
            propagated = sub_payload
    return True, propagated


def _derive_lo_hi(spec):
    """Extract human-readable low/high bounds from a version_range spec
    ``">=5.8,<=5.16.11"`` → ``("5.8", "5.16.11")``. Used to render the
    evidence template's ``{{lo}}`` / ``{{hi}}`` slots so a kernel-CVE port
    reproduces the inlined driver's ``"kernel 5.15.0 in 5.8–5.16.11"``
    evidence string. Unbounded ends collapse to ``"*"``."""
    lo, hi = "*", "*"
    for raw in str(spec).split(","):
        raw = raw.strip()
        for op in _OP_ORDER:
            if raw.startswith(op):
                ver = raw[len(op):].strip()
                if op in (">=", ">"):
                    lo = ver
                elif op in ("<=", "<"):
                    hi = ver
                elif op == "==":
                    lo = hi = ver
                break
    return lo, hi


_PREDICATES = {
    "always":         _p_always,
    "sudo_allows":    _p_sudo_allows,
    "suid":           _p_suid,
    "capability":     _p_capability,
    "facts_match":    _p_facts_match,
    "privilege":      _p_privilege,
    "group_member":   _p_group_member,
    "version_range":  _p_version_range,
    "no_hotfix_from": _p_no_hotfix_from,
    "all_of":         _p_all_of,
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


def _stage_for(ttp, ctx):
    """The platform-appropriate stage dir for this TTP. Windows TTPs read
    ctx.stage_win; Linux/mac read ctx.stage_lin. TTPs that declare multiple
    platforms fall back to whichever ctx attribute is set."""
    if "windows" in ttp.platform:
        return getattr(ctx, "stage_win", None) or getattr(ctx, "stage_lin", None) or ""
    return getattr(ctx, "stage_lin", None) or getattr(ctx, "stage_win", None) or ""


def _substitute(command, payload, stage):
    """Fill template variables in the command with the matched payload / stage.

    Supported:
      * ``{{binary}}`` — the binary basename the predicate matched (a
        sudo-allowed binary, a cap-carrying binary, …).
      * ``{{stage}}`` — the platform-appropriate staging dir (windows:
        stage_win; linux: stage_lin). Matches the inlined `_win_vector`'s
        ``{stage}`` substitution convention.
    """
    out = command
    if payload and isinstance(payload, str) and "{{binary}}" in out:
        out = out.replace("{{binary}}", payload)
    if "{{stage}}" in out:
        out = out.replace("{{stage}}", stage)
    return out


def _render_evidence(ttp, payload, facts):
    """Render ``ttp.report.evidence`` template into the Vector.evidence string.

    Supported template variables:
      * ``{{field}}`` / ``{{version}}`` — from a version_range payload
        (e.g. ``kernel`` / ``5.15.0``).
      * ``{{lo}}`` / ``{{hi}}`` — bounds derived from the version_range spec
        for the payload's field (``5.8`` / ``5.16.11``).
      * ``{{binary}}`` — the basename that a suid/capability/sudo_allows
        predicate matched.

    When no template is declared, falls back to a generic
    ``"detected via TTP T1068 (version_range)"`` — the shape existing TTPs
    already emit.
    """
    template = ttp.report.evidence
    if not template:
        return f"detected via TTP {ttp.technique} ({ttp.detect.kind})"
    out = template
    if isinstance(payload, dict):
        # version_range (or a compound predicate that wraps it) hands back
        # field/version/lo/hi already extracted, so rendering the template
        # doesn't need to walk ttp.detect.value — that walk gets fragile
        # under `all_of` where the version_range spec lives one level down.
        out = out.replace("{{field}}",   payload.get("field", ""))
        out = out.replace("{{version}}", payload.get("version", ""))
        out = out.replace("{{lo}}",      payload.get("lo", "*"))
        out = out.replace("{{hi}}",      payload.get("hi", "*"))
    elif isinstance(payload, str):
        out = out.replace("{{binary}}", payload)
    _ = facts
    return out


def _build_playbook(ttp, payload, stage):
    """Convert ``ttp.playbook`` (a schema.Playbook) into a runtime
    :class:`fieldkit.privesc.Playbook`, applying ``{{stage}}`` / ``{{binary}}``
    substitution to place / steps / restore. Returns None when the TTP has no
    playbook.

    The runtime Playbook is what fieldkit.privesc.Vector.manual reads to
    decide "prepare, don't fire" — kernel-CVE routes against client hosts
    carry one; auto-firing TTPs (sudo, caps) do not.
    """
    pb = ttp.playbook
    if pb is None:
        return None
    return Playbook(
        summary=_substitute(pb.summary, payload, stage),
        place=_substitute(pb.place, payload, stage),
        steps=tuple(_substitute(s, payload, stage) for s in pb.steps),
        restore=_substitute(pb.restore, payload, stage) if pb.restore else None,
    )


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
    stage = _stage_for(ttp, ctx)
    # For {{binary}} substitution the payload is expected to be a string
    # (suid/cap/sudo_allows return the matched binary). version_range returns
    # a dict — pass an empty string so {{binary}} is a no-op there.
    binary = payload if isinstance(payload, str) else ""
    # stages: substitute {{stage}} in the remote path so a YAML can say
    # `as: "{{stage}}\\GodPotato.exe"` and get "C:\Windows\Temp\GodPotato.exe".
    stages = tuple(
        (name, _substitute(remote, binary, stage))
        for name, remote in ttp.execute.stages
    )
    return Vector(
        key=_key_for(ttp, payload),
        title=ttp.name,
        exploitability=ttp.ranking.exploitability,
        safety=ttp.ranking.safety,
        detection=ttp.ranking.detection,
        command=_substitute(ttp.execute.command, binary, stage),
        shell=shell,
        host=ctx.host,
        detail=ttp.report.description or f"loaded from TTP {ttp.technique}",
        evidence=_render_evidence(ttp, payload, facts),
        safe_proof=_substitute(ttp.verify.proof, binary, stage) if ttp.verify.proof else None,
        cleanup=_substitute(ttp.cleanup.command, binary, stage) if ttp.cleanup.command else None,
        report_type=ttp.report.vector_type,
        family=ttp.family or None,
        delivery=ttp.delivery or None,
        stages=stages,
        serves=ttp.execute.serves,
        playbook=_build_playbook(ttp, binary, stage),
    )
