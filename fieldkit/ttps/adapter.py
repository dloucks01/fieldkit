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

from ..privesc import Vector


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

_VERSION_RE = re.compile(r"^\s*(\d+(?:\.\d+)*)")


def _parse_version(s):
    """Turn a version string into a normalized 4-tuple of ints. Ignores
    trailing non-numeric suffixes (`5.15.0-generic` → `(5,15,0,0)`),
    pads short versions with zeros so tuple compare is honest
    (`5.15` == `5.15.0.0` == `(5,15,0,0)`).

    Returns None for unparseable input — the predicate treats that as
    "cannot decide, don't match".
    """
    if not s:
        return None
    m = _VERSION_RE.match(str(s))
    if not m:
        return None
    parts = tuple(int(x) for x in m.group(1).split("."))
    while len(parts) < 4:
        parts = parts + (0,)
    return parts[:4]


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
        pkexec_version, glibc_version) OR a dotted path into a dict-valued
        attribute (``services.apache``, ``services.openssh``);
      * ``spec`` is a comma-separated list of constraints, each of the form
        ``<op><version>`` where op is one of ``<``, ``<=``, ``>``, ``>=``,
        ``==``, ``!=``. All constraints on a field are AND-ed; all fields
        in the dict are AND-ed. E.g. ``kernel: ">=2.6.22,<=4.8.3"``.

    Missing / unparseable host versions are treated as "cannot decide → no
    match" so a partially-enumerated host never spuriously fires a version-
    gated exploit.
    """
    if not isinstance(value, dict):
        return False, None
    for field, spec in value.items():
        host_v = _parse_version(_resolve_field(facts, field))
        if host_v is None:
            return False, None
        for raw in str(spec).split(","):
            parsed = _parse_constraint(raw)
            if parsed is None:
                return False, None
            op_fn, target_v = parsed
            if not op_fn(host_v, target_v):
                return False, None
    return True, None


_PREDICATES = {
    "always":        _p_always,
    "sudo_allows":   _p_sudo_allows,
    "suid":          _p_suid,
    "capability":    _p_capability,
    "facts_match":   _p_facts_match,
    "privilege":     _p_privilege,
    "group_member":  _p_group_member,
    "version_range": _p_version_range,
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
    # stages: substitute {{stage}} in the remote path so a YAML can say
    # `as: "{{stage}}\\GodPotato.exe"` and get "C:\Windows\Temp\GodPotato.exe".
    stages = tuple(
        (name, _substitute(remote, payload, ctx))
        for name, remote in ttp.execute.stages
    )
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
        family=ttp.family or None,
        delivery=ttp.delivery or None,
        stages=stages,
        serves=ttp.execute.serves,
    )
