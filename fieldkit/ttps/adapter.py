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

from ..privesc import Playbook, Vector, _canon, _slug


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


def _p_capability_on_binary(facts, value):
    """Matches when a specific binary carries a specific capability.

    ``value`` is a dict ``{"binary": <canon>, "cap": <capname>}``. The
    binary match is ``_canon``-aware: ``binary: python`` matches ``python``,
    ``python3``, ``python3.8``, etc. (mirroring what the inlined
    :func:`fieldkit.privesc._cap_vector` did for the interpreter+cap_setuid
    case).

    Payload is the ACTUAL host basename, so ``{{binary}}`` in the command
    renders as the real invokable file and the vector key ends
    ``cap:python3.8`` instead of the abstract ``cap:python``. Used by the
    T1548.001-cap_setuid-*.yaml ports for python / perl / ruby / php.
    """
    if not isinstance(value, dict):
        return False, None
    want_bin = value.get("binary")
    want_cap = value.get("cap")
    if not want_bin or not want_cap:
        return False, None
    for binname, cap in facts.caps.items():
        if cap != want_cap:
            continue
        if binname == want_bin or _canon(binname) == want_bin:
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


def _p_linux_group(facts, value):
    """Linux: matches when `value` (a group name, e.g. `docker`) is in
    ``facts.groups`` AND the caller is not already root.

    Mirrors the inlined :func:`fieldkit.privesc._d_docker_group`'s
    "docker group + not root" gate: an escalation vector against uid=0
    is nonsense, so the vector never fires for a root operator. Payload
    is the group name (matches the inlined driver's evidence).
    """
    if facts.is_root:
        return False, None
    if value in getattr(facts, "groups", set()):
        return True, value
    return False, None


def _p_sudo_env_keep_any(facts, value):
    """Matches when ANY of the listed env vars is preserved by sudo
    (``facts.sudo_env_keep``).

    ``value`` is a list of env-var names to watch, e.g.
    ``[LD_PRELOAD, LD_LIBRARY_PATH]`` for the classic sudo LD_PRELOAD
    escalation. Mirrors the inlined :func:`fieldkit.privesc._d_sudo_env`'s
    intersection check.

    Payload is a comma-joined sorted string of the matched vars
    (``"LD_PRELOAD"`` or ``"LD_LIBRARY_PATH, LD_PRELOAD"``) so the
    evidence template can render "sudo -l: env_keep+={{binary}}"
    reusing the {{binary}} slot for the matched-env-var string.
    """
    if not isinstance(value, (list, tuple)):
        return False, None
    kept = getattr(facts, "sudo_env_keep", set()) or set()
    matched = sorted(kept & set(value))
    if not matched:
        return False, None
    return True, ", ".join(matched)


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


# -------- per-item iterable predicates (Windows service abuse) -----------
#
# These predicates return a LIST of payload dicts — one per matching service
# — instead of the single (bool, payload) tuple the classic predicates use.
# `ttp_to_vectors` detects the list return and emits ONE Vector per payload,
# so a single TTP YAML can cover N services in facts.<attr>. Mirrors the
# inlined _d_win_unquoted / _d_win_weak_service / _d_win_writable_service /
# _d_win_dll_hijack drivers' per-service iteration.
#
# The convention: a list return with 0 items = no match (the caller emits
# nothing); a list with N items = N matches. Non-list returns keep the
# classic single-fire semantics.


def _p_unquoted_services(facts, value):
    """One payload per entry in ``facts.unquoted_services``, optionally
    filtered by whether the enumerator recovered a service name.

    HostFacts stores unquoted services as a list of ``(service_name_or_None,
    path)`` tuples. This yields per-service payloads with:
      * ``name`` — the service name (or ``"?"`` when unnamed);
      * ``path`` — the raw unquoted service binPath;
      * ``candidate`` — the first space-truncated candidate Windows would
        try to run (``path.split(" ", 1)[0] + ".exe"``) — the file the
        operator plants;
      * ``proof`` — where the built payload writes its whoami output.

    ``value`` — optional dict with ``has_name: <bool>`` to filter to the
    named / unnamed subset. Two TTPs share this predicate: the
    ``has_name: true`` variant auto-fires (it can `sc stop <name> &
    sc start <name>`), the ``has_name: false`` variant is
    guidance-only (mirrors the inlined driver's `if name: … else: …`
    branch). Omitting the filter returns every unquoted service.
    """
    want_named = value.get("has_name") if isinstance(value, dict) else None
    out = []
    for entry in getattr(facts, "unquoted_services", None) or ():
        name, path = entry
        if want_named is True and not name:
            continue
        if want_named is False and name:
            continue
        candidate = path.split(" ", 1)[0] + ".exe"
        out.append({
            "name": name or "?",
            "path": path,
            "candidate": candidate,
            "proof": "{{stage}}\\up.txt",
        })
    return (True, out) if out else (False, None)


def _p_reconfigurable_services(facts, value):
    """One payload per entry in ``facts.reconfigurable_services`` (dict
    ``name → current_binPath``). Each payload carries:
      * ``name`` — the service name;
      * ``binpath`` — the current binPath (needed to restore after the
        exploit re-configures it);
      * ``slug`` — sanitized name (``_slug(name)``) for filename-safe use
        in the proof file path.
    Sorted by name for deterministic output (matches the inlined driver).
    """
    _ = value
    out = []
    for name, binpath in sorted((getattr(facts, "reconfigurable_services", None) or {}).items()):
        out.append({"name": name, "binpath": binpath, "slug": _slug(name)})
    return (True, out) if out else (False, None)


def _p_writable_service_bins(facts, value):
    """One payload per entry in ``facts.writable_service_bins`` (dict
    ``name → writable exe path``). Each payload carries:
      * ``name`` — the service name;
      * ``exe`` — the writable service binary the operator overwrites;
      * ``slug`` — sanitized name for a per-service staged filename.
    """
    _ = value
    out = []
    for name, exe in sorted((getattr(facts, "writable_service_bins", None) or {}).items()):
        out.append({"name": name, "exe": exe, "slug": _slug(name)})
    return (True, out) if out else (False, None)


def _p_writable_service_dirs(facts, value):
    """One payload per entry in ``facts.writable_service_dirs`` (dict
    ``name → writable dir path``), SKIPPING services that also appear in
    ``facts.writable_service_bins`` — mirrors the inlined
    ``_d_win_dll_hijack``'s dedup ("a writable binary is the simpler route
    — don't offer both"). Each surviving payload carries:
      * ``name`` — the service name;
      * ``dir`` — the writable directory the operator plants a DLL into;
      * ``slug`` — sanitized name.
    """
    _ = value
    also_writable_bin = set((getattr(facts, "writable_service_bins", None) or {}).keys())
    out = []
    for name, dir_ in sorted((getattr(facts, "writable_service_dirs", None) or {}).items()):
        if name in also_writable_bin:
            continue
        out.append({"name": name, "dir": dir_, "slug": _slug(name)})
    return (True, out) if out else (False, None)


_PREDICATES = {
    "always":                     _p_always,
    "sudo_allows":                _p_sudo_allows,
    "suid":                       _p_suid,
    "capability":                 _p_capability,
    "capability_on_binary":       _p_capability_on_binary,
    "facts_match":                _p_facts_match,
    "privilege":                  _p_privilege,
    "group_member":               _p_group_member,
    "linux_group":                _p_linux_group,
    "sudo_env_keep_any":          _p_sudo_env_keep_any,
    "version_range":              _p_version_range,
    "no_hotfix_from":             _p_no_hotfix_from,
    "all_of":                     _p_all_of,
    "unquoted_services":          _p_unquoted_services,
    "reconfigurable_services":    _p_reconfigurable_services,
    "writable_service_bins":      _p_writable_service_bins,
    "writable_service_dirs":      _p_writable_service_dirs,
}


def _key_for(ttp, matched_payload, stage=""):
    """Vector key that matches the inlined-driver naming so `vectors_for`'s
    dedup collapses same-target vectors regardless of source.

    When ``ttp.key`` contains ``{{…}}`` template variables and the payload
    is a dict, the key is rendered per-payload — used by the per-item
    Windows service TTPs so each service gets a distinct key
    (``unquoted:C:\\Program Files\\svc.exe`` / ``weakservice:AppMgmt``).
    """
    if ttp.key:
        if "{{" in ttp.key and isinstance(matched_payload, dict):
            return _substitute(ttp.key, matched_payload, stage)
        return ttp.key
    kind = ttp.detect.kind
    if kind == "sudo_allows" and matched_payload:
        return f"sudo:{matched_payload}"
    if kind == "suid" and matched_payload:
        return f"suid:{matched_payload}"
    if kind == "capability" and matched_payload:
        return f"cap:{matched_payload}"
    if kind == "capability_on_binary" and matched_payload:
        # Same key namespace as the inlined _cap_vector — a per-binary
        # capability route dedups against the generic `capability` TTPs
        # (cap_dac_read_search, cap_dac_override) that also use `cap:<bin>`.
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
        sudo-allowed binary, a cap-carrying binary, …). When ``payload`` is
        a string it fills this slot directly.
      * Any ``{{<key>}}`` where ``<key>`` is a key in ``payload`` (dict) —
        used by the per-item Windows service predicates whose payloads
        carry rich context (``{{name}}`` / ``{{path}}`` / ``{{proof}}``…).
      * ``{{stage}}`` — the platform-appropriate staging dir (windows:
        stage_win; linux: stage_lin). Matches the inlined `_win_vector`'s
        ``{stage}`` substitution convention.
    """
    if command is None:
        return None
    out = command
    if isinstance(payload, str) and payload and "{{binary}}" in out:
        out = out.replace("{{binary}}", payload)
    elif isinstance(payload, dict):
        for key, value in payload.items():
            token = "{{" + key + "}}"
            if token in out:
                out = out.replace(token, str(value))
    if "{{stage}}" in out:
        out = out.replace("{{stage}}", stage)
    return out


def _render_evidence(ttp, payload, facts):
    """Render ``ttp.report.evidence`` template into the Vector.evidence string.

    Supported template variables:
      * ``{{binary}}`` — the basename that a suid/capability/sudo_allows
        predicate matched (payload is a string);
      * Any ``{{<key>}}`` where ``<key>`` is a key in ``payload`` (dict)
        — covers version_range's ``{{field}}``/``{{version}}``/``{{lo}}``/
        ``{{hi}}`` as well as the per-item service predicates' rich keys
        (``{{name}}`` / ``{{path}}`` / ``{{binpath}}`` / …).

    When no template is declared, falls back to a generic
    ``"detected via TTP T1068 (version_range)"`` — the shape existing TTPs
    already emit.
    """
    _ = facts
    template = ttp.report.evidence
    if not template:
        return f"detected via TTP {ttp.technique} ({ttp.detect.kind})"
    out = template
    if isinstance(payload, dict):
        for key, value in payload.items():
            out = out.replace("{{" + key + "}}", str(value))
        # Unbound {{lo}}/{{hi}} for a payload that didn't carry them
        # collapse to '*' — same convention _derive_lo_hi uses.
        out = out.replace("{{lo}}", "*").replace("{{hi}}", "*")
    elif isinstance(payload, str):
        out = out.replace("{{binary}}", payload)
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


def _build_vector(ttp, payload, facts, ctx, stage):
    """Assemble one :class:`Vector` from a TTP + matched payload. Split out
    of :func:`ttp_to_vector` so :func:`ttp_to_vectors` can call it per-item
    when a predicate hands back a list of payloads (Windows service abuse)."""
    # Shell selection: honor YAML's `execute.shell` if declared, else default
    # per platform (`cmd` on windows, `sh` on linux). Windows TTPs that use
    # PowerShell explicitly set `execute.shell: powershell`.
    shell = ttp.execute.shell or ("cmd" if facts.os == "windows" else "sh")
    # For {{binary}} substitution the payload is expected to be a string
    # (suid/cap/sudo_allows return the matched binary). version_range and
    # the iterable service predicates return a dict — pass it through so
    # _substitute renders arbitrary {{key}} tokens.
    subst = payload if isinstance(payload, (str, dict)) else ""
    stages = tuple(
        (name, _substitute(remote, subst, stage))
        for name, remote in ttp.execute.stages
    )
    builds = tuple(
        (fmt,
         _substitute(remote, subst, stage),
         _substitute(run, subst, stage) if run else None)
        for fmt, remote, run in ttp.execute.builds
    )
    return Vector(
        key=_key_for(ttp, payload, stage),
        title=ttp.name,
        exploitability=ttp.ranking.exploitability,
        safety=ttp.ranking.safety,
        detection=ttp.ranking.detection,
        command=_substitute(ttp.execute.command, subst, stage),
        shell=shell,
        host=ctx.host,
        detail=ttp.report.description or f"loaded from TTP {ttp.technique}",
        evidence=_render_evidence(ttp, payload, facts),
        safe_proof=_substitute(ttp.verify.proof, subst, stage) if ttp.verify.proof else None,
        cleanup=_substitute(ttp.cleanup.command, subst, stage) if ttp.cleanup.command else None,
        report_type=ttp.report.vector_type,
        family=ttp.family or None,
        delivery=ttp.delivery or None,
        stages=stages,
        serves=ttp.execute.serves,
        builds=builds,
        playbook=_build_playbook(ttp, subst, stage),
    )


def ttp_to_vectors(ttp, facts, ctx):
    """Return every :class:`Vector` this TTP produces against the given facts.

    Most TTPs fire at most once per host and return either ``[]`` or a
    one-element list. Per-item iterable predicates (the Windows service-abuse
    quartet: unquoted / weak / writable / dllhijack) return one Vector PER
    matching service — a single YAML covers N services in ``facts.<attr>``.

    The dispatch is uniform: a predicate that returns ``(True, <list>)``
    with a list payload triggers per-item emission; anything else
    (single-payload string / dict / None) emits one Vector.
    """
    if facts.os not in ttp.platform:
        return []
    predicate = _PREDICATES.get(ttp.detect.kind)
    if predicate is None:
        return []
    matched, payload = predicate(facts, ttp.detect.value)
    if not matched:
        return []
    stage = _stage_for(ttp, ctx)
    if isinstance(payload, list):
        return [_build_vector(ttp, item, facts, ctx, stage) for item in payload]
    return [_build_vector(ttp, payload, facts, ctx, stage)]


def ttp_to_vector(ttp, facts, ctx):
    """Legacy single-vector convenience wrapper. Returns the first Vector
    :func:`ttp_to_vectors` produces or ``None``. Preserved for existing
    callers (test suites, single-vector integration checks); the vector
    emission path uses :func:`ttp_to_vectors` so per-item iteration works.
    """
    vs = ttp_to_vectors(ttp, facts, ctx)
    return vs[0] if vs else None
