"""Offline CVE lookup for the components fieldkit's TTP catalog already
tracks.

The catalog itself is the source of truth: every ``cve:*`` TTP carries
its CVE identifier, the component it targets (kernel / sudo / pkexec /
glibc / windows build), and the version range it affects. This module
projects that information into a dict keyed by component — the operator
asks "which CVEs apply to kernel 5.15.0?" and we answer without touching
the network and without re-pasting NVD data that would drift.

Zero network. Zero external data file. Zero drift risk — if a new CVE
TTP lands in the catalog, this module picks it up on the next import.
"""
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class CVEMatch:
    """One CVE that applies to a component at a given version.

    ``cve`` is the identifier (``CVE-2022-0847``), ``name`` is a short
    label (``Dirty Pipe``), ``component`` is the HostFacts attribute
    (``kernel``, ``sudo_version``, ``pkexec_version``, ``glibc_version``),
    ``range_spec`` is the raw version-range string the TTP carried
    (``>=5.8,<=5.16.11``), ``ttp_key`` is the matching ``cve:*`` key so
    the caller can look up the full TTP for playbook / stages."""
    cve: str
    name: str
    component: str
    range_spec: str
    ttp_key: str


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def _parse_version(s):
    """Return a tuple-of-ints version from a string, dropping trailing
    non-numeric suffixes (``5.16.11-rc1`` → ``(5, 16, 11)``, same as
    ``fieldkit.ttps.adapter._parse_version``'s shape so matches agree)."""
    if not s:
        return None
    out = []
    for part in str(s).split("."):
        m = re.match(r"(\d+)", part)
        if not m:
            break
        out.append(int(m.group(1)))
    return tuple(out) if out else None


def _parse_constraint(c):
    """Parse ``>=5.8``, ``<=5.16.11``, ``!=1.9.5p2`` → (op, version_tuple).
    Returns None if the constraint doesn't parse cleanly."""
    c = c.strip()
    for op in ("<=", ">=", "==", "!=", "<", ">"):
        if c.startswith(op):
            v = _parse_version(c[len(op):].strip())
            if v is None:
                return None
            return op, v
    return None


def _version_in_range(version_tuple, spec):
    """Return True if ``version_tuple`` satisfies every constraint in
    ``spec`` (comma-separated AND)."""
    if version_tuple is None:
        return False
    for raw in spec.split(","):
        parsed = _parse_constraint(raw)
        if parsed is None:
            return False
        op, target = parsed
        # Pad shorter tuples so comparison is apples-to-apples.
        a, b = version_tuple, target
        if len(a) < len(b):
            a = a + (0,) * (len(b) - len(a))
        elif len(b) < len(a):
            b = b + (0,) * (len(a) - len(b))
        if op == ">=" and not a >= b: return False
        if op == "<=" and not a <= b: return False
        if op == ">"  and not a >  b: return False
        if op == "<"  and not a <  b: return False
        if op == "==" and not a == b: return False
        if op == "!=" and not a != b: return False
    return True


def _build_catalog():
    """Walk the TTP loader output + extract every ``cve:*`` TTP whose
    detect is ``version_range``. Returns a list of :class:`CVEMatch`
    with ``range_spec`` ready to feed to ``_version_in_range``."""
    from .ttps.loader import load_all
    cat = []
    for t in load_all():
        if not t.key or not t.key.startswith("cve:"):
            continue
        if t.detect.kind != "version_range":
            continue
        for component, spec in (t.detect.value or {}).items():
            cve_ids = _CVE_RE.findall(" ".join(t.report.refs or []))
            cve_id = cve_ids[0] if cve_ids else t.key.replace("cve:", "").upper()
            cat.append(CVEMatch(
                cve=cve_id, name=t.name, component=component,
                range_spec=str(spec), ttp_key=t.key))
    return cat


_CATALOG_CACHE = None


def _catalog():
    global _CATALOG_CACHE
    if _CATALOG_CACHE is None:
        _CATALOG_CACHE = _build_catalog()
    return _CATALOG_CACHE


def _reset_cache_for_tests():
    """Force the next ``_catalog()`` call to re-read the TTP catalog."""
    global _CATALOG_CACHE
    _CATALOG_CACHE = None


def lookup(component, version):
    """Return every :class:`CVEMatch` whose component matches and whose
    range spec contains ``version``.

    ``component`` is a HostFacts attribute name (``kernel``,
    ``sudo_version``, ``pkexec_version``, ``glibc_version``).
    ``version`` is the version string as HostFacts would carry it."""
    v = _parse_version(version)
    if v is None:
        return []
    return [c for c in _catalog()
            if c.component == component and _version_in_range(v, c.range_spec)]


def lookup_facts(facts):
    """Convenience: lookup CVEs across every version-bearing attribute
    on a :class:`HostFacts` instance. Returns a flat list sorted by
    component then CVE id."""
    out = []
    for component in ("kernel", "sudo_version", "pkexec_version",
                      "glibc_version"):
        v = getattr(facts, component, None)
        if v:
            out.extend(lookup(component, v))
    out.sort(key=lambda c: (c.component, c.cve))
    return out
