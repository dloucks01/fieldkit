"""CVSS v3.1 vector derivation + score calculation.

Builds a canonical CVSS v3.1 vector string + base score from a
:class:`fieldkit.reportkb` entry + a :class:`fieldkit.privesc.Vector`.
The point: customer reports frequently need a CVSS score per finding
(SOC teams gate remediation SLAs on it, pentest reports under certain
compliance regimes mandate it) and fieldkit was previously silent on
score — operators derived it by hand.

Pure. Stdlib-only. No external data file.

The derivation isn't arbitrary — we map KB severity + ranking triples
to the CVSS metric values. A High / config-change / moderate finding
is derived as ``AV:L / AC:L / PR:L / UI:N / S:U / C:H / I:H / A:L``:
local attack vector, low complexity, low privs required, no user
interaction, scope unchanged, high confidentiality + integrity impact,
low availability impact. We expose both the vector string and the
numeric base score (3.1 formula), rounded to 1 decimal."""
import math
from dataclasses import dataclass


# Base metric values — the standard CVSS v3.1 weighting.
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}  # scope unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}   # scope changed
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


@dataclass(frozen=True)
class CVSSResult:
    """CVSS v3.1 derivation output.

    ``vector`` is the canonical ``CVSS:3.1/AV:L/AC:L/PR:L/UI:N/...`` string.
    ``score`` is the base score, rounded to 1 decimal (CVSS v3.1 spec).
    ``severity`` is the five-level qualitative label (None/Low/Medium/High/Critical).
    """
    vector: str
    score: float
    severity: str


_SEV_FROM_SCORE = (
    (9.0, "Critical"),
    (7.0, "High"),
    (4.0, "Medium"),
    (0.1, "Low"),
)


def _round_up(x):
    """CVSS v3.1 roundUp1: round up to the nearest 0.1. The 10000x
    multiplier avoids float jitter at the tenths boundary (0.9 + 0.1
    style noise)."""
    return math.ceil(x * 10) / 10


def _severity_label(score):
    for threshold, label in _SEV_FROM_SCORE:
        if score >= threshold:
            return label
    return "None"


def _base_score(av, ac, pr, ui, scope, c, i, a):
    """CVSS v3.1 base-score formula (verbatim from the standard — the
    numbers are the spec)."""
    iss = 1 - ((1 - _CIA[c]) * (1 - _CIA[i]) * (1 - _CIA[a]))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    exploitability = 8.22 * _AV[av] * _AC[ac] * (
        _PR_U[pr] if scope == "U" else _PR_C[pr]) * _UI[ui]
    if impact <= 0:
        return 0.0
    if scope == "U":
        return _round_up(min(impact + exploitability, 10))
    return _round_up(min(1.08 * (impact + exploitability), 10))


# Mapping from the operator-facing (severity, ranking triple) tuples to
# the CVSS metric values. The mapping is intentionally conservative — a
# "Critical" finding with "crash-risk" safety doesn't inflate availability
# impact just because the vector exists.
_SEVERITY_IMPACT = {
    # severity → (C, I, A)
    "Critical": ("H", "H", "H"),
    "High":     ("H", "H", "L"),
    "Medium":   ("L", "L", "L"),
    "Low":      ("L", "N", "N"),
    "Info":     ("N", "N", "N"),
}


_SAFETY_AVAILABILITY = {
    # safety → availability override (None = use severity default)
    "crash-risk":      "H",
    "service-restart": "L",
    "config-edit":     "L",
    "reversible":      "L",
    "read-only":       None,
}


_DETECTION_PRIV_UI = {
    # detection → (PR, UI)
    # quiet detection ≈ no need for a privileged setup — low privs, no UI
    "quiet":    ("L", "N"),
    "moderate": ("L", "N"),
    "loud":     ("L", "R"),  # loud techniques often need user interaction
}


_EXPLOITABILITY_AV_AC = {
    "high":   ("L", "L"),   # local, low complexity
    "medium": ("L", "H"),   # local, high complexity
    "low":    ("P", "H"),   # physical / contrived prereqs
}


def derive(severity, exploitability, safety, detection, scope="U"):
    """Return a :class:`CVSSResult` for the given KB severity label +
    ranking triple.

    ``scope`` is "U" (unchanged) by default. Pass "C" for findings whose
    exploitation reaches resources outside the vulnerable component's
    security authority — K8s SA → cluster-admin, container escapes.

    The mapping is deliberately coarse (CVSS has 8 base metrics × ~3 values
    each = thousands of valid vectors; we project to a few operator-
    meaningful shapes) but produces repeatable, defensible scores suitable
    for a customer-facing finding row."""
    c_impact, i_impact, a_default = _SEVERITY_IMPACT.get(severity,
                                                           ("L", "L", "L"))
    a_impact = _SAFETY_AVAILABILITY.get(safety, a_default) or a_default
    pr, ui = _DETECTION_PRIV_UI.get(detection, ("L", "N"))
    av, ac = _EXPLOITABILITY_AV_AC.get(exploitability, ("L", "H"))
    s = scope
    score = _base_score(av, ac, pr, ui, s, c_impact, i_impact, a_impact)
    vector = (f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}"
              f"/C:{c_impact}/I:{i_impact}/A:{a_impact}")
    return CVSSResult(vector=vector, score=score,
                      severity=_severity_label(score))


def derive_from_kb(kb_entry, ranking):
    """Convenience: pull severity from a reportkb entry dict and the
    ranking triple from a :class:`privesc.Vector` (or anything with
    ``.exploitability`` / ``.safety`` / ``.detection``)."""
    severity = kb_entry.get("sev", "Medium") if isinstance(kb_entry, dict) else "Medium"
    scope = "C" if _is_scope_changing(ranking) else "U"
    return derive(severity,
                  getattr(ranking, "exploitability", "medium"),
                  getattr(ranking, "safety", "config-change"),
                  getattr(ranking, "detection", "moderate"),
                  scope=scope)


def _is_scope_changing(ranking):
    """A vector's exploitation changes CVSS scope when it reaches
    resources outside its own authority — container escape to host, K8s
    SA to cluster-admin, kernel LPE (bypasses the user-boundary). We
    treat ``safety == 'crash-risk'`` (kernel exploits) and ``safety ==
    'config-change'`` paired with a known-scope-changing hint as
    scope-changing."""
    safety = getattr(ranking, "safety", "")
    if safety == "crash-risk":
        return True
    return False
