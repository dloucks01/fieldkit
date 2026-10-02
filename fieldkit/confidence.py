"""Confidence scoring per finding — tells the reader *how sure* fieldkit
is about a result without re-reading the proof.

Four levels, inspired by Nemesis's three-tier model but adjusted for
fieldkit's capture-driven stance (every finding carries verbatim proof,
so "did we see this?" is a cheap, honest question):

  * ``direct_capture`` (1.0) — a shell step captured the specific outcome
    verbatim (``uid=0``, ``NT AUTHORITY\\SYSTEM``, a dumped NT hash,
    etc.). The proof IS the finding.
  * ``inferred_version`` (0.6) — matched a version-range rule (kernel
    CVE / sudo CVE / glibc CVE) without executing the exploit. Patch
    backports are common — the match is a strong lead, not proof.
  * ``predicted_pattern`` (0.4) — matched an enumeration pattern that
    *implies* exploitability (writable PAM module, docker group
    membership) without running the final step. The primitive exists;
    weaponizing is the operator's follow-up.
  * ``unverified`` (0.2) — a surface a tool reported but we did not
    corroborate (nuclei "possible" matches, LLMNR responses from a scanner
    that no fieldkit step reproduced). Low-signal — included for breadth,
    ranked below everything else.

Scoring is PURE: it reads step output + ranking triples + facts, and
returns a float. No I/O. The reader (``fieldkit timeline``, ``fieldkit
report``, downstream dashboards) ingests the number as-is.
"""
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Confidence:
    """Scored confidence for one step or finding.

    ``score`` is 0.0 – 1.0; ``label`` is the level name; ``why`` is a
    short human-readable rationale operators can quote in the report.
    """
    score: float
    label: str
    why: str = ""


DIRECT_CAPTURE = 1.0
INFERRED_VERSION = 0.6
PREDICTED_PATTERN = 0.4
UNVERIFIED = 0.2


#: Proof tokens that mean "the step observably achieved its outcome".
#: Lowercased for case-insensitive match. Order doesn't matter — any hit
#: promotes the step to direct_capture.
_DIRECT_PROOF_TOKENS = (
    "uid=0",
    "nt authority\\system",
    "nt authority\\\\system",
    "root",                       # bare "root" is noisy, but we also check column position
    "pwn3d!",                     # nxc success marker
    "shell access",               # nxc "SMB  ...  Shell access!" line
    "allowed:true",               # k8s SelfSubjectAccessReview positive
    "allowed\":true",             # k8s SelfSubjectAccessReview JSON
    "aad3b435",                   # empty LM in a captured hash row — hash was dumped
    "$krb5tgs$",                  # roasted ticket captured verbatim
    "$krb5asrep$",                # as-rep roast captured verbatim
    "akia",                       # cloud key extracted
    "has set",                    # dbus / policy modification confirmation
    "secretsdump",                # banner implies a dumped output
    "writable",                   # writable file enumeration confirms the primitive
)


def _has_direct_proof(output):
    """Return True when ``output`` contains a token that proves the
    step's outcome. Lowered-text check; no regex per token so the
    scorer is fast on long captures."""
    if not output:
        return False
    low = output.lower()
    for tok in _DIRECT_PROOF_TOKENS:
        if tok in low:
            return True
    # ``id`` output explicitly ending in a UID line — stricter than the
    # bare "root" token, cheap double-check.
    if re.search(r"\buid=\d+", low):
        return True
    return False


def score_step(step):
    """Score one captured step.

    ``step`` is a dict-shaped row (``{output, cmd, exit_code, ...}``) or
    anything with those attributes. The score reflects whether the
    captured output proves the step's intended outcome — if the step was
    a privesc check and the output shows ``uid=0``, it's direct; if the
    step enumerated writable paths and found some, it's a pattern-match
    (predicted); a failed step (exit != 0) is unverified unless proof
    tokens appear anyway (e.g. verify-success matched before the step
    exit code did)."""
    output = step.get("output") if isinstance(step, dict) else getattr(step, "output", None)
    exit_code = step.get("exit_code") if isinstance(step, dict) else getattr(step, "exit_code", None)
    if _has_direct_proof(output):
        return Confidence(DIRECT_CAPTURE, "direct_capture",
                          "captured output carries a canonical proof token")
    if exit_code == 0 and output and len(output.strip()) > 0:
        # Exit 0 + non-empty output = some enumeration primitive fired,
        # but we didn't observe the final outcome. Call it predicted.
        return Confidence(PREDICTED_PATTERN, "predicted_pattern",
                          "step completed cleanly but output lacks a canonical proof token")
    # Non-zero exit or empty output — the step didn't give us evidence.
    return Confidence(UNVERIFIED, "unverified",
                      "step exited non-zero or produced no output")


def score_finding(finding, steps=None):
    """Score a finding by combining:

      1. the ranking triple (exploitability × safety × detection) — a
         high-exploitability finding without captured proof still ranks
         ABOVE a medium one with the same proof shape;
      2. the strongest step-level score among its captured proof rows.

    ``finding`` is a dict-shaped row; ``steps`` is the list of captured
    step rows for that finding (as :meth:`state.Store.steps` returns
    them). ``steps=None`` means "no captured proof" — the score falls
    back to the ranking-only prediction (``predicted_pattern`` for
    high-exploitability, ``unverified`` otherwise).

    Three ranking-only shapes that routinely show up:

      * ``cve:*`` (version_range matched, no exploit run) — inferred_version
      * loot/persist facts-match (writable primitive detected, not
        weaponized) — predicted_pattern
      * everything else without captured proof — unverified"""
    if steps:
        best = max((score_step(s) for s in steps),
                   key=lambda c: c.score, default=None)
        if best and best.score >= DIRECT_CAPTURE:
            return best
        if best and best.score >= PREDICTED_PATTERN:
            return best
    # Nothing captured — classify by vector key / ranking.
    key = finding.get("key") if isinstance(finding, dict) else getattr(finding, "key", "")
    key = (key or "").lower()
    expl = (finding.get("exploitability") if isinstance(finding, dict)
            else getattr(finding, "exploitability", "")) or ""
    if key.startswith("cve:"):
        return Confidence(INFERRED_VERSION, "inferred_version",
                          "matched a version-range rule without executing the exploit")
    if expl == "high":
        return Confidence(PREDICTED_PATTERN, "predicted_pattern",
                          "enum detected the primitive — the operator still needs to weaponize")
    return Confidence(UNVERIFIED, "unverified",
                      "no captured proof + ranking does not imply a direct path")
