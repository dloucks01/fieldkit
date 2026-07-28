"""Failure classifier — an inspectable ruleset over captured tool output.

fieldkit is agent-less: it drives tools (nxc/impacket/ssh/mingw) and only ever sees
what they relay back — text + an exit code (see :class:`fieldkit.runner.RunResult`).
This module turns that into a :class:`Verdict` — *what happened and what to do next* —
via an **ordered, readable ruleset** you can inspect and tune (:data:`SIGNATURES`),
not logic buried in a driver.

Design for robustness:

  * **structural signals first** — exit code / timeout / tool-missing are high-
    confidence and checked before any fuzzy string match;
  * **the success marker is the positive proof** — a vector runs ``id``/``whoami`` and
    relays it; its presence is SUCCESS, its *absence after a clean run* is the "caught
    or didn't-elevate" fork;
  * **unknown is a first-class outcome** — if nothing matches, it says so and surfaces
    to the operator instead of guessing a branch;
  * every verdict records **which rule fired**, so the report shows the decision trail.

Each outcome maps to a **fallback axis** (:data:`FALLBACK`) the orchestrator walks:
a CAUGHT result tries a different *evasion technique*, a DENIED/RAN_NO_PROOF tries the
next *vector*, a BUILD_ERROR tries a different *build*. See :func:`classify`.
"""
import re
from dataclasses import dataclass

# ---- outcomes ---------------------------------------------------------------
SUCCESS = "success"            # the vector proved elevation (marker present)
CAUGHT = "caught"              # AV / AMSI / EDR blocked it
DENIED = "denied"             # ran, but access/precondition refused it
DELIVERY = "delivery"         # the artifact/command wasn't there to run
BUILD_ERROR = "build_error"   # toolchain/compile failure (attacker-side)
BAD_BUILD = "bad_build"       # ran, but wrong arch / .NET / corrupt image
NO_TOOL = "no_tool"           # a required binary is missing
TIMEOUT = "timeout"           # timed out / no response
RAN_NO_PROOF = "ran_no_proof"  # clean run, no elevation marker (didn't elevate / out-of-band)
UNKNOWN = "unknown"           # nothing matched — surface to the operator

#: outcome -> (fallback axis, one-line operator guidance). The orchestrator reads the
#: axis; the text goes in the decision trail.
FALLBACK = {
    SUCCESS:      ("done", "proved — stop and record"),
    CAUGHT:       ("evasion", "blocked — mark the technique red, try the next delivery in posture order"),
    DENIED:       ("vector", "precondition/permission failed — try the next-ranked vector"),
    DELIVERY:     ("delivery", "artifact didn't land — try another stage dir / delivery"),
    BUILD_ERROR:  ("build", "build failed — try another format (exe→ps1) or emit source+command"),
    BAD_BUILD:    ("rebuild", "wrong arch/.NET/image — rebuild corrected once, then next vector"),
    NO_TOOL:      ("stage", "required tool missing — stage it (`fieldkit arsenal`) or fetch it"),
    TIMEOUT:      ("retry", "no response — retry once, then next vector"),
    RAN_NO_PROOF: ("vector", "ran but no proof — next vector (or, if revshell, check your listener)"),
    UNKNOWN:      ("surface", "unrecognized — stop and show the operator the raw output"),
}


@dataclass(frozen=True)
class Rule:
    """One signature: a regex over the relayed output, and what it means."""

    outcome: str
    pattern: str          # matched case-insensitively against stdout+stderr
    note: str

    def matches(self, text):
        return re.search(self.pattern, text, re.I) is not None


#: The ruleset, in priority order (first match wins). Grouped by outcome. Edit freely —
#: this is the whole "how it knows something went wrong" surface. Structural signals
#: (exit code, timeout, tool-missing) are handled in classify() before these run.
SIGNATURES = (
    # -- caught (AV / AMSI / EDR) --------------------------------------------
    Rule(CAUGHT, r"amsi", "AMSI referenced (script scan)"),
    Rule(CAUGHT, r"this script contains malicious content", "AMSI block"),
    Rule(CAUGHT, r"malicious content.{0,30}blocked", "AMSI/content block"),
    Rule(CAUGHT, r"contains a virus|virus or potentially unwanted", "Defender AV verdict"),
    Rule(CAUGHT, r"operation did not complete successfully because the file contains",
         "Defender on-access block"),
    Rule(CAUGHT, r"threat.{0,30}(found|detected|removed|quarantin)", "Defender threat"),
    Rule(CAUGHT, r"blocked by (group policy|your (it )?administrator)", "ASR/policy block"),
    Rule(CAUGHT, r"operation was blocked", "generic block"),
    # -- denied / precondition ----------------------------------------------
    Rule(DENIED, r"access is denied|status_access_denied", "access denied"),
    Rule(DENIED, r"permission denied|eacces", "permission denied"),
    Rule(DENIED, r"requires elevation|operation requires elevation|must be an administrator",
         "needs elevation (precondition not met)"),
    Rule(DENIED, r"a required privilege is not held|status_privilege_not_held",
         "privilege not held"),
    Rule(DENIED, r"logon failure|status_logon_failure", "auth rejected"),
    # -- bad build (ran, but wrong image) -----------------------------------
    Rule(BAD_BUILD, r"is not a valid win32 application|bad exe format|%1 is not a valid",
         "wrong architecture"),
    Rule(BAD_BUILD, r"could not load file or assembly|mismatch between processor architecture",
         ".NET / arch mismatch"),
    # -- delivery (artifact/command not present) -----------------------------
    Rule(DELIVERY, r"cannot find the (file|path)|system cannot find", "file/path not found"),
    Rule(DELIVERY, r"no such file or directory", "not on disk"),
    Rule(DELIVERY, r"is not recognized as an internal or external", "command/exe absent"),
    # -- build error (compiler output; usually attacker-side) ----------------
    Rule(BUILD_ERROR, r"\berror:\s|undefined reference|fatal error", "compiler error"),
    Rule(BUILD_ERROR, r"command not found.*(gcc|mingw|wixl)", "build toolchain missing"),
)


# ---- elevation proof --------------------------------------------------------

def looks_elevated(output, os_name):
    """True when the relayed output shows an elevated context (the vector's proof)."""
    low = (output or "").lower()
    if os_name == "windows":
        return "nt authority\\system" in low or "\\administrator" in low
    return "uid=0(" in low or re.search(r"\buid=0\b", low) is not None


@dataclass
class Verdict:
    """What happened, why the classifier thinks so, and the fallback axis."""

    outcome: str
    rule: str            # which SIGNATURES rule fired, or "structural"/"marker"/"default"
    confidence: str      # high | medium | low
    detail: str

    @property
    def axis(self):
        return FALLBACK[self.outcome][0]

    @property
    def guidance(self):
        return FALLBACK[self.outcome][1]

    @property
    def ok(self):
        return self.outcome == SUCCESS


def classify(result, *, context="exec", os_name=None, expect_marker=None):
    """Classify a :class:`~fieldkit.runner.RunResult` into a :class:`Verdict`.

    ``context`` is ``build`` | ``exec`` | ``spray`` (a nonzero exit means different
    things per context). ``os_name`` selects the elevation marker; ``expect_marker`` is
    an explicit success token a vector wired in (overrides the OS heuristic).
    """
    text = getattr(result, "output", "") or ""

    # 1) structural — highest confidence, before any string matching. Timeout is
    # checked first (a timed-out result also carries an error string).
    if getattr(result, "timed_out", False):
        return Verdict(TIMEOUT, "structural", "high", "no response before the timeout")
    if getattr(result, "error", None):
        if re.search(r"not found|no such|is not installed", result.error, re.I):
            return Verdict(NO_TOOL, "structural", "high", result.error)
        if context == "build":  # a build that couldn't even run its toolchain
            return Verdict(BUILD_ERROR, "structural", "high", result.error)
        return Verdict(UNKNOWN, "structural", "low", result.error)
    if context == "build" and getattr(result, "exit_code", 0) not in (0, None):
        return Verdict(BUILD_ERROR, "structural", "high",
                       f"compiler exited {result.exit_code}: {text[-200:].strip()}")

    # 2) positive proof — a relayed elevation marker is success, full stop.
    if expect_marker and expect_marker.lower() in text.lower():
        return Verdict(SUCCESS, "marker", "high", f"marker {expect_marker!r} returned")
    if looks_elevated(text, os_name):
        return Verdict(SUCCESS, "marker", "high", "elevated context in the output")

    # 3) the ruleset — first signature to match wins.
    for rule in SIGNATURES:
        if rule.matches(text):
            conf = "high" if rule.outcome in (CAUGHT, DENIED, BAD_BUILD) else "medium"
            return Verdict(rule.outcome, rule.note, conf, _snippet(text))

    # 4) fallthrough — a clean run that returned no proof, or genuinely unrecognized.
    if getattr(result, "ok", True) and getattr(result, "exit_code", 0) in (0, None):
        return Verdict(RAN_NO_PROOF, "default", "medium",
                       "ran without error but returned no elevation marker")
    return Verdict(UNKNOWN, "default", "low", _snippet(text) or "no output")


def _snippet(text):
    t = (text or "").strip()
    return (t[:200] + "…") if len(t) > 200 else t


def describe_rules():
    """The ruleset as readable lines — for `fieldkit arsenal rules` / inspection."""
    lines = ["structural: error→no_tool/build_error · timed_out→timeout · "
             "build+nonzero→build_error", "marker: elevated output → success", ""]
    for r in SIGNATURES:
        lines.append(f"  {r.outcome:<12} /{r.pattern}/   — {r.note}")
    return "\n".join(lines)
