"""The escalation orchestrator — walk the fallback axis until something proves.

Phase 5 gave every executed vector a :class:`~fieldkit.classify.Verdict` with a
*fallback axis* (``done``/``vector``/``evasion``/``retry``/…). This module is the loop
that **walks** that axis: fire the best-ranked vector, classify what came back, and let
the verdict decide the next move — advance to the next vector, retry a transient
failure, stop on proof, or halt and surface something it doesn't understand — instead
of stopping at one vector the way the manual ``fieldkit run`` does.

Design, kept parallel to :mod:`fieldkit.classify`:

  * **an inspectable policy table** (:data:`POLICY`) maps each classifier *axis* to one
    of four honest loop actions. It is the whole "what the loop does about a verdict"
    surface — read it, tune it, and the behaviour follows;
  * **only what the kit can actually do** — the loop advances, retries, stops or
    surfaces. It does *not* pretend to auto-rebuild a bad image, auto-stage a missing
    tool, or swap an alternate delivery for a caught technique (no per-vector delivery
    ladder exists yet), so those axes ``ADVANCE`` while the trail still carries the
    classifier's guidance for the operator's manual step;
  * **the safety gate is upheld** — a vector whose blast radius exceeds ``allow`` is
    *skipped without firing*; the loop never escalates its own authorisation;
  * **a decision trail** — every step (fired, retried, gated, skipped) is recorded, so
    the operator and the report can see exactly how the loop reasoned;
  * **injected execution** — the loop calls an injected ``fire(vector) -> ExecResult``,
    so tests drive it with canned results and no subprocess, exactly as the runner is
    injected everywhere else. Classification is the real thing under test.
"""
from dataclasses import dataclass, field

from . import classify as classify_mod
from . import executor as executor_mod

# ---- loop actions -----------------------------------------------------------
STOP = "stop"            # proof in hand — record it and halt
SURFACE = "surface"      # unrecognised — halt and show the operator the raw output
RETRY = "retry"          # transient (no response) — re-fire the same vector, then advance
ADVANCE = "advance"      # this vector is spent — move to the next-ranked one
GATED = "gated"          # blast radius exceeds --allow — never fired
SKIPPED = "skipped"      # not fired for another reason (blocked transport, budget)

#: classifier fallback *axis* -> what the loop does about it. The axes the current kit
#: cannot yet act on (build/rebuild/stage/evasion) fall through to ADVANCE; the trail
#: still carries the classifier's guidance so the operator sees the recommended step.
POLICY = {
    "done":     STOP,
    "surface":  SURFACE,
    "retry":    RETRY,
    "vector":   ADVANCE,
    "evasion":  ADVANCE,   # no alternate delivery per vector yet — advance, note the block
    "delivery": ADVANCE,
    "build":    ADVANCE,
    "rebuild":  ADVANCE,
    "stage":    ADVANCE,
}

#: how many vectors the loop is allowed to fire against the target by default. A cap so
#: the loop cannot hammer a client host indefinitely; the CLI can override it.
DEFAULT_BUDGET = 12


@dataclass
class Attempt:
    """One step the loop took, and why — the decision trail, one row at a time."""

    vector: object              # the Vector considered
    action: str                 # STOP | SURFACE | RETRY | ADVANCE | GATED | SKIPPED
    verdict: object = None      # classify.Verdict, or None when nothing was fired
    note: str = ""

    @property
    def fired(self):
        return self.verdict is not None


@dataclass
class Outcome:
    """The result of a run: whether it proved anything, and the whole trail."""

    proven: object = None       # the Vector that proved elevation, or None
    attempts: list = field(default_factory=list)
    stopped: str = ""           # proven | surfaced | exhausted | budget | empty

    @property
    def ok(self):
        return self.proven is not None

    @property
    def fired(self):
        return [a for a in self.attempts if a.fired]


def escalate(vectors, *, fire, allow="read-only", os_name=None,
             budget=DEFAULT_BUDGET, retries=1, on_event=None):
    """Walk ``vectors`` (already ranked best-first) along the fallback axis.

    ``fire(vector) -> ExecResult`` runs one vector and is injected (the CLI wires it to
    :func:`fieldkit.executor.execute`; tests pass a fake). ``allow`` is the authorised
    blast radius — vectors above it are skipped, never fired. The loop fires at most
    ``budget`` vectors and re-fires a :data:`RETRY` (timeout) vector up to ``retries``
    extra times. Returns an :class:`Outcome` with the winning vector and the full trail.
    """
    def emit(msg):
        if on_event:
            on_event(msg)

    attempts = []
    if not vectors:
        return Outcome(attempts=attempts, stopped="empty")

    fired = 0
    for vector in vectors:
        # safety gate — never fire above the authorised blast radius.
        if not executor_mod.gate(vector.safety, allow):
            note = f"{vector.safety} exceeds --allow — skipped (re-run with --allow {vector.safety})"
            attempts.append(Attempt(vector, GATED, note=note))
            emit(f"  gated  {vector.key}: {note}")
            continue

        if fired >= budget:
            attempts.append(Attempt(vector, SKIPPED, note=f"attempt budget {budget} reached"))
            emit(f"  budget reached ({budget}) — {vector.key} and any further vectors not tried")
            return Outcome(attempts=attempts, stopped="budget")

        tries = 0
        while True:
            emit(f"  fire   {vector.key}  ({vector.axes}, {vector.safety})")
            result = fire(vector)
            fired += 1

            if getattr(result, "blocked", None):
                # the executor refused before running (no transport, unknown name).
                attempts.append(Attempt(vector, SKIPPED, note=result.blocked))
                emit(f"  skip   {vector.key}: {result.blocked}")
                break  # advance

            verdict = classify_mod.classify(result.run, os_name=os_name)
            axis_action = POLICY.get(verdict.axis, SURFACE)

            if axis_action == RETRY and tries < retries and fired < budget:
                tries += 1
                attempts.append(Attempt(vector, RETRY, verdict,
                                        f"{verdict.detail} — retry {tries}/{retries}"))
                emit(f"  retry  {vector.key}: {verdict.outcome} — re-firing")
                continue

            # settle this vector: STOP / SURFACE end the loop, everything else advances.
            action = STOP if axis_action == STOP else \
                SURFACE if axis_action == SURFACE else ADVANCE
            attempts.append(Attempt(vector, action, verdict, verdict.guidance))
            emit(f"  {action:<7}{vector.key}: {verdict.outcome} — {verdict.guidance}")

            if action == STOP:
                return Outcome(proven=vector, attempts=attempts, stopped="proven")
            if action == SURFACE:
                return Outcome(attempts=attempts, stopped="surfaced")
            break  # ADVANCE — next vector

    return Outcome(attempts=attempts, stopped="exhausted")


# ---- inspection -------------------------------------------------------------

def describe_policy():
    """The policy table as readable lines — for inspection alongside the ruleset."""
    axis_action = {}
    for axis, act in POLICY.items():
        axis_action.setdefault(act, []).append(axis)
    order = [(STOP, "proof — record and halt"),
             (RETRY, "transient — re-fire once, then advance"),
             (ADVANCE, "vector spent — try the next-ranked one"),
             (SURFACE, "unrecognised — halt and show the operator")]
    lines = ["escalation policy (classifier axis -> loop action):"]
    for act, gloss in order:
        axes = ", ".join(sorted(axis_action.get(act, [])))
        lines.append(f"  {act:<8} {gloss}\n           axes: {axes}")
    lines.append("  gated    a vector above --allow is skipped, never fired")
    return "\n".join(lines)
