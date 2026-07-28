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
  * **the evasion axis re-delivers** — a CAUGHT verdict does not just advance: the loop
    *records the caught delivery as red* (live evidence, into state via ``mark_caught``)
    and climbs to the next alternate of the same objective in **evasion-posture order**
    (native PE → in-memory → script). A delivery already known-caught (lab or a live
    catch this run) is skipped without firing — assume-caught applied live, so the loop
    never re-burns a burned delivery on the client. See :data:`fieldkit.privesc` families;
  * **auto-provision a missing artifact** — when a vector fails because the artifact it
    needs is not on the target (the ``stage`` axis, or its Windows phrasing on the
    ``delivery`` axis), the loop *stages* it from the arsenal (vector ``stages``) or
    *builds* it (:mod:`fieldkit.poc`, vector ``builds``) and pushes it, then re-fires
    once. No source → it advances, carrying the classifier's guidance;
  * **rebuild a bad image** — a ``rebuild`` verdict (BAD_BUILD: ran but wrong
    arch/.NET) rebuilds the vector's artifact corrected once, then re-fires. A
    ``build`` verdict (BUILD_ERROR: the builder itself failed) advances — the toolchain,
    not fieldkit, is what to fix;
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
BURNED = "burned"        # delivery is known-caught — skipped without firing (assume-caught)
STAGED = "staged"        # pushed a missing artifact from the arsenal, then re-fired

#: fallback axes that mean "the artifact this vector needs is not on the target". The
#: same missing-binary shows as NO_TOOL on linux (`command not found`) and DELIVERY on
#: windows (`is not recognized`), so auto-stage triggers on both — but only for a vector
#: that declares what to stage.
STAGE_AXES = ("stage", "delivery")

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


@dataclass
class StageResult:
    """The result of an attempt to stage a vector's missing artifact(s)."""

    ok: bool
    detail: str = ""


def order_deliveries(vectors, delivery_order):
    """Order each delivery *family*'s alternates by evasion posture, in place of the raw
    score tiebreak. ``delivery_order`` is technique keys best-first (from
    :func:`fieldkit.evasion.posture`). A family's block stays where its best-ranked member
    sat; non-family vectors keep their position. No posture → the list is unchanged.
    """
    vs = list(vectors)
    if not delivery_order:
        return vs
    rank = {k: i for i, k in enumerate(delivery_order)}
    anchor = {}
    for i, v in enumerate(vs):
        fam = getattr(v, "family", None)
        if fam and fam not in anchor:
            anchor[fam] = i

    def key(pair):
        i, v = pair
        fam = getattr(v, "family", None)
        if fam:
            return (anchor[fam], rank.get(getattr(v, "delivery", None), len(rank)), i)
        return (i, 0, i)
    return [v for _, v in sorted(enumerate(vs), key=key)]


def escalate(vectors, *, fire, allow="read-only", os_name=None,
             budget=DEFAULT_BUDGET, retries=1, on_event=None,
             delivery_order=None, caught=None, mark_caught=None, stage=None, build=None):
    """Walk ``vectors`` (already ranked best-first) along the fallback axis.

    ``fire(vector) -> ExecResult`` runs one vector and is injected (the CLI wires it to
    :func:`fieldkit.executor.execute`; tests pass a fake). ``allow`` is the authorised
    blast radius — vectors above it are skipped, never fired. The loop fires at most
    ``budget`` vectors and re-fires a :data:`RETRY` (timeout) vector up to ``retries``
    extra times.

    Evasion re-delivery: ``delivery_order`` (evasion posture, best-first) orders each
    objective's delivery alternates; ``caught`` is the set of technique keys already known
    caught (those vectors are skipped without firing); ``mark_caught(technique)`` is called
    when a delivery is caught live, so the catch persists and the same delivery is not
    re-burned.

    Auto-provision: ``stage(vector) -> StageResult`` pushes a vector's ``stages``
    artifacts from the arsenal; ``build(vector, corrected) -> StageResult`` builds+pushes
    its ``builds`` artifacts (``corrected=True`` rebuilds a bad image). Each is called
    once per vector — stage/build on a missing-artifact verdict (:data:`STAGE_AXES`),
    rebuild on a ``rebuild`` verdict — and on success the vector is re-fired. Returns an
    :class:`Outcome` with the winning vector and the full trail.
    """
    def emit(msg):
        if on_event:
            on_event(msg)

    attempts = []
    if not vectors:
        return Outcome(attempts=attempts, stopped="empty")

    vectors = order_deliveries(vectors, delivery_order)
    caught = set(caught or ())
    provisioned = set()   # vectors we've staged/built-for once (don't re-provision forever)
    rebuilt = set()       # vectors we've rebuilt-corrected once (BAD_BUILD)

    fired = 0
    for vector in vectors:
        # safety gate — never fire above the authorised blast radius.
        if not executor_mod.gate(vector.safety, allow):
            note = f"{vector.safety} exceeds --allow — skipped (re-run with --allow {vector.safety})"
            attempts.append(Attempt(vector, GATED, note=note))
            emit(f"  gated  {vector.key}: {note}")
            continue

        # assume-caught, live: never re-fire a delivery already known caught.
        delivery = getattr(vector, "delivery", None)
        if delivery and delivery in caught:
            note = f"delivery {delivery!r} is known-caught — not fired (assume-caught)"
            attempts.append(Attempt(vector, BURNED, note=note))
            emit(f"  burned {vector.key}: {note}")
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

            # auto-provision: the artifact this vector needs isn't on the target (a
            # stage/delivery miss). Stage it from the arsenal, or build it (fieldkit.poc)
            # and stage it, then re-fire — once per vector, within budget.
            how, provision = None, None
            if getattr(vector, "stages", ()) and stage is not None:
                how, provision = "stage", (lambda v: stage(v))
            elif getattr(vector, "builds", ()) and build is not None:
                how, provision = "build", (lambda v: build(v, False))
            if (verdict.axis in STAGE_AXES and provision
                    and vector.key not in provisioned and fired < budget):
                provisioned.add(vector.key)
                emit(f"  {how:<6} {vector.key}: {verdict.outcome} — {how} then retry")
                pres = provision(vector)
                if pres and pres.ok:
                    attempts.append(Attempt(vector, STAGED, verdict, pres.detail))
                    emit(f"  staged {vector.key}: {pres.detail} — retrying")
                    continue  # re-fire the same vector, now that its artifact is present
                why = pres.detail if pres else "no source"
                attempts.append(Attempt(vector, ADVANCE, verdict, f"{how} failed: {why}"))
                emit(f"  advance  {vector.key}: {verdict.outcome} — {how} failed: {why}")
                break

            # rebuild: the artifact ran but was the wrong image (BAD_BUILD, axis rebuild).
            # Rebuild it corrected once, then re-fire.
            if (verdict.axis == "rebuild" and getattr(vector, "builds", ())
                    and build is not None and vector.key not in rebuilt and fired < budget):
                rebuilt.add(vector.key)
                emit(f"  rebuild {vector.key}: {verdict.outcome} — rebuilding corrected")
                bres = build(vector, True)
                if bres and bres.ok:
                    attempts.append(Attempt(vector, STAGED, verdict, f"rebuilt: {bres.detail}"))
                    emit(f"  staged {vector.key}: {bres.detail} — retrying")
                    continue
                why = bres.detail if bres else "rebuild failed"
                attempts.append(Attempt(vector, ADVANCE, verdict, f"rebuild failed: {why}"))
                emit(f"  advance  {vector.key}: {verdict.outcome} — rebuild failed: {why}")
                break

            if axis_action == RETRY and tries < retries and fired < budget:
                tries += 1
                attempts.append(Attempt(vector, RETRY, verdict,
                                        f"{verdict.detail} — retry {tries}/{retries}"))
                emit(f"  retry  {vector.key}: {verdict.outcome} — re-firing")
                continue

            # evasion axis: a caught delivery is learned (red, live) so it is not
            # re-burned, and the loop climbs to the next delivery of the same objective.
            note = verdict.guidance
            if verdict.axis == "evasion" and delivery:
                if delivery not in caught:
                    caught.add(delivery)
                    if mark_caught:
                        mark_caught(delivery)
                note = f"marked {delivery!r} red; re-delivering in posture order"
                emit(f"  caught {vector.key}: delivery {delivery!r} marked red")

            # settle this vector: STOP / SURFACE end the loop, everything else advances.
            action = STOP if axis_action == STOP else \
                SURFACE if axis_action == SURFACE else ADVANCE
            attempts.append(Attempt(vector, action, verdict, note))
            emit(f"  {action:<8} {vector.key}: {verdict.outcome} — {note}")

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
    lines.append("  burned   a delivery known-caught (lab/live) is skipped, never fired")
    lines.append("  staged   a missing artifact is staged/built + pushed, then re-fired")
    lines.append("\nevasion axis: a CAUGHT fire marks its delivery red (live) and the loop "
                 "climbs\n           to the next delivery of the same objective, in posture order.")
    lines.append("stage/delivery axes: a vector's missing artifact is staged from the arsenal "
                 "or\n           built (fieldkit.poc) and pushed, then re-fired once, else advance.")
    lines.append("rebuild axis: a BAD_BUILD rebuilds the artifact corrected once; a BUILD_ERROR "
                 "(the\n           builder failed) advances — fix the toolchain (`fieldkit poc --check`).")
    return "\n".join(lines)
