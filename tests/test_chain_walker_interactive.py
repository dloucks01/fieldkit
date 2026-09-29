#!/usr/bin/env python3
"""`fieldkit chain walk` — interactive walker with per-step confirm (C8 slice 4).

Adds a `before_step` callback to walk() that returns "go" / "skip" /
"stop", letting the operator gate every step. Same underlying
state-machine as `walk()`; the callback is a thin control surface.

Test pins:

  * before_step returning "go" runs the step normally (default);
  * before_step returning "skip" advances past the step with a
    manual outcome ("operator skipped");
  * before_step returning "stop" ends the walk with a manual outcome
    ("operator stopped") — chain status stays in_progress, not
    aborted;
  * a raised exception in before_step defaults to "go" (don't kill
    a chain because of a UI bug in the callback);
  * unknown return values default to "go" (permissive).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _mk_chain_with_stub_steps(step_count=3):
    """Small synthetic chain with actions that return `ok`. Lets us
    isolate the walker's control flow without pulling primitives in."""
    from fieldkit.chain import Chain, Step, Outcome
    def _ok(chain, ctx):
        return Outcome(kind="ok", evidence="ran")
    return Chain(
        profile="test", target="10.0.0.1",
        steps=tuple(Step(name=f"s{i}", kind="preflight",
                          action=_ok, detection_cost=1)
                     for i in range(step_count)))


class WalkerBeforeStepTest(unittest.TestCase):

    def test_default_go_runs_every_step(self):
        from fieldkit.chain import walk
        ch = _mk_chain_with_stub_steps(3)
        walk(ch, None, before_step=lambda c, s: "go")
        kinds = [o.kind for o in ch.outcomes]
        self.assertEqual(kinds, ["ok", "ok", "ok"])
        self.assertEqual(ch.status, "proven")

    def test_skip_advances_past_step_with_manual_outcome(self):
        from fieldkit.chain import walk
        ch = _mk_chain_with_stub_steps(3)
        # skip step 1 (index 1), run the others
        seen = []
        def _before(chain, step):
            seen.append(step.name)
            return "skip" if step.name == "s1" else "go"
        walk(ch, None, before_step=_before)
        # Every step was considered (before_step invoked)
        self.assertEqual(seen, ["s0", "s1", "s2"])
        kinds = [o.kind for o in ch.outcomes]
        self.assertEqual(kinds, ["ok", "manual", "ok"])
        # s1's manual evidence should record it as operator-skipped
        self.assertIn("skipped", ch.outcomes[1].evidence)
        self.assertIn("s1", ch.outcomes[1].evidence)
        self.assertEqual(ch.status, "proven")   # chain still completes

    def test_stop_ends_walk_without_aborting(self):
        from fieldkit.chain import walk
        ch = _mk_chain_with_stub_steps(3)
        notified = []
        # stop before step 2
        def _before(chain, step):
            return "stop" if step.name == "s2" else "go"
        def _on_step(chain, step, outcome):
            notified.append((step.name, outcome.kind, outcome.evidence))
        walk(ch, None, before_step=_before, on_step=_on_step)
        # s0, s1 ran (ok). s2 was paused BEFORE running, so it records NO outcome —
        # current stays on s2 so resume() re-runs it instead of skipping it.
        self.assertEqual([o.kind for o in ch.outcomes], ["ok", "ok"])
        self.assertEqual(ch.current, 2)
        self.assertEqual(ch.status, "in_progress")   # resumable
        self.assertIsNone(ch.aborted_reason)
        # the pause is still surfaced to the operator via on_step (display only)
        self.assertIn("stopped", notified[-1][2])
        self.assertEqual(notified[-1][0], "s2")

    def test_stop_at_first_step_records_nothing(self):
        from fieldkit.chain import walk
        ch = _mk_chain_with_stub_steps(3)
        walk(ch, None, before_step=lambda c, s: "stop")
        # nothing ran → no outcomes → planned (re-running the profile starts at s0)
        self.assertEqual(len(ch.outcomes), 0)
        self.assertEqual(ch.current, 0)
        self.assertEqual(ch.status, "planned")

    def test_exception_in_before_step_defaults_to_go(self):
        # A UI bug in the callback shouldn't kill the chain.
        from fieldkit.chain import walk
        ch = _mk_chain_with_stub_steps(3)
        def _explodes(chain, step):
            raise RuntimeError("simulated UI bug")
        walk(ch, None, before_step=_explodes)
        # Every step ran normally despite the exception.
        kinds = [o.kind for o in ch.outcomes]
        self.assertEqual(kinds, ["ok", "ok", "ok"])

    def test_unknown_return_value_defaults_to_go(self):
        from fieldkit.chain import walk
        ch = _mk_chain_with_stub_steps(2)
        walk(ch, None, before_step=lambda c, s: "totally-fine")
        self.assertEqual([o.kind for o in ch.outcomes], ["ok", "ok"])

    def test_missing_before_step_callback_is_unchanged_behavior(self):
        # Backward compat — omitting before_step must behave exactly
        # as walk() did before slice 4.
        from fieldkit.chain import walk
        ch = _mk_chain_with_stub_steps(3)
        walk(ch, None)
        self.assertEqual([o.kind for o in ch.outcomes], ["ok", "ok", "ok"])
        self.assertEqual(ch.status, "proven")


if __name__ == "__main__":
    unittest.main()
