#!/usr/bin/env python3
"""The escalation orchestrator — walking the fallback axis.

Pinned:

  * the loop stops at the first vector that proves elevation;
  * a DENIED/RAN_NO_PROOF verdict advances to the next-ranked vector;
  * a TIMEOUT re-fires the same vector once, then advances;
  * an UNKNOWN verdict halts the loop and surfaces (never blindly continues);
  * a vector above --allow is skipped and NEVER fired (the safety gate holds);
  * the attempt budget caps how many vectors touch the target.

The real classifier runs on canned RunResults; only execution is faked.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import escalate as esc  # noqa: E402
from fieldkit.runner import RunResult  # noqa: E402


class _Vector:
    """The slice of privesc.Vector the orchestrator reads."""

    def __init__(self, key, safety="read-only", family=None, delivery=None, stages=()):
        self.key = key
        self.title = key
        self.safety = safety
        self.axes = "high/read-only/quiet"
        self.command = "id"
        self.shell = "sh"
        self.host = "10.0.0.5"
        self.cleanup = None
        self.report_type = ""
        self.family = family
        self.delivery = delivery
        self.stages = stages


class _Exec:
    """A stand-in for executor.ExecResult: what escalate reads off a fire()."""

    def __init__(self, run=None, blocked=None):
        self.run = run
        self.blocked = blocked


def run(stdout="", exit_code=0, error=None, timed_out=False):
    return RunResult(argv=["x"], exit_code=exit_code, stdout=stdout, stderr="",
                     error=error, timed_out=timed_out)


def scripted(mapping):
    """A fire() that returns a canned _Exec per vector key; records every call."""
    calls = []

    def fire(vector):
        calls.append(vector.key)
        return mapping[vector.key]
    fire.calls = calls
    return fire


ROOT = run("uid=0(root) gid=0(root)")            # SUCCESS on linux
WIN_ROOT = run("nt authority\\system")           # SUCCESS on windows
DENIED = _Exec(run("Access is denied."))         # -> vector -> ADVANCE
BENIGN = _Exec(run("nothing interesting"))       # -> ran_no_proof -> ADVANCE
GIBBERISH = _Exec(run("???", exit_code=3))       # -> unknown -> SURFACE


class ProofTest(unittest.TestCase):
    def test_stops_at_first_proof(self):
        v1, v2 = _Vector("sudo:find"), _Vector("suid:bash")
        fire = scripted({"sudo:find": _Exec(ROOT), "suid:bash": _Exec(ROOT)})
        out = esc.escalate([v1, v2], fire=fire, os_name="linux")
        self.assertTrue(out.ok)
        self.assertIs(out.proven, v1)
        self.assertEqual(out.stopped, "proven")
        self.assertEqual(fire.calls, ["sudo:find"])  # v2 never touched

    def test_advances_past_denied(self):
        v1, v2 = _Vector("a"), _Vector("b")
        fire = scripted({"a": DENIED, "b": _Exec(ROOT)})
        out = esc.escalate([v1, v2], fire=fire, os_name="linux")
        self.assertIs(out.proven, v2)
        self.assertEqual(fire.calls, ["a", "b"])
        self.assertEqual(out.attempts[0].action, esc.ADVANCE)
        self.assertEqual(out.attempts[0].verdict.outcome, "denied")

    def test_advances_past_ran_no_proof(self):
        v1, v2 = _Vector("a"), _Vector("b")
        fire = scripted({"a": BENIGN, "b": _Exec(ROOT)})
        out = esc.escalate([v1, v2], fire=fire, os_name="linux")
        self.assertIs(out.proven, v2)


class RetryTest(unittest.TestCase):
    def test_timeout_retries_once_then_advances(self):
        v1, v2 = _Vector("slow"), _Vector("b")
        timeout = _Exec(run(error="timed out after 600s", timed_out=True))
        fire = scripted({"slow": timeout, "b": _Exec(ROOT)})
        out = esc.escalate([v1, v2], fire=fire, os_name="linux", retries=1)
        self.assertIs(out.proven, v2)
        # slow fired twice (initial + one retry), then b once
        self.assertEqual(fire.calls, ["slow", "slow", "b"])
        self.assertEqual(out.attempts[0].action, esc.RETRY)
        self.assertEqual(out.attempts[1].action, esc.ADVANCE)

    def test_no_retries_advances_immediately(self):
        v1, v2 = _Vector("slow"), _Vector("b")
        timeout = _Exec(run(error="timed out", timed_out=True))
        fire = scripted({"slow": timeout, "b": _Exec(ROOT)})
        out = esc.escalate([v1, v2], fire=fire, os_name="linux", retries=0)
        self.assertEqual(fire.calls, ["slow", "b"])
        self.assertEqual(out.attempts[0].action, esc.ADVANCE)


class SurfaceTest(unittest.TestCase):
    def test_unknown_halts_and_surfaces(self):
        v1, v2 = _Vector("a"), _Vector("b")
        fire = scripted({"a": GIBBERISH, "b": _Exec(ROOT)})
        out = esc.escalate([v1, v2], fire=fire, os_name="linux")
        self.assertFalse(out.ok)
        self.assertEqual(out.stopped, "surfaced")
        self.assertEqual(fire.calls, ["a"])  # halted before b


class GateTest(unittest.TestCase):
    def test_gated_vector_never_fires(self):
        v1 = _Vector("kernel", safety="crash-risk")
        v2 = _Vector("safe", safety="read-only")
        fire = scripted({"safe": _Exec(ROOT)})  # note: no entry for "kernel"
        out = esc.escalate([v1, v2], fire=fire, allow="read-only", os_name="linux")
        self.assertIs(out.proven, v2)
        self.assertEqual(fire.calls, ["safe"])          # kernel skipped, never fired
        self.assertEqual(out.attempts[0].action, esc.GATED)
        self.assertIsNone(out.attempts[0].verdict)

    def test_allow_unlocks_gated_vector(self):
        v1 = _Vector("cc", safety="config-change")
        fire = scripted({"cc": _Exec(ROOT)})
        out = esc.escalate([v1], fire=fire, allow=["read-only", "config-change"],
                           os_name="linux")
        self.assertTrue(out.ok)
        self.assertEqual(fire.calls, ["cc"])


class BudgetTest(unittest.TestCase):
    def test_budget_caps_fires(self):
        v1, v2 = _Vector("a"), _Vector("b")
        fire = scripted({"a": DENIED, "b": _Exec(ROOT)})
        out = esc.escalate([v1, v2], fire=fire, os_name="linux", budget=1)
        self.assertFalse(out.ok)
        self.assertEqual(out.stopped, "budget")
        self.assertEqual(fire.calls, ["a"])  # b never fired — budget reached

    def test_empty_vectors(self):
        out = esc.escalate([], fire=scripted({}), os_name="linux")
        self.assertEqual(out.stopped, "empty")
        self.assertFalse(out.ok)


class BlockedTest(unittest.TestCase):
    def test_blocked_execresult_advances(self):
        v1, v2 = _Vector("a"), _Vector("b")
        fire = scripted({"a": _Exec(blocked="no proven transport"), "b": _Exec(ROOT)})
        out = esc.escalate([v1, v2], fire=fire, os_name="linux")
        self.assertIs(out.proven, v2)
        self.assertEqual(out.attempts[0].action, esc.SKIPPED)
        self.assertIn("transport", out.attempts[0].note)


class ExhaustedTest(unittest.TestCase):
    def test_all_tried_none_proved(self):
        v1, v2 = _Vector("a"), _Vector("b")
        fire = scripted({"a": DENIED, "b": BENIGN})
        out = esc.escalate([v1, v2], fire=fire, os_name="linux")
        self.assertFalse(out.ok)
        self.assertEqual(out.stopped, "exhausted")
        self.assertEqual(len(out.fired), 2)


class AxisRoutingTest(unittest.TestCase):
    """Every classifier axis routes to the loop action the policy promises."""

    def test_caught_advances_and_is_recorded(self):
        # CAUGHT -> evasion axis -> ADVANCE (no per-vector alt-delivery yet), noted.
        v1, v2 = _Vector("a"), _Vector("b")
        caught = _Exec(run("This script contains malicious content and has been blocked"))
        fire = scripted({"a": caught, "b": _Exec(WIN_ROOT)})
        out = esc.escalate([v1, v2], fire=fire, os_name="windows")
        self.assertIs(out.proven, v2)
        self.assertEqual(out.attempts[0].action, esc.ADVANCE)
        self.assertEqual(out.attempts[0].verdict.outcome, "caught")

    def test_no_tool_advances(self):
        # NO_TOOL -> stage axis -> ADVANCE; the loop can't auto-stage, but keeps going.
        v1, v2 = _Vector("a"), _Vector("b")
        missing = _Exec(run("bash: certipy: command not found"))
        fire = scripted({"a": missing, "b": _Exec(ROOT)})
        out = esc.escalate([v1, v2], fire=fire, os_name="linux")
        self.assertIs(out.proven, v2)
        self.assertEqual(out.attempts[0].verdict.outcome, "no_tool")

    def test_bad_build_advances(self):
        v1, v2 = _Vector("a"), _Vector("b")
        badimg = _Exec(run("%1 is not a valid Win32 application"))
        fire = scripted({"a": badimg, "b": _Exec(WIN_ROOT)})
        out = esc.escalate([v1, v2], fire=fire, os_name="windows")
        self.assertIs(out.proven, v2)
        self.assertEqual(out.attempts[0].verdict.outcome, "bad_build")


class MixedSequenceTest(unittest.TestCase):
    """A realistic run: several dead ends, a retry, then proof deep in the list."""

    def test_denied_caught_timeout_then_success(self):
        vs = [_Vector("v1"), _Vector("v2"), _Vector("v3"), _Vector("v4")]
        timeout = _Exec(run(error="timed out", timed_out=True))
        fire = scripted({
            "v1": DENIED,
            "v2": _Exec(run("This script contains malicious content and has been blocked")),
            "v3": timeout,
            "v4": _Exec(WIN_ROOT),
        })
        out = esc.escalate(vs, fire=fire, os_name="windows", retries=1)
        self.assertIs(out.proven, vs[3])
        # v3 fired twice (timeout + one retry); v1,v2,v4 once each -> 5 fires
        self.assertEqual(fire.calls, ["v1", "v2", "v3", "v3", "v4"])
        outcomes = [a.verdict.outcome for a in out.attempts if a.verdict]
        self.assertEqual(outcomes, ["denied", "caught", "timeout", "timeout", "success"])


class BudgetRetryTest(unittest.TestCase):
    """A retry may not spend more than the budget allows."""

    def test_retry_does_not_exceed_budget(self):
        v1, v2 = _Vector("slow"), _Vector("b")
        timeout = _Exec(run(error="timed out", timed_out=True))
        fire = scripted({"slow": timeout, "b": _Exec(ROOT)})
        # budget 1: the single fire is the timeout; no retry (would exceed), then stop.
        out = esc.escalate([v1, v2], fire=fire, os_name="linux", retries=1, budget=1)
        self.assertEqual(fire.calls, ["slow"])
        self.assertEqual(out.stopped, "budget")
        self.assertEqual(out.attempts[0].action, esc.ADVANCE)  # settled, not retried


CAUGHT = _Exec(run("This script contains malicious content and has been blocked"))


class ReDeliveryTest(unittest.TestCase):
    """The evasion axis: a caught delivery is learned red and re-delivered in posture order."""

    def _ladder(self):
        # one objective, three delivery methods (posture: native -> inmem -> ps)
        return [
            _Vector("imp:native", "config-change", family="imp", delivery="native-exe"),
            _Vector("imp:inmem", "config-change", family="imp", delivery="inmem-fileless"),
            _Vector("imp:ps", "config-change", family="imp", delivery="ps-amsi-revshell"),
        ]

    def test_caught_climbs_to_next_delivery_and_learns(self):
        vs = self._ladder()
        marked = []
        fire = scripted({"imp:native": CAUGHT, "imp:inmem": _Exec(WIN_ROOT)})
        out = esc.escalate(vs, fire=fire, allow=["read-only", "config-change"],
                           os_name="windows", mark_caught=marked.append)
        self.assertIs(out.proven, vs[1])                 # climbed native -> inmem
        self.assertEqual(fire.calls, ["imp:native", "imp:inmem"])
        self.assertEqual(marked, ["native-exe"])         # the caught delivery was learned
        self.assertEqual(out.attempts[0].action, esc.ADVANCE)
        self.assertEqual(out.attempts[0].verdict.outcome, "caught")

    def test_known_caught_delivery_is_skipped_not_fired(self):
        vs = self._ladder()
        fire = scripted({"imp:inmem": _Exec(WIN_ROOT)})  # native must never be fired
        out = esc.escalate(vs, fire=fire, allow=["read-only", "config-change"],
                           os_name="windows", caught={"native-exe"})
        self.assertIs(out.proven, vs[1])
        self.assertEqual(fire.calls, ["imp:inmem"])      # native skipped pre-emptively
        self.assertEqual(out.attempts[0].action, esc.BURNED)
        self.assertIsNone(out.attempts[0].verdict)

    def test_all_deliveries_caught_exhausts_family(self):
        vs = self._ladder()
        fire = scripted({"imp:native": CAUGHT, "imp:inmem": CAUGHT, "imp:ps": CAUGHT})
        marked = []
        out = esc.escalate(vs, fire=fire, allow=["read-only", "config-change"],
                           os_name="windows", mark_caught=marked.append)
        self.assertFalse(out.ok)
        self.assertEqual(out.stopped, "exhausted")
        self.assertEqual(marked, ["native-exe", "inmem-fileless", "ps-amsi-revshell"])


class OrderDeliveriesTest(unittest.TestCase):
    def test_posture_reorders_within_family(self):
        # list arrives inmem-first (e.g. score tiebreak); posture prefers native.
        vs = [_Vector("imp:inmem", family="imp", delivery="inmem-fileless"),
              _Vector("imp:native", family="imp", delivery="native-exe"),
              _Vector("other")]
        order = ["native-exe", "inmem-fileless", "ps-amsi-revshell"]
        got = [v.key for v in esc.order_deliveries(vs, order)]
        self.assertEqual(got, ["imp:native", "imp:inmem", "other"])

    def test_no_posture_keeps_order(self):
        vs = [_Vector("a"), _Vector("b")]
        self.assertEqual([v.key for v in esc.order_deliveries(vs, None)], ["a", "b"])

    def test_non_family_vectors_keep_position(self):
        vs = [_Vector("x"),
              _Vector("imp:inmem", family="imp", delivery="inmem-fileless"),
              _Vector("imp:native", family="imp", delivery="native-exe")]
        order = ["native-exe", "inmem-fileless"]
        got = [v.key for v in esc.order_deliveries(vs, order)]
        # x stays first; the imp block reorders native-first at its anchor slot
        self.assertEqual(got, ["x", "imp:native", "imp:inmem"])


# missing-artifact outputs: windows phrasing (delivery axis) + linux phrasing (stage axis)
WIN_MISSING = run("'GodPotato.exe' is not recognized as an internal or external command")
LIN_MISSING = run("bash: tool: command not found")


class AutoStageTest(unittest.TestCase):
    """The stage axis: push a missing artifact from the arsenal, then re-fire."""

    def _staged_fire(self, miss, hit):
        """Return (fire, state): fire yields `miss` until state['ok'], then `hit`."""
        state = {"ok": False, "calls": 0}

        def fire(vector):
            state["calls"] += 1
            return _Exec(hit) if state["ok"] else _Exec(miss)
        return fire, state

    def _stager(self, result, flips=None):
        calls = []

        def stage(vector):
            calls.append(vector.key)
            if flips is not None:
                flips["ok"] = True
            return result
        stage.calls = calls
        return stage

    def test_stage_then_retry_proves(self):
        v = _Vector("imp:native", "config-change",
                    stages=(("GodPotato", "C:\\t\\GodPotato.exe"),))
        fire, state = self._staged_fire(WIN_MISSING, WIN_ROOT)
        stage = self._stager(esc.StageResult(True, "staged GodPotato"), flips=state)
        out = esc.escalate([v], fire=fire, allow=["read-only", "config-change"],
                           os_name="windows", stage=stage)
        self.assertTrue(out.ok)
        self.assertEqual(stage.calls, ["imp:native"])
        self.assertEqual(state["calls"], 2)               # miss, then hit after staging
        self.assertEqual([a.action for a in out.attempts], [esc.STAGED, esc.STOP])

    def test_stage_triggers_on_linux_no_tool_axis(self):
        v = _Vector("v", "read-only", stages=(("tool", "/tmp/tool"),))
        fire, state = self._staged_fire(LIN_MISSING, ROOT)
        stage = self._stager(esc.StageResult(True, "staged tool"), flips=state)
        out = esc.escalate([v], fire=fire, os_name="linux", stage=stage)
        self.assertTrue(out.ok)
        self.assertEqual(stage.calls, ["v"])

    def test_stage_failure_advances_with_reason(self):
        v1 = _Vector("imp:native", "config-change", stages=(("GodPotato", "C:\\t\\g.exe"),))
        v2 = _Vector("imp:inmem", "config-change")
        fire = scripted({"imp:native": _Exec(WIN_MISSING), "imp:inmem": _Exec(WIN_ROOT)})
        stage = self._stager(esc.StageResult(False, "GodPotato not in the arsenal"))
        out = esc.escalate([v1, v2], fire=fire, allow=["read-only", "config-change"],
                           os_name="windows", stage=stage)
        self.assertIs(out.proven, v2)                     # couldn't stage -> next delivery
        self.assertEqual(out.attempts[0].action, esc.ADVANCE)
        self.assertIn("stage failed", out.attempts[0].note)

    def test_stage_attempted_once_per_vector(self):
        # arsenal claims success but the artifact still doesn't land -> don't loop.
        v = _Vector("imp:native", "config-change", stages=(("GodPotato", "C:\\t\\g.exe"),))
        fire = scripted({"imp:native": _Exec(WIN_MISSING)})   # always missing
        stage = self._stager(esc.StageResult(True, "staged"))  # claims ok, no flip
        out = esc.escalate([v], fire=fire, allow=["read-only", "config-change"],
                           os_name="windows", stage=stage)
        self.assertFalse(out.ok)
        self.assertEqual(len(stage.calls), 1)              # staged once, not forever
        self.assertEqual(len(out.fired), 2)               # initial + one post-stage re-fire

    def test_no_stages_does_not_invoke_stager(self):
        v = _Vector("v")                                   # no stageable artifacts
        fire = scripted({"v": _Exec(LIN_MISSING)})
        stage = self._stager(esc.StageResult(True, "x"))
        out = esc.escalate([v], fire=fire, os_name="linux", stage=stage)
        self.assertEqual(stage.calls, [])                  # nothing declared -> never called
        self.assertEqual(out.stopped, "exhausted")

    def test_stage_none_is_backward_compatible(self):
        v = _Vector("imp:native", "config-change", stages=(("GodPotato", "C:\\t\\g.exe"),))
        fire = scripted({"imp:native": _Exec(WIN_MISSING)})
        out = esc.escalate([v], fire=fire, allow=["read-only", "config-change"],
                           os_name="windows", stage=None)  # no stager -> plain advance
        self.assertEqual(out.attempts[0].action, esc.ADVANCE)
        self.assertEqual(len(out.fired), 1)


class InspectTest(unittest.TestCase):
    def test_describe_policy(self):
        text = esc.describe_policy()
        self.assertIn("advance", text)
        self.assertIn("surface", text)
        self.assertIn("gated", text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
