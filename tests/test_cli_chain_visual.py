#!/usr/bin/env python3
"""`fieldkit chain visual <id>` — kill-chain visualization (C8 slice 3).

Compact operator's-eye view of one walked chain: profile → target
header, per-step outcome markers, ASCII flow connector, terminal
summary. Same information a full Textual kill-chain widget would
render, no Textual dependency.
"""
import contextlib
import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _make_store(test_case):
    tmp = tempfile.TemporaryDirectory()
    test_case.addCleanup(tmp.cleanup)
    from fieldkit.state import Store
    s = Store.create(os.path.join(tmp.name, "e.db"))
    s.init_engagement("test-visual")
    test_case.addCleanup(s.close)
    return s


def _persist_chain(s, target, outcome_kinds):
    """Push a chain with the given outcome kinds into Store. Returns
    the chain id."""
    from fieldkit.chain import esc8_chain, Outcome
    ch = esc8_chain(target)
    assert len(outcome_kinds) <= len(ch.steps)
    for step, kind in zip(ch.steps, outcome_kinds):
        ch.outcomes.append(Outcome(kind=kind,
                                     evidence=f"{step.name} outcome"))
    ch.current = len(ch.outcomes)
    if outcome_kinds and outcome_kinds[-1] in ("fail", "skip"):
        ch.aborted_reason = (
            f"step '{ch.steps[len(outcome_kinds) - 1].name}' returned "
            f"{outcome_kinds[-1]}: mock")
    cid = s.reserve_chain_id(ch)
    s.finalize_chain(cid, ch)
    return cid


def _run_visual(chain_id, store):
    from fieldkit.cli import cmd_chain_visual as _wrapped
    cmd_chain_visual = _wrapped.__wrapped__
    class Args: pass
    Args.chain_id = chain_id
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        rc = cmd_chain_visual(Args(), store)
    return rc, buf.getvalue()


class ChainVisualTest(unittest.TestCase):

    def test_missing_chain_id_returns_2(self):
        s = _make_store(self)
        rc, out = _run_visual(999, s)
        self.assertEqual(rc, 2)
        self.assertIn("no chain #999", out)

    def test_full_walked_chain_renders_header_and_steps(self):
        s = _make_store(self)
        cid = _persist_chain(s, "10.0.0.1", ["ok"] * 7)
        rc, out = _run_visual(cid, s)
        self.assertEqual(rc, 0)
        self.assertIn(f"chain #{cid}: esc8 → 10.0.0.1", out)
        self.assertIn("status = proven", out)
        for step_name in ("preflight:reachability",
                           "coerce:petitpotam",
                           "relay:listen",
                           "relay:capture",
                           "post:cert-request",
                           "post:pkinit-tgt",
                           "post:dcsync"):
            self.assertIn(step_name, out)
        self.assertIn("chain complete", out)
        self.assertIn("(running", out)

    def test_manual_outcomes_render_with_question_marker(self):
        s = _make_store(self)
        cid = _persist_chain(s, "10.0.0.1", ["ok"] * 6 + ["manual"])
        rc, out = _run_visual(cid, s)
        self.assertEqual(rc, 0)
        self.assertIn("[?] post:dcsync", out)

    def test_aborted_chain_renders_abort_marker_and_reason(self):
        s = _make_store(self)
        cid = _persist_chain(s, "10.0.0.1", ["ok", "ok", "fail"])
        rc, out = _run_visual(cid, s)
        self.assertEqual(rc, 0)
        self.assertIn("status = aborted", out)
        self.assertIn("[X]", out)
        self.assertIn("chain aborted at", out)
        self.assertIn("relay:listen", out)

    def test_running_cost_accumulator_matches_step_costs(self):
        # esc8's chain_step.detection_cost per step (legacy field).
        # C12 slice 1 dropped post:cert-request from 1 → 0
        # (honest zero: local-only cert-material validation with
        # no target-visible signals), so running total finishes
        # at 9 rather than 10.
        s = _make_store(self)
        cid = _persist_chain(s, "10.0.0.1", ["ok"] * 7)
        _, out = _run_visual(cid, s)
        self.assertIn("(running   9)", out)


if __name__ == "__main__":
    unittest.main()
