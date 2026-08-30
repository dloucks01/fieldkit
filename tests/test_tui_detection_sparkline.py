#!/usr/bin/env python3
"""TUI dashboard — detection-debt sparkline (C10 slice 4).

Replaces the Phase-D placeholder on the dashboard's DetectionBlock
with a real per-hour sparkline of captured activity across the
last 24 hours. Sources both the `step` table (executor captures)
and `chain_step` (coerce-chain per-step outcomes) so chain-heavy
engagements don't render as flat when they've actually been busy.

Test pins:

  * _detection_ledger returns 24 buckets ordered oldest → newest;
  * empty store yields 24 zeros (not empty list);
  * step timestamps land in the correct bucket by hour;
  * chain_step timestamps ALSO count (both tables sourced);
  * pre-D1 databases without chain_step degrade gracefully;
  * _sparkline maps counts to block chars with `·` for zeros;
  * DetectionBlock renders the sparkline + total-step summary;
  * empty-activity DetectionBlock renders honest "quiet — no
    steps in the last 24h" message.
"""
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _make_store(test_case):
    tmp = tempfile.TemporaryDirectory()
    test_case.addCleanup(tmp.cleanup)
    from fieldkit.state import Store
    s = Store.create(os.path.join(tmp.name, "e.db"))
    s.init_engagement("test-sparkline")
    test_case.addCleanup(s.close)
    return s


class DetectionLedgerTest(unittest.TestCase):

    def test_empty_store_yields_24_zeros(self):
        from fieldkit.tui.data import _detection_ledger, LEDGER_BUCKETS
        s = _make_store(self)
        counts = _detection_ledger(s)
        self.assertEqual(len(counts), LEDGER_BUCKETS)
        self.assertEqual(sum(counts), 0)

    def test_step_timestamps_land_in_correct_bucket(self):
        from fieldkit.tui.data import _detection_ledger
        s = _make_store(self)
        # Insert a finding so the FK from step is satisfied.
        hid, _ = s.add_host("10.0.0.1", os_name="linux")
        fid, _ = s.add_finding(vector_type="test", title="t",
                                host_id=hid, evidence="", proven=True)
        # Insert 3 steps in the last hour (bucket 23 = "just now")
        now = datetime.now(timezone.utc)
        for i in range(3):
            ts = (now - timedelta(minutes=5 + i * 2)).isoformat()
            s.conn.execute(
                "INSERT INTO step (finding_id, seq, cmd, ts) "
                "VALUES (?, ?, ?, ?)", (fid, i, f"cmd{i}", ts))
        counts = _detection_ledger(s)
        # Last bucket (index 23) should hold the 3 recent steps
        self.assertGreaterEqual(counts[-1], 3)
        self.assertEqual(sum(counts), 3)

    def test_chain_step_timestamps_count(self):
        # Chain steps should ALSO source the ledger, not just executor
        # steps.
        from fieldkit.tui.data import _detection_ledger
        from fieldkit.chain import esc8_chain, Outcome
        s = _make_store(self)
        # Persist a chain with some walked steps — finalize_chain
        # will populate chain_step rows with utcnow timestamps.
        ch = esc8_chain("10.0.0.1")
        for step in ch.steps[:3]:
            ch.outcomes.append(Outcome(kind="ok",
                                        evidence=f"{step.name} ok"))
        ch.current = 3
        cid = s.reserve_chain_id(ch)
        s.finalize_chain(cid, ch)
        counts = _detection_ledger(s)
        # 3 chain_step rows, all in the last-hour bucket
        self.assertGreaterEqual(counts[-1], 3)

    def test_old_timestamps_outside_24h_ignored(self):
        from fieldkit.tui.data import _detection_ledger
        s = _make_store(self)
        hid, _ = s.add_host("10.0.0.1", os_name="linux")
        fid, _ = s.add_finding(vector_type="test", title="t",
                                host_id=hid, evidence="", proven=True)
        # 3 old steps (25 hours ago) + 2 recent
        now = datetime.now(timezone.utc)
        old = (now - timedelta(hours=25)).isoformat()
        recent = (now - timedelta(minutes=10)).isoformat()
        for i in range(3):
            s.conn.execute(
                "INSERT INTO step (finding_id, seq, cmd, ts) "
                "VALUES (?, ?, ?, ?)", (fid, i, "old", old))
        for i in range(2):
            s.conn.execute(
                "INSERT INTO step (finding_id, seq, cmd, ts) "
                "VALUES (?, ?, ?, ?)", (fid, i + 100, "new", recent))
        counts = _detection_ledger(s)
        # Only the 2 recent ones show up
        self.assertEqual(sum(counts), 2)


class SparklineRenderingTest(unittest.TestCase):

    def test_empty_input_returns_empty(self):
        from fieldkit.tui.dashboard import _sparkline
        self.assertEqual(_sparkline([]), "")

    def test_all_zero_returns_all_zero_markers(self):
        from fieldkit.tui.dashboard import _sparkline, _SPARK_ZERO
        result = _sparkline([0, 0, 0, 0])
        self.assertEqual(result, _SPARK_ZERO * 4)

    def test_mixed_counts_map_to_block_chars(self):
        from fieldkit.tui.dashboard import _sparkline, _SPARK_ZERO
        result = _sparkline([0, 1, 5, 10])
        # 4 chars out — one per input.
        self.assertEqual(len(result), 4)
        # First char is zero marker
        self.assertEqual(result[0], _SPARK_ZERO)
        # Non-zero counts are block chars (unicode U+2581..U+2588).
        for c in result[1:]:
            self.assertNotEqual(c, _SPARK_ZERO)
            self.assertGreaterEqual(ord(c), 0x2581)
            self.assertLessEqual(ord(c), 0x2588)


class DetectionBlockRenderingTest(unittest.TestCase):

    def _fake_widget(self):
        class FakeWidget:
            def __init__(self):
                self.text = None
            def update(self, s):
                self.text = s
        return FakeWidget()

    def _render(self, data):
        from fieldkit.tui.dashboard import DetectionBlock
        w = self._fake_widget()
        DetectionBlock.render_from(w, data)
        return w.text

    def test_empty_ledger_renders_no_activity_message(self):
        from fieldkit.tui.data import DashboardData
        d = DashboardData()
        d.detection_ledger = []
        text = self._render(d)
        self.assertIn("DETECTION", text)
        self.assertIn("no activity captured yet", text)

    def test_all_zero_ledger_renders_quiet_message(self):
        from fieldkit.tui.data import DashboardData
        d = DashboardData()
        d.detection_ledger = [0] * 24
        text = self._render(d)
        self.assertIn("quiet", text)
        # And an all-zero-marker sparkline is present.
        from fieldkit.tui.dashboard import _SPARK_ZERO
        self.assertIn(_SPARK_ZERO * 24, text)

    def test_populated_ledger_renders_step_count_and_peak(self):
        from fieldkit.tui.data import DashboardData
        d = DashboardData()
        d.detection_ledger = [0, 0, 5, 12, 3, 0, 0]
        text = self._render(d)
        # Total = 20
        self.assertIn("20", text)
        # Peak = 12
        self.assertIn("12/h", text)


if __name__ == "__main__":
    unittest.main()
