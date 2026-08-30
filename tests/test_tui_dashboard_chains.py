#!/usr/bin/env python3
"""TUI dashboard — chain-history widget (C9 slice 5).

DashboardData grows two new fields:
  * chains_recent: last 5 chains, newest-first
  * chains_summary: {total, proven, in_progress, aborted}

ChainsBlock renders both when at least one chain is recorded;
stays silent on engagements with no chain history so the
dashboard is clean for non-chain workflows.
"""
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
    s.init_engagement("test-dash-chains")
    test_case.addCleanup(s.close)
    return s, tmp.name


def _persist_chain(s, target, status_kind):
    """Persist a chain in the given final status:
       'proven'      — all steps ran ok
       'in_progress' — reserve only, no finalize
       'aborted'     — walk with a fail on step 2
    """
    from fieldkit.chain import esc8_chain, Outcome
    ch = esc8_chain(target)
    if status_kind == "proven":
        for step in ch.steps:
            ch.outcomes.append(Outcome(kind="ok",
                                         evidence=f"{step.name} ok"))
        ch.current = len(ch.steps)
    elif status_kind == "aborted":
        ch.outcomes.append(Outcome(kind="ok", evidence="ok"))
        ch.outcomes.append(Outcome(kind="fail", evidence="mock failure"))
        ch.current = 1
        ch.aborted_reason = "step returned fail: mock"
    cid = s.reserve_chain_id(ch)
    if status_kind != "in_progress":
        s.finalize_chain(cid, ch)
    return cid


class DashboardDataChainsTest(unittest.TestCase):
    """dashboard() populates chains_recent + chains_summary from
    the coerce_chain table."""

    def test_no_chains_recorded_yields_empty_summary(self):
        from fieldkit.tui.data import dashboard
        s, path = _make_store(self)
        d = dashboard(os.path.join(path, "e.db"))
        self.assertEqual(d.chains_summary["total"], 0)
        self.assertEqual(d.chains_recent, [])

    def test_summary_counts_by_status(self):
        from fieldkit.tui.data import dashboard
        s, path = _make_store(self)
        _persist_chain(s, "10.0.0.1", "proven")
        _persist_chain(s, "10.0.0.2", "proven")
        _persist_chain(s, "10.0.0.3", "aborted")
        _persist_chain(s, "10.0.0.4", "in_progress")
        d = dashboard(os.path.join(path, "e.db"))
        self.assertEqual(d.chains_summary["total"], 4)
        self.assertEqual(d.chains_summary["proven"], 2)
        self.assertEqual(d.chains_summary["aborted"], 1)
        self.assertEqual(d.chains_summary["in_progress"], 1)

    def test_recent_lists_newest_first_capped_at_5(self):
        from fieldkit.tui.data import dashboard
        s, path = _make_store(self)
        for i in range(7):
            _persist_chain(s, f"10.0.0.{i}", "proven")
        d = dashboard(os.path.join(path, "e.db"))
        self.assertEqual(len(d.chains_recent), 5)
        # Newest-first: last-persisted (10.0.0.6) is first
        self.assertEqual(d.chains_recent[0]["target"], "10.0.0.6")


class ChainsBlockRenderingTest(unittest.TestCase):
    """ChainsBlock renders the widget content given a DashboardData
    (tested without a Textual runtime by calling render_from on a
    minimal captured widget)."""

    def _fake_widget(self):
        # Minimal object with an .update method that captures the
        # text — bypasses Textual's Static widget entirely.
        class FakeWidget:
            def __init__(self):
                self.text = None
            def update(self, s):
                self.text = s
        return FakeWidget()

    def _render(self, data):
        from fieldkit.tui.dashboard import ChainsBlock
        # Instantiate a bare ChainsBlock but never mount it — pull
        # render_from off the class + call it with a fake widget.
        widget = self._fake_widget()
        ChainsBlock.render_from(widget, data)
        return widget.text

    def test_empty_summary_renders_nothing(self):
        from fieldkit.tui.data import DashboardData
        d = DashboardData()
        text = self._render(d)
        self.assertEqual(text, "")

    def test_populated_summary_renders_header_and_rows(self):
        from fieldkit.tui.data import DashboardData
        d = DashboardData()
        d.chains_summary = {"total": 3, "proven": 2,
                             "in_progress": 0, "aborted": 1}
        d.chains_recent = [
            {"id": 3, "profile": "esc8", "target": "10.0.0.3",
             "status": "aborted", "detection_debt": 5},
            {"id": 2, "profile": "esc1", "target": "10.0.0.2",
             "status": "proven", "detection_debt": 33},
            {"id": 1, "profile": "esc8", "target": "10.0.0.1",
             "status": "proven", "detection_debt": 47},
        ]
        text = self._render(d)
        # Header
        self.assertIn("CHAINS", text)
        self.assertIn("3 recorded", text)
        self.assertIn("2 proven", text)
        self.assertIn("1 aborted", text)
        # Rows — profile names + targets present
        self.assertIn("esc8", text)
        self.assertIn("esc1", text)
        self.assertIn("10.0.0.1", text)
        self.assertIn("10.0.0.3", text)
        # Debt figures rendered
        self.assertIn("debt  47", text)


class DashboardScreenIntegrationTest(unittest.TestCase):

    def test_chains_block_registered_on_screen(self):
        # Structural pin — ChainsBlock is a member of the dashboard
        # module + wired into the screen's compose. Full Textual-
        # runtime tests would exercise refresh_data end-to-end;
        # for now assert the block class exists and is imported by
        # the module's compose() implementation.
        from fieldkit.tui import dashboard as dm
        self.assertTrue(hasattr(dm, "ChainsBlock"))
        # Confirm the id "chains" appears in the module source
        # (Textual's Widget(id=...) call captures it).
        import inspect
        src = inspect.getsource(dm.DashboardScreen.compose)
        self.assertIn('id="chains"', src)


if __name__ == "__main__":
    unittest.main()
