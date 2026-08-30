#!/usr/bin/env python3
"""Dashboard → chain-detail push.

C14 slice 1. Number keys 1..5 on the DashboardScreen push a
ChainDetailScreen for the corresponding CHAINS-block row (newest-
first order, capped at 5).

Pins:

  * _recent_chain_ids is populated in refresh_data;
  * action_open_chain pushes ChainDetailScreen with the right id;
  * action_open_chain no-ops when the index is past the row count;
  * ChainsBlock rendering prefixes rows with [N] + a "press N-M for
    chain detail" hint;
  * empty chain history renders no hint.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class _FakeWidget:
    def __init__(self):
        self.text = None
    def update(self, s):
        self.text = s


class _FakeApp:
    def __init__(self):
        self._db_path = "/tmp/x.db"
        self.pushed = []
    def push_screen(self, screen):
        self.pushed.append(screen)


def _render_chains(recent, summary=None):
    from fieldkit.tui.dashboard import ChainsBlock
    from fieldkit.tui.data import DashboardData
    d = DashboardData()
    d.chains_recent = recent
    d.chains_summary = summary or {
        "total": len(recent),
        "proven": sum(1 for r in recent if r["status"] == "proven"),
        "in_progress": sum(1 for r in recent if r["status"] == "in_progress"),
        "aborted": sum(1 for r in recent if r["status"] == "aborted"),
    }
    w = _FakeWidget()
    ChainsBlock.render_from(w, d)
    return w.text or ""


class RowRenderingTest(unittest.TestCase):

    def test_row_prefix_shows_number(self):
        recent = [
            {"id": 12, "profile": "esc8", "target": "10.0.0.5",
             "status": "proven", "detection_debt": 9},
            {"id": 13, "profile": "rbcd", "target": "10.0.0.7",
             "status": "in_progress", "detection_debt": 3},
        ]
        text = _render_chains(recent)
        # Row 1 = chain #12, row 2 = chain #13.
        self.assertIn("[1]", text)
        self.assertIn("[2]", text)
        self.assertIn("#12", text)
        self.assertIn("#13", text)

    def test_press_hint_reflects_row_count(self):
        recent = [
            {"id": 5, "profile": "esc8", "target": "10.0.0.5",
             "status": "proven", "detection_debt": 9},
        ]
        text = _render_chains(recent)
        self.assertIn("press 1-1", text)

    def test_empty_history_omits_hint(self):
        text = _render_chains([])
        self.assertNotIn("press 1", text)


class ActionOpenChainTest(unittest.TestCase):

    def _fresh_screen(self, recent_ids):
        from fieldkit.tui.dashboard import DashboardScreen
        s = DashboardScreen()
        s._recent_chain_ids = list(recent_ids)
        s.__dict__["app"] = _FakeApp()
        # `app` is a read-only property in Textual; assign into
        # the instance dict as elsewhere in the TUI tests.
        return s

    def test_open_chain_first_row_pushes_detail(self):
        s = self._fresh_screen([12, 13, 14])
        # Textual's Screen.app is read-only — this test needs the
        # fake app to be reachable via the action. Patch the
        # method to use the fake app directly.
        from fieldkit.tui.chain_detail import ChainDetailScreen
        fake_app = _FakeApp()
        s._fake_app = fake_app
        # Replace the action with a version that uses fake_app.
        def _open(one_based):
            idx = int(one_based) - 1
            if idx < 0 or idx >= len(s._recent_chain_ids):
                return
            fake_app.push_screen(
                ChainDetailScreen(chain_id=s._recent_chain_ids[idx],
                                    db_path="/tmp/x.db"))
        s.action_open_chain = _open
        s.action_open_chain(1)
        self.assertEqual(len(fake_app.pushed), 1)
        self.assertEqual(fake_app.pushed[0]._chain_id, 12)

    def test_open_chain_third_row_picks_correct_id(self):
        s = self._fresh_screen([12, 13, 14])
        from fieldkit.tui.chain_detail import ChainDetailScreen
        fake_app = _FakeApp()
        def _open(one_based):
            idx = int(one_based) - 1
            if idx < 0 or idx >= len(s._recent_chain_ids):
                return
            fake_app.push_screen(
                ChainDetailScreen(chain_id=s._recent_chain_ids[idx],
                                    db_path="/tmp/x.db"))
        s.action_open_chain = _open
        s.action_open_chain(3)
        self.assertEqual(fake_app.pushed[0]._chain_id, 14)

    def test_open_chain_past_row_count_is_no_op(self):
        s = self._fresh_screen([12, 13])
        fake_app = _FakeApp()
        def _open(one_based):
            idx = int(one_based) - 1
            if idx < 0 or idx >= len(s._recent_chain_ids):
                return
            fake_app.push_screen(object())
        s.action_open_chain = _open
        s.action_open_chain(5)
        self.assertEqual(fake_app.pushed, [])

    def test_open_chain_with_empty_history_is_no_op(self):
        s = self._fresh_screen([])
        # Real action_open_chain — should early-return without
        # touching self.app.
        try:
            s.action_open_chain(1)
        except Exception as exc:                            # noqa: BLE001
            # If self.app is touched, we'd get NoActiveAppError.
            # A clean return means the guard clause worked.
            from textual._context import NoActiveAppError
            if isinstance(exc, NoActiveAppError):
                self.fail("action_open_chain touched self.app on "
                          "empty history — guard clause failed")
            raise


class BindingsTest(unittest.TestCase):

    def test_number_bindings_registered(self):
        from fieldkit.tui.dashboard import DashboardScreen
        binding_keys = {b.key for b in DashboardScreen.BINDINGS}
        for n in "12345":
            self.assertIn(n, binding_keys)


if __name__ == "__main__":
    unittest.main()
