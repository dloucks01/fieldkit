#!/usr/bin/env python3
"""fieldkit.tui.analyze — ranked opportunities screen.

Pinned:

  * `data.opportunities()` returns all moves (not capped at 3 like top_moves);
  * severity-dot color derives from exploitability+safety per §7 rules;
  * filter matches title / axes / host / any axis component (substring);
  * screen imports cleanly with vendored Textual.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class OpportunitiesDataTest(unittest.TestCase):
    def _make_store(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        from fieldkit.state import Store
        db_path = os.path.join(tmp.name, "e.db")
        store = Store.create(db_path)
        store.init_engagement("ACME")
        self.addCleanup(store.close)
        return store, db_path

    def test_missing_db_returns_empty_list(self):
        from fieldkit.tui import data
        self.assertEqual(data.opportunities("/nonexistent.db"), [])

    def test_returns_display_ready_dicts_not_opportunity_objects(self):
        from fieldkit.tui import data
        store, db_path = self._make_store()
        hid, _ = store.add_host("10.0.0.7", hostname="WS02", os_name="windows")
        store.add_finding("recce_confirmed_vuln", "[recce] EternalBlue",
                          host_id=hid, severity="critical")
        moves = data.opportunities(db_path)
        self.assertGreaterEqual(len(moves), 1)
        m = moves[0]
        # Every field the screen consumes is a plain scalar (dict, not object)
        self.assertIsInstance(m, dict)
        for key in ("key", "title", "host", "axes", "score",
                    "exploitability", "safety", "detection", "next_step",
                    "detail", "evidence"):
            self.assertIn(key, m, f"opportunities dict missing {key!r}")

    def test_all_recce_findings_surface_not_just_top_3(self):
        from fieldkit.tui import data
        store, db_path = self._make_store()
        hid, _ = store.add_host("10.0.0.7", hostname="WS02", os_name="windows")
        for i in range(5):
            store.add_finding("recce_confirmed_vuln", f"[recce] Finding {i}",
                              host_id=hid, severity="high")
        moves = data.opportunities(db_path)
        titles = [m["title"] for m in moves]
        self.assertEqual(sum(1 for t in titles if "Finding" in t), 5,
                         f"expected 5 recce opps, got {titles}")


class SeverityDotTest(unittest.TestCase):
    def test_high_config_change_reads_critical(self):
        from fieldkit.tui.analyze import _severity_dots_for, _severity_dot_color
        from fieldkit.tui import theme
        self.assertEqual(_severity_dots_for("high", "config-change"), "●●●")
        self.assertEqual(_severity_dot_color("high", "config-change"), theme.C.CRIT)

    def test_high_readonly_reads_high_not_critical(self):
        from fieldkit.tui.analyze import _severity_dots_for, _severity_dot_color
        from fieldkit.tui import theme
        self.assertEqual(_severity_dots_for("high", "read-only"), "●●○")
        self.assertEqual(_severity_dot_color("high", "read-only"), theme.C.WARN)

    def test_medium_reads_info(self):
        from fieldkit.tui.analyze import _severity_dots_for, _severity_dot_color
        from fieldkit.tui import theme
        self.assertEqual(_severity_dots_for("medium", "read-only"), "●○○")
        self.assertEqual(_severity_dot_color("medium", "read-only"), theme.C.INFO)


class FilterTest(unittest.TestCase):
    """Filter matches any of title/axes/host/exploitability/safety/detection.
    Directly tests the screen's _visible_moves logic without booting Textual."""

    def _screen(self):
        # Build a fake screen with the _visible_moves method; avoids full App
        import importlib
        importlib.import_module("fieldkit.tui")
        from fieldkit.tui.analyze import AnalyzeScreen
        s = object.__new__(AnalyzeScreen)  # bypass Screen.__init__
        s._filter = ""
        s._moves = [
            {"key": "a", "title": "EternalBlue on WS02", "host": "10.0.0.7",
             "axes": "high/config-change/moderate",
             "exploitability": "high", "safety": "config-change",
             "detection": "moderate"},
            {"key": "b", "title": "Password reuse", "host": "",
             "axes": "high/read-only/quiet",
             "exploitability": "high", "safety": "read-only",
             "detection": "quiet"},
            {"key": "c", "title": "MSSQL sysadmin", "host": "10.0.0.11",
             "axes": "medium/config-change/loud",
             "exploitability": "medium", "safety": "config-change",
             "detection": "loud"},
        ]
        return s

    def test_empty_filter_returns_all(self):
        s = self._screen()
        self.assertEqual(len(s._visible_moves()), 3)

    def test_title_substring_match(self):
        s = self._screen()
        s._filter = "eternal"
        self.assertEqual([m["key"] for m in s._visible_moves()], ["a"])

    def test_host_substring_match(self):
        s = self._screen()
        s._filter = "10.0.0.11"
        self.assertEqual([m["key"] for m in s._visible_moves()], ["c"])

    def test_axis_component_match(self):
        s = self._screen()
        s._filter = "quiet"
        self.assertEqual([m["key"] for m in s._visible_moves()], ["b"])
        s._filter = "config-change"
        self.assertEqual(sorted(m["key"] for m in s._visible_moves()), ["a", "c"])


class ScreenImportTest(unittest.TestCase):
    def test_analyze_screen_imports(self):
        import importlib
        importlib.import_module("fieldkit.tui")
        from fieldkit.tui.analyze import AnalyzeScreen, ANALYZE_TCSS
        self.assertTrue(AnalyzeScreen.BINDINGS)
        self.assertIn("move-list", ANALYZE_TCSS)

    def test_app_registers_analyze_screen(self):
        import importlib
        importlib.import_module("fieldkit.tui")
        from fieldkit.tui.app import FieldkitTUI
        app = FieldkitTUI()
        self.assertIn("analyze", app.SCREENS)


if __name__ == "__main__":
    unittest.main()
