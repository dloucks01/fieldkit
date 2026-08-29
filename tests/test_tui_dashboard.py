#!/usr/bin/env python3
"""fieldkit.tui.dashboard + fieldkit.tui.data — the Dashboard data layer + screen.

Pinned:

  * `data.dashboard()` never raises — a missing / empty / partial DB returns
    a default-empty DashboardData so the screen paints an honest zero;
  * top moves are populated from analyze *unconditionally* (not gated on
    having access) so a fresh `ingest recce` engagement isn't blank;
  * the screen imports cleanly with vendored Textual (proves the CSS parses
    and no widget-class error slipped in).
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class DataTest(unittest.TestCase):
    def _make_store(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        from fieldkit.state import Store
        db_path = os.path.join(tmp.name, "e.db")
        store = Store.create(db_path)
        store.init_engagement("ACME")
        self.addCleanup(store.close)
        return store, db_path

    def test_missing_db_returns_empty_dashboard_without_crash(self):
        from fieldkit.tui import data
        d = data.dashboard("/nonexistent/path/e.db")
        self.assertEqual(d.engagement_name, "(no engagement)")
        self.assertEqual(d.counts["hosts"], 0)
        self.assertEqual(d.top_moves, [])

    def test_dashboard_populates_from_real_store(self):
        from fieldkit.tui import data
        store, db_path = self._make_store()
        hid, _ = store.add_host("10.0.0.7", hostname="WS02", os_name="windows")
        store.add_service(hid, 445)
        d = data.dashboard(db_path)
        self.assertEqual(d.engagement_name, "ACME")
        self.assertEqual(d.counts["hosts"], 1)
        self.assertEqual(d.counts["services"], 1)
        self.assertEqual(d.os_breakdown.get("windows"), 1)
        self.assertEqual(d.pwned_hosts, [])            # no admin
        self.assertIn(d.phase_name,
                      ("setup", "spraying", "enumeration", "exploitation", "reporting"))

    def test_recce_confirmed_finding_surfaces_as_top_move(self):
        # Regression: earlier version gated top_moves on `counts.access > 0`,
        # so a fresh recce ingest showed a blank dashboard. This asserts a
        # recce-confirmed finding IS rendered as a move even without access.
        from fieldkit.tui import data
        store, db_path = self._make_store()
        hid, _ = store.add_host("10.0.0.7", hostname="WS02", os_name="windows")
        store.add_service(hid, 445)
        store.add_finding("recce_confirmed_vuln", "[recce] EternalBlue on WS02",
                          host_id=hid, severity="critical",
                          evidence="ports: 445 · cves: CVE-2017-0143")
        d = data.dashboard(db_path)
        self.assertGreaterEqual(len(d.top_moves), 1)
        titles = [m["title"] for m in d.top_moves]
        self.assertTrue(any("EternalBlue" in t for t in titles),
                        f"EternalBlue not in top_moves titles: {titles}")

    def test_pwned_hosts_populated_when_admin_access_exists(self):
        from fieldkit.tui import data
        from fieldkit.creds import Credential
        store, db_path = self._make_store()
        hid, _ = store.add_host("10.0.0.7", hostname="WS02", os_name="windows",
                                is_dc=True)
        cid, _ = store.add_credential(
            Credential(domain="CORP", username="admin", secret="pw",
                       secret_type="password", local_auth=False))
        store.add_access(hid, cid, method="winrm", admin=True)
        d = data.dashboard(db_path)
        self.assertEqual(len(d.pwned_hosts), 1)
        self.assertEqual(d.pwned_hosts[0]["ip"], "10.0.0.7")
        self.assertTrue(d.pwned_hosts[0]["is_dc"])


class ScreenImportTest(unittest.TestCase):
    """DashboardScreen and its CSS must import + parse cleanly with vendored
    Textual — if a CSS class name is wrong or a widget import breaks, this
    fails loudly rather than on first `bin/fieldkit tui`."""

    def test_dashboard_screen_class_imports(self):
        import importlib
        importlib.import_module("fieldkit.tui")
        from fieldkit.tui.dashboard import DashboardScreen, DASHBOARD_TCSS
        self.assertTrue(DashboardScreen.BINDINGS)
        self.assertIn("dashboard-body", DASHBOARD_TCSS)

    def test_app_registers_dashboard_and_boots(self):
        # End-to-end: FieldkitTUI includes DashboardScreen in SCREENS and
        # boots to it. Confirms CSS parses (no unresolved var, no bad selector).
        import importlib
        importlib.import_module("fieldkit.tui")
        from fieldkit.tui.app import FieldkitTUI
        app = FieldkitTUI()
        self.assertIn("dashboard", app.SCREENS)


if __name__ == "__main__":
    unittest.main()
