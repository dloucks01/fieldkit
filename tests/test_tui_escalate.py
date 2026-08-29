#!/usr/bin/env python3
"""fieldkit.tui.escalate — the confirm-before-fire screen.

Pinned:

  * `_build_command` produces a proper argv for a host-scoped move, or
    None+reason for a move without a host (password-reuse, roast-loot);
  * host-scoped moves at safety=read-only don't add --allow (matches CLI);
  * config-change / crash-risk moves DO add --allow at the correct tier;
  * screen imports and constructs with a real move dict;
  * Analyze ⏎ pushes the Escalate screen (integration).
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _move(host="10.0.0.7", safety="config-change", title="EternalBlue on WS02"):
    return {
        "key": "recce-conf:1", "title": title, "host": host,
        "axes": f"high/{safety}/moderate", "score": 320,
        "exploitability": "high", "safety": safety, "detection": "moderate",
        "next_step": f"fieldkit escalate {host}",
        "detail": "recce confirmed", "evidence": "ports: 445",
    }


class BuildCommandTest(unittest.TestCase):
    def test_host_scoped_config_change_has_allow(self):
        from fieldkit.tui.escalate import _build_command
        argv, _ = _build_command(_move(safety="config-change"), db_path=None)
        self.assertIsNotNone(argv)
        self.assertIn("escalate", argv)
        self.assertIn("10.0.0.7", argv)
        self.assertIn("--allow", argv)
        self.assertIn("config-change", argv)
        self.assertIn("--yes", argv)

    def test_host_scoped_read_only_omits_allow(self):
        from fieldkit.tui.escalate import _build_command
        argv, _ = _build_command(_move(safety="read-only"), db_path=None)
        self.assertIsNotNone(argv)
        self.assertNotIn("--allow", argv)   # read-only is the default gate

    def test_host_scoped_crash_risk_has_crash_risk_allow(self):
        from fieldkit.tui.escalate import _build_command
        argv, _ = _build_command(_move(safety="crash-risk"), db_path=None)
        self.assertIn("--allow", argv)
        self.assertIn("crash-risk", argv)

    def test_no_host_returns_none_with_reason(self):
        from fieldkit.tui.escalate import _build_command
        argv, reason = _build_command(_move(host=None), db_path=None)
        self.assertIsNone(argv)
        self.assertIn("no host", reason)

    def test_db_path_flows_into_argv(self):
        from fieldkit.tui.escalate import _build_command
        argv, _ = _build_command(_move(), db_path="/tmp/x.db")
        self.assertIn("--db", argv)
        self.assertIn("/tmp/x.db", argv)


class HostContextTest(unittest.TestCase):
    def _store(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        from fieldkit.state import Store
        db = os.path.join(tmp.name, "e.db")
        s = Store.create(db)
        s.init_engagement("ACME")
        self.addCleanup(s.close)
        return s, db

    def test_missing_db_returns_bare_ip(self):
        from fieldkit.tui.escalate import _host_context
        info = _host_context("/nonexistent.db", "10.0.0.7")
        self.assertEqual(info["ip"], "10.0.0.7")
        self.assertNotIn("hostname", info)

    def test_populated_host_returns_full_info(self):
        from fieldkit.tui.escalate import _host_context
        from fieldkit.creds import Credential
        s, db = self._store()
        hid, _ = s.add_host("10.0.0.7", hostname="WS02", os_name="windows",
                            is_dc=True)
        cid, _ = s.add_credential(Credential(
            domain="CORP", username="admin", secret="pw",
            secret_type="password", local_auth=False))
        s.add_access(hid, cid, method="winrm", admin=True)
        info = _host_context(db, "10.0.0.7")
        self.assertEqual(info["ip"], "10.0.0.7")
        self.assertEqual(info["hostname"], "WS02")
        self.assertEqual(info["os"], "windows")
        self.assertTrue(info["is_dc"])
        self.assertEqual(info["access"], [{"method": "winrm", "admin": True}])


class ScreenImportTest(unittest.TestCase):
    def test_escalate_screen_imports(self):
        import importlib
        importlib.import_module("fieldkit.tui")
        from fieldkit.tui.escalate import EscalateScreen, ESCALATE_TCSS
        s = EscalateScreen(_move())
        self.assertTrue(s.BINDINGS)
        self.assertIn("escalate-body", ESCALATE_TCSS)

    def test_analyze_screen_pushes_escalate_on_enter(self):
        # Full integration — Analyze ⏎ pushes EscalateScreen with the
        # highlighted move. Uses the run_test harness so we drive the app.
        import importlib
        importlib.import_module("fieldkit.tui")
        import asyncio
        from fieldkit.state import Store
        from fieldkit.tui.app import FieldkitTUI
        from fieldkit.tui.escalate import EscalateScreen

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = os.path.join(tmp.name, "e.db")
        with Store.create(db) as s:
            s.init_engagement("ACME")
            hid, _ = s.add_host("10.0.0.7", hostname="WS02", os_name="windows")
            s.add_finding("recce_confirmed_vuln", "[recce] EternalBlue",
                          host_id=hid, severity="critical")

        async def _drive():
            app = FieldkitTUI(db_path=db)
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause()
                await pilot.press("a")
                await pilot.pause()
                await pilot.press("enter")
                await pilot.pause()
                self.assertIsInstance(app.screen, EscalateScreen)
                # esc → back to Analyze
                await pilot.press("escape")
                await pilot.pause()
                self.assertNotIsInstance(app.screen, EscalateScreen)

        asyncio.run(_drive())


if __name__ == "__main__":
    unittest.main()
