#!/usr/bin/env python3
"""fieldkit.tui.watch_screen — live event tail formatter + screen.

Pinned:

  * every event kind has a formatter; missing formatter is a build-time error;
  * formatters return Rich-markup strings, never raise on partial event dicts;
  * a non-zero exit code renders as CAUGHT in critical color, zero as exit 0
    in success color — the operator picks a caught step out of a scan by color;
  * screen imports cleanly with vendored Textual (proves CSS parses + widget
    class names are right).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _step_event(cmd="whoami", exit_code=0, host_id=1, transport="winrm"):
    return {
        "event": "step", "id": 1, "ts": "2026-08-28T14:32:18+00:00",
        "host_id": host_id, "finding_id": None,
        "cmd": cmd, "exit_code": exit_code, "transport": transport,
        "label": "test", "output_len": 20,
    }


def _finding_event(title="EternalBlue on WS02", severity="critical",
                    proven=True, host_id=1):
    return {
        "event": "finding", "id": 1, "ts": "2026-08-28T14:32:31+00:00",
        "host_id": host_id, "vector_type": "recce_confirmed_vuln",
        "title": title, "severity": severity, "proven": proven,
    }


class FormatterTest(unittest.TestCase):
    def setUp(self):
        from fieldkit.tui.watch_screen import _FORMATTERS
        self.fmts = _FORMATTERS

    def test_all_event_kinds_have_a_formatter(self):
        from fieldkit.watch import EVENT_KINDS
        for k in EVENT_KINDS:
            self.assertIn(k, self.fmts, f"no formatter for event kind {k!r}")

    def test_step_success_is_green_success_color(self):
        from fieldkit.tui import theme
        line = self.fmts["step"](_step_event(exit_code=0),
                                  {1: "WS02"})
        self.assertIn(theme.C.GOOD, line)     # exit 0 in success color
        self.assertNotIn(theme.C.CRIT, line)  # no crit color on a clean row
        self.assertIn("exit 0", line)
        self.assertIn("whoami", line)
        self.assertIn("winrm@WS02", line)

    def test_step_nonzero_exit_renders_as_caught_in_crit(self):
        from fieldkit.tui import theme
        line = self.fmts["step"](_step_event(cmd="lsassy", exit_code=1),
                                  {1: "WS02"})
        self.assertIn("CAUGHT", line)
        self.assertIn(theme.C.CRIT, line)     # critical color on the whole row
        self.assertIn(theme.G.CAUGHT, line)   # ⚠ glyph replaces ▸

    def test_finding_proven_uses_proven_glyph_and_good_color(self):
        from fieldkit.tui import theme
        line = self.fmts["finding"](_finding_event(proven=True), {1: "WS02"})
        self.assertIn(theme.G.PROVEN, line)   # ★
        self.assertIn("proven", line)
        self.assertIn(theme.C.GOOD, line)
        self.assertIn("EternalBlue", line)

    def test_finding_observation_uses_observation_glyph(self):
        from fieldkit.tui import theme
        line = self.fmts["finding"](_finding_event(proven=False), {1: "WS02"})
        self.assertIn(theme.G.OBSERVATION, line)   # ◇
        self.assertIn("observed", line)

    def test_access_admin_shows_admin_badge_in_accent(self):
        from fieldkit.tui import theme
        event = {
            "event": "access", "id": 1, "ts": "2026-08-28T14:32:23+00:00",
            "host_id": 1, "cred_id": 1, "method": "winrm", "admin": True,
        }
        line = self.fmts["access"](event, {1: "WS02"})
        self.assertIn("admin", line)
        self.assertIn(theme.C.ACCENT, line)
        self.assertIn("winrm", line)

    def test_credential_renders_principal_and_source(self):
        event = {
            "event": "credential", "id": 1, "ts": "2026-08-28T14:32:36+00:00",
            "domain": "CORP", "username": "jdoe",
            "secret_type": "nt", "source": "loot",
        }
        line = self.fmts["credential"](event, {})
        self.assertIn("CORP\\jdoe", line)
        self.assertIn("nt", line)
        self.assertIn("loot", line)

    def test_loot_renders_kind_and_host(self):
        event = {
            "event": "loot", "id": 1, "ts": "2026-08-28T14:32:40+00:00",
            "host_id": 1, "kind": "sam",
        }
        line = self.fmts["loot"](event, {1: "WS02"})
        self.assertIn("loot", line)
        self.assertIn("WS02", line)
        self.assertIn("sam", line)

    def test_formatter_handles_missing_optional_fields(self):
        # missing transport, missing host, missing exit_code
        event = _step_event()
        event["transport"] = None
        event["host_id"] = None
        event["exit_code"] = None
        line = self.fmts["step"](event, {})
        # doesn't crash and produces something legible
        self.assertIn("?", line)
        self.assertIn("whoami", line)


class ScreenImportTest(unittest.TestCase):
    def test_watch_screen_imports_with_vendored_textual(self):
        import importlib
        importlib.import_module("fieldkit.tui")
        from fieldkit.tui.watch_screen import WatchScreen, WATCH_TCSS
        self.assertTrue(WatchScreen.BINDINGS)
        self.assertIn("event-log", WATCH_TCSS)

    def test_app_boots_with_watch_screen_registered(self):
        import importlib
        importlib.import_module("fieldkit.tui")
        from fieldkit.tui.app import FieldkitTUI
        app = FieldkitTUI()
        self.assertIn("watch", app.SCREENS)


if __name__ == "__main__":
    unittest.main()
