#!/usr/bin/env python3
"""TUI title-bar session-recording indicator.

C15 continue slice 2. When FIELDKIT_SESSION_LOG is set, the
dashboard's TitleBar suffixes a ● REC marker so an operator
running the TUI while recording sees the state visually. When
disabled, the title bar reads identically to before recording
landed.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class RecordingMarkerTest(unittest.TestCase):

    def test_marker_empty_when_env_var_unset(self):
        from fieldkit.tui.dashboard import _recording_marker
        os.environ.pop("FIELDKIT_SESSION_LOG", None)
        self.assertEqual(_recording_marker(), "")

    def test_marker_present_when_env_var_set(self):
        from fieldkit.tui.dashboard import _recording_marker
        os.environ["FIELDKIT_SESSION_LOG"] = "/tmp/x.jsonl"
        self.addCleanup(lambda: os.environ.pop("FIELDKIT_SESSION_LOG", None))
        marker = _recording_marker()
        self.assertIn("REC", marker)
        self.assertIn("●", marker)

    def test_marker_empty_when_env_var_empty_string(self):
        from fieldkit.tui.dashboard import _recording_marker
        os.environ["FIELDKIT_SESSION_LOG"] = ""
        self.addCleanup(lambda: os.environ.pop("FIELDKIT_SESSION_LOG", None))
        self.assertEqual(_recording_marker(), "")


class TitleBarIntegrationTest(unittest.TestCase):

    def test_title_bar_helper_importable(self):
        # Regression pin — the app.TitleBar._tick reaches into
        # dashboard._recording_marker; if the export ever moves,
        # this catches it.
        from fieldkit.tui.dashboard import _recording_marker
        self.assertTrue(callable(_recording_marker))


if __name__ == "__main__":
    unittest.main()
