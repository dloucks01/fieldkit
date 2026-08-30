#!/usr/bin/env python3
"""TUI dashboard — resume-nudge line on the ChainsBlock.

C12 slice 3. When any recorded chain has status in_progress, the
ChainsBlock surfaces a one-liner with the resumable chain ids +
the exact `fieldkit chain resume <id>` command shape. Ties the
C11 `chain resume` command into the primary screen so a returning
operator sees mid-flight work at a glance.

Pins:

  * empty chain history → no nudge (block renders nothing);
  * proven-only history → no nudge (nothing to resume);
  * aborted-only history → no nudge (aborted is terminal);
  * one in_progress chain → nudge lists that id + resume-command;
  * multiple in_progress chains → nudge lists all ids, comma-joined;
  * mixed (proven + in_progress + aborted) → nudge lists only the
    in_progress ids;
  * "resume" and "in_progress" both appear (visual affordance +
    machine-readable status).
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


def _render(recent, summary=None):
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


class EmptyHistoryTest(unittest.TestCase):

    def test_empty_history_renders_nothing(self):
        text = _render([])
        self.assertEqual(text, "")


class NoResumableStatesTest(unittest.TestCase):

    def test_proven_only_history_omits_nudge(self):
        recent = [{"id": 1, "profile": "esc8", "target": "10.0.0.5",
                    "status": "proven", "detection_debt": 9}]
        text = _render(recent)
        self.assertNotIn("resumable", text)
        self.assertNotIn("chain resume", text)

    def test_aborted_only_history_omits_nudge(self):
        recent = [{"id": 2, "profile": "rbcd", "target": "10.0.0.7",
                    "status": "aborted", "detection_debt": 3}]
        text = _render(recent)
        self.assertNotIn("resumable", text)


class ResumableTest(unittest.TestCase):

    def test_single_in_progress_surfaces_nudge(self):
        recent = [{"id": 12, "profile": "esc8", "target": "10.0.0.5",
                    "status": "in_progress", "detection_debt": 5}]
        text = _render(recent)
        self.assertIn("resumable", text)
        self.assertIn("#12", text)
        self.assertIn("fieldkit chain resume", text)

    def test_multiple_in_progress_lists_all_ids(self):
        recent = [
            {"id": 12, "profile": "esc8", "target": "10.0.0.5",
             "status": "in_progress", "detection_debt": 5},
            {"id": 14, "profile": "rbcd", "target": "10.0.0.7",
             "status": "in_progress", "detection_debt": 3},
        ]
        text = _render(recent)
        self.assertIn("resumable", text)
        self.assertIn("#12", text)
        self.assertIn("#14", text)
        # Comma-joined
        self.assertIn("#12, #14", text)

    def test_mixed_history_lists_only_in_progress(self):
        recent = [
            {"id": 1, "profile": "esc8", "target": "10.0.0.5",
             "status": "proven", "detection_debt": 9},
            {"id": 2, "profile": "rbcd", "target": "10.0.0.7",
             "status": "in_progress", "detection_debt": 3},
            {"id": 3, "profile": "esc1", "target": "10.0.0.9",
             "status": "aborted", "detection_debt": 1},
        ]
        text = _render(recent)
        # Only #2 is resumable
        self.assertIn("resumable", text)
        self.assertIn("#2", text)
        # But the general chain-history rows still show all three
        # (nudge is additive, not exclusive)
        self.assertIn("proven", text)
        self.assertIn("aborted", text)


if __name__ == "__main__":
    unittest.main()
