#!/usr/bin/env python3
"""Timeline projection — walks every timestamped row in the store, sorts by
ts, renders as either a ribbon or a prose narrative."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import timeline


class _FakeStore:
    """Minimal store shape for timeline testing — the real Store returns
    sqlite3.Row (which supports ``row["key"]`` + ``.keys()``). Dicts
    satisfy the same shape, so this stub is faithful."""
    def __init__(self, steps=None, findings=None, credentials=None, evasion=None):
        self._steps = steps or []
        self._findings = findings or []
        self._creds = credentials or []
        self._evasion = evasion or []

    def steps(self):
        return self._steps

    def findings(self):
        return self._findings

    def credentials(self):
        return self._creds

    def evasion_results(self):
        return self._evasion


class TestBuildTimeline(unittest.TestCase):

    def test_merges_all_four_sources(self):
        store = _FakeStore(
            steps=[{"ts": "2026-10-01T10:00:00", "cmd": "id", "output": "uid=0", "exit_code": 0}],
            findings=[{"ts": "2026-10-01T10:05:00", "key": "sudo:ALL", "host": "10.0.0.5", "proven": True}],
            credentials=[{"ts": "2026-10-01T10:10:00", "username": "admin",
                          "domain": "CORP", "secret_type": "password",
                          "source": "nxc"}],
            evasion=[{"ts": "2026-10-01T10:15:00", "technique": "amsi.patch",
                      "verdict": "clean"}])
        events = timeline.build_timeline(store)
        self.assertEqual(len(events), 4)
        kinds = [e.kind for e in events]
        self.assertEqual(kinds, ["step", "finding", "credential", "evasion"])

    def test_sorts_by_timestamp(self):
        """ISO-8601 strings sort lexically — build_timeline must respect that."""
        store = _FakeStore(
            steps=[{"ts": "2026-10-01T12:00:00", "cmd": "late", "output": "x", "exit_code": 0}],
            findings=[{"ts": "2026-10-01T11:00:00", "key": "f1", "host": "h"},
                      {"ts": "2026-10-01T13:00:00", "key": "f2", "host": "h"}])
        events = timeline.build_timeline(store)
        self.assertEqual([e.ts for e in events],
                         ["2026-10-01T11:00:00",
                          "2026-10-01T12:00:00",
                          "2026-10-01T13:00:00"])

    def test_undated_events_sink_to_the_end(self):
        """A missing ts shouldn't silently sort to the top (empty < any
        ISO-8601 string) and distort the ribbon."""
        store = _FakeStore(
            steps=[{"ts": "2026-10-01T10:00:00", "cmd": "early", "output": "x", "exit_code": 0},
                   {"ts": "", "cmd": "undated", "output": "y", "exit_code": 0}])
        events = timeline.build_timeline(store)
        self.assertEqual(events[0].ts, "2026-10-01T10:00:00")
        self.assertEqual(events[-1].ts, "")

    def test_missing_credentials_method_tolerated(self):
        class StoreNoCreds:
            def steps(self): return []
            def findings(self): return []
            def evasion_results(self): return []
        self.assertEqual(timeline.build_timeline(StoreNoCreds()), [])

    def test_missing_evasion_method_tolerated(self):
        class StoreNoEvasion:
            def steps(self): return []
            def findings(self): return []
            def credentials(self): return []
        self.assertEqual(timeline.build_timeline(StoreNoEvasion()), [])


class TestRender(unittest.TestCase):

    def test_render_empty_message(self):
        self.assertIn("no timeline", timeline.render([]))

    def test_render_filters_by_kind(self):
        events = [timeline.Event(ts="t1", kind="step", summary="s"),
                  timeline.Event(ts="t2", kind="finding", summary="f")]
        out = timeline.render(events, kinds={"finding"})
        self.assertIn("f", out)
        self.assertNotIn("s", out)

    def test_render_includes_every_event(self):
        events = [timeline.Event(ts="t1", kind="step", summary="s1"),
                  timeline.Event(ts="t2", kind="finding", summary="s2")]
        out = timeline.render(events)
        self.assertIn("s1", out)
        self.assertIn("s2", out)


class TestRenderNarrative(unittest.TestCase):

    def test_empty_narrative(self):
        self.assertIn("No activity", timeline.render_narrative([]))

    def test_counts_each_kind(self):
        events = [
            timeline.Event(ts="t1", kind="step", summary="s1"),
            timeline.Event(ts="t2", kind="step", summary="s2"),
            timeline.Event(ts="t3", kind="finding", summary="f1"),
            timeline.Event(ts="t4", kind="credential", summary="c1"),
        ]
        narrative = timeline.render_narrative(events)
        self.assertIn("2 step rows", narrative)
        self.assertIn("1 finding", narrative)
        self.assertIn("1 credential", narrative)

    def test_evasion_verdict_breakdown(self):
        events = [
            timeline.Event(ts="t1", kind="evasion", summary="amsi.patch: clean"),
            timeline.Event(ts="t2", kind="evasion", summary="amsi.hook: caught"),
            timeline.Event(ts="t3", kind="evasion", summary="etw.patch: clean"),
        ]
        narrative = timeline.render_narrative(events)
        # Both verdicts named with counts
        self.assertIn("2 clean", narrative)
        self.assertIn("1 caught", narrative)


class TestEventIsFrozen(unittest.TestCase):

    def test_event_is_immutable(self):
        e = timeline.Event(ts="t", kind="step", summary="s")
        with self.assertRaises(Exception):
            e.kind = "modified"


if __name__ == "__main__":
    unittest.main()
