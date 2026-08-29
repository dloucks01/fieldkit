#!/usr/bin/env python3
"""watch — JSONL event stream via polling.

Pinned:

  * `poll_once` is pure — no sleep, no printing; returns (events, cursors)
  * cursors are per-kind so a step doesn't advance the finding cursor
  * `--from-now` semantics: prime cursors to the current max id
  * `watch` generator yields events; `run` callable is injectable so tests
    control the loop lifetime
  * event shape carries `event`, `ts`, and a stable id — TUI consumers rely on
    (event, id) to dedupe if a network hiccup replays a poll
  * `dumps` produces JSONL — one event per line, sort_keys for deterministic
    ordering that a `diff` can compare across runs
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import watch  # noqa: E402
from fieldkit.creds import Credential  # noqa: E402
from fieldkit.state import Store  # noqa: E402


class PollOnceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME")
        self.host_id, _ = self.store.add_host("10.0.0.7", os_name="windows")

    def test_empty_engagement_yields_nothing(self):
        events, cursors = watch.poll_once(self.store)
        self.assertEqual(events, [])
        # cursors defaulted to 0 for every kind
        self.assertEqual(set(cursors.keys()), set(watch.EVENT_KINDS))

    def test_new_step_is_emitted_once(self):
        step_id = self.store.add_step(cmd="whoami", output="root",
                                       exit_code=0, host_id=self.host_id,
                                       label="test", transport="ssh")
        events, cursors = watch.poll_once(self.store)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event"], "step")
        self.assertEqual(events[0]["id"], step_id)
        self.assertEqual(events[0]["cmd"], "whoami")
        self.assertEqual(events[0]["exit_code"], 0)
        self.assertEqual(events[0]["transport"], "ssh")
        # step's output is summarized, not full — length only
        self.assertNotIn("output", events[0])
        self.assertEqual(events[0]["output_len"], len("root"))
        # second poll with the advanced cursor emits nothing (idempotent)
        events2, _ = watch.poll_once(self.store, cursors)
        self.assertEqual(events2, [])

    def test_new_finding_is_emitted(self):
        fid, _ = self.store.add_finding("test_vector", "A test finding",
                                         host_id=self.host_id, severity="high")
        events, _ = watch.poll_once(self.store)
        finding_events = [e for e in events if e["event"] == "finding"]
        self.assertEqual(len(finding_events), 1)
        self.assertEqual(finding_events[0]["id"], fid)
        self.assertEqual(finding_events[0]["severity"], "high")
        self.assertFalse(finding_events[0]["proven"])

    def test_cursors_advance_per_kind_independently(self):
        # write a step and a credential
        self.store.add_step(cmd="id", host_id=self.host_id, label="l", transport="t")
        self.store.add_credential(Credential(
            domain="CORP", username="jdoe", secret="x", secret_type="password",
            local_auth=False))
        events, cursors = watch.poll_once(self.store)
        # both events appear; each advances its own cursor
        kinds = {e["event"] for e in events}
        self.assertEqual(kinds, {"step", "credential"})
        self.assertGreater(cursors["step"], 0)
        self.assertGreater(cursors["credential"], 0)
        # add another credential; only that one should show up on the next poll
        self.store.add_credential(Credential(
            domain="CORP", username="alice", secret="y", secret_type="password",
            local_auth=False))
        events2, _ = watch.poll_once(self.store, cursors)
        self.assertEqual({e["event"] for e in events2}, {"credential"})

    def test_kinds_narrows_which_tables_are_watched(self):
        # write a step; poll with only 'finding' — no events
        self.store.add_step(cmd="x", host_id=self.host_id, label="l", transport="t")
        events, _ = watch.poll_once(self.store, kinds=("finding",))
        self.assertEqual(events, [])

    def test_dumps_produces_stable_jsonl(self):
        event = {"event": "step", "id": 1, "cmd": "whoami", "ts": "2026-01-01T00:00:00Z"}
        line = watch.dumps(event)
        self.assertNotIn("\n", line)                # one line
        # sort_keys means dumps is deterministic across runs — a diff-friendly wire format
        again = watch.dumps(event)
        self.assertEqual(line, again)
        # round-trips
        self.assertEqual(json.loads(line)["cmd"], "whoami")


class WatchGeneratorTest(unittest.TestCase):
    """The `watch()` generator drives poll_once in a loop; `run` is injectable."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME")
        self.host_id, _ = self.store.add_host("10.0.0.7", os_name="windows")

    def test_generator_stops_when_run_returns_false(self):
        self.store.add_step(cmd="a", host_id=self.host_id, label="l", transport="t")
        self.store.add_step(cmd="b", host_id=self.host_id, label="l", transport="t")
        # run returns True on first check, False after — one poll pass, then stop
        state = {"n": 0}
        def run():
            state["n"] += 1
            return state["n"] <= 1
        events = list(watch.watch(self.store, run=run, sleep=lambda: None))
        self.assertEqual(len(events), 2)
        self.assertEqual([e["event"] for e in events], ["step", "step"])

    def test_generator_emits_only_new_rows_from_seeded_cursor(self):
        # simulate --from-now: seed the step cursor past the two existing rows
        self.store.add_step(cmd="old1", host_id=self.host_id, label="l", transport="t")
        old2_id = self.store.add_step(cmd="old2", host_id=self.host_id, label="l",
                                       transport="t")
        cursors = {k: 0 for k in watch.EVENT_KINDS}
        cursors["step"] = old2_id                # skip both existing steps
        # add a new step; poll once — only the new one shows
        self.store.add_step(cmd="new", host_id=self.host_id, label="l", transport="t")
        state = {"n": 0}
        def run():
            state["n"] += 1
            return state["n"] <= 1
        events = list(watch.watch(self.store, cursors=cursors, run=run,
                                  sleep=lambda: None))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["cmd"], "new")


if __name__ == "__main__":
    unittest.main()
