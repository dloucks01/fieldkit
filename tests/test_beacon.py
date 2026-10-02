#!/usr/bin/env python3
"""Beacon orchestration — fieldkit's engagement-side view of operator
beacons. Tests the SQLite schema (v12) + the module API + the per-build
mutation seed derivation."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import beacon
from fieldkit.state import Store


def _store_with_engagement():
    """Open a fresh engagement store for a test."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    path = tmp.name
    tmp.close()
    os.unlink(path)  # Store.open(create=True) refuses to overwrite
    cm = Store.open(path, create=True)
    store = cm.__enter__()
    store.init_engagement("beacon-test")
    return cm, store, path


class TestBuildSeed(unittest.TestCase):

    def test_new_build_seed_is_32_hex_chars(self):
        seed = beacon.new_build_seed()
        self.assertEqual(len(seed), 32)
        int(seed, 16)  # must parse as hex

    def test_two_build_seeds_differ(self):
        self.assertNotEqual(beacon.new_build_seed(),
                            beacon.new_build_seed())


class TestRegister(unittest.TestCase):

    def setUp(self):
        self.cm, self.store, self.path = _store_with_engagement()

    def tearDown(self):
        self.cm.__exit__(None, None, None)
        os.unlink(self.path)

    def test_register_persists_the_beacon(self):
        cfg = beacon.BeaconConfig(
            name="corp-ws02", platform="windows", transport="https",
            callback_url="https://c2.example.com/api")
        bid = beacon.register_beacon(self.store, cfg)
        self.assertGreater(bid, 0)
        rows = beacon.list_beacons(self.store)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "corp-ws02")

    def test_register_rejects_unknown_transport(self):
        cfg = beacon.BeaconConfig(
            name="bad", platform="windows", transport="ipx",
            callback_url="https://x")
        with self.assertRaises(ValueError):
            beacon.register_beacon(self.store, cfg)

    def test_register_assigns_a_build_seed_if_absent(self):
        cfg = beacon.BeaconConfig(
            name="auto-seed", platform="linux", transport="https",
            callback_url="https://x")
        beacon.register_beacon(self.store, cfg)
        rows = beacon.list_beacons(self.store)
        self.assertEqual(len(rows[0]["build_seed"]), 32)

    def test_register_honors_operator_provided_seed(self):
        cfg = beacon.BeaconConfig(
            name="pinned-seed", platform="linux", transport="https",
            callback_url="https://x",
            build_seed="deadbeefcafebabedeadbeefcafebabe")
        beacon.register_beacon(self.store, cfg)
        self.assertEqual(beacon.by_name(self.store, "pinned-seed")["build_seed"],
                         "deadbeefcafebabedeadbeefcafebabe")

    def test_duplicate_name_fails(self):
        cfg = beacon.BeaconConfig(
            name="dup", platform="windows", transport="https",
            callback_url="https://x")
        beacon.register_beacon(self.store, cfg)
        import sqlite3
        with self.assertRaises(sqlite3.IntegrityError):
            beacon.register_beacon(self.store, cfg)


class TestTasking(unittest.TestCase):

    def setUp(self):
        self.cm, self.store, self.path = _store_with_engagement()
        self.bid = beacon.register_beacon(self.store, beacon.BeaconConfig(
            name="b1", platform="linux", transport="https",
            callback_url="https://x"))

    def tearDown(self):
        self.cm.__exit__(None, None, None)
        os.unlink(self.path)

    def test_issue_task_round_trips(self):
        beacon.issue_task(self.store, self.bid, "shell", ["id", "-u"])
        tasks = beacon.pending_tasks(self.store, self.bid)
        self.assertEqual(len(tasks), 1)
        t = tasks[0]
        self.assertEqual(t["cmd"], "shell")
        self.assertEqual(t["args"], ["id", "-u"])

    def test_unknown_cmd_rejected(self):
        with self.assertRaises(ValueError):
            beacon.issue_task(self.store, self.bid, "arbitrary", [])

    def test_args_must_be_a_list(self):
        with self.assertRaises(TypeError):
            beacon.issue_task(self.store, self.bid, "shell", "not a list")

    def test_result_promotes_task_out_of_pending(self):
        tid = beacon.issue_task(self.store, self.bid, "shell", ["id"])
        beacon.record_result(self.store, tid, "uid=0(root)")
        self.assertEqual(beacon.pending_tasks(self.store, self.bid), [])
        hist = beacon.task_history(self.store, self.bid)
        self.assertEqual(len(hist), 1)
        self.assertEqual(hist[0]["result"], "uid=0(root)")

    def test_result_updates_beacon_last_seen(self):
        before = beacon.by_name(self.store, "b1")["last_seen"]
        tid = beacon.issue_task(self.store, self.bid, "shell", ["id"])
        beacon.record_result(self.store, tid, "ok")
        after = beacon.by_name(self.store, "b1")["last_seen"]
        self.assertIsNone(before)
        self.assertIsNotNone(after)

    def test_record_result_on_unknown_task_raises(self):
        with self.assertRaises(LookupError):
            beacon.record_result(self.store, 9999, "stuff")

    def test_history_shows_pending_and_completed_both(self):
        t1 = beacon.issue_task(self.store, self.bid, "shell", ["id"])
        beacon.issue_task(self.store, self.bid, "sleep", ["120"])
        beacon.record_result(self.store, t1, "uid=0")
        hist = beacon.task_history(self.store, self.bid)
        self.assertEqual(len(hist), 2)
        statuses = [("completed" if t.get("completed_at") else "pending")
                    for t in hist]
        self.assertIn("completed", statuses)
        self.assertIn("pending", statuses)


class TestBuildConfig(unittest.TestCase):

    def test_render_includes_substitution_keys(self):
        cfg = beacon.BeaconConfig(
            name="demo", platform="linux", transport="https",
            callback_url="https://c2.example.com/api",
            interval_s=120, jitter_pct=25,
            build_seed="deadbeef" * 4)
        d = beacon.render_build_config(cfg)
        self.assertEqual(d["c2_url"], "https://c2.example.com/api")
        self.assertEqual(d["beacon_id"], "demo")
        self.assertEqual(d["interval_s"], 120)
        self.assertEqual(d["jitter_pct"], 25)
        self.assertIn("Mozilla", d["user_agent"])
        self.assertEqual(d["build_seed"], "deadbeef" * 4)

    def test_seed_drives_deterministic_user_agent(self):
        """Same seed → same UA; different seeds → likely different UAs
        (not guaranteed since the pool is small, but at least deterministic)."""
        a = beacon.render_build_config(beacon.BeaconConfig(
            name="a", platform="linux", transport="https",
            callback_url="x", build_seed="1" * 32))
        b = beacon.render_build_config(beacon.BeaconConfig(
            name="b", platform="linux", transport="https",
            callback_url="x", build_seed="1" * 32))
        self.assertEqual(a["user_agent"], b["user_agent"])

    def test_empty_seed_uses_first_UA(self):
        d = beacon.render_build_config(beacon.BeaconConfig(
            name="x", platform="linux", transport="https",
            callback_url="x"))
        self.assertEqual(d["user_agent"], beacon._UA_POOL[0])


class TestTransportCatalog(unittest.TestCase):

    def test_https_has_a_reference_template(self):
        self.assertEqual(beacon.TRANSPORTS["https"]["template"],
                         "https_beacon.py.j2")

    def test_every_transport_has_a_description(self):
        for name, meta in beacon.TRANSPORTS.items():
            self.assertTrue(meta["description"])


class TestConfigShape(unittest.TestCase):

    def test_beacon_config_is_frozen(self):
        c = beacon.BeaconConfig(name="x", platform="linux",
                                  transport="https", callback_url="x")
        with self.assertRaises(Exception):
            c.name = "modified"

    def test_valid_task_commands_pinned(self):
        self.assertEqual(set(beacon.TASK_COMMANDS),
                         {"shell", "upload", "download", "sleep", "kill"})


if __name__ == "__main__":
    unittest.main()
