#!/usr/bin/env python3
"""fieldkit refresh — returning-operator one-liner.

C13 slice 5. Re-ingests recce bridge + runs analyze. Prints
counts delta so the operator sees at a glance what changed,
then delegates to cmd_analyze for the ranked-moves output.

Pins:

  * bridge as positional arg re-ingests + analyze runs;
  * missing bridge (positional None + no config recce_bridge)
    → analyze still runs, "no bridge path" printed;
  * config recce_bridge default is picked up when no positional;
  * counts delta line surfaces changed keys;
  * exit 0 on successful ingest, 1 on ingest failure w/
    analyze still running, 2 on bad invocation;
  * recce_bridge is a first-class config key (config set accepts it);
  * --proof flag passes through to analyze.
"""
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _make_store(test_case):
    tmp = tempfile.TemporaryDirectory()
    test_case.addCleanup(tmp.cleanup)
    from fieldkit.state import Store
    s = Store.create(os.path.join(tmp.name, "e.db"))
    s.init_engagement("test-refresh")
    test_case.addCleanup(s.close)
    return s, tmp.name


def _bridge_file(dirpath, hosts=(("10.0.0.5", "linux"),)):
    """Write a minimal recce-bridge.json in the shape recce.parse
    expects (BRIDGE_MAJOR = 1, requires ``_recce_bridge`` field)."""
    import json
    payload = {
        "_recce_bridge": 1,
        "engagement": "test-refresh-bridge",
        "generated": "2026-01-01T00:00:00Z",
        "hosts": [
            {"ip": ip, "os": os_} for ip, os_ in hosts
        ],
        "findings": [],
        "credentials": [],
    }
    path = os.path.join(dirpath, "bridge.json")
    with open(path, "w") as fh:
        json.dump(payload, fh)
    return path


def _run(argv, store):
    from fieldkit.cli import build_parser, cmd_refresh
    parser = build_parser()
    args = parser.parse_args(argv)
    buf = io.StringIO()
    errbuf = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(errbuf):
        code = cmd_refresh.__wrapped__(args, store)
    return code, buf.getvalue(), errbuf.getvalue()


class BridgePositionalTest(unittest.TestCase):

    def test_bridge_arg_ingests_and_analyzes(self):
        s, tmp = _make_store(self)
        b = _bridge_file(tmp)
        code, out, _ = _run(["refresh", b], s)
        self.assertEqual(code, 0)
        self.assertIn("re-ingested", out)
        # counts delta line always prints
        self.assertIn("[refresh]", out)


class NoBridgeTest(unittest.TestCase):

    def test_no_bridge_no_config_prints_analyze_only(self):
        s, _ = _make_store(self)
        code, out, _ = _run(["refresh"], s)
        self.assertEqual(code, 0)
        self.assertIn("no bridge path", out)

    def test_config_recce_bridge_is_picked_up(self):
        from fieldkit import config as config_mod
        s, tmp = _make_store(self)
        b = _bridge_file(tmp)
        cfg = config_mod.load(s)
        cfg.set("recce_bridge", b)
        code, out, _ = _run(["refresh"], s)
        self.assertEqual(code, 0)
        self.assertIn("from config recce_bridge", out)


class CountsDeltaTest(unittest.TestCase):

    def test_delta_line_surfaces_changed_keys(self):
        s, tmp = _make_store(self)
        # empty engagement — bridge with 1 host → counts.hosts 0→1
        b = _bridge_file(tmp)
        code, out, _ = _run(["refresh", b], s)
        self.assertEqual(code, 0)
        self.assertIn("hosts:", out)
        self.assertIn("0→1", out)

    def test_no_change_line_when_nothing_moved(self):
        # Ingest once so state is populated; run refresh again
        # against the same bridge → no counts change.
        s, tmp = _make_store(self)
        b = _bridge_file(tmp)
        _run(["refresh", b], s)     # first ingest
        code, out, _ = _run(["refresh", b], s)   # second, idempotent
        self.assertEqual(code, 0)
        self.assertIn("no state change", out)


class IngestFailureTest(unittest.TestCase):

    def test_bad_bridge_returns_1_still_analyzes(self):
        s, tmp = _make_store(self)
        bad = os.path.join(tmp, "bad.json")
        with open(bad, "w") as fh:
            fh.write("not valid json")
        code, out, _ = _run(["refresh", bad], s)
        # Exit 1 — ingest failed, analyze still ran
        self.assertEqual(code, 1)
        self.assertIn("ingest failed", out)


class ConfigKeyTest(unittest.TestCase):

    def test_recce_bridge_is_registered_config_key(self):
        from fieldkit.config import KEYS
        self.assertIn("recce_bridge", KEYS)


if __name__ == "__main__":
    unittest.main()
