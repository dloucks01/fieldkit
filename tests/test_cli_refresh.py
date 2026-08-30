#!/usr/bin/env python3
"""`analyze --refresh` / `escalate --refresh` — recce ingest in one command.

Wraps `fieldkit recce <path>` into a flag on the analyze + escalate
commands so operators don't need a separate step to pull the latest
recce data. Non-fatal on ingest failure — both commands continue
against the previously-ingested state.

Test pins:

  * _refresh_from_recce reads the file, parses via recce_mod, applies
    it to the store, returns 0 on success;
  * missing file → returns 2 (non-zero for the caller to detect);
  * malformed JSON → returns 2;
  * empty hosts → returns 2;
  * apply exception → returns 2;
  * successful refresh populates the store's services table (proves
    end-to-end that the ingest actually landed).
"""
import io
import json
import os
import sys
import tempfile
import unittest
import contextlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _make_store(test_case):
    tmp = tempfile.TemporaryDirectory()
    test_case.addCleanup(tmp.cleanup)
    from fieldkit.state import Store
    s = Store.create(os.path.join(tmp.name, "e.db"))
    s.init_engagement("test-refresh")
    test_case.addCleanup(s.close)
    return s, tmp.name


def _minimal_bridge():
    """The smallest recce-bridge JSON that recce_mod.parse accepts.
    Bridge major-version 1 uses the `_recce_bridge` sentinel + the
    `ports` list per host (not `services`). Kept in the test file so
    a bridge-schema change surfaces here as a test edit."""
    return {
        "_recce_bridge": 1,
        "engagement": "test-refresh",
        "generated": "2026-01-01T00:00:00+00:00",
        "hosts": [
            {
                "ip": "10.0.0.5",
                "hostname": "test-host",
                "os": "linux",
                "ports": [
                    {"port": 443, "product": "Apache httpd",
                     "version": "2.4.49"},
                ],
                "findings": [],
            }
        ],
        "users": [],
    }


class RefreshFromRecceTest(unittest.TestCase):

    def test_missing_file_returns_2(self):
        from fieldkit.cli import _refresh_from_recce
        s, _ = _make_store(self)
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            rc = _refresh_from_recce("/nonexistent/bridge.json", s)
        self.assertEqual(rc, 2)
        self.assertIn("cannot read", buf.getvalue())

    def test_malformed_json_returns_2(self):
        from fieldkit.cli import _refresh_from_recce
        s, tmp = _make_store(self)
        path = os.path.join(tmp, "bad.json")
        with open(path, "w") as fh:
            fh.write("this is not JSON at all")
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            rc = _refresh_from_recce(path, s)
        self.assertEqual(rc, 2)

    def test_empty_hosts_returns_2(self):
        from fieldkit.cli import _refresh_from_recce
        s, tmp = _make_store(self)
        bridge = _minimal_bridge()
        bridge["hosts"] = []
        path = os.path.join(tmp, "empty.json")
        with open(path, "w") as fh:
            json.dump(bridge, fh)
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            rc = _refresh_from_recce(path, s)
        self.assertEqual(rc, 2)
        self.assertIn("no hosts", buf.getvalue())

    def test_successful_refresh_populates_store(self):
        from fieldkit.cli import _refresh_from_recce
        s, tmp = _make_store(self)
        path = os.path.join(tmp, "bridge.json")
        with open(path, "w") as fh:
            json.dump(_minimal_bridge(), fh)
        rc = _refresh_from_recce(path, s)
        self.assertEqual(rc, 0)
        # The host + service actually landed in the store.
        hosts = s.hosts()
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]["ip"], "10.0.0.5")
        services = s.services(host_id=hosts[0]["id"])
        self.assertEqual(len(services), 1)
        self.assertEqual(services[0]["product"], "Apache httpd")
        self.assertEqual(services[0]["version"], "2.4.49")

    def test_refresh_is_idempotent(self):
        # Re-applying the same bridge should not create duplicate
        # host or service rows.
        from fieldkit.cli import _refresh_from_recce
        s, tmp = _make_store(self)
        path = os.path.join(tmp, "bridge.json")
        with open(path, "w") as fh:
            json.dump(_minimal_bridge(), fh)
        _refresh_from_recce(path, s)
        _refresh_from_recce(path, s)
        self.assertEqual(len(s.hosts()), 1)
        # Same product+port row should NOT double.
        services = s.services(host_id=s.hosts()[0]["id"])
        self.assertEqual(len(services), 1)


class AnalyzeRefreshIntegrationTest(unittest.TestCase):
    """The --refresh flag on `fieldkit analyze` runs the refresh
    before ranking, populating facts.services so a version_range
    TTP fires."""

    def test_analyze_refresh_populates_services_facts(self):
        from fieldkit.cli import cmd_analyze as _wrapped_cmd
        cmd_analyze = _wrapped_cmd.__wrapped__
        s, tmp = _make_store(self)
        path = os.path.join(tmp, "bridge.json")
        with open(path, "w") as fh:
            json.dump(_minimal_bridge(), fh)

        class Args:
            refresh = path
            proof = False

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cmd_analyze(Args(), s)
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        # Refresh header printed
        self.assertIn("[refresh] re-ingested", out)
        # And the host actually landed in the store.
        self.assertEqual(len(s.hosts()), 1)


if __name__ == "__main__":
    unittest.main()
