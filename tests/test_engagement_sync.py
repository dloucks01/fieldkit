#!/usr/bin/env python3
"""fieldkit sync — walk an engagement folder + auto-ingest.

C19. Unit tests exercise the folder-walking + dispatch logic
without a live lab (each artifact type built as a small
fixture); integration tests in tests/integration/ verify
against a real recce-provisioned folder.
"""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _mk_store(test_case):
    tmp = tempfile.TemporaryDirectory()
    test_case.addCleanup(tmp.cleanup)
    from fieldkit.state import Store
    s = Store.create(os.path.join(tmp.name, "e.db"))
    s.init_engagement("test-sync")
    test_case.addCleanup(s.close)
    return s


def _mk_lab_folder(test_case):
    tmp = tempfile.TemporaryDirectory()
    test_case.addCleanup(tmp.cleanup)
    return tmp.name


def _write_bridge(root, hosts=(("10.0.0.5", "linux"),)):
    """Write a minimal recce-bridge.json into root."""
    payload = {
        "_recce_bridge": 1,
        "engagement": "test",
        "generated": "2026-09-01T00:00:00Z",
        "hosts": [{"ip": ip, "os": os_} for ip, os_ in hosts],
        "findings": [],
        "credentials": [],
    }
    path = os.path.join(root, "recce-bridge.json")
    with open(path, "w") as fh:
        json.dump(payload, fh)
    return path


class BareFolderTest(unittest.TestCase):

    def test_empty_folder_returns_empty_report(self):
        from fieldkit import engagement_sync
        s = _mk_store(self)
        root = _mk_lab_folder(self)
        report = engagement_sync.sync_folder(s, root)
        self.assertEqual(report.processed, [])
        self.assertEqual(report.delta, {})

    def test_missing_folder_raises_value_error(self):
        from fieldkit import engagement_sync
        s = _mk_store(self)
        with self.assertRaises(ValueError):
            engagement_sync.sync_folder(s, "/nonexistent/path")


class RecceBridgeTest(unittest.TestCase):

    def test_bridge_processed_and_hosts_folded(self):
        from fieldkit import engagement_sync
        s = _mk_store(self)
        root = _mk_lab_folder(self)
        _write_bridge(root, hosts=[
            ("10.0.0.5", "linux"), ("10.0.0.7", "windows")])
        report = engagement_sync.sync_folder(s, root)
        kinds = {e["kind"] for e in report.processed}
        self.assertIn("recce-bridge", kinds)
        self.assertEqual(s.counts()["hosts"], 2)
        self.assertIn("hosts", report.delta)

    def test_sync_is_idempotent(self):
        from fieldkit import engagement_sync
        s = _mk_store(self)
        root = _mk_lab_folder(self)
        _write_bridge(root)
        engagement_sync.sync_folder(s, root)
        second = engagement_sync.sync_folder(s, root)
        # Second run shouldn't add any hosts
        self.assertNotIn("hosts", second.delta)

    def test_bad_bridge_lands_as_skipped(self):
        from fieldkit import engagement_sync
        s = _mk_store(self)
        root = _mk_lab_folder(self)
        with open(os.path.join(root, "recce-bridge.json"), "w") as fh:
            fh.write("not valid json")
        report = engagement_sync.sync_folder(s, root)
        # Not in processed
        self.assertEqual(
            [e for e in report.processed if e["kind"] == "recce-bridge"], [])
        # In skipped with a reason
        skipped_bridge = [e for e in report.skipped
                            if e["kind"] == "recce-bridge"]
        self.assertEqual(len(skipped_bridge), 1)
        self.assertEqual(skipped_bridge[0]["action"], "failed")


class NmapTest(unittest.TestCase):

    def test_nmap_xml_processed(self):
        from fieldkit import engagement_sync
        s = _mk_store(self)
        root = _mk_lab_folder(self)
        os.makedirs(os.path.join(root, "nmap"))
        # Minimal nmap XML
        with open(os.path.join(root, "nmap", "scan.xml"), "w") as fh:
            fh.write(
                '<?xml version="1.0"?><nmaprun scanner="nmap">'
                '<host><status state="up"/>'
                '<address addr="10.0.0.9" addrtype="ipv4"/>'
                '</host></nmaprun>')
        report = engagement_sync.sync_folder(s, root)
        kinds = {e["kind"] for e in report.processed}
        self.assertIn("nmap", kinds)


class CLITest(unittest.TestCase):

    def _run(self, argv, store):
        from fieldkit.cli import build_parser, cmd_sync
        parser = build_parser()
        args = parser.parse_args(argv)
        buf = io.StringIO()
        errbuf = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(errbuf):
            code = cmd_sync.__wrapped__(args, store)
        return code, buf.getvalue(), errbuf.getvalue()

    def test_cli_sync_walks_folder(self):
        s = _mk_store(self)
        root = _mk_lab_folder(self)
        _write_bridge(root)
        code, out, _ = self._run(["sync", root], s)
        self.assertEqual(code, 0)
        self.assertIn("processed:", out)
        self.assertIn("recce-bridge", out)
        self.assertIn("hosts:", out)

    def test_cli_sync_missing_folder_exits_2(self):
        s = _mk_store(self)
        code, _, err = self._run(["sync", "/nonexistent"], s)
        self.assertEqual(code, 2)
        self.assertIn("not a directory", err)

    def test_cli_sync_json_output(self):
        s = _mk_store(self)
        root = _mk_lab_folder(self)
        _write_bridge(root)
        code, out, _ = self._run(["sync", "--json", root], s)
        self.assertEqual(code, 0)
        doc = json.loads(out)
        self.assertIn("processed", doc)
        self.assertIn("delta", doc)


if __name__ == "__main__":
    unittest.main()
