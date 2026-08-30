#!/usr/bin/env python3
"""fieldkit retest — re-execute proven findings.

C18 gap-slice G. Post-remediation audit cycle.
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
    s.init_engagement("test-retest")
    test_case.addCleanup(s.close)
    return s


def _add_finding_with_step(store, title, cmd, output, host="10.0.0.5"):
    hid, _ = store.add_host(host, os_name="linux")
    fid, _ = store.add_finding(vector_type="test", title=title,
                                 host_id=hid, evidence=output, proven=True)
    store.add_step(cmd=cmd, output=output, exit_code=0,
                    finding_id=fid, transport="local")
    return fid


def _run(argv, store):
    from fieldkit.cli import build_parser, cmd_retest
    parser = build_parser()
    args = parser.parse_args(argv)
    buf = io.StringIO()
    errbuf = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(errbuf):
        code = cmd_retest.__wrapped__(args, store)
    return code, buf.getvalue(), errbuf.getvalue()


def _fake_runner(store, canned_map):
    """Monkey-patch runner_mod.run on cli module to return the
    canned response keyed by cmd. Returns undo."""
    from fieldkit import runner as runner_mod
    orig = runner_mod.run
    def _run(argv, timeout=None):
        cmd = argv[-1] if argv else ""
        class _R: pass
        r = _R()
        r.stdout = canned_map.get(cmd, {}).get("stdout", "")
        r.stderr = canned_map.get(cmd, {}).get("stderr", "")
        r.exit_code = 0
        r.timed_out = False
        r.error = None
        return r
    runner_mod.run = _run
    return lambda: setattr(runner_mod, "run", orig)


class RetestTest(unittest.TestCase):

    def test_no_findings(self):
        s = _mk_store(self)
        code, out, _ = _run(["retest"], s)
        self.assertEqual(code, 0)
        self.assertIn("no proven findings", out)

    def test_still_exploitable(self):
        s = _mk_store(self)
        _add_finding_with_step(s, "A", "id", "uid=0(root)")
        undo = _fake_runner(s, {"id": {"stdout": "uid=0(root)"}})
        self.addCleanup(undo)
        code, out, _ = _run(["retest"], s)
        self.assertEqual(code, 0)
        self.assertIn("still-exploitable: 1", out)

    def test_no_longer_exploitable(self):
        s = _mk_store(self)
        _add_finding_with_step(s, "A", "id", "uid=0(root)")
        undo = _fake_runner(s, {"id": {"stdout": "uid=1000(alice)"}})
        self.addCleanup(undo)
        code, out, _ = _run(["retest"], s)
        self.assertEqual(code, 0)
        self.assertIn("no-longer:         1", out)

    def test_needs_check_when_no_steps(self):
        s = _mk_store(self)
        hid, _ = s.add_host("10.0.0.5", os_name="linux")
        s.add_finding(vector_type="test", title="A",
                       host_id=hid, evidence="e", proven=True)
        # No step added
        code, out, _ = _run(["retest"], s)
        self.assertEqual(code, 0)
        self.assertIn("needs-check:       1", out)

    def test_json_output(self):
        s = _mk_store(self)
        _add_finding_with_step(s, "A", "id", "uid=0(root)")
        undo = _fake_runner(s, {"id": {"stdout": "uid=0(root)"}})
        self.addCleanup(undo)
        code, out, _ = _run(["retest", "--json"], s)
        self.assertEqual(code, 0)
        doc = json.loads(out)
        self.assertEqual(len(doc), 1)
        self.assertEqual(doc[0]["verdict"], "still-exploitable")


if __name__ == "__main__":
    unittest.main()
