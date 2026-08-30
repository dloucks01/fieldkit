#!/usr/bin/env python3
"""fieldkit persist — persistence one-liner emission."""
import io
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
    s.init_engagement("test-persist")
    test_case.addCleanup(s.close)
    return s


def _run(argv, store):
    from fieldkit.cli import build_parser, cmd_persist
    parser = build_parser()
    args = parser.parse_args(argv)
    buf = io.StringIO()
    errbuf = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(errbuf):
        code = cmd_persist.__wrapped__(args, store)
    return code, buf.getvalue(), errbuf.getvalue()


class PersistTest(unittest.TestCase):

    def test_default_both_platforms(self):
        s = _mk_store(self)
        code, out, _ = _run(["persist"], s)
        self.assertEqual(code, 0)
        self.assertIn("Windows", out)
        self.assertIn("Linux", out)
        self.assertIn("scheduled task", out)
        self.assertIn("systemd", out)

    def test_windows_only(self):
        s = _mk_store(self)
        code, out, _ = _run(["persist", "--platform", "windows"], s)
        self.assertEqual(code, 0)
        self.assertIn("Windows", out)
        self.assertNotIn("systemd", out)

    def test_linux_only(self):
        s = _mk_store(self)
        code, out, _ = _run(["persist", "--platform", "linux"], s)
        self.assertEqual(code, 0)
        self.assertIn("systemd", out)
        self.assertNotIn("schtasks", out)

    def test_reminder_present(self):
        s = _mk_store(self)
        code, out, _ = _run(["persist"], s)
        self.assertIn("REMINDER", out)
        self.assertIn("cleanup manifest", out)

    def test_host_lookup_bad_ip_exits_2(self):
        s = _mk_store(self)
        code, _, err = _run(["persist", "--host", "10.99.99.99"], s)
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
