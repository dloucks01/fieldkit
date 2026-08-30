#!/usr/bin/env python3
"""fieldkit pivot — SOCKS/SSH tunnel command emission."""
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
    s.init_engagement("test-pivot")
    test_case.addCleanup(s.close)
    return s


def _run(argv, store):
    from fieldkit.cli import build_parser, cmd_pivot
    parser = build_parser()
    args = parser.parse_args(argv)
    buf = io.StringIO()
    errbuf = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(errbuf):
        code = cmd_pivot.__wrapped__(args, store)
    return code, buf.getvalue(), errbuf.getvalue()


class PivotTest(unittest.TestCase):

    def test_no_host_prints_placeholder(self):
        s = _mk_store(self)
        code, out, _ = _run(["pivot"], s)
        self.assertEqual(code, 0)
        self.assertIn("<foothold-host>", out)
        self.assertIn("SSH dynamic SOCKS", out)
        self.assertIn("chisel", out)
        self.assertIn("reverse SSH", out)

    def test_with_host_uses_ip(self):
        s = _mk_store(self)
        s.add_host("10.0.0.5", os_name="linux")
        code, out, _ = _run(["pivot", "--host", "10.0.0.5"], s)
        self.assertEqual(code, 0)
        self.assertIn("10.0.0.5", out)
        self.assertNotIn("<foothold-host>", out)

    def test_unknown_host_exits_2(self):
        s = _mk_store(self)
        code, _, err = _run(["pivot", "--host", "10.99.99.99"], s)
        self.assertEqual(code, 2)
        self.assertIn("not in the engagement", err)

    def test_socks_port_override(self):
        s = _mk_store(self)
        code, out, _ = _run(["pivot", "--socks-port", "9999"], s)
        self.assertEqual(code, 0)
        self.assertIn("-D 9999", out)


if __name__ == "__main__":
    unittest.main()
