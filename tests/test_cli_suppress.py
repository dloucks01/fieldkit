#!/usr/bin/env python3
"""fieldkit suppress add/list/remove — finding suppression.

C18 gap-slice H. Per-engagement suppression table + CLI.
"""
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
    s.init_engagement("test-sup")
    test_case.addCleanup(s.close)
    return s


def _run(argv, store):
    from fieldkit.cli import build_parser
    parser = build_parser()
    args = parser.parse_args(argv)
    buf = io.StringIO()
    errbuf = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(errbuf):
        # Handlers use __wrapped__ for injected store
        code = args.func.__wrapped__(args, store) \
            if hasattr(args.func, "__wrapped__") else args.func(args)
    return code, buf.getvalue(), errbuf.getvalue()


class StoreMethodTest(unittest.TestCase):

    def test_add_and_list(self):
        s = _mk_store(self)
        sid = s.add_suppression("lsass", reason="accepted risk")
        self.assertGreater(sid, 0)
        rows = list(s.suppressions())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["vector_type"], "lsass")

    def test_is_suppressed_exact_match(self):
        s = _mk_store(self)
        s.add_suppression("lsass")
        self.assertTrue(s.is_suppressed("lsass"))
        self.assertFalse(s.is_suppressed("kerberoast"))

    def test_is_suppressed_wildcard(self):
        s = _mk_store(self)
        s.add_suppression("*")
        self.assertTrue(s.is_suppressed("anything"))

    def test_is_suppressed_host_scoped(self):
        s = _mk_store(self)
        hid, _ = s.add_host("10.0.0.5", os_name="linux")
        hid2, _ = s.add_host("10.0.0.7", os_name="linux")
        s.add_suppression("lsass", host_id=hid)
        self.assertTrue(s.is_suppressed("lsass", host_id=hid))
        self.assertFalse(s.is_suppressed("lsass", host_id=hid2))

    def test_is_suppressed_title_pattern(self):
        s = _mk_store(self)
        s.add_suppression("*", title_pattern="known-old-issue")
        self.assertTrue(s.is_suppressed("x", title="the known-old-issue on box"))
        self.assertFalse(s.is_suppressed("x", title="different issue"))

    def test_remove(self):
        s = _mk_store(self)
        sid = s.add_suppression("lsass")
        self.assertTrue(s.remove_suppression(sid))
        self.assertEqual(len(list(s.suppressions())), 0)
        self.assertFalse(s.remove_suppression(9999))


class CLITest(unittest.TestCase):

    def test_add_lists_removes(self):
        s = _mk_store(self)
        # add
        code, out, _ = _run(["suppress", "add",
                                "--vector-type", "lsass",
                                "--reason", "known"], s)
        self.assertEqual(code, 0)
        self.assertIn("added suppression", out)
        # list
        code, out, _ = _run(["suppress", "list"], s)
        self.assertEqual(code, 0)
        self.assertIn("lsass", out)
        self.assertIn("known", out)
        # remove
        rows = list(s.suppressions())
        sid = rows[0]["id"]
        code, out, _ = _run(["suppress", "remove", str(sid)], s)
        self.assertEqual(code, 0)
        self.assertIn("removed", out)

    def test_remove_bad_id_exits_2(self):
        s = _mk_store(self)
        code, _, err = _run(["suppress", "remove", "9999"], s)
        self.assertEqual(code, 2)
        self.assertIn("no suppression", err)

    def test_add_with_unknown_host_exits_2(self):
        s = _mk_store(self)
        code, _, err = _run(["suppress", "add",
                                "--vector-type", "lsass",
                                "--host", "10.99.99.99"], s)
        self.assertEqual(code, 2)
        self.assertIn("not in the engagement", err)

    def test_list_empty(self):
        s = _mk_store(self)
        code, out, _ = _run(["suppress", "list"], s)
        self.assertEqual(code, 0)
        self.assertIn("no suppressions", out)


if __name__ == "__main__":
    unittest.main()
