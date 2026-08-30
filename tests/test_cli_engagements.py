#!/usr/bin/env python3
"""fieldkit engagements list/switch — cross-engagement view.

C17 continue slice 1. Walks a directory for engagement DBs;
switch prints the export line to make one active for
subsequent invocations.
"""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _mk_engagement(dirpath, name):
    from fieldkit.state import Store
    path = os.path.join(dirpath, f"{name}.db")
    s = Store.create(path)
    s.init_engagement(name)
    s.close()
    return path


def _run(argv):
    from fieldkit.cli import build_parser
    parser = build_parser()
    args = parser.parse_args(argv)
    buf = io.StringIO()
    errbuf = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(errbuf):
        code = args.func(args)
    return code, buf.getvalue(), errbuf.getvalue()


class ListTest(unittest.TestCase):

    def test_list_finds_engagement_dbs(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        _mk_engagement(tmp.name, "eng-one")
        _mk_engagement(tmp.name, "eng-two")
        code, out, _ = _run(["engagements", "list", "--dir", tmp.name])
        self.assertEqual(code, 0)
        self.assertIn("eng-one", out)
        self.assertIn("eng-two", out)
        self.assertIn("2 engagement", out)

    def test_list_empty_dir(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        code, out, _ = _run(["engagements", "list", "--dir", tmp.name])
        self.assertEqual(code, 0)
        self.assertIn("no *.db files", out)

    def test_list_non_fieldkit_dbs_skipped(self):
        # A random .db file that isn't a fieldkit engagement should
        # be skipped, not counted or crash.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        _mk_engagement(tmp.name, "real")
        # Create a random file with .db extension (not a valid sqlite)
        with open(os.path.join(tmp.name, "garbage.db"), "w") as fh:
            fh.write("not sqlite")
        code, out, _ = _run(["engagements", "list", "--dir", tmp.name])
        self.assertEqual(code, 0)
        # Only the real engagement should appear
        self.assertIn("real", out)
        self.assertNotIn("garbage", out)

    def test_list_json_output(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        _mk_engagement(tmp.name, "eng-json-1")
        code, out, _ = _run([
            "engagements", "list", "--dir", tmp.name, "--json"])
        self.assertEqual(code, 0)
        doc = json.loads(out)
        self.assertEqual(len(doc), 1)
        self.assertEqual(doc[0]["name"], "eng-json-1")
        for f in ("path", "name", "hosts", "creds", "findings"):
            self.assertIn(f, doc[0])

    def test_list_recursive_walks_subdirs(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        sub = os.path.join(tmp.name, "sub")
        os.mkdir(sub)
        _mk_engagement(sub, "nested-eng")
        # Non-recursive: no results
        code, out, _ = _run(["engagements", "list", "--dir", tmp.name])
        self.assertEqual(code, 0)
        self.assertIn("no *.db files", out)
        # Recursive: finds it
        code, out, _ = _run([
            "engagements", "list", "--dir", tmp.name, "--recursive"])
        self.assertEqual(code, 0)
        self.assertIn("nested-eng", out)

    def test_list_bad_dir_exits_2(self):
        code, _, err = _run(["engagements", "list", "--dir",
                                "/nonexistent/xyz"])
        self.assertEqual(code, 2)
        self.assertIn("not a directory", err)


class SwitchTest(unittest.TestCase):

    def test_switch_valid_db_prints_export(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = _mk_engagement(tmp.name, "switch-target")
        code, out, _ = _run(["engagements", "switch", db])
        self.assertEqual(code, 0)
        self.assertIn(f"export FIELDKIT_DB={os.path.abspath(db)}", out)

    def test_switch_missing_file_exits_2(self):
        code, _, err = _run([
            "engagements", "switch", "/nonexistent/x.db"])
        self.assertEqual(code, 2)
        self.assertIn("no such file", err)

    def test_switch_non_engagement_exits_2(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        # Create a valid sqlite DB but no engagement row
        from fieldkit.state import Store
        db = os.path.join(tmp.name, "empty.db")
        s = Store.create(db)
        s.close()
        code, _, err = _run(["engagements", "switch", db])
        self.assertEqual(code, 2)
        self.assertIn("no engagement", err)


if __name__ == "__main__":
    unittest.main()
