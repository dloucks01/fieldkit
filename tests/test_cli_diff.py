#!/usr/bin/env python3
"""fieldkit diff — compare findings between the current
engagement and a baseline DB.

C17 continue slice 2. Identity for a finding is
(vector_type, title, host_id).
"""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _mk_store(test_case, name="test-diff"):
    tmp = tempfile.TemporaryDirectory()
    test_case.addCleanup(tmp.cleanup)
    from fieldkit.state import Store
    s = Store.create(os.path.join(tmp.name, "e.db"))
    s.init_engagement(name)
    test_case.addCleanup(s.close)
    return s, tmp.name


def _add_finding(store, title, vector_type="lsass", host_ip="10.0.0.5"):
    hid, _ = store.add_host(host_ip, os_name="linux")
    store.add_finding(vector_type=vector_type, title=title,
                       host_id=hid, evidence="e", proven=True)


def _run(argv, store):
    from fieldkit.cli import build_parser, cmd_diff
    parser = build_parser()
    args = parser.parse_args(argv)
    buf = io.StringIO()
    errbuf = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(errbuf):
        code = cmd_diff.__wrapped__(args, store)
    return code, buf.getvalue(), errbuf.getvalue()


class DiffTest(unittest.TestCase):

    def _two_dbs(self, current_findings, baseline_findings):
        from fieldkit.state import Store
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        # Current
        cur_path = os.path.join(tmp.name, "cur.db")
        cur = Store.create(cur_path)
        cur.init_engagement("current-eng")
        for t in current_findings:
            hid, _ = cur.add_host("10.0.0.5", os_name="linux")
            cur.add_finding(vector_type="lsass", title=t,
                             host_id=hid, evidence="e", proven=True)
        # Baseline
        base_path = os.path.join(tmp.name, "base.db")
        base = Store.create(base_path)
        base.init_engagement("baseline-eng")
        for t in baseline_findings:
            hid, _ = base.add_host("10.0.0.5", os_name="linux")
            base.add_finding(vector_type="lsass", title=t,
                              host_id=hid, evidence="e", proven=True)
        base.close()
        self.addCleanup(cur.close)
        return cur, base_path

    def test_all_new_findings(self):
        cur, base = self._two_dbs(current_findings=["A", "B"],
                                     baseline_findings=[])
        code, out, _ = _run(["diff", base], cur)
        self.assertEqual(code, 0)
        self.assertIn("new:         2", out)
        self.assertIn("gone:        0", out)

    def test_all_gone_findings(self):
        cur, base = self._two_dbs(current_findings=[],
                                     baseline_findings=["A", "B"])
        code, out, _ = _run(["diff", base], cur)
        self.assertEqual(code, 0)
        self.assertIn("new:         0", out)
        self.assertIn("gone:        2", out)

    def test_unchanged_findings(self):
        cur, base = self._two_dbs(current_findings=["A", "B"],
                                     baseline_findings=["A", "B"])
        code, out, _ = _run(["diff", base], cur)
        self.assertEqual(code, 0)
        self.assertIn("new:         0", out)
        self.assertIn("gone:        0", out)
        self.assertIn("unchanged:   2", out)

    def test_mixed_new_and_gone(self):
        cur, base = self._two_dbs(current_findings=["A", "B"],
                                     baseline_findings=["B", "C"])
        code, out, _ = _run(["diff", base], cur)
        self.assertEqual(code, 0)
        self.assertIn("new:         1", out)
        self.assertIn("gone:        1", out)
        self.assertIn("unchanged:   1", out)
        # The new finding (A) shown in NEW section
        self.assertIn("+ A", out)
        # The gone finding (C) shown in GONE section
        self.assertIn("- C", out)

    def test_verbose_shows_unchanged(self):
        cur, base = self._two_dbs(current_findings=["A"],
                                     baseline_findings=["A"])
        code, out, _ = _run(["diff", "--verbose", base], cur)
        self.assertEqual(code, 0)
        self.assertIn("UNCHANGED", out)
        self.assertIn("= A", out)

    def test_non_verbose_hides_unchanged_list(self):
        cur, base = self._two_dbs(current_findings=["A"],
                                     baseline_findings=["A"])
        code, out, _ = _run(["diff", base], cur)
        self.assertEqual(code, 0)
        self.assertNotIn("= A", out)

    def test_json_output(self):
        cur, base = self._two_dbs(current_findings=["A", "B"],
                                     baseline_findings=["B", "C"])
        code, out, _ = _run(["diff", "--json", base], cur)
        self.assertEqual(code, 0)
        doc = json.loads(out)
        self.assertEqual(doc["counts"]["new"], 1)
        self.assertEqual(doc["counts"]["gone"], 1)
        self.assertEqual(doc["counts"]["unchanged"], 1)
        self.assertIn("current", doc)
        self.assertIn("baseline", doc)

    def test_missing_baseline_file_exits_2(self):
        cur, _ = self._two_dbs(current_findings=["A"], baseline_findings=[])
        code, _, err = _run(["diff", "/nonexistent/foo.db"], cur)
        self.assertEqual(code, 2)
        self.assertIn("no such file", err)


if __name__ == "__main__":
    unittest.main()
