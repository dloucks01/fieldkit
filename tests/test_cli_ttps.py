#!/usr/bin/env python3
"""fieldkit ttps list/show — browse the shipped TTP catalog.

C13 slice 3. No engagement needed — reads the YAML catalog via
the loader. Pins:

  * bare list prints every TTP with the header + rows;
  * --grep filters case-insensitively over key/name/tech/tactic;
  * empty match set prints "no TTPs match" and exits 0;
  * show <key> prints every populated section;
  * show <unknown-key> exits 2 with a hint;
  * show handles a TTP whose detect uses version_range (the
    common shape shipped) — no AttributeError regression.
"""
import io
import os
import sys
import unittest
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


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

    def test_bare_list_prints_header_and_rows(self):
        code, out, _ = _run(["ttps", "list"])
        self.assertEqual(code, 0)
        self.assertIn("technique", out)
        self.assertIn("key", out)
        self.assertIn("platform", out)
        # And some rows — the catalog has 100+ TTPs
        self.assertGreater(len(out.splitlines()), 100)

    def test_grep_filters_case_insensitively(self):
        code, out, _ = _run(["ttps", "list", "--grep", "FORTIGATE"])
        self.assertEqual(code, 0)
        self.assertIn("service_cve:2024-55591", out)
        # A different CVE key should not match this grep.
        self.assertNotIn("service_cve:2024-53961", out)

    def test_grep_over_tactic_matches(self):
        # esc1 template ttps have tactic "privilege-escalation"
        code, out, _ = _run(["ttps", "list", "--grep",
                              "privilege-escalation"])
        self.assertEqual(code, 0)
        # At least one match
        rows = [ln for ln in out.splitlines() if "T1" in ln]
        self.assertGreater(len(rows), 0)

    def test_grep_with_no_matches_returns_0(self):
        code, out, _ = _run(["ttps", "list", "--grep",
                              "xyz-no-such-thing-xyz"])
        self.assertEqual(code, 0)
        self.assertIn("no TTPs match", out)


class ShowTest(unittest.TestCase):

    def test_show_prints_every_section(self):
        code, out, _ = _run(["ttps", "show", "service_cve:2024-55591"])
        self.assertEqual(code, 0)
        # Every section header we render
        for header in ("detect", "execute", "verify", "report", "playbook"):
            self.assertIn(header, out)
        # And the technique + ranking + source
        self.assertIn("T1190", out)
        self.assertIn("exploit=high", out)
        self.assertIn("source:", out)

    def test_show_handles_version_range_detect(self):
        # Regression pin — a shipped TTP whose detect uses
        # `version_range` should print without AttributeError.
        code, out, _ = _run(["ttps", "show", "service_cve:2024-55591"])
        self.assertEqual(code, 0)
        self.assertIn("version_range", out)
        self.assertIn("services.fortigate", out)

    def test_show_unknown_key_exits_2(self):
        code, _, err = _run(["ttps", "show", "no-such-key-really"])
        self.assertEqual(code, 2)
        self.assertIn("no TTP", err)
        self.assertIn("`fieldkit ttps list`", err)

    def test_show_prints_playbook_when_present(self):
        code, out, _ = _run(["ttps", "show", "service_cve:2024-55591"])
        self.assertEqual(code, 0)
        # This TTP ships a full playbook
        self.assertIn("summary", out)
        self.assertIn("steps", out)
        self.assertIn("1.", out)


if __name__ == "__main__":
    unittest.main()
