#!/usr/bin/env python3
"""fieldkit changelog — auto-generate CHANGELOG.md from git log.

C17 continue slice 4. Groups commits by conventional-commit
prefix (feat / fix / refactor / …) into markdown sections.
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


class ChangelogTest(unittest.TestCase):
    """Live git-log integration — this test file lives inside the
    fieldkit repo, so `git log` returns real commits. The tests
    assert structural shape rather than specific commits."""

    def test_changelog_returns_markdown(self):
        code, out, _ = _run(["changelog", "--since", "HEAD~5"])
        self.assertEqual(code, 0)
        self.assertIn("# Changelog", out)
        self.assertIn("Commits since", out)

    def test_conventional_commit_grouping(self):
        # A recent slice with feat: commits should surface under Features
        code, out, _ = _run(["changelog", "--since", "HEAD~30"])
        self.assertEqual(code, 0)
        # At least one section header should appear
        self.assertTrue(any(header in out
                             for header in ("## Features", "## Bug fixes",
                                             "## Refactoring")))

    def test_out_flag_writes_to_file(self):
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        outp = os.path.join(tmp.name, "CHANGELOG.md")
        code, stdout, _ = _run([
            "changelog", "--since", "HEAD~5", "--out", outp])
        self.assertEqual(code, 0)
        self.assertIn("wrote", stdout)
        with open(outp) as fh:
            content = fh.read()
        self.assertIn("# Changelog", content)

    def test_scope_extraction(self):
        # feat(chain): ... should render as **chain:** bold prefix
        code, out, _ = _run(["changelog", "--since", "HEAD~30"])
        self.assertEqual(code, 0)
        # Scope prefixes appear as bold
        self.assertIn("**", out)


class ArgparseTest(unittest.TestCase):

    def test_bare_changelog_no_args_registered(self):
        from fieldkit.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["changelog"])
        self.assertIsNone(args.out)
        self.assertIsNone(args.since)

    def test_since_flag(self):
        from fieldkit.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["changelog", "--since", "v1.0"])
        self.assertEqual(args.since, "v1.0")


if __name__ == "__main__":
    unittest.main()
