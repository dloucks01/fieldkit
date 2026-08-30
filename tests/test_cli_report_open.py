#!/usr/bin/env python3
"""fieldkit report --open — hand the richest export to the OS default handler.

C14 slice 5. Silent no-op when no opener is on PATH or when
nothing lands. Pins:

  * _pick_open_path picks html > pdf > docx > md;
  * _pick_open_path returns None when no file lands;
  * --open argparse flag registered;
  * _open_file returns non-zero when opener missing;
  * _open_file uses runner_mod (never bare subprocess).
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class PickPathTest(unittest.TestCase):

    def test_picks_html_when_present(self):
        from fieldkit.cli import _pick_open_path
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = os.path.join(tmp.name, "report")
        for ext in ("md", "docx", "pdf", "html"):
            with open(f"{base}.{ext}", "w") as fh:
                fh.write("x")
        p = _pick_open_path(base, ["md", "docx", "pdf", "html"])
        self.assertEqual(p, f"{base}.html")

    def test_picks_pdf_when_no_html(self):
        from fieldkit.cli import _pick_open_path
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = os.path.join(tmp.name, "report")
        for ext in ("md", "pdf"):
            with open(f"{base}.{ext}", "w") as fh:
                fh.write("x")
        p = _pick_open_path(base, ["md", "pdf"])
        self.assertEqual(p, f"{base}.pdf")

    def test_picks_md_fallback(self):
        from fieldkit.cli import _pick_open_path
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = os.path.join(tmp.name, "report")
        with open(f"{base}.md", "w") as fh:
            fh.write("x")
        p = _pick_open_path(base, ["md"])
        self.assertEqual(p, f"{base}.md")

    def test_returns_none_when_no_file_lands(self):
        from fieldkit.cli import _pick_open_path
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = os.path.join(tmp.name, "report")
        # No files produced despite formats requested (pandoc missing).
        p = _pick_open_path(base, ["docx", "pdf"])
        self.assertIsNone(p)

    def test_returns_none_when_format_not_requested(self):
        from fieldkit.cli import _pick_open_path
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = os.path.join(tmp.name, "report")
        with open(f"{base}.html", "w") as fh:
            fh.write("x")
        # HTML exists but wasn't requested — still returns None
        # because the picker respects the requested list.
        p = _pick_open_path(base, ["md"])
        self.assertIsNone(p)


class OpenFileTest(unittest.TestCase):

    def test_open_file_nonexistent_opener_returns_nonzero(self):
        # Monkey-patch sys.platform to something with no shipped
        # opener path (win32 requires cmd.exe, which shutil.which
        # won't find on Linux CI).
        from fieldkit import cli
        import shutil as _shutil
        orig_which = _shutil.which
        _shutil.which = lambda x: None
        try:
            rc = cli._open_file("/tmp/x")
            self.assertNotEqual(rc, 0)
        finally:
            _shutil.which = orig_which

    def test_open_file_uses_injected_runner(self):
        # Regression: _open_file must NOT do a bare subprocess call
        # — it delegates through runner_mod so the "only runner
        # spawns subprocesses" architecture invariant holds.
        # Verify by counting runner_mod.run invocations.
        from fieldkit import cli, runner as runner_mod
        import shutil as _shutil
        # Fake shutil.which so the opener is "on PATH"
        orig_which = _shutil.which
        _shutil.which = lambda x: "/bin/" + x
        # Fake runner.run to capture the call
        orig_run = runner_mod.run
        calls = []
        class _Result:
            exit_code = 0
        runner_mod.run = lambda cmd, timeout=None: (calls.append(cmd)
                                                        or _Result())
        try:
            rc = cli._open_file("/tmp/x")
            self.assertEqual(rc, 0)
            self.assertEqual(len(calls), 1)
        finally:
            _shutil.which = orig_which
            runner_mod.run = orig_run


class ArgparseTest(unittest.TestCase):

    def test_open_flag_registered(self):
        from fieldkit.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["report", "--open"])
        self.assertTrue(args.open)

    def test_open_flag_default_false(self):
        from fieldkit.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["report"])
        self.assertFalse(getattr(args, "open", False))


if __name__ == "__main__":
    unittest.main()
