#!/usr/bin/env python3
"""Report export — pandoc-backed docx/pdf/html generation (C10 slice 2).

fieldkit.report.export() wraps pandoc so `fieldkit report --formats
md,docx,pdf,html` produces every one the customer wants in one
command. Previously covered docx + pdf; this slice adds HTML and
tests the whole export flow.

Test pins:

  * html format on pandoc-present: fires the pandoc HTML writer
    with -s (standalone) + -H (include-in-header) pointing at a
    generated CSS file;
  * html format on pandoc-missing: emits a hint line instead of
    silently doing nothing;
  * docx + pdf paths (existing behavior) still work;
  * pdf falls back to hint when weasyprint is missing even if
    pandoc is present;
  * runner errors bubble up as "<label> FAILED" lines (not
    exceptions) so `fieldkit report` prints diagnostics + keeps
    going for the other formats.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class FakeRunner:
    """Records every argv passed to it + returns a canned RunResult."""

    def __init__(self, exit_code=0, error=None, timed_out=False, stderr=""):
        self.calls = []
        self.exit_code = exit_code
        self.error = error
        self.timed_out = timed_out
        self.stderr = stderr

    def __call__(self, argv):
        from fieldkit.runner import RunResult
        self.calls.append(list(argv))
        return RunResult(argv=list(argv), exit_code=self.exit_code,
                          stdout="", stderr=self.stderr,
                          error=self.error, timed_out=self.timed_out)


def _fake_have(*present):
    """Returns a `have(tool)` shim that reports only ``present`` tools."""
    present_set = set(present)
    return lambda tool: tool in present_set


class HTMLExportTest(unittest.TestCase):

    def test_pandoc_present_calls_pandoc_html_writer(self):
        from fieldkit.report import export
        run = FakeRunner()
        lines = export("in.md", "out", ["html"], run=run,
                        have=_fake_have("pandoc"))
        self.assertEqual(len(run.calls), 1)
        argv = run.calls[0]
        self.assertEqual(argv[0], "pandoc")
        self.assertEqual(argv[1], "in.md")
        self.assertIn("-o", argv)
        self.assertIn("out.html", argv)
        # standalone mode — needed for the <head> + inline CSS to
        # take effect.
        self.assertIn("-s", argv)
        # style injected via -H (include-in-header).
        self.assertIn("-H", argv)
        # Line reports the write.
        self.assertIn("wrote out.html", lines[0])

    def test_pandoc_missing_emits_hint(self):
        from fieldkit.report import export
        run = FakeRunner()
        lines = export("in.md", "out", ["html"], run=run,
                        have=_fake_have())     # nothing installed
        self.assertEqual(run.calls, [])
        self.assertIn("install pandoc", lines[0])
        self.assertIn("-s -o", lines[0])

    def test_pandoc_error_surfaces_as_fail_line(self):
        from fieldkit.report import export
        run = FakeRunner(exit_code=1, stderr="conversion failure")
        lines = export("in.md", "out", ["html"], run=run,
                        have=_fake_have("pandoc"))
        self.assertIn("html FAILED", lines[0])
        self.assertIn("conversion failure", lines[0])

    def test_pandoc_timeout_surfaces_as_fail_line(self):
        from fieldkit.report import export
        run = FakeRunner(timed_out=True, error="timed out after 300s")
        lines = export("in.md", "out", ["html"], run=run,
                        have=_fake_have("pandoc"))
        self.assertIn("html FAILED", lines[0])
        self.assertIn("timed out", lines[0])

    def test_generated_css_file_cleaned_up(self):
        # The temp CSS file the -H flag points at must be deleted
        # after the pandoc call — succeed or fail. Grab the path
        # from the recorded argv, then assert it no longer exists.
        from fieldkit.report import export
        run = FakeRunner()
        export("in.md", "out", ["html"], run=run,
                have=_fake_have("pandoc"))
        argv = run.calls[0]
        css_path = argv[argv.index("-H") + 1]
        self.assertFalse(os.path.exists(css_path))


class MultipleFormatsTest(unittest.TestCase):
    """Docx + pdf + html can be requested in one export() call."""

    def test_all_three_formats_produce_three_lines(self):
        from fieldkit.report import export
        run = FakeRunner()
        lines = export("in.md", "out", ["docx", "pdf", "html"], run=run,
                        have=_fake_have("pandoc", "weasyprint"))
        self.assertEqual(len(lines), 3)
        self.assertEqual(len(run.calls), 3)
        # Each call names its output.
        outputs = set()
        for call in run.calls:
            outputs.add(call[call.index("-o") + 1])
        self.assertEqual(outputs, {"out.docx", "out.pdf", "out.html"})

    def test_pdf_missing_weasyprint_still_emits_others(self):
        # pandoc present but weasyprint missing: docx + html still
        # produced; pdf falls back to hint.
        from fieldkit.report import export
        run = FakeRunner()
        lines = export("in.md", "out", ["docx", "pdf", "html"], run=run,
                        have=_fake_have("pandoc"))     # no weasyprint
        self.assertEqual(len(lines), 3)
        self.assertEqual(len(run.calls), 2)   # docx + html only
        # PDF line is a hint, not a fail
        pdf_line = [l for l in lines if "pdf" in l][0]
        self.assertIn("install pandoc + weasyprint", pdf_line)


class HTMLStyleTest(unittest.TestCase):
    """The embedded CSS is minimal + self-contained (no external
    font refs, no CDN assets) so exports render offline."""

    def test_style_has_no_external_urls(self):
        from fieldkit.report import _HTML_STYLE
        # No @import, no url(), no http/https references.
        self.assertNotIn("@import", _HTML_STYLE)
        self.assertNotIn("url(", _HTML_STYLE)
        self.assertNotIn("http://", _HTML_STYLE)
        self.assertNotIn("https://", _HTML_STYLE)

    def test_style_includes_dark_mode_query(self):
        # prefers-color-scheme: dark handled — otherwise light-mode-only
        # HTML report looks bad in dark browsers, which is many.
        from fieldkit.report import _HTML_STYLE
        self.assertIn("prefers-color-scheme: dark", _HTML_STYLE)

    def test_style_is_reasonably_sized(self):
        # Not empty, not enormous (< 3KB). Keeps every HTML export
        # small while covering the readability essentials.
        from fieldkit.report import _HTML_STYLE
        self.assertGreater(len(_HTML_STYLE), 100)
        self.assertLess(len(_HTML_STYLE), 3000)


if __name__ == "__main__":
    unittest.main()
