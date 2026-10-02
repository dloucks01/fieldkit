#!/usr/bin/env python3
"""Standalone interactive HTML report — self-contained document, inline
CSS/JS, embedded SVG attack path."""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import html_report


def _finding(**kw):
    base = dict(title="x", vector_type="exposed_secret", affected_host="h1",
                severity="High", proven=True, evidence="", steps=[])
    base.update(kw)
    return base


class TestRenderShape(unittest.TestCase):

    def test_document_is_well_formed_html5(self):
        html = html_report.render({"name": "test", "scope": "lab"}, [])
        self.assertTrue(html.lstrip().startswith("<!doctype html>"))
        self.assertIn('<html lang="en">', html)
        self.assertIn("</html>", html.strip()[-100:])

    def test_everything_inline_no_external_assets(self):
        """Standalone HTML: no http(s) URLs, no src= to external files,
        no CDN includes."""
        html = html_report.render({"name": "test"}, [])
        self.assertNotIn("http://", html)
        self.assertNotIn("https://", html.replace("http://www.w3.org/2000/svg", ""))
        self.assertNotIn("<link ", html)
        # script tags must be inline (no src=)
        for m in re.finditer(r"<script\b([^>]*)>", html):
            self.assertNotIn("src=", m.group(1))

    def test_viewport_meta_present(self):
        html = html_report.render({"name": "test"}, [])
        self.assertIn('name="viewport"', html)

    def test_dark_mode_css_present(self):
        html = html_report.render({"name": "test"}, [])
        self.assertIn("prefers-color-scheme: dark", html)
        self.assertIn('data-theme="dark"', html)

    def test_filter_controls_rendered(self):
        html = html_report.render({"name": "test"}, [_finding()])
        for ctl in ("f-sev", "f-status", "f-host", "theme-toggle"):
            self.assertIn(ctl, html, f"missing control {ctl}")


class TestRenderFindings(unittest.TestCase):

    def test_critical_sev_rendered_with_class(self):
        html = html_report.render({"name": "t"},
                                   [_finding(severity="Critical", title="pwned")])
        self.assertIn("sev-Critical", html)
        self.assertIn("pwned", html)

    def test_proven_vs_observation_data_status(self):
        html = html_report.render({"name": "t"}, [
            _finding(proven=True, affected_host="h1"),
            _finding(proven=False, affected_host="h2")])
        self.assertIn('data-status="proven"', html)
        self.assertIn('data-status="observation"', html)

    def test_findings_grouped_by_host(self):
        html = html_report.render({"name": "t"}, [
            _finding(affected_host="dc01"),
            _finding(affected_host="dc01"),
            _finding(affected_host="fs01")])
        # One section per host
        self.assertEqual(html.count('class="host-section"'), 2)

    def test_findings_sorted_by_severity_within_host(self):
        html = html_report.render({"name": "t"}, [
            _finding(severity="Low", title="aaa", affected_host="h"),
            _finding(severity="Critical", title="bbb", affected_host="h")])
        # Critical appears before Low in the rendered document
        self.assertLess(html.index("bbb"), html.index("aaa"))

    def test_evidence_rendered_safely_escaped(self):
        html = html_report.render({"name": "t"}, [
            _finding(evidence="<script>alert(1)</script>")])
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_step_output_truncated_at_1000_chars(self):
        """Long captures should truncate — a dumped LSASS blob would
        otherwise blow the HTML past readability."""
        huge = "A" * 5000
        html = html_report.render({"name": "t"}, [
            _finding(steps=[{"cmd": "dump", "output": huge}])])
        # Count A's in the output — must be around 1000, not 5000
        a_count = html.count("A")
        self.assertLess(a_count, 1500)


class TestRenderSVG(unittest.TestCase):

    def test_svg_embedded_when_chain_data_present(self):
        html = html_report.render({"name": "t"}, [_finding(affected_host="dc01")],
            chains_by_host={"dc01": [
                {"name": "coerce", "outcome": "ok"},
                {"name": "relay", "outcome": "ok"},
                {"name": "esc1", "outcome": "manual"}]})
        self.assertIn('<svg class="attack-path"', html)
        # Each node name is in the SVG
        for n in ("coerce", "relay", "esc1"):
            self.assertIn(n, html)

    def test_no_svg_when_no_chain_data(self):
        html = html_report.render({"name": "t"}, [_finding(affected_host="dc01")])
        self.assertNotIn("<svg", html)

    def test_svg_outcome_colors_differ_by_status(self):
        """ok / manual / skip / fail must each get a distinct stroke color."""
        html = html_report.render({"name": "t"}, [_finding(affected_host="h1")],
            chains_by_host={"h1": [
                {"name": "ok-step",    "outcome": "ok"},
                {"name": "manual",     "outcome": "manual"},
                {"name": "skip-step",  "outcome": "skip"},
                {"name": "fail-step",  "outcome": "fail"}]})
        # Four distinct stroke colors (one per outcome)
        strokes = set(re.findall(r'stroke="(#[0-9a-f]{6})"', html, re.I))
        self.assertGreaterEqual(len(strokes), 4)


class TestFiltersAndSelectors(unittest.TestCase):

    def test_severity_select_lists_each_present_severity(self):
        html = html_report.render({"name": "t"}, [
            _finding(severity="Critical"), _finding(severity="High"),
            _finding(severity="Low")])
        # The severity select must offer these three options.
        sev_section = re.search(r'<select id="f-sev">(.+?)</select>', html, re.S)
        self.assertTrue(sev_section)
        for s in ("Critical", "High", "Low"):
            self.assertIn(s, sev_section.group(1))

    def test_host_select_lists_each_affected_host(self):
        html = html_report.render({"name": "t"}, [
            _finding(affected_host="dc01"), _finding(affected_host="fs01")])
        host_section = re.search(r'<select id="f-host">(.+?)</select>', html, re.S)
        self.assertIn("dc01", host_section.group(1))
        self.assertIn("fs01", host_section.group(1))


class TestEmptyEngagement(unittest.TestCase):

    def test_empty_findings_still_renders(self):
        html = html_report.render({"name": "empty", "scope": "lab"}, [])
        self.assertIn("empty", html)
        # No host sections but the shell still renders
        self.assertIn("fieldkit report", html)


if __name__ == "__main__":
    unittest.main()
