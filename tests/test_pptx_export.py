#!/usr/bin/env python3
"""PPTX executive deck exporter — stdlib-only hand-crafted .pptx."""
import io
import os
import sys
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import pptx_export


def _f(**kw):
    base = dict(severity="High", vector_type="exposed_secret",
                affected_host="h1", proven=True)
    base.update(kw)
    return base


class TestZipShape(unittest.TestCase):

    def test_produces_valid_zip(self):
        data = pptx_export.render({"name": "t"}, [])
        self.assertTrue(zipfile.is_zipfile(io.BytesIO(data)))

    def test_minimal_pptx_parts_present(self):
        """Must have the parts every PPTX reader expects: content types,
        root rels, presentation, slide master, slide layout, theme."""
        data = pptx_export.render({"name": "t"}, [])
        z = zipfile.ZipFile(io.BytesIO(data))
        names = set(z.namelist())
        for required in ("[Content_Types].xml", "_rels/.rels",
                          "ppt/presentation.xml",
                          "ppt/_rels/presentation.xml.rels",
                          "ppt/slideMasters/slideMaster1.xml",
                          "ppt/slideLayouts/slideLayout1.xml",
                          "ppt/theme/theme1.xml"):
            self.assertIn(required, names, f"missing part {required}")

    def test_five_slides_produced(self):
        data = pptx_export.render({"name": "t"}, [])
        z = zipfile.ZipFile(io.BytesIO(data))
        slide_names = [n for n in z.namelist()
                       if n.startswith("ppt/slides/slide")
                       and n.endswith(".xml")]
        self.assertEqual(len(slide_names), 5)

    def test_every_slide_has_a_rels_file(self):
        data = pptx_export.render({"name": "t"}, [])
        z = zipfile.ZipFile(io.BytesIO(data))
        for i in range(1, 6):
            self.assertIn(f"ppt/slides/_rels/slide{i}.xml.rels",
                          z.namelist())

    def test_content_types_declares_every_slide(self):
        data = pptx_export.render({"name": "t"}, [])
        z = zipfile.ZipFile(io.BytesIO(data))
        ct = z.read("[Content_Types].xml").decode()
        for i in range(1, 6):
            self.assertIn(f"/ppt/slides/slide{i}.xml", ct)


class TestSlideContent(unittest.TestCase):

    def test_title_slide_has_engagement_name_and_scope(self):
        data = pptx_export.render({"name": "redteam-q3",
                                     "scope": "172.20.0.0/24"}, [])
        z = zipfile.ZipFile(io.BytesIO(data))
        s1 = z.read("ppt/slides/slide1.xml").decode()
        self.assertIn("redteam-q3", s1)
        self.assertIn("172.20.0.0/24", s1)

    def test_severity_slide_counts_each_level(self):
        findings = [_f(severity="Critical"), _f(severity="Critical"),
                    _f(severity="High")]
        data = pptx_export.render({"name": "t"}, findings)
        z = zipfile.ZipFile(io.BytesIO(data))
        s2 = z.read("ppt/slides/slide2.xml").decode()
        # Both "Critical" shows up as a label + "2" as its count
        self.assertIn("Critical", s2)
        self.assertIn(">2<", s2)
        self.assertIn("High", s2)

    def test_top_findings_slide_sorts_critical_first(self):
        data = pptx_export.render({"name": "t"}, [
            _f(severity="Low", vector_type="low_vt"),
            _f(severity="Critical", vector_type="crit_vt")])
        z = zipfile.ZipFile(io.BytesIO(data))
        s3 = z.read("ppt/slides/slide3.xml").decode()
        self.assertLess(s3.index("crit_vt"), s3.index("low_vt"))

    def test_narrative_slide_carries_the_text(self):
        data = pptx_export.render({"name": "t"}, [],
                                    narrative="The engagement went well.")
        z = zipfile.ZipFile(io.BytesIO(data))
        s4 = z.read("ppt/slides/slide4.xml").decode()
        self.assertIn("The engagement went well.", s4)

    def test_remediation_slide_counts_by_vector_type(self):
        findings = [_f(vector_type="writable_cron"),
                    _f(vector_type="writable_cron"),
                    _f(vector_type="exposed_secret")]
        data = pptx_export.render({"name": "t"}, findings)
        z = zipfile.ZipFile(io.BytesIO(data))
        s5 = z.read("ppt/slides/slide5.xml").decode()
        self.assertIn("writable_cron", s5)
        self.assertIn("2 finding(s)", s5)


class TestEscaping(unittest.TestCase):

    def test_engagement_name_is_xml_escaped(self):
        """XML metachars in the engagement name must not break the file."""
        data = pptx_export.render({"name": "<pwned> & 'ok'", "scope": ""},
                                    [])
        self.assertTrue(zipfile.is_zipfile(io.BytesIO(data)))
        z = zipfile.ZipFile(io.BytesIO(data))
        s1 = z.read("ppt/slides/slide1.xml").decode()
        self.assertIn("&lt;pwned&gt;", s1)
        self.assertNotIn("<pwned>", s1)

    def test_vector_type_with_metachars_safe(self):
        data = pptx_export.render({"name": "t"}, [
            _f(vector_type="<evil>", severity="Critical")])
        self.assertTrue(zipfile.is_zipfile(io.BytesIO(data)))

    def test_narrative_with_metachars_safe(self):
        data = pptx_export.render({"name": "t"}, [],
                                    narrative="user said: <script>alert(1)</script>")
        z = zipfile.ZipFile(io.BytesIO(data))
        s4 = z.read("ppt/slides/slide4.xml").decode()
        self.assertNotIn("<script>", s4)
        self.assertIn("&lt;script&gt;", s4)


class TestBranding(unittest.TestCase):

    def test_default_brand_applies_default_colors(self):
        data = pptx_export.render({"name": "t"}, [])
        z = zipfile.ZipFile(io.BytesIO(data))
        theme = z.read("ppt/theme/theme1.xml").decode()
        self.assertIn("1a1a1a", theme)
        self.assertIn("0366d6", theme)

    def test_custom_brand_colors_propagate_to_theme(self):
        brand = pptx_export.BrandConfig(title_rgb="FF00FF",
                                          accent_rgb="00FF00")
        data = pptx_export.render({"name": "t"}, [], brand=brand)
        z = zipfile.ZipFile(io.BytesIO(data))
        theme = z.read("ppt/theme/theme1.xml").decode()
        self.assertIn("FF00FF", theme)
        self.assertIn("00FF00", theme)

    def test_footer_appears_on_each_slide_when_set(self):
        brand = pptx_export.BrandConfig(footer="CONFIDENTIAL — ACME 2026")
        data = pptx_export.render({"name": "t"}, [_f()], brand=brand)
        z = zipfile.ZipFile(io.BytesIO(data))
        for i in range(1, 6):
            s = z.read(f"ppt/slides/slide{i}.xml").decode()
            self.assertIn("CONFIDENTIAL", s)

    def test_empty_footer_not_rendered(self):
        """A blank footer config should produce slides without a footer
        shape — not a hollow text box."""
        data = pptx_export.render({"name": "t"}, [])
        z = zipfile.ZipFile(io.BytesIO(data))
        s1 = z.read("ppt/slides/slide1.xml").decode()
        # Shape id 99 is reserved for the footer; it shouldn't appear
        self.assertNotIn('id="99"', s1)

    def test_brand_is_frozen(self):
        b = pptx_export.BrandConfig()
        with self.assertRaises(Exception):
            b.title_rgb = "modified"


class TestFileOutput(unittest.TestCase):

    def test_render_to_file_writes_pptx(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".pptx", delete=False) as fh:
            path = fh.name
        try:
            size = pptx_export.render_to_file(path, {"name": "t"}, [_f()])
            self.assertGreater(size, 1000)
            self.assertTrue(os.path.getsize(path), size)
            self.assertTrue(zipfile.is_zipfile(path))
        finally:
            os.unlink(path)


class TestEmptyEngagement(unittest.TestCase):

    def test_empty_findings_still_produces_valid_pptx(self):
        data = pptx_export.render({"name": "empty"}, [])
        self.assertTrue(zipfile.is_zipfile(io.BytesIO(data)))

    def test_empty_findings_narrative_placeholder(self):
        data = pptx_export.render({"name": "empty"}, [])
        z = zipfile.ZipFile(io.BytesIO(data))
        s3 = z.read("ppt/slides/slide3.xml").decode()
        self.assertIn("no proven findings", s3)
        s5 = z.read("ppt/slides/slide5.xml").decode()
        self.assertIn("no proven findings to remediate", s5)


if __name__ == "__main__":
    unittest.main()
