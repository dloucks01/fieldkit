#!/usr/bin/env python3
"""Report TTP cross-references — findings cite matching TTPs (C9 slice 3).

Each finding in the report gets a `related_ttps` list — the shipped
TTP keys whose `report.vector_type` matches the finding's
`vector_type`. Rendered as a "See also — fieldkit TTP catalog"
section under each finding + observation. Empty (no output) when
the vector_type doesn't match any shipped TTP.

Test pins:

  * build() attaches related_ttps to every finding based on the
    shipped TTP catalog;
  * findings with an unrelated vector_type get an empty list (not
    a crash);
  * _collect_ttp_index degrades gracefully on catalog load failure
    (empty dict, no crash);
  * _render_related_ttps renders nothing when empty;
  * _render_related_ttps renders the See-also section when
    populated;
  * end-to-end: a finding with vector_type=exposed_service_cve
    renders with several service-CVE TTP citations under its
    remediation block.
"""
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _make_store(test_case):
    tmp = tempfile.TemporaryDirectory()
    test_case.addCleanup(tmp.cleanup)
    from fieldkit.state import Store
    s = Store.create(os.path.join(tmp.name, "e.db"))
    s.init_engagement("test-citations")
    test_case.addCleanup(s.close)
    return s


class CollectTTPIndexTest(unittest.TestCase):

    def test_returns_dict_keyed_by_vector_type(self):
        from fieldkit.report import _collect_ttp_index
        idx = _collect_ttp_index()
        # Every shipped TTP has SOME vector_type — the index shouldn't
        # be empty on a healthy repo.
        self.assertGreater(len(idx), 0)
        # A concrete key we know ships (from C-arc slices).
        self.assertIn("exposed_service_cve", idx)
        # And it maps to multiple TTP keys (multiple service-CVEs
        # ported across the C-arc).
        self.assertGreater(len(idx["exposed_service_cve"]), 5)

    def test_degrades_gracefully_on_loader_exception(self):
        from fieldkit.report import _collect_ttp_index
        from fieldkit.ttps import loader as ttp_loader
        with patch.object(ttp_loader, "load_all",
                    side_effect=RuntimeError("simulated schema mismatch")):
            idx = _collect_ttp_index()
        self.assertEqual(idx, {})


class BuildAttachesRelatedTTPsTest(unittest.TestCase):

    def test_findings_get_related_ttps_from_catalog(self):
        from fieldkit.report import build
        s = _make_store(self)
        # Add a host + proven finding with a shipped vector_type.
        hid, _ = s.add_host("10.0.0.1", os_name="linux",
                            hostname="test01")
        s.add_finding(vector_type="exposed_service_cve",
                       title="CVE-2023-46604 exploitable",
                       host_id=hid, evidence="",
                       proven=True)
        _, findings = build(s, {})
        self.assertEqual(len(findings), 1)
        related = findings[0].get("related_ttps") or []
        self.assertTrue(related)
        # Every returned key should look like a service_cve:* key
        # (that's what maps to exposed_service_cve in the shipped
        # catalog).
        self.assertTrue(any("service_cve" in k for k in related))

    def test_unrelated_vector_type_gets_empty_list(self):
        from fieldkit.report import build
        s = _make_store(self)
        hid, _ = s.add_host("10.0.0.1", os_name="linux")
        s.add_finding(vector_type="totally_made_up_vector_type",
                       title="fake finding", host_id=hid,
                       evidence="", proven=True)
        _, findings = build(s, {})
        self.assertEqual(findings[0].get("related_ttps"), [])


class RenderRelatedTTPsTest(unittest.TestCase):

    def test_empty_related_renders_nothing(self):
        from fieldkit.report import _render_related_ttps
        L = []
        _render_related_ttps(L.append, {"related_ttps": []})
        self.assertEqual(L, [])
        # Also handle the missing-key case (older serialized findings).
        _render_related_ttps(L.append, {})
        self.assertEqual(L, [])

    def test_populated_related_renders_see_also_section(self):
        from fieldkit.report import _render_related_ttps
        L = []
        finding = {"related_ttps": ["service_cve:2023-46604",
                                     "service_cve:2024-3400"]}
        _render_related_ttps(L.append, finding)
        output = "\n".join(L)
        self.assertIn("### See also", output)
        self.assertIn("`service_cve:2023-46604`", output)
        self.assertIn("`service_cve:2024-3400`", output)


class FullReportIntegrationTest(unittest.TestCase):

    def test_finding_renders_with_see_also_citation(self):
        from fieldkit.report import build, render_markdown
        s = _make_store(self)
        hid, _ = s.add_host("10.0.0.1", os_name="linux",
                            hostname="test01")
        s.add_finding(vector_type="exposed_service_cve",
                       title="RCE on Confluence",
                       host_id=hid, evidence="body",
                       proven=True)
        engagement, findings = build(s, {})
        md = render_markdown(engagement, findings)
        self.assertIn("### See also — fieldkit TTP catalog", md)
        self.assertIn("`service_cve:", md)

    def test_finding_without_related_ttps_omits_section(self):
        # A finding with a fabricated vector_type keeps a clean
        # report — the See-also section stays absent.
        from fieldkit.report import build, render_markdown
        s = _make_store(self)
        hid, _ = s.add_host("10.0.0.1", os_name="linux")
        s.add_finding(vector_type="totally_made_up",
                       title="fake finding", host_id=hid,
                       evidence="body", proven=True)
        engagement, findings = build(s, {})
        md = render_markdown(engagement, findings)
        self.assertNotIn("### See also", md)


if __name__ == "__main__":
    unittest.main()
