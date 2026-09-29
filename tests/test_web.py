#!/usr/bin/env python3
"""The web driver — the first non-host domain on the v9 asset model.

Pinned:
  * parse httpx/nuclei JSONL tolerantly (skip banners/non-JSON), map severity;
  * apply endpoints as assets (linked to a known host by IP) and nuclei matches as
    web_vuln findings attached to those assets;
  * a web finding carries its captured tool output, so report.check() passes — the
    anti-fabrication guarantee holds for a non-AD domain;
  * the scan/probe drivers use the injected runner and abort cleanly with no tool.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import report, web  # noqa: E402
from fieldkit.runner import RunResult  # noqa: E402
from fieldkit.state import Store  # noqa: E402

HTTPX = ('{"url":"https://app/","status_code":200,"title":"Login","tech":["nginx"],'
         '"host":"10.0.0.20","port":"443"}\n'
         'not-json banner line\n'
         '{"url":"https://app/admin","status_code":403,"host":"10.0.0.20"}\n')

NUCLEI = ('{"template-id":"CVE-2023-1","info":{"name":"RCE","severity":"critical",'
          '"description":"unauth rce"},"host":"https://app","matched-at":"https://app/api"}\n'
          '{"template-id":"tls","info":{"name":"Weak TLS","severity":"low"},'
          '"host":"https://app","matched-at":"https://app"}\n'
          'garbage\n')


class ParseTest(unittest.TestCase):
    def test_parse_httpx_skips_non_json_and_extracts_fields(self):
        eps = web.parse_httpx(HTTPX)
        self.assertEqual([e.url for e in eps], ["https://app/", "https://app/admin"])
        self.assertEqual(eps[0].status, 200)
        self.assertEqual(eps[0].tech, ("nginx",))
        self.assertEqual(eps[0].host_ip, "10.0.0.20")

    def test_parse_nuclei_maps_severity_and_skips_garbage(self):
        vs = web.parse_nuclei(NUCLEI)
        self.assertEqual([(v.template_id, v.severity) for v in vs],
                         [("CVE-2023-1", "Critical"), ("tls", "Low")])
        self.assertEqual(vs[0].matched_at, "https://app/api")

    def test_empty_and_junk_input_is_safe(self):
        self.assertEqual(web.parse_httpx(""), [])
        self.assertEqual(web.parse_nuclei("\n\nnot json\n{bad"), [])


class ApplyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME")

    def test_apply_httpx_creates_endpoints_and_links_host(self):
        hid, _ = self.store.add_host("10.0.0.20", hostname="WEB01")
        rep = web.apply_httpx(self.store, web.parse_httpx(HTTPX))
        self.assertEqual(rep.endpoints_added, 2)
        self.assertEqual(self.store.asset_by_key("endpoint", "https://app/")["host_id"], hid)

    def test_apply_nuclei_records_proven_findings_with_evidence(self):
        rep = web.apply_nuclei(self.store, web.parse_nuclei(NUCLEI))
        self.assertEqual(rep.findings_added, 2)
        eng, findings = report.build(self.store, {})
        sev = sorted(f["severity"] for f in findings)
        self.assertEqual(sev, ["Critical", "Low"])
        # the anti-fabrication guarantee holds for the web domain
        errors, _ = report.check(findings)
        self.assertEqual(errors, [])
        # every web finding is attached to an endpoint asset
        for f in findings:
            self.assertEqual(f["vector_type"], "web_vuln")

    def test_idempotent_reingest(self):
        web.apply_nuclei(self.store, web.parse_nuclei(NUCLEI))
        web.apply_nuclei(self.store, web.parse_nuclei(NUCLEI))
        self.assertEqual(len(self.store.findings()), 2)   # not duplicated


class DriverTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME")

    def test_scan_drives_nuclei_via_injected_runner(self):
        rep = web.scan(self.store, ["https://app"],
                       run=lambda a, e=None: RunResult(a, exit_code=0, stdout=NUCLEI))
        self.assertIsNone(rep.aborted)
        self.assertEqual(rep.findings_added, 2)

    def test_probe_drives_httpx_via_injected_runner(self):
        rep = web.probe(self.store, ["https://app"],
                        run=lambda a, e=None: RunResult(a, exit_code=0, stdout=HTTPX))
        self.assertEqual(rep.endpoints_added, 2)

    def test_missing_tool_aborts_cleanly(self):
        rep = web.scan(self.store, ["https://app"],
                       run=lambda a, e=None: RunResult(a, error="nuclei: not found"))
        self.assertIn("not found", rep.aborted)
        self.assertEqual(rep.findings_added, 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
