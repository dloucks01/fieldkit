#!/usr/bin/env python3
"""The external-exploit loop — match discovered services against the CVE TTP library.

Pinned:
  * only version_range-on-services TTPs are selected (not on-host kernel/glibc LPE);
  * nmap product strings map to the right services.<key>;
  * a service in a CVE's vulnerable window matches (regardless of host OS, since the
    service's presence implies its platform); a patched version does not;
  * apply() records unproven `exposed_service_cve` observations that flow through the
    report as observations (report.check does not flag them as fabrication);
  * matching is idempotent.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import external, report  # noqa: E402
from fieldkit.state import Store  # noqa: E402


class ExternalTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("EXT")

    def _svc(self, ip, port, product, version, os_name=None):
        hid, _ = self.store.add_host(ip, os_name=os_name)
        self.store.add_service(hid, port, product=product, version=version)
        return hid


class LibraryTest(ExternalTestCase):
    def test_only_service_version_ttps_are_selected(self):
        ttps = external._service_cve_ttps()
        self.assertGreater(len(ttps), 10)
        for t in ttps:
            self.assertEqual(t.detect.kind, "version_range")
            for field_name in t.detect.value:
                self.assertTrue(str(field_name).startswith("services."))

    def test_product_keyword_mapping(self):
        keys = external._referenced_keys(external._service_cve_ttps())
        rows = [{"product": "Microsoft Exchange", "version": "15.1.2044", "banner": ""},
                {"product": "Apache httpd", "version": "2.4.49", "banner": ""},
                {"product": "OpenSSH", "version": "9.0", "banner": ""}]
        mapped = external._service_versions(rows, keys)
        self.assertEqual(mapped.get("exchange"), "15.1.2044")
        self.assertEqual(mapped.get("apache"), "2.4.49")
        self.assertEqual(mapped.get("openssh"), "9.0")


class MatchTest(ExternalTestCase):
    def test_vulnerable_service_matches_regardless_of_host_os(self):
        # Exchange (windows TTP) on an OS-unknown host still matches — the service's
        # presence implies its platform.
        self._svc("10.0.0.50", 443, "Microsoft Exchange", "15.1.2044", os_name=None)
        titles = [v.title for _h, v in external.match(self.store)]
        self.assertTrue(any("ProxyShell" in t for t in titles))

    def test_patched_version_does_not_match(self):
        self._svc("10.0.0.52", 443, "Microsoft Exchange", "15.2.9999")
        self.assertEqual(external.match(self.store), [])

    def test_no_services_no_matches(self):
        self.store.add_host("10.0.0.9")   # host, no services
        self.assertEqual(external.match(self.store), [])


class ApplyTest(ExternalTestCase):
    def setUp(self):
        super().setUp()
        self._svc("10.0.0.50", 443, "Microsoft Exchange", "15.1.2044")
        self._svc("10.0.0.51", 80, "Apache httpd", "2.4.49")

    def test_records_unproven_observations_that_pass_check(self):
        rep = external.apply(self.store)
        self.assertGreaterEqual(rep.findings_added, 3)
        eng, findings = report.build(self.store, {}, proven_only=False)
        self.assertTrue(findings)
        for f in findings:
            self.assertFalse(f["proven"])           # observations, not proven claims
            self.assertIn(f["vector_type"], ("exposed_service_cve", "path_traversal"))
        errors, _ = report.check(findings)
        self.assertEqual(errors, [])                # observations aren't fabrication

    def test_idempotent(self):
        external.apply(self.store)
        n1 = len(self.store.findings())
        external.apply(self.store)
        self.assertEqual(len(self.store.findings()), n1)   # no duplicate findings


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
