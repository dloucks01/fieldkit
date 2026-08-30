#!/usr/bin/env python3
"""Recent-CVE TTPs — new coverage via services.<product> version_range.

Ships 4 real high-impact CVEs the operator is likely to encounter in
2024-2025 engagements:

  * CVE-2023-46604 — Apache ActiveMQ OpenWire → unauth RCE
  * CVE-2023-22515 — Confluence Data Center → unauth admin creation
  * CVE-2024-3400  — PAN-OS GlobalProtect → root RCE (actively exploited zero-day)
  * CVE-2023-50164 — Apache Struts file upload → RCE

Prerequisite refinement: extended _canon_product to prefer the LAST
non-vendor non-generic token when multiple candidates exist. This
lets "Apache ActiveMQ" → activemq (previously "apache"), "Apache
Struts" → struts, "Atlassian Confluence" → confluence — CVE
matching now uses product-specific keys instead of collapsing to
the shared vendor prefix.

All 4 use existing version_range predicate + services.<product>
recce-bridge fact. All are prepare-only playbook routes — fieldkit
doesn't blind-hit exposed services on client hosts.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class CanonProductRefinementTest(unittest.TestCase):
    """The load-bearing predicate change: canon now prefers the last
    non-vendor non-generic token when the string is compound. This is
    what makes services.activemq / services.struts / services.tomcat
    exist as distinct facts."""

    def test_apache_httpd_still_maps_to_apache(self):
        # Preserved: bare Apache (httpd generic-filtered) → apache.
        # The existing httpd CVEs (41773, 42013) still work.
        from fieldkit.hostenum import _canon_product
        self.assertEqual(_canon_product("Apache httpd"), "apache")
        self.assertEqual(_canon_product("apache"), "apache")

    def test_compound_apache_products_map_to_product_name(self):
        # NEW behavior: last non-vendor non-generic token wins.
        from fieldkit.hostenum import _canon_product
        self.assertEqual(_canon_product("Apache Tomcat"), "tomcat")
        self.assertEqual(_canon_product("Apache ActiveMQ"), "activemq")
        self.assertEqual(_canon_product("Apache Struts"), "struts")

    def test_atlassian_and_palo_alto_composite_vendors(self):
        from fieldkit.hostenum import _canon_product
        self.assertEqual(_canon_product("Atlassian Confluence"), "confluence")
        self.assertEqual(_canon_product("Palo Alto Networks PAN-OS"), "pan-os")

    def test_microsoft_vendor_still_stripped(self):
        # Preserved: Microsoft prefix still skipped.
        from fieldkit.hostenum import _canon_product
        self.assertEqual(_canon_product("Microsoft IIS httpd"), "iis")
        self.assertEqual(_canon_product("Microsoft SQL Server"), "sql")


class ActiveMQCVE202346604Test(unittest.TestCase):

    def _fires_on(self, version):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=LINUX, user="alice", uid=1000,
                       services={"activemq": version}),
            "10.0.0.7")
        return any(v.key == "service_cve:2023-46604" for v in vs)

    def test_fires_across_58_window(self):
        # Vulnerable range 5.15.0-5.18.2 covers the whole 5.15-5.18
        # LTS series.
        self.assertTrue(self._fires_on("5.15.0"))
        self.assertTrue(self._fires_on("5.16.5"))
        self.assertTrue(self._fires_on("5.17.4"))
        self.assertTrue(self._fires_on("5.18.2"))

    def test_does_not_fire_on_first_patched(self):
        # 5.18.3 is the first patched in the 5.18 branch.
        self.assertFalse(self._fires_on("5.18.3"))
        self.assertFalse(self._fires_on("5.19.0"))

    def test_does_not_fire_on_pre_vulnerable_versions(self):
        self.assertFalse(self._fires_on("5.14.5"))

    def test_is_prepare_only(self):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(HostFacts(os=LINUX, user="alice", uid=1000,
                                       services={"activemq": "5.16.5"}),
                          "10.0.0.7")
        v = [x for x in vs if x.key == "service_cve:2023-46604"][0]
        self.assertTrue(v.manual)
        self.assertEqual(v.report_type, "exposed_service_cve")


class ConfluenceCVE202322515Test(unittest.TestCase):

    def _fires_on(self, version):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=LINUX, user="alice", uid=1000,
                       services={"confluence": version}),
            "10.0.0.7")
        return any(v.key == "service_cve:2023-22515" for v in vs)

    def test_fires_in_window(self):
        self.assertTrue(self._fires_on("8.0.0"))
        self.assertTrue(self._fires_on("8.2.4"))
        self.assertTrue(self._fires_on("8.5.1"))

    def test_does_not_fire_on_patched_versions(self):
        self.assertFalse(self._fires_on("8.5.2"))
        self.assertFalse(self._fires_on("8.7.0"))

    def test_does_not_fire_on_pre_8_versions(self):
        # 7.x uses a different setup flow; the CVE only affects 8.0+.
        self.assertFalse(self._fires_on("7.19.5"))


class PANOSCVE20243400Test(unittest.TestCase):

    def _fires_on(self, version):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=LINUX, user="alice", uid=1000,
                       services={"pan-os": version}),
            "10.0.0.7")
        return any(v.key == "service_cve:2024-3400" for v in vs)

    def test_fires_in_window(self):
        # 10.2.0 - 11.1.2 all vulnerable pending version-specific hotfixes.
        self.assertTrue(self._fires_on("10.2.0"))
        self.assertTrue(self._fires_on("10.2.8"))
        self.assertTrue(self._fires_on("11.0.3"))
        self.assertTrue(self._fires_on("11.1.2"))

    def test_does_not_fire_on_patched_versions(self):
        self.assertFalse(self._fires_on("11.1.3"))
        self.assertFalse(self._fires_on("11.2.0"))

    def test_does_not_fire_on_pre_vulnerable_versions(self):
        # PAN-OS 9.x + 10.0/10.1 aren't in the vulnerable range.
        self.assertFalse(self._fires_on("9.1.15"))
        self.assertFalse(self._fires_on("10.1.11"))


class StrutsCVE202350164Test(unittest.TestCase):
    """Struts 6.x branch only in this TTP (see docstring in the YAML —
    2.5.x needs an OR-predicate that the schema doesn't have yet).
    2.5.34+ hosts don't false-positive."""

    def _fires_on(self, version):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=LINUX, user="alice", uid=1000,
                       services={"struts": version}),
            "10.0.0.7")
        return any(v.key == "service_cve:2023-50164" for v in vs)

    def test_fires_in_6_x_window(self):
        self.assertTrue(self._fires_on("6.0.0"))
        self.assertTrue(self._fires_on("6.2.0"))
        self.assertTrue(self._fires_on("6.3.0"))

    def test_does_not_fire_on_first_patched(self):
        # 6.3.0.2 is the fix; version parser truncates the .2 suffix
        # so we test both 6.3.1 (unambiguously above) and 6.4.0.
        self.assertFalse(self._fires_on("6.3.1"))
        self.assertFalse(self._fires_on("6.4.0"))

    def test_does_not_fire_on_2_5_branch(self):
        # Deliberate under-coverage — the 2.5 branch has its own
        # fix at 2.5.33; without an OR-predicate we skip that
        # branch entirely rather than false-positive on 2.5.34+.
        self.assertFalse(self._fires_on("2.5.30"))
        self.assertFalse(self._fires_on("2.5.34"))


class ServiceCVETTPCoverageTest(unittest.TestCase):
    """Sanity check on the whole recent-CVE family."""

    def _load(self):
        from fieldkit.ttps.loader import load_all
        return [t for t in load_all()
                if t.key.startswith("service_cve:")]

    def test_all_report_under_exposed_service_cve(self):
        for t in self._load():
            with self.subTest(key=t.key):
                self.assertEqual(t.report.vector_type,
                                  "exposed_service_cve")

    def test_all_are_prepare_only_playbook_routes(self):
        # Every service-CVE TTP surfaces a manual step (playbook);
        # fieldkit doesn't blind-hit exposed services on client hosts.
        for t in self._load():
            with self.subTest(key=t.key):
                self.assertIsNotNone(t.playbook)

    def test_the_four_new_cves_all_shipped(self):
        keys = {t.key for t in self._load()}
        for cve_key in ("service_cve:2023-46604",
                         "service_cve:2023-22515",
                         "service_cve:2024-3400",
                         "service_cve:2023-50164"):
            with self.subTest(cve=cve_key):
                self.assertIn(cve_key, keys)


if __name__ == "__main__":
    unittest.main()
