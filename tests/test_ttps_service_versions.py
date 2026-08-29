#!/usr/bin/env python3
"""Service versions in HostFacts + dotted-path version_range predicate.

The recce bridge already ingests per-host per-port product+version rows into
the `service` table. This ties that data to the TTP layer:

  * `facts_for` now folds service rows into `facts.services` (product → version)
  * `version_range` predicate accepts dotted paths like `services.apache`
  * `_canon_product` normalizes recce/nmap service names into a single-word
    key so TTPs can match on `apache` regardless of whether recce called it
    "Apache httpd", "Apache/2.4.49" or bare "apache"

Also pins the CVE-2019-14287 (sudo negative-UID bypass) TTP that ships with
this — first TTP to use the existing `sudo_version` field via version_range.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class CanonProductTest(unittest.TestCase):
    """Normalization from recce/nmap product strings to TTP-matchable keys."""

    def _cases(self):
        return [
            # Vendor prefix must be skipped ("Microsoft" isn't the product).
            ("Microsoft IIS httpd", "iis"),
            ("Microsoft SQL Server", "sql"),
            # Vendor-adjacent tokens that ARE product names must survive
            # (Apache is the product for httpd, not a vendor).
            ("Apache httpd", "apache"),
            ("Apache Tomcat", "apache"),
            # Single-word products pass through.
            ("nginx", "nginx"),
            ("OpenSSH", "openssh"),
            ("MySQL", "mysql"),
            # Generic-only strings collapse to empty.
            ("httpd", ""),
            ("service", ""),
            ("", ""),
            (None, ""),
        ]

    def test_all_canon_cases(self):
        from fieldkit.hostenum import _canon_product
        for name, expected in self._cases():
            with self.subTest(name=name):
                self.assertEqual(_canon_product(name), expected)


class FactsForServicePopulationTest(unittest.TestCase):
    """`facts_for` reads the service table and populates facts.services."""

    def _make_store(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        from fieldkit.state import Store
        db = os.path.join(tmp.name, "e.db")
        s = Store.create(db)
        s.init_engagement("test")
        self.addCleanup(s.close)
        return s

    def test_multiple_services_flow_into_facts(self):
        from fieldkit.hostenum import facts_for
        s = self._make_store()
        hid, _ = s.add_host("10.0.0.11", os_name="linux")
        s.add_service(hid, 80, product="Apache httpd", version="2.4.49")
        s.add_service(hid, 22, product="OpenSSH", version="8.1p1")
        s.add_service(hid, 443, product="nginx", version="1.18.0")
        facts = facts_for(s, hid)
        self.assertEqual(facts.services["apache"],  "2.4.49")
        self.assertEqual(facts.services["openssh"], "8.1p1")
        self.assertEqual(facts.services["nginx"],   "1.18.0")

    def test_missing_version_or_product_is_skipped(self):
        # A service row with no version, or no recognizable product, must
        # not create a facts.services entry with garbage.
        from fieldkit.hostenum import facts_for
        s = self._make_store()
        hid, _ = s.add_host("10.0.0.11", os_name="linux")
        s.add_service(hid, 80, product="Apache httpd", version="")     # no version
        s.add_service(hid, 22, product="", version="8.1p1")            # no product
        s.add_service(hid, 8080, product="httpd", version="1.0")       # generic only
        facts = facts_for(s, hid)
        self.assertEqual(facts.services, {})

    def test_first_version_wins_for_same_product_on_multiple_ports(self):
        # Same product on multiple ports usually reports the same version.
        # setdefault preserves the first — this is the honest choice; a
        # discrepancy would be a discovery finding, not a TTP-predicate concern.
        from fieldkit.hostenum import facts_for
        s = self._make_store()
        hid, _ = s.add_host("10.0.0.11", os_name="linux")
        s.add_service(hid, 80, product="Apache httpd", version="2.4.49")
        s.add_service(hid, 443, product="Apache httpd", version="2.4.49")
        facts = facts_for(s, hid)
        self.assertEqual(facts.services["apache"], "2.4.49")


class DottedPathVersionRangeTest(unittest.TestCase):
    """`version_range` predicate now accepts dotted paths so `services.apache`
    reads facts.services['apache'] instead of facts.apache."""

    def _facts(self, **kw):
        from fieldkit.hostenum import HostFacts, LINUX
        base = dict(os=LINUX, user="alice", uid=1000)
        base.update(kw)
        return HostFacts(**base)

    def test_dotted_path_reads_services_dict(self):
        from fieldkit.ttps.adapter import _p_version_range
        facts = self._facts(services={"apache": "2.4.49"})
        matched, _ = _p_version_range(facts, {"services.apache": "==2.4.49"})
        self.assertTrue(matched)

    def test_dotted_path_range_boundary(self):
        # Apache 2.4.49 = vulnerable to CVE-2021-41773; 2.4.50 patched.
        from fieldkit.ttps.adapter import _p_version_range
        spec = {"services.apache": ">=2.4.49,<2.4.50"}
        self.assertTrue(_p_version_range(self._facts(services={"apache": "2.4.49"}),
                                          spec)[0])
        self.assertFalse(_p_version_range(self._facts(services={"apache": "2.4.50"}),
                                           spec)[0])

    def test_dotted_path_missing_service_declines(self):
        # If the host doesn't have the product recorded, refuse to match —
        # firing a CVE claim on a host we can't verify would be dishonest.
        from fieldkit.ttps.adapter import _p_version_range
        facts = self._facts(services={"nginx": "1.18.0"})
        matched, _ = _p_version_range(facts, {"services.apache": ">=1.0"})
        self.assertFalse(matched)

    def test_top_level_field_still_works(self):
        # Non-dotted paths must keep working (backward compat with all the
        # kernel/sudo/pkexec/glibc TTPs shipped in the previous slice).
        from fieldkit.ttps.adapter import _p_version_range
        facts = self._facts(kernel="5.15.0")
        self.assertTrue(_p_version_range(facts, {"kernel": ">=5.0"})[0])


class CVE201914287SudoTest(unittest.TestCase):
    """The shipped CVE-2019-14287 (sudo -u#-1 runas bypass) TTP."""

    def _fires_on(self, sudo_version):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=LINUX, user="alice", uid=1000, sudo_version=sudo_version),
            "10.0.0.7")
        return any(v.key == "sudo_cve:2019-14287" for v in vs)

    def test_fires_before_fix(self):
        self.assertTrue(self._fires_on("1.8.20"))
        self.assertTrue(self._fires_on("1.8.27"))
        self.assertTrue(self._fires_on("1.8.10"))

    def test_does_not_fire_at_first_patched(self):
        self.assertFalse(self._fires_on("1.8.28"))

    def test_does_not_fire_on_modern(self):
        self.assertFalse(self._fires_on("1.9.5p1"))

    def test_does_not_fire_when_sudo_version_unknown(self):
        # Partial enum — don't fabricate a CVE claim.
        self.assertFalse(self._fires_on(None))


class RecceBridgeToServiceCVETest(unittest.TestCase):
    """End-to-end: recce-bridge ingest → facts.services → version_range TTP.

    Pins that the whole chain works: recce hands us service versions, they
    flow into HostFacts, and a version_range TTP with a dotted path can
    read them.
    """

    def test_apache_version_flows_from_bridge_ingest_to_predicate(self):
        import tempfile
        from fieldkit.hostenum import facts_for
        from fieldkit.state import Store
        from fieldkit.ttps.adapter import _p_version_range
        with tempfile.TemporaryDirectory() as tmp:
            s = Store.create(os.path.join(tmp, "e.db"))
            s.init_engagement("test")
            hid, _ = s.add_host("10.0.0.11", os_name="linux")
            # Simulate what recce-bridge ingest does: product + version.
            s.add_service(hid, 80, product="Apache httpd", version="2.4.49")
            facts = facts_for(s, hid)
            self.assertEqual(facts.services.get("apache"), "2.4.49")
            # A hypothetical CVE-gated TTP predicate matches this fact.
            matched, _ = _p_version_range(
                facts, {"services.apache": ">=2.4.49,<2.4.50"})
            self.assertTrue(matched)
            s.close()


if __name__ == "__main__":
    unittest.main()
