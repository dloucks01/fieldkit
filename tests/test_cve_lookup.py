#!/usr/bin/env python3
"""Offline CVE lookup — projects the TTP catalog's version-range rules
into a (component, version) → list[CVE] lookup. Zero network. Zero
external data. The TTP catalog IS the catalog, so a new cve:* TTP
auto-populates here on next import."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import cve_lookup
from fieldkit.hostenum import HostFacts


class TestLookupKernel(unittest.TestCase):

    def test_dirtypipe_in_range(self):
        matches = cve_lookup.lookup("kernel", "5.15.0")
        cves = {m.cve for m in matches}
        self.assertIn("CVE-2022-0847", cves)

    def test_dirtypipe_above_window_misses(self):
        """Dirty Pipe caps at 5.16.11 — kernel 6.11 must NOT match."""
        matches = cve_lookup.lookup("kernel", "6.11.0")
        cves = {m.cve for m in matches}
        self.assertNotIn("CVE-2022-0847", cves)

    def test_cve_2024_26925_in_range(self):
        """Our slice-2 kernel CVE: >=5.14.0, <6.9.0."""
        matches = cve_lookup.lookup("kernel", "5.15.0")
        cves = {m.cve for m in matches}
        self.assertIn("CVE-2024-26925", cves)

    def test_patched_modern_kernel_matches_nothing_kernel(self):
        """A truly post-everything kernel (far above every rule's hi)
        must return an empty list for kernel."""
        matches = cve_lookup.lookup("kernel", "9.99.99")
        self.assertEqual(matches, [])


class TestLookupSudo(unittest.TestCase):

    def test_baronsamedit_in_range(self):
        """CVE-2021-3156, hi=1.9.5p1 — 1.8.31 fires."""
        matches = cve_lookup.lookup("sudo_version", "1.8.31")
        cves = {m.cve for m in matches}
        self.assertIn("CVE-2021-3156", cves)

    def test_patched_sudo_misses(self):
        matches = cve_lookup.lookup("sudo_version", "1.9.15")
        self.assertEqual(matches, [])


class TestLookupPkexec(unittest.TestCase):

    def test_polkit_v109_in_window(self):
        matches = cve_lookup.lookup("pkexec_version", "0.115")
        cves = {m.cve for m in matches}
        self.assertIn("CVE-2021-3560", cves)

    def test_modern_polkit_misses(self):
        matches = cve_lookup.lookup("pkexec_version", "0.125")
        self.assertEqual(matches, [])


class TestLookupFacts(unittest.TestCase):

    def test_combines_every_versioned_attribute(self):
        f = HostFacts(os="linux", user="alice", uid=1000,
                      kernel="5.15.0", sudo_version="1.8.31",
                      pkexec_version="0.115")
        matches = cve_lookup.lookup_facts(f)
        cves = {m.cve for m in matches}
        self.assertIn("CVE-2022-0847", cves)
        self.assertIn("CVE-2021-3156", cves)
        self.assertIn("CVE-2021-3560", cves)

    def test_empty_facts_returns_nothing(self):
        f = HostFacts(os="linux", user="alice", uid=1000)
        self.assertEqual(cve_lookup.lookup_facts(f), [])


class TestLookupShapes(unittest.TestCase):

    def test_unknown_component_returns_empty(self):
        self.assertEqual(cve_lookup.lookup("totally_fake", "1.0"), [])

    def test_unparseable_version_returns_empty(self):
        self.assertEqual(cve_lookup.lookup("kernel", "not-a-version"), [])

    def test_match_is_frozen(self):
        m = cve_lookup.CVEMatch(cve="CVE-2022-0847", name="x",
                                 component="kernel", range_spec=">=1,<2",
                                 ttp_key="cve:x")
        with self.assertRaises(Exception):
            m.cve = "modified"

    def test_catalog_cached_across_calls(self):
        """Repeated calls should re-use the parsed catalog — not re-scan
        the TTP YAML tree each time."""
        cve_lookup._reset_cache_for_tests()
        cat1 = cve_lookup._catalog()
        cat2 = cve_lookup._catalog()
        self.assertIs(cat1, cat2)


if __name__ == "__main__":
    unittest.main()
