#!/usr/bin/env python3
"""Remote service CVE TTPs — genuinely new coverage on top of the
recce-bridge → services.<product> → version_range chain from B5b.

Three TTPs land in this slice:

  * CVE-2021-41773 — Apache 2.4.49 path traversal
  * CVE-2021-42013 — Apache 2.4.49/50 traversal (incomplete-fix bypass)
  * CVE-2024-6387  — OpenSSH pre-auth RCE (regreSSHion)

Zero inlined predecessor for any of these; they're the first pin that
the whole chain works end-to-end for remote-service CVEs the operator
attacks over the network. All three are prepare-only playbook routes
— fieldkit doesn't blind-hit a client's exposed web/ssh service; the
operator runs the check attacker-side after fieldkit surfaces the
version-window match.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class ApacheCVE202141773Test(unittest.TestCase):
    """Apache 2.4.49 path traversal — one specific version window."""

    def _fires_on(self, apache_version):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=LINUX, user="alice", uid=1000,
                       services={"apache": apache_version}),
            "10.0.0.7")
        return any(v.key == "apache_cve:2021-41773" for v in vs)

    def test_fires_on_vulnerable_version(self):
        self.assertTrue(self._fires_on("2.4.49"))

    def test_does_not_fire_on_2450_fix_attempt(self):
        # The 2.4.50 attempt-fix closes 41773 (a different bypass
        # in 2.4.50 lands 42013).
        self.assertFalse(self._fires_on("2.4.50"))

    def test_does_not_fire_on_full_fix(self):
        self.assertFalse(self._fires_on("2.4.51"))
        self.assertFalse(self._fires_on("2.4.62"))

    def test_does_not_fire_on_older_version(self):
        self.assertFalse(self._fires_on("2.4.48"))
        self.assertFalse(self._fires_on("2.4.10"))

    def test_does_not_fire_when_apache_unknown(self):
        # Partial enum → refuse to fire (matches the version_range
        # predicate's "cannot decide, don't match" contract).
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=LINUX, user="alice", uid=1000, services={}),
            "10.0.0.7")
        self.assertFalse(any(v.key == "apache_cve:2021-41773" for v in vs))

    def test_is_prepare_only_playbook_route(self):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=LINUX, user="alice", uid=1000,
                       services={"apache": "2.4.49"}),
            "10.0.0.7")
        v = [x for x in vs if x.key == "apache_cve:2021-41773"][0]
        self.assertTrue(v.manual)
        self.assertIsNotNone(v.playbook)
        self.assertEqual(v.report_type, "path_traversal")


class ApacheCVE202142013Test(unittest.TestCase):
    """Apache 2.4.49/50 double-encoded traversal — wider window (2.4.50
    is ALSO vulnerable because the .50 fix was incomplete)."""

    def _fires_on(self, apache_version):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=LINUX, user="alice", uid=1000,
                       services={"apache": apache_version}),
            "10.0.0.7")
        return any(v.key == "apache_cve:2021-42013" for v in vs)

    def test_fires_on_2449(self):
        self.assertTrue(self._fires_on("2.4.49"))

    def test_fires_on_2450_incomplete_fix(self):
        self.assertTrue(self._fires_on("2.4.50"))

    def test_does_not_fire_on_full_fix(self):
        self.assertFalse(self._fires_on("2.4.51"))
        self.assertFalse(self._fires_on("2.4.62"))

    def test_both_apache_ttps_fire_together_on_2449(self):
        # A 2.4.49 host is inside BOTH windows — the operator sees both
        # routes surfaced and picks whichever is easier attacker-side.
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=LINUX, user="alice", uid=1000,
                       services={"apache": "2.4.49"}),
            "10.0.0.7")
        keys = {v.key for v in vs if v.key.startswith("apache_cve:")}
        self.assertEqual(keys, {"apache_cve:2021-41773", "apache_cve:2021-42013"})

    def test_only_42013_fires_on_2450(self):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=LINUX, user="alice", uid=1000,
                       services={"apache": "2.4.50"}),
            "10.0.0.7")
        keys = {v.key for v in vs if v.key.startswith("apache_cve:")}
        self.assertEqual(keys, {"apache_cve:2021-42013"})


class OpenSSHRegreSSHionTest(unittest.TestCase):
    """CVE-2024-6387 — signal-handler race, only in 8.5p1–9.7p1 (regression
    from a 2006 fix that got reverted). The p-suffix distinguishes
    9.7p1 (vulnerable) from 9.8p1 (fixed) — load-bearing case for the
    _parse_version p-suffix work from B5c."""

    def _fires_on(self, openssh_version):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=LINUX, user="alice", uid=1000,
                       services={"openssh": openssh_version}),
            "10.0.0.7")
        return any(v.key == "openssh_cve:2024-6387" for v in vs)

    def test_fires_in_regression_window(self):
        self.assertTrue(self._fires_on("8.5p1"))
        self.assertTrue(self._fires_on("9.0p1"))
        self.assertTrue(self._fires_on("9.6p1"))
        self.assertTrue(self._fires_on("9.7p1"))

    def test_does_not_fire_on_first_patched(self):
        # 9.8p1 restores the pre-8.5p1 fix.
        self.assertFalse(self._fires_on("9.8p1"))

    def test_does_not_fire_on_pre_regression_versions(self):
        # 4.4p1 was the ORIGINAL fix (CVE-2006-5051). 8.5p1 reverted it.
        # Anything before 8.5p1 is safe.
        self.assertFalse(self._fires_on("4.9p1"))
        self.assertFalse(self._fires_on("8.4p1"))

    def test_ranks_crash_risk(self):
        # Heap corruption can crash sshd children.
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=LINUX, user="alice", uid=1000,
                       services={"openssh": "9.7p1"}),
            "10.0.0.7")
        v = [x for x in vs if x.key == "openssh_cve:2024-6387"][0]
        self.assertEqual(v.safety, "crash-risk")
        self.assertTrue(v.manual)   # not blind-fired against client SSH
        self.assertEqual(v.report_type, "exposed_service_cve")


class ServiceCVEEndToEndTest(unittest.TestCase):
    """Pin the whole chain: recce-bridge ingest → HostFacts.services →
    services.<product> version_range predicate → Vector emission."""

    def test_apache_ingest_to_ttp_emission(self):
        import tempfile
        from fieldkit.hostenum import facts_for, LINUX
        from fieldkit.state import Store
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        with tempfile.TemporaryDirectory() as tmp:
            s = Store.create(os.path.join(tmp, "e.db"))
            s.init_engagement("test")
            hid, _ = s.add_host("10.0.0.11", os_name="linux")
            # Simulate recce ingest — the same shape B5b's test used.
            s.add_service(hid, 80, product="Apache httpd", version="2.4.49")
            facts = facts_for(s, hid)
            self.assertEqual(facts.services.get("apache"), "2.4.49")
            vs = vectors_for(facts, "10.0.0.11")
            apache_cves = {v.key for v in vs
                           if v.key.startswith("apache_cve:")}
            self.assertEqual(apache_cves, {"apache_cve:2021-41773",
                                             "apache_cve:2021-42013"})
            s.close()

    def test_openssh_ingest_to_ttp_emission(self):
        import tempfile
        from fieldkit.hostenum import facts_for, LINUX
        from fieldkit.state import Store
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        with tempfile.TemporaryDirectory() as tmp:
            s = Store.create(os.path.join(tmp, "e.db"))
            s.init_engagement("test")
            hid, _ = s.add_host("10.0.0.11", os_name="linux")
            s.add_service(hid, 22, product="OpenSSH", version="9.6p1")
            facts = facts_for(s, hid)
            self.assertEqual(facts.services.get("openssh"), "9.6p1")
            vs = vectors_for(facts, "10.0.0.11")
            self.assertTrue(any(v.key == "openssh_cve:2024-6387" for v in vs))
            s.close()


if __name__ == "__main__":
    unittest.main()
