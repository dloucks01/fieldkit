#!/usr/bin/env python3
"""The opportunity KB — detect predicates fire only on proven state, and rank right.

analyze must never invent a move: each opportunity is backed by an access/credential
row. Pinned here are which predicates fire for a given board, that looting a host
removes it from the "unlooted" set, and that the three-axis score floats the
high-impact moves above a foothold that still needs a local exploit.

Run:  python3 -m unittest discover -s tests
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit.creds import Credential  # noqa: E402
from fieldkit.kb import Opportunity, analyze  # noqa: E402
from fieldkit.state import Store  # noqa: E402

NT = "31d6cfe0d16ae931b73c59d7e0c089c0"


class KbTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME")
        s = self.store
        self.dc, _ = s.add_host("10.0.0.6", hostname="DC01", is_dc=True, os_name="windows")
        self.ws2, _ = s.add_host("10.0.0.7", hostname="WS02", os_name="windows")
        self.ws3, _ = s.add_host("10.0.0.8", hostname="WS03", os_name="linux")
        # jdoe: domain admin on the DC and WS02 (reuse + takeover + unlooted)
        self.jdoe, _ = s.add_credential(Credential("jdoe", "Winter2025!", domain="corp"))
        s.add_access(self.dc, self.jdoe, "smb", admin=True)
        s.add_access(self.ws2, self.jdoe, "smb", admin=True)
        # a recovered local admin hash (pass-the-hash)
        self.la, _ = s.add_credential(
            Credential("Administrator", NT, secret_type="nt", local_auth=True), source="sam")
        s.add_access(self.ws2, self.la, "smb", admin=True)
        # svc: a non-admin foothold on the Linux host
        self.svc, _ = s.add_credential(Credential("svc", "s3cret", domain="corp"))
        s.add_access(self.ws3, self.svc, "ssh", admin=False)

    def keys(self):
        return [o.key for o in analyze(self.store)]


class PredicateTest(KbTestCase):
    def test_all_expected_predicates_fire(self):
        self.assertEqual(
            set(self.keys()),
            {"dc-takeover", "password-reuse", "pth-local-admin",
             "loot-admin-host", "foothold-enum"})

    def test_dc_takeover_points_at_the_dc(self):
        opp = [o for o in analyze(self.store) if o.key == "dc-takeover"][0]
        self.assertEqual(opp.host, "10.0.0.6")
        self.assertIn("ntds", opp.next_step.lower())

    def test_password_reuse_counts_hosts(self):
        opp = [o for o in analyze(self.store) if o.key == "password-reuse"][0]
        self.assertIn("2 hosts", opp.title)
        self.assertEqual(opp.exploitability, "high")  # has admin hits

    def test_foothold_names_the_right_privesc_module(self):
        opp = [o for o in analyze(self.store) if o.key == "foothold-enum"][0]
        self.assertEqual(opp.host, "10.0.0.8")
        self.assertIn("linpriv", opp.next_step)  # linux host

    def test_looting_a_host_drops_it_from_unlooted(self):
        before = [o for o in analyze(self.store) if o.key == "loot-admin-host"]
        self.assertEqual({o.host for o in before}, {"10.0.0.6", "10.0.0.7"})
        self.store.add_loot(self.dc, "ntds_hash", value="krbtgt:502:...")
        after = [o for o in analyze(self.store) if o.key == "loot-admin-host"]
        self.assertEqual({o.host for o in after}, {"10.0.0.7"})


class RankingTest(KbTestCase):
    def test_foothold_ranks_last(self):
        opps = analyze(self.store)
        self.assertEqual(opps[-1].key, "foothold-enum")

    def test_high_impact_beats_medium(self):
        opps = analyze(self.store)
        foothold = next(o for o in opps if o.key == "foothold-enum")
        for o in opps:
            if o.key != "foothold-enum":
                self.assertGreater(o.score, foothold.score)

    def test_score_prefers_quiet_over_loud_within_a_tier(self):
        quiet = Opportunity("a", "t", "high", "read-only", "quiet", "n")
        loud = Opportunity("b", "t", "high", "read-only", "loud", "n")
        self.assertGreater(quiet.score, loud.score)

    def test_safety_outranks_detection(self):
        safe_loud = Opportunity("a", "t", "high", "read-only", "loud", "n")
        risky_quiet = Opportunity("b", "t", "high", "crash-risk", "quiet", "n")
        self.assertGreater(safe_loud.score, risky_quiet.score)


class EmptyTest(unittest.TestCase):
    def test_no_access_no_opportunities(self):
        with tempfile.TemporaryDirectory() as d:
            store = Store.create(os.path.join(d, "e.db"))
            store.init_engagement("ACME")
            store.add_host("10.0.0.5")
            self.assertEqual(analyze(store), [])
            store.close()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
