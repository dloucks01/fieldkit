#!/usr/bin/env python3
"""AD-escalation adroute TTPs — BloodHound-adjacent, playbook-driven.

Extends the C4 AD-visibility slice with 4 escalation-side routes.
Each surfaces a specific BloodHound edge type as a ranked next-move
with an inline Cypher query + exec one-liner. Gated on group_member:
Domain Users (any authenticated domain foothold).

Routes:

  * adroute:generic-all-user      T1078.002 — force password reset
  * adroute:writeowner-group      T1222.001 — SetOwner → WriteDACL → self-add
  * adroute:readlaps-password     T1555.005 — cleartext local admin
  * adroute:shadow-credentials    T1098     — msDS-KeyCredentialLink write → PKINIT

All ranked to reflect operational value:
  * readlaps         — high/read-only/quiet  (loud primitive; quiet exec)
  * shadow-creds     — high/config-change/quiet  (writes attribute; hard to alert on)
  * generic-all      — medium/config-change/moderate  (event 4724 is on by default)
  * writeowner       — medium/config-change/moderate  (event 4735 group edit)

Read-only wins the tier; shadow-creds wins the config-change tier
(quieter than GenericAll's password reset).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

AD_ESCALATION_KEYS = {
    "adroute:generic-all-user",
    "adroute:writeowner-group",
    "adroute:readlaps-password",
    "adroute:shadow-credentials",
}


class ADEscalationCoverageTest(unittest.TestCase):

    def _load(self):
        from fieldkit.ttps.loader import load_all
        return [t for t in load_all() if t.key in AD_ESCALATION_KEYS]

    def test_four_ad_escalation_ttps_shipped(self):
        keys = {t.key for t in self._load()}
        self.assertEqual(keys, AD_ESCALATION_KEYS)

    def test_all_gate_on_domain_users(self):
        # Same gate as the C4 AD-visibility slice — any authenticated
        # domain user is in Domain Users by default.
        for t in self._load():
            with self.subTest(key=t.key):
                self.assertEqual(t.detect.kind, "group_member")
                self.assertEqual(t.detect.value, "Domain Users")

    def test_all_target_windows_only(self):
        for t in self._load():
            with self.subTest(key=t.key):
                self.assertEqual(t.platform, ("windows",))

    def test_readlaps_is_high_read_only_quiet(self):
        # Load-bearing ranking: cleartext local admin via a single
        # LDAP query is the highest-value + quietest AD escalation
        # move, so it should top the ranking.
        t = [x for x in self._load()
             if x.key == "adroute:readlaps-password"][0]
        self.assertEqual(t.ranking.exploitability, "high")
        self.assertEqual(t.ranking.safety, "read-only")
        self.assertEqual(t.ranking.detection, "quiet")

    def test_shadow_credentials_ranking_prefers_quietness(self):
        # ShadowCredentials writes msDS-KeyCredentialLink but is
        # quieter than GenericAll's password reset (no event 4724);
        # quiet detection axis reflects that.
        t = [x for x in self._load()
             if x.key == "adroute:shadow-credentials"][0]
        self.assertEqual(t.ranking.exploitability, "high")
        self.assertEqual(t.ranking.detection, "quiet")


class ADEscalationFiringTest(unittest.TestCase):

    def _fire(self, **kw):
        from fieldkit.hostenum import HostFacts, WINDOWS
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        base = dict(os=WINDOWS, user="alice", uid=1000)
        base.update(kw)
        return vectors_for(HostFacts(**base), "10.0.0.7")

    def test_all_four_fire_on_domain_joined(self):
        vs = self._fire(win_groups={"Domain Users"})
        keys = {v.key for v in vs
                if v.key in AD_ESCALATION_KEYS}
        self.assertEqual(keys, AD_ESCALATION_KEYS)

    def test_none_fire_on_non_domain_windows(self):
        vs = self._fire(win_groups={"Users"})
        keys = {v.key for v in vs
                if v.key in AD_ESCALATION_KEYS}
        self.assertEqual(keys, set())

    def test_none_fire_on_linux(self):
        # Platform gate — even a Linux host with a Domain Users
        # win_group entry (which is nonsense but possible via ingest
        # mistake) never fires the Windows TTPs.
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=LINUX, user="alice", uid=1000,
                       win_groups={"Domain Users"}),
            "10.0.0.7")
        keys = {v.key for v in vs
                if v.key in AD_ESCALATION_KEYS}
        self.assertEqual(keys, set())


class ADEscalationRankingTest(unittest.TestCase):
    """Verify the read-only quiet primitive (readlaps) leads."""

    def _fire(self, **kw):
        from fieldkit.hostenum import HostFacts, WINDOWS
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        base = dict(os=WINDOWS, user="alice", uid=1000)
        base.update(kw)
        return vectors_for(HostFacts(**base), "10.0.0.7")

    def test_readlaps_outranks_configchange_ad_routes(self):
        # high/read-only/quiet = 333 vs high/config-change/quiet = 323
        vs = self._fire(win_groups={"Domain Users"})
        by_key = {v.key: v for v in vs}
        readlaps = by_key["adroute:readlaps-password"]
        shadow = by_key["adroute:shadow-credentials"]
        self.assertGreater(readlaps.score, shadow.score)

    def test_shadow_credentials_outranks_generic_all(self):
        # Shadow creds (high/config-change/quiet=323) is quieter
        # than GenericAll's password reset (medium/config-change/
        # moderate=222). The ranking encodes operator preference.
        vs = self._fire(win_groups={"Domain Users"})
        by_key = {v.key: v for v in vs}
        self.assertGreater(by_key["adroute:shadow-credentials"].score,
                           by_key["adroute:generic-all-user"].score)


class ADEscalationPlaybookTest(unittest.TestCase):
    """Every route surfaces a Cypher query for BloodHound + exec
    one-liners. This is the operator's payoff — a ranked next-move
    with the exact command to run."""

    def _load_by_key(self, key):
        from fieldkit.ttps.loader import load_all
        return [t for t in load_all() if t.key == key][0]

    def test_generic_all_playbook_names_bloodyad_or_net_rpc(self):
        t = self._load_by_key("adroute:generic-all-user")
        joined = " ".join(t.playbook.steps).lower()
        self.assertIn("bloodyad", joined)
        # Cypher edge type name must be in the playbook so the
        # operator can search BloodHound for the exact edge.
        self.assertIn("genericall", joined.replace(" ", "").lower())

    def test_writeowner_playbook_names_setowner_and_addmember(self):
        t = self._load_by_key("adroute:writeowner-group")
        joined = " ".join(t.playbook.steps).lower()
        self.assertIn("setowner", joined.replace(" ", "").lower())
        self.assertIn("groupmember", joined.replace(" ", "").lower())

    def test_readlaps_playbook_names_msLAPS_attribute(self):
        t = self._load_by_key("adroute:readlaps-password")
        joined = " ".join(t.playbook.steps)
        # Both current LAPS + legacy LAPS attribute names, in EITHER
        # the playbook body or the description (the description gets
        # rendered too).
        combined = joined + " " + t.report.description
        self.assertIn("msLAPS-Password", combined)

    def test_shadow_creds_playbook_names_certipy(self):
        t = self._load_by_key("adroute:shadow-credentials")
        joined = " ".join(t.playbook.steps).lower()
        self.assertIn("certipy", joined)
        self.assertIn("shadow", joined)


if __name__ == "__main__":
    unittest.main()
