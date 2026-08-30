#!/usr/bin/env python3
"""AD-side visibility TTPs — C4.

Five TTPs land here, all Windows, all gated on `group_member: Domain
Users` (every authenticated domain user is in this group by default,
so the gate is a proxy for "we're on a domain"):

  * adroute:kerberoast          T1558.003 — SPN enum → roast playbook
  * adroute:asrep-roast         T1558.004 — DONT_REQ_PREAUTH enum
  * adroute:gpp-cpassword       T1552.006 — SYSVOL cpassword hunt
  * adroute:domain-admins-enum  T1069.002 — DA / EA / SA member list
  * adroute:gpo-cache-discovery T1615     — gpresult /r output

Bridges fieldkit's existing `fieldkit roast` CLI + BloodHound
integrations into the ranked TOP MOVES surface — before C4 those
routes had no visibility in analyze / escalate, so operators had to
know to run them.

Rankings picked so kerberoast (the highest-hit AD move most days)
sits at high/read-only/quiet = 333 and outranks seimpersonate's
322 — quiet recon before loud escalation matches operator instinct.
AS-REP + GPP are medium (narrower target sets). Discovery-only
(domain-admins-enum, gpo-cache-discovery) is low so they surface
but don't crowd.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

#: The C4-shipped AD-visibility routes. C6 adds escalation-side
#: routes (adroute:generic-all-user etc.) — those live in a separate
#: test file and this set stays scoped to what C4 pinned.
AD_ROUTE_KEYS = {
    "adroute:kerberoast",
    "adroute:asrep-roast",
    "adroute:gpp-cpassword",
    "adroute:domain-admins-enum",
    "adroute:gpo-cache-discovery",
}


class ADRouteCoverageTest(unittest.TestCase):

    def _load_ad(self):
        from fieldkit.ttps.loader import load_all
        return [t for t in load_all() if t.key.startswith("adroute:")]

    def test_five_ad_route_ttps_shipped(self):
        # subset check — C6 adds more adroute:* TTPs (escalation-side);
        # this pin stays scoped to the C4 visibility routes.
        keys = {t.key for t in self._load_ad()}
        self.assertTrue(AD_ROUTE_KEYS.issubset(keys),
                         f"missing: {AD_ROUTE_KEYS - keys}")

    def test_all_target_windows_only(self):
        for t in self._load_ad():
            with self.subTest(key=t.key):
                self.assertEqual(t.platform, ("windows",))

    def test_all_gate_on_domain_users(self):
        # Every C4-shipped AD-visibility TTP uses group_member:
        # Domain Users as the "we're on a domain" proxy. Later
        # slices (C7 slice 4) add adroute:* TTPs gated on
        # different facts (bh_owned_reaches_hv) — that's fine, the
        # invariant here is scoped to the C4-shipped set.
        for t in self._load_ad():
            if t.key not in AD_ROUTE_KEYS:
                continue
            with self.subTest(key=t.key):
                self.assertEqual(t.detect.kind, "group_member")
                self.assertEqual(t.detect.value, "Domain Users")


class ADRouteFiringTest(unittest.TestCase):

    def _fire(self, os_name="windows", win_groups=None, **kw):
        from fieldkit.hostenum import HostFacts
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        base = dict(os=os_name, user="alice", uid=1000)
        if win_groups is not None:
            base["win_groups"] = win_groups
        base.update(kw)
        return vectors_for(HostFacts(**base), "10.0.0.7")

    def test_all_five_fire_on_domain_joined_windows(self):
        # Subset — C6 adds more adroute:* firings on the same gate.
        vs = self._fire(win_groups={"Domain Users"})
        keys = {v.key for v in vs if v.key.startswith("adroute:")}
        self.assertTrue(AD_ROUTE_KEYS.issubset(keys),
                         f"missing: {AD_ROUTE_KEYS - keys}")

    def test_none_fire_on_non_domain_windows(self):
        # A local-account foothold shouldn't surface AD moves.
        vs = self._fire(win_groups={"Users"})
        keys = {v.key for v in vs if v.key.startswith("adroute:")}
        self.assertEqual(keys, set())

    def test_none_fire_on_linux(self):
        vs = self._fire(os_name="linux", win_groups={"Domain Users"})
        keys = {v.key for v in vs if v.key.startswith("adroute:")}
        self.assertEqual(keys, set())


class ADRouteRankingTest(unittest.TestCase):
    """Verifies the ranking story: kerberoast (highest-hit AD move)
    tops seimpersonate on a domain-joined Windows foothold."""

    def _fire(self, **kw):
        from fieldkit.hostenum import HostFacts, WINDOWS
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        base = dict(os=WINDOWS, user="alice", uid=1000,
                    win_groups={"Domain Users"})
        base.update(kw)
        return vectors_for(HostFacts(**base), "10.0.0.7")

    def test_kerberoast_outranks_seimpersonate(self):
        # kerberoast: high/read-only/quiet = 333
        # seimpersonate:*: high/config-change/moderate = 322
        # Quiet recon before loud escalation is the correct operator
        # instinct.
        vs = self._fire(privs={"SeImpersonatePrivilege"})
        self.assertEqual(vs[0].key, "adroute:kerberoast")

    def test_asrep_and_gpp_rank_medium(self):
        # 233 — below high/read-only routes, above low/read-only
        # discovery.
        vs = self._fire()
        for v in vs:
            if v.key in ("adroute:asrep-roast", "adroute:gpp-cpassword"):
                with self.subTest(key=v.key):
                    self.assertEqual(v.score, 233)

    def test_discovery_only_ttps_rank_low(self):
        # 133 — surfaces but doesn't crowd.
        vs = self._fire()
        for v in vs:
            if v.key in ("adroute:domain-admins-enum",
                          "adroute:gpo-cache-discovery"):
                with self.subTest(key=v.key):
                    self.assertEqual(v.score, 133)

    def test_all_ad_routes_are_read_only(self):
        # Scoped to the C4 visibility TTPs — those are all read-only
        # by design (recon + hunt only). C6 adds escalation-side
        # routes (adroute:writeowner-group etc.) that are
        # deliberately config-change and land in a separate test
        # file; excluding them here keeps the C4 invariant intact.
        vs = self._fire()
        for v in vs:
            if v.key in AD_ROUTE_KEYS:
                with self.subTest(key=v.key):
                    self.assertEqual(v.safety, "read-only")


class ADRouteCommandShapeTest(unittest.TestCase):
    """The commands are AD-tool-driven — each should invoke the
    tool the description promises. Regression guard against a
    typo swapping setspn for something else."""

    def _load_by_key(self, key):
        from fieldkit.ttps.loader import load_all
        return [t for t in load_all() if t.key == key][0]

    def test_kerberoast_uses_setspn_query(self):
        t = self._load_by_key("adroute:kerberoast")
        self.assertIn("setspn -Q", t.execute.command)

    def test_asrep_uses_dsquery_uac_bit(self):
        t = self._load_by_key("adroute:asrep-roast")
        # UAC bit 22 = 0x400000 = 4194304 for DONT_REQ_PREAUTH.
        self.assertIn("dsquery", t.execute.command)
        self.assertIn("4194304", t.execute.command)

    def test_gpp_cpassword_scans_sysvol_xml(self):
        t = self._load_by_key("adroute:gpp-cpassword")
        self.assertIn("cpassword", t.execute.command)
        self.assertIn("SYSVOL", t.execute.command)
        self.assertIn("*.xml", t.execute.command)

    def test_domain_admins_enum_covers_all_high_privilege_groups(self):
        t = self._load_by_key("adroute:domain-admins-enum")
        for group in ("Domain Admins", "Enterprise Admins",
                       "Schema Admins", "Administrators"):
            with self.subTest(group=group):
                self.assertIn(f'"{group}" /domain', t.execute.command)

    def test_gpo_cache_covers_computer_and_user_scope(self):
        t = self._load_by_key("adroute:gpo-cache-discovery")
        self.assertIn("gpresult /r /scope:computer", t.execute.command)
        self.assertIn("gpresult /r /scope:user", t.execute.command)


class ADRoutePlaybookHandoffTest(unittest.TestCase):
    """Kerberoast + AS-REP TTPs are prepare-only routes that hand
    off to `fieldkit roast` attacker-side. Verify the playbook
    exists and names the CLI command explicitly (so the operator
    isn't left guessing)."""

    def _load_by_key(self, key):
        from fieldkit.ttps.loader import load_all
        return [t for t in load_all() if t.key == key][0]

    def test_kerberoast_playbook_names_fieldkit_roast(self):
        t = self._load_by_key("adroute:kerberoast")
        self.assertIsNotNone(t.playbook)
        joined = " ".join(t.playbook.steps)
        self.assertIn("fieldkit roast", joined)
        self.assertIn("kerberoast", joined.lower())

    def test_asrep_playbook_names_fieldkit_roast(self):
        t = self._load_by_key("adroute:asrep-roast")
        self.assertIsNotNone(t.playbook)
        joined = " ".join(t.playbook.steps)
        self.assertIn("fieldkit roast", joined)
        self.assertIn("asrep", joined.lower())


if __name__ == "__main__":
    unittest.main()
