#!/usr/bin/env python3
"""Cross-domain path stitching — one owned→admin graph across all domains.

Pinned:
  * pivot derivation: federated SaaS→cloud identity (shared email), declared `aliases`,
    and explicit `add_pivot`; synthetic admin-equivalent nodes are never pivoted;
  * cross_domain_paths steps over a NEARER in-domain admin to surface a path that
    reaches admin in a different domain;
  * single-domain graphs yield no cross-domain paths; cross paths outscore equal-length
    single-domain ones (the cross bump) and carry the domains traversed;
  * record_cross_domain records unproven cross_domain_privesc findings that pass check;
  * end-to-end: SaaS foothold → federated cloud identity → cloud admin.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import assetgraph, cloud_iam, k8s, report, saas  # noqa: E402
from fieldkit.state import Store  # noqa: E402


class CrossDomainTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("XD")

    def _saas(self, principals):
        saas.apply_saas(self.store, json.dumps({"tenant": "t", "principals": principals}))

    def _cloud(self, principals):
        cloud_iam.apply_iam(self.store, json.dumps(
            {"provider": "aws", "principals": principals}))


class PivotDerivationTest(CrossDomainTestCase):
    def test_federated_email_links_saas_to_cloud(self):
        # a SaaS user and a cloud principal that share an email -> a directed pivot
        self._saas([{"id": "u:helga", "name": "helga@corp.com", "owned": True}])
        self._cloud([{"arn": "arn:aws:iam::1:role/helga", "name": "helga@corp.com"}])
        added = assetgraph.derive_pivots(self.store)
        self.assertGreaterEqual(added, 1)
        # the pivot goes saas -> cloud (own the IdP identity -> the federated one)
        saas_id = self.store.asset_by_key("saas_principal", "u:helga")["id"]
        cloud_id = self.store.asset_by_key("cloud_principal",
                                           "arn:aws:iam::1:role/helga")["id"]
        kinds = {(e["src_id"], e["dst_id"]): e["kind"]
                 for e in self.store.asset_edges()}
        self.assertIn((saas_id, cloud_id), kinds)
        self.assertTrue(kinds[(saas_id, cloud_id)].startswith(assetgraph.PIVOT_PREFIX))

    def test_alias_prop_links_across_domains(self):
        self._saas([{"id": "u:svc", "name": "svc", "owned": True,
                     "permissions": [], "props": {"aliases": ["sa:ci/deployer"]}}])
        k8s.apply_rbac(self.store, json.dumps(
            {"cluster": "c", "subjects": [{"id": "sa:ci/deployer", "name": "deployer"}]}))
        added = assetgraph.derive_pivots(self.store)
        self.assertGreaterEqual(added, 1)

    def test_derivation_is_idempotent_and_skips_synthetic(self):
        self._saas([{"id": "u:a", "name": "a@corp.com", "owned": True,
                     "permissions": ["Global Administrator"]}])   # makes a synthetic node
        self._cloud([{"arn": "arn:x:user/a", "name": "a@corp.com",
                      "permissions": ["iam:CreateAccessKey"]}])    # another synthetic node
        first = assetgraph.derive_pivots(self.store)
        second = assetgraph.derive_pivots(self.store)
        self.assertEqual(second, 0)                     # idempotent
        # no pivot points at a synthetic admin-equivalent node
        synth = {a["id"] for a in self.store.assets()
                 if json.loads(a["props_json"] or "{}").get("type") == "synthetic"}
        for e in self.store.asset_edges():
            if e["kind"].startswith(assetgraph.PIVOT_PREFIX):
                self.assertNotIn(e["dst_id"], synth)
                self.assertNotIn(e["src_id"], synth)


class ExplicitPivotTest(CrossDomainTestCase):
    def test_add_pivot_between_existing_assets(self):
        self._saas([{"id": "u:x", "name": "x", "owned": True}])
        self._cloud([{"arn": "arn:x", "name": "x-role"}])
        created, err = assetgraph.add_pivot(
            self.store, "saas_principal", "u:x", "cloud_principal", "arn:x", "webshell")
        self.assertIsNone(err)
        self.assertTrue(created)
        self.assertTrue(any(e["kind"] == "pivot:webshell"
                            for e in self.store.asset_edges()))

    def test_add_pivot_missing_asset_reports_error(self):
        self._saas([{"id": "u:x", "name": "x", "owned": True}])
        created, err = assetgraph.add_pivot(
            self.store, "saas_principal", "u:x", "cloud_principal", "nope")
        self.assertFalse(created)
        self.assertIn("cloud_principal", err)


class StitchingTest(CrossDomainTestCase):
    def _federated_scenario(self):
        # SaaS foothold 'helga' (also holds a SaaS admin role -> a NEARER in-domain
        # admin) federates to cloud 'helga', who can self-escalate to cloud admin.
        self._saas([{"id": "u:helga", "name": "helga@corp.com", "owned": True,
                     "permissions": ["Application Administrator"]}])
        self._cloud([{"arn": "arn:aws:iam::1:user/helga", "name": "helga@corp.com",
                      "permissions": ["iam:CreateAccessKey"]}])

    def test_stitches_over_nearer_in_domain_admin(self):
        self._federated_scenario()
        paths = assetgraph.record_cross_domain(self.store)[2]
        self.assertEqual(len(paths), 1)
        p = paths[0]
        self.assertTrue(p["cross_domain"])
        self.assertEqual(p["domains"], ["saas", "cloud"])
        self.assertIn("federated identity", p["evidence"])
        self.assertIn("[saas]", p["evidence"])
        self.assertIn("[cloud]", p["evidence"])

    def test_single_domain_only_yields_nothing(self):
        # cloud graph alone, no pivot to another domain
        self._cloud([{"arn": "arn:a", "name": "a", "owned": True,
                      "permissions": ["iam:CreateAccessKey"]}])
        self.assertEqual(assetgraph.cross_domain_paths(self.store), [])

    def test_cross_bump_outscores_equal_length_single_domain(self):
        self._federated_scenario()
        assetgraph.derive_pivots(self.store)   # cross_domain_paths is read-only
        cross = assetgraph.cross_domain_paths(self.store)[0]
        single = saas.escalation_paths(self.store)[0]     # helga -> saas admin (1 hop)
        # cross path is 2 hops but the cross bump keeps it a serious finding
        self.assertGreaterEqual(cross["score"], single["score"] - assetgraph._W_EASE)
        self.assertTrue(cross["score"] > assetgraph._score_path(cross["hop_count"],
                                                                cross["blast_radius"],
                                                                True))

    def test_recorded_finding_passes_check(self):
        self._federated_scenario()
        pivots, added, paths = assetgraph.record_cross_domain(self.store)
        self.assertGreaterEqual(pivots, 1)
        self.assertEqual(added, 1)
        eng, findings = report.build(self.store, {}, proven_only=False)
        xd = [f for f in findings if f["vector_type"] == "cross_domain_privesc"]
        self.assertEqual(len(xd), 1)
        self.assertFalse(xd[0]["proven"])
        errors, _ = report.check(findings)
        self.assertEqual(errors, [])

    def test_record_is_idempotent(self):
        self._federated_scenario()
        assetgraph.record_cross_domain(self.store)
        assetgraph.record_cross_domain(self.store)
        xd = [f for f in self.store.findings()
              if f["vector_type"] == "cross_domain_privesc"]
        self.assertEqual(len(xd), 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
