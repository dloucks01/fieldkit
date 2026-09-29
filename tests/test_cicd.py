#!/usr/bin/env python3
"""CI/CD pipeline privilege-escalation pathing — the seventh domain.

Pinned:
  * parse a normalized CI/CD graph; bad JSON → CicdError;
  * apply → cicd_principal assets + asset_edge rows + cicd_privesc findings;
  * multi-hop pathfinder (shared assetgraph BFS) + unreachable-admin exclusion;
  * capability derivation recognizes CI/CD primitives and honors `*`;
  * findings are unproven observations that pass report.check; idempotent;
  * a CI principal with a cloud-role alias stitches CI→cloud cross-domain.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import assetgraph, cicd, cloud_iam, report  # noqa: E402
from fieldkit.state import Store  # noqa: E402

GRAPH = {
    "platform": "github",
    "principals": [
        {"id": "gh:dev", "name": "dev", "type": "user", "owned": True},
        {"id": "repo:app", "name": "app", "type": "repo"},
        {"id": "pipe:deploy", "name": "deploy", "type": "pipeline", "admin": True},
        {"id": "pipe:isolated", "name": "isolated", "type": "pipeline",
         "admin": True},   # admin but unreachable
    ],
    "edges": [
        {"src": "gh:dev", "dst": "repo:app", "kind": "write workflow"},
        {"src": "repo:app", "dst": "pipe:deploy", "kind": "triggers"},
    ],
}


class CicdTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("CICD")


class ParseTest(CicdTestCase):
    def test_parse_valid(self):
        platform, principals, edges = cicd.parse_cicd(json.dumps(GRAPH))
        self.assertEqual(platform, "github")
        self.assertEqual(len(principals), 4)
        self.assertEqual(len(edges), 2)

    def test_bad_json_raises(self):
        with self.assertRaises(cicd.CicdError):
            cicd.parse_cicd("{not json")
        with self.assertRaises(cicd.CicdError):
            cicd.parse_cicd('"a string"')


class PathTest(CicdTestCase):
    def test_multi_hop_and_unreachable_admin_excluded(self):
        cicd.apply_cicd(self.store, json.dumps(GRAPH))
        paths = cicd.escalation_paths(self.store)
        self.assertEqual(len(paths), 1)
        p = paths[0]
        self.assertEqual(p["start"], "dev")
        self.assertEqual(p["target"], "deploy")       # not "isolated"
        self.assertIn("write workflow", p["evidence"])

    def test_no_owned_no_paths(self):
        g = json.loads(json.dumps(GRAPH))
        for pr in g["principals"]:
            pr["owned"] = False
        cicd.apply_cicd(self.store, json.dumps(g))
        self.assertEqual(cicd.escalation_paths(self.store), [])


class ApplyTest(CicdTestCase):
    def test_records_observations_that_pass_check(self):
        rep = cicd.apply_cicd(self.store, json.dumps(GRAPH))
        self.assertEqual(rep.principals_added, 4)
        self.assertEqual(rep.findings_added, 1)
        eng, findings = report.build(self.store, {}, proven_only=False)
        self.assertEqual(findings[0]["vector_type"], "cicd_privesc")
        self.assertFalse(findings[0]["proven"])
        errors, _ = report.check(findings)
        self.assertEqual(errors, [])

    def test_idempotent(self):
        cicd.apply_cicd(self.store, json.dumps(GRAPH))
        cicd.apply_cicd(self.store, json.dumps(GRAPH))
        self.assertEqual(len(self.store.assets("cicd_principal")), 4)
        self.assertEqual(len(self.store.findings()), 1)


class DeriveTest(CicdTestCase):
    def _apply(self, principals):
        cicd.apply_cicd(self.store, json.dumps({"platform": "gh",
                                                "principals": principals}))

    def test_write_workflow_reaches_deploy_admin(self):
        self._apply([{"id": "gh:a", "name": "a", "owned": True,
                      "permissions": ["read secrets", "write workflow"]}])
        paths = cicd.escalation_paths(self.store)
        self.assertEqual(len(paths), 1)
        self.assertIn("deploy-admin-equivalent", paths[0]["evidence"])

    def test_wildcard_matches(self):
        self._apply([{"id": "gh:w", "name": "w", "owned": True, "permissions": ["*"]}])
        self.assertEqual(len(cicd.escalation_paths(self.store)), 1)

    def test_benign_capability_yields_no_path(self):
        self._apply([{"id": "gh:r", "name": "r", "owned": True,
                      "permissions": ["pull", "triage"]}])
        self.assertEqual(cicd.escalation_paths(self.store), [])


class CrossDomainTest(CicdTestCase):
    def test_cicd_oidc_alias_stitches_into_cloud(self):
        # a pipeline that can deploy AND (via OIDC) assumes a cloud role that self-
        # escalates to cloud admin → CI/CD → cloud cross-domain path.
        cicd.apply_cicd(self.store, json.dumps({"platform": "gh", "principals": [
            {"id": "pipe:deploy", "name": "deploy", "owned": True,
             "permissions": ["deploy"],
             "props": {"aliases": ["arn:aws:iam::1:role/ci-deploy"]}}]}))
        cloud_iam.apply_iam(self.store, json.dumps({"provider": "aws", "principals": [
            {"arn": "arn:aws:iam::1:role/ci-deploy", "name": "ci-deploy",
             "permissions": ["iam:CreateAccessKey"]}]}))
        assetgraph.derive_pivots(self.store)
        cross = assetgraph.cross_domain_paths(self.store)
        self.assertTrue(cross)
        self.assertEqual(cross[0]["domains"], ["cicd", "cloud"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
