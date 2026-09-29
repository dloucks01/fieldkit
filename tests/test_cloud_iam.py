#!/usr/bin/env python3
"""Cloud IAM privilege-escalation pathing — the third domain on the asset model.

Pinned:
  * parse a normalized cloud-IAM graph; bad JSON → CloudIamError;
  * apply → cloud_principal assets + asset_edge rows + cloud_privesc findings;
  * the owned→admin pathfinder (the SAME BFS as AD BloodHound) finds a multi-hop
    escalation and excludes an admin with no inbound edge;
  * findings are unproven observations that pass report.check; ingest is idempotent.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import cloud_iam, report  # noqa: E402
from fieldkit.state import Store  # noqa: E402

GRAPH = {
    "provider": "aws",
    "principals": [
        {"arn": "arn:aws:iam::1:user/dev", "name": "dev", "type": "user", "owned": True},
        {"arn": "arn:aws:iam::1:role/ci", "name": "ci", "type": "role"},
        {"arn": "arn:aws:iam::1:role/admin", "name": "admin", "type": "role", "admin": True},
        {"arn": "arn:aws:iam::1:role/isolated", "name": "isolated", "type": "role",
         "admin": True},   # admin but no inbound edge → unreachable
    ],
    "edges": [
        {"src": "arn:aws:iam::1:user/dev", "dst": "arn:aws:iam::1:role/ci",
         "kind": "sts:AssumeRole"},
        {"src": "arn:aws:iam::1:role/ci", "dst": "arn:aws:iam::1:role/admin",
         "kind": "iam:PassRole"},
    ],
}


class CloudTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("CLOUD")


class ParseTest(CloudTestCase):
    def test_parse_valid(self):
        provider, principals, edges = cloud_iam.parse_iam(json.dumps(GRAPH))
        self.assertEqual(provider, "aws")
        self.assertEqual(len(principals), 4)
        self.assertEqual(len(edges), 2)
        self.assertTrue(any(p["owned"] for p in principals))

    def test_bad_json_raises(self):
        with self.assertRaises(cloud_iam.CloudIamError):
            cloud_iam.parse_iam("not json{")
        with self.assertRaises(cloud_iam.CloudIamError):
            cloud_iam.parse_iam("[]")   # not an object


class PathTest(CloudTestCase):
    def test_multi_hop_escalation_found_unreachable_admin_excluded(self):
        cloud_iam.apply_iam(self.store, json.dumps(GRAPH))
        paths = cloud_iam.escalation_paths(self.store)
        self.assertEqual(len(paths), 1)
        p = paths[0]
        self.assertEqual(p["start"], "dev")
        self.assertEqual(p["target"], "admin")          # not "isolated"
        self.assertIn("sts:AssumeRole", p["evidence"])
        self.assertIn("iam:PassRole", p["evidence"])

    def test_no_owned_principal_no_paths(self):
        g = json.loads(json.dumps(GRAPH))
        for pr in g["principals"]:
            pr["owned"] = False
        cloud_iam.apply_iam(self.store, json.dumps(g))
        self.assertEqual(cloud_iam.escalation_paths(self.store), [])

    def test_dead_end_owned_has_no_path(self):
        g = {"provider": "aws", "principals": [
            {"arn": "a", "name": "a", "owned": True},
            {"arn": "b", "name": "b", "admin": True}], "edges": []}   # no edge a→b
        cloud_iam.apply_iam(self.store, json.dumps(g))
        self.assertEqual(cloud_iam.escalation_paths(self.store), [])


class ApplyTest(CloudTestCase):
    def test_records_observations_that_pass_check(self):
        rep = cloud_iam.apply_iam(self.store, json.dumps(GRAPH))
        self.assertEqual(rep.principals_added, 4)
        self.assertEqual(rep.edges_added, 2)
        self.assertEqual(rep.findings_added, 1)
        eng, findings = report.build(self.store, {}, proven_only=False)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vector_type"], "cloud_privesc")
        self.assertFalse(findings[0]["proven"])
        errors, _ = report.check(findings)
        self.assertEqual(errors, [])

    def test_idempotent(self):
        cloud_iam.apply_iam(self.store, json.dumps(GRAPH))
        cloud_iam.apply_iam(self.store, json.dumps(GRAPH))
        self.assertEqual(len(self.store.assets("cloud_principal")), 4)
        self.assertEqual(len(self.store.asset_edges()), 2)
        self.assertEqual(len(self.store.findings()), 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
