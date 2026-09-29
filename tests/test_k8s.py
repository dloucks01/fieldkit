#!/usr/bin/env python3
"""Kubernetes RBAC privilege-escalation pathing — fourth domain on the asset model.

Pinned:
  * parse a normalized RBAC graph; bad JSON → K8sRbacError;
  * apply → k8s_subject assets + asset_edge rows + k8s_privesc findings;
  * the owned→admin pathfinder (the shared assetgraph BFS) finds a multi-hop RBAC
    escalation and excludes an admin with no inbound edge;
  * findings are unproven observations that pass report.check; ingest is idempotent.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import k8s, report  # noqa: E402
from fieldkit.state import Store  # noqa: E402

GRAPH = {
    "cluster": "prod",
    "subjects": [
        {"id": "sa:default/app", "name": "app", "kind": "serviceaccount", "owned": True},
        {"id": "sa:ci/runner", "name": "runner", "kind": "serviceaccount"},
        {"id": "sa:kube-system/cadmin", "name": "cadmin", "kind": "serviceaccount",
         "admin": True},
        {"id": "sa:isolated/x", "name": "isolated", "kind": "serviceaccount",
         "admin": True},   # admin but unreachable
    ],
    "edges": [
        {"src": "sa:default/app", "dst": "sa:ci/runner", "kind": "pods/create"},
        {"src": "sa:ci/runner", "dst": "sa:kube-system/cadmin", "kind": "bind"},
    ],
}


class K8sTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("K8S")


class ParseTest(K8sTestCase):
    def test_parse_valid(self):
        cluster, subjects, edges = k8s.parse_rbac(json.dumps(GRAPH))
        self.assertEqual(cluster, "prod")
        self.assertEqual(len(subjects), 4)
        self.assertEqual(len(edges), 2)

    def test_bad_json_raises(self):
        with self.assertRaises(k8s.K8sRbacError):
            k8s.parse_rbac("{not json")
        with self.assertRaises(k8s.K8sRbacError):
            k8s.parse_rbac('"a string"')


class PathTest(K8sTestCase):
    def test_multi_hop_escalation_found_unreachable_admin_excluded(self):
        k8s.apply_rbac(self.store, json.dumps(GRAPH))
        paths = k8s.escalation_paths(self.store)
        self.assertEqual(len(paths), 1)
        p = paths[0]
        self.assertEqual(p["start"], "app")
        self.assertEqual(p["target"], "cadmin")       # not "isolated"
        self.assertIn("pods/create", p["evidence"])
        self.assertIn("bind", p["evidence"])

    def test_no_owned_subject_no_paths(self):
        g = json.loads(json.dumps(GRAPH))
        for s in g["subjects"]:
            s["owned"] = False
        k8s.apply_rbac(self.store, json.dumps(g))
        self.assertEqual(k8s.escalation_paths(self.store), [])


class ApplyTest(K8sTestCase):
    def test_records_observations_that_pass_check(self):
        rep = k8s.apply_rbac(self.store, json.dumps(GRAPH))
        self.assertEqual(rep.subjects_added, 4)
        self.assertEqual(rep.edges_added, 2)
        self.assertEqual(rep.findings_added, 1)
        eng, findings = report.build(self.store, {}, proven_only=False)
        self.assertEqual(findings[0]["vector_type"], "k8s_privesc")
        self.assertFalse(findings[0]["proven"])
        errors, _ = report.check(findings)
        self.assertEqual(errors, [])

    def test_idempotent(self):
        k8s.apply_rbac(self.store, json.dumps(GRAPH))
        k8s.apply_rbac(self.store, json.dumps(GRAPH))
        self.assertEqual(len(self.store.assets("k8s_subject")), 4)
        self.assertEqual(len(self.store.findings()), 1)

    def test_cloud_and_k8s_graphs_are_independent(self):
        # the two domains share the asset-edge table but must not cross-contaminate:
        # a k8s subgraph produces no cloud paths and vice-versa.
        from fieldkit import cloud_iam
        k8s.apply_rbac(self.store, json.dumps(GRAPH))
        self.assertEqual(cloud_iam.escalation_paths(self.store), [])
        self.assertEqual(len(k8s.escalation_paths(self.store)), 1)


class PrivescRuleTest(K8sTestCase):
    """Edges are DERIVED from raw RBAC grants (kubectl auth can-i --list) via the
    privesc-primitive ruleset, so an operator can feed a grants dump, not a graph."""

    def _apply(self, subjects, edges=None):
        k8s.apply_rbac(self.store, json.dumps(
            {"cluster": "p", "subjects": subjects, "edges": edges or []}))

    def test_create_pods_reaches_cluster_admin(self):
        self._apply([{"id": "sa:default/app", "name": "app", "owned": True,
                      "permissions": ["get configmaps", "create pods"]}])
        paths = k8s.escalation_paths(self.store)
        self.assertEqual(len(paths), 1)
        self.assertIn("create pods", paths[0]["evidence"])
        self.assertIn("cluster-admin-equivalent", paths[0]["evidence"])

    def test_full_wildcard_matches(self):
        self._apply([{"id": "sa:x/y", "name": "y", "owned": True,
                      "permissions": ["* *"]}])
        self.assertEqual(len(k8s.escalation_paths(self.store)), 1)

    def test_multi_hop_pod_create_then_bind(self):
        self._apply(
            [{"id": "sa:default/app", "name": "app", "owned": True},
             {"id": "sa:ci/runner", "name": "runner",
              "permissions": ["bind clusterroles"]}],
            edges=[{"src": "sa:default/app", "dst": "sa:ci/runner", "kind": "pods/create"}])
        ev = k8s.escalation_paths(self.store)[0]["evidence"]
        self.assertIn("pods/create", ev)
        self.assertIn("bind clusterroles", ev)

    def test_benign_grants_yield_no_path(self):
        self._apply([{"id": "sa:x/w", "name": "w", "owned": True,
                      "permissions": ["get pods", "list configmaps"]}])
        self.assertEqual(k8s.escalation_paths(self.store), [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
