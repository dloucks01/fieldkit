#!/usr/bin/env python3
"""SaaS / identity-provider privilege-escalation pathing — the sixth domain.

Pinned:
  * parse a normalized SaaS/IdP graph; bad JSON → SaasError;
  * apply → saas_principal assets + asset_edge rows + saas_privesc findings;
  * the owned→admin pathfinder (shared assetgraph BFS) finds a multi-hop role
    escalation and excludes an admin with no inbound edge;
  * held-role derivation recognizes Entra + Okta primitives and honors `*`;
  * findings are unproven observations that pass report.check; ingest is idempotent;
  * cloud/k8s/saas graphs share the edge table without cross-contaminating.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import report, saas  # noqa: E402
from fieldkit.state import Store  # noqa: E402

GRAPH = {
    "tenant": "contoso.onmicrosoft.com",
    "principals": [
        {"id": "u:helpdesk", "name": "helpdesk", "type": "user", "owned": True},
        {"id": "g:app-admins", "name": "app-admins", "type": "group"},
        {"id": "u:ga", "name": "ga", "type": "user", "admin": True},
        {"id": "u:isolated", "name": "isolated", "type": "user",
         "admin": True},   # admin but unreachable
    ],
    "edges": [
        {"src": "u:helpdesk", "dst": "g:app-admins", "kind": "member of"},
        {"src": "g:app-admins", "dst": "u:ga", "kind": "Application Administrator"},
    ],
}


class SaasTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("SAAS")


class ParseTest(SaasTestCase):
    def test_parse_valid(self):
        tenant, principals, edges = saas.parse_saas(json.dumps(GRAPH))
        self.assertEqual(tenant, "contoso.onmicrosoft.com")
        self.assertEqual(len(principals), 4)
        self.assertEqual(len(edges), 2)

    def test_bad_json_raises(self):
        with self.assertRaises(saas.SaasError):
            saas.parse_saas("{not json")
        with self.assertRaises(saas.SaasError):
            saas.parse_saas('"a string"')


class PathTest(SaasTestCase):
    def test_multi_hop_escalation_found_unreachable_admin_excluded(self):
        saas.apply_saas(self.store, json.dumps(GRAPH))
        paths = saas.escalation_paths(self.store)
        self.assertEqual(len(paths), 1)
        p = paths[0]
        self.assertEqual(p["start"], "helpdesk")
        self.assertEqual(p["target"], "ga")            # not "isolated"
        self.assertIn("member of", p["evidence"])
        self.assertIn("Application Administrator", p["evidence"])

    def test_no_owned_principal_no_paths(self):
        g = json.loads(json.dumps(GRAPH))
        for p in g["principals"]:
            p["owned"] = False
        saas.apply_saas(self.store, json.dumps(g))
        self.assertEqual(saas.escalation_paths(self.store), [])


class ApplyTest(SaasTestCase):
    def test_records_observations_that_pass_check(self):
        rep = saas.apply_saas(self.store, json.dumps(GRAPH))
        self.assertEqual(rep.principals_added, 4)
        self.assertEqual(rep.edges_added, 2)
        self.assertEqual(rep.findings_added, 1)
        eng, findings = report.build(self.store, {}, proven_only=False)
        self.assertEqual(findings[0]["vector_type"], "saas_privesc")
        self.assertFalse(findings[0]["proven"])
        errors, _ = report.check(findings)
        self.assertEqual(errors, [])

    def test_idempotent(self):
        saas.apply_saas(self.store, json.dumps(GRAPH))
        saas.apply_saas(self.store, json.dumps(GRAPH))
        self.assertEqual(len(self.store.assets("saas_principal")), 4)
        self.assertEqual(len(self.store.findings()), 1)

    def test_domains_are_independent(self):
        from fieldkit import cloud_iam, k8s
        saas.apply_saas(self.store, json.dumps(GRAPH))
        self.assertEqual(cloud_iam.escalation_paths(self.store), [])
        self.assertEqual(k8s.escalation_paths(self.store), [])
        self.assertEqual(len(saas.escalation_paths(self.store)), 1)


class PrivescRuleTest(SaasTestCase):
    """Edges are DERIVED from held directory roles / Graph permissions via the
    privesc-primitive ruleset, so an operator can feed a role dump, not a graph."""

    def _apply(self, principals, edges=None):
        saas.apply_saas(self.store, json.dumps(
            {"tenant": "t", "principals": principals, "edges": edges or []}))

    def test_global_admin_role_reaches_admin(self):
        self._apply([{"id": "u:a", "name": "a", "owned": True,
                      "permissions": ["Global Administrator"]}])
        paths = saas.escalation_paths(self.store)
        self.assertEqual(len(paths), 1)
        self.assertIn("Global Administrator", paths[0]["evidence"])

    def test_graph_app_permission_reaches_admin(self):
        self._apply([{"id": "sp:x", "name": "x", "type": "serviceprincipal",
                      "owned": True,
                      "permissions": ["RoleManagement.ReadWrite.Directory"]}])
        self.assertEqual(len(saas.escalation_paths(self.store)), 1)

    def test_wildcard_matches(self):
        self._apply([{"id": "u:w", "name": "w", "owned": True, "permissions": ["*"]}])
        self.assertEqual(len(saas.escalation_paths(self.store)), 1)

    def test_benign_role_yields_no_path(self):
        self._apply([{"id": "u:r", "name": "r", "owned": True,
                      "permissions": ["Reports Reader", "Message Center Reader"]}])
        self.assertEqual(saas.escalation_paths(self.store), [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
