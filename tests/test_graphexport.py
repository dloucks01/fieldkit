#!/usr/bin/env python3
"""Export the unified asset graph as JSON / DOT.

Pinned:
  * JSON carries nodes (id/key/label/kind/domain/owned/admin) and edges (src/dst/kind
    + pivot flag); a cross-domain pivot edge is flagged;
  * DOT is a well-formed digraph — domain fill colours, owned footholds bordered,
    high-value targets as double-octagons, pivot edges dashed; labels are escaped;
  * an empty engagement exports an empty-but-valid graph.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import assetgraph, cloud_iam, graphexport, saas  # noqa: E402
from fieldkit.state import Store  # noqa: E402


class GraphExportTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("GX")

    def _federated(self):
        saas.apply_saas(self.store, json.dumps({"tenant": "t", "principals": [
            {"id": "u:helga", "name": "helga@corp.com", "owned": True,
             "permissions": ["Application Administrator"]}]}))
        cloud_iam.apply_iam(self.store, json.dumps({"provider": "aws", "principals": [
            {"arn": "arn:aws:iam::1:role/helga", "name": "helga@corp.com",
             "permissions": ["iam:CreateAccessKey"]}]}))
        assetgraph.derive_pivots(self.store)


class JsonTest(GraphExportTestCase):
    def test_nodes_and_edges_with_pivot_flag(self):
        self._federated()
        doc = graphexport.to_json(self.store)
        self.assertEqual(doc["engagement"], "GX")
        by_key = {n["key"]: n for n in doc["nodes"]}
        helga = by_key["u:helga"]
        self.assertEqual(helga["domain"], "saas")
        self.assertTrue(helga["owned"])
        # a cross-domain pivot edge is present and flagged
        pivots = [e for e in doc["edges"] if e["pivot"]]
        self.assertTrue(pivots)
        self.assertTrue(all(e["kind"].startswith(assetgraph.PIVOT_PREFIX)
                            for e in pivots))
        # intra-domain edges are not flagged pivot
        self.assertTrue(any(not e["pivot"] for e in doc["edges"]))

    def test_admin_node_flagged(self):
        self._federated()
        doc = graphexport.to_json(self.store)
        self.assertTrue(any(n["admin"] for n in doc["nodes"]))   # admin-equivalent

    def test_empty_engagement(self):
        doc = graphexport.to_json(self.store)
        self.assertEqual(doc["nodes"], [])
        self.assertEqual(doc["edges"], [])


class DotTest(GraphExportTestCase):
    def test_wellformed_digraph(self):
        self._federated()
        dot = graphexport.to_dot(self.store)
        self.assertTrue(dot.startswith("digraph fieldkit {"))
        self.assertTrue(dot.rstrip().endswith("}"))
        self.assertIn("->", dot)
        self.assertIn("doubleoctagon", dot)          # a high-value target
        self.assertIn("style=dashed", dot)           # a pivot edge
        self.assertIn("penwidth=3", dot)             # an owned foothold
        self.assertIn("fillcolor", dot)

    def test_label_escaping(self):
        # a label containing a double quote must be escaped, not break the DOT
        self.store.add_asset("cloud_principal", 'arn:weird"name', label='weird"name')
        dot = graphexport.to_dot(self.store)
        self.assertIn('weird\\"name', dot)
        self.assertNotIn('weird"name"', dot)         # the raw unescaped form is absent

    def test_empty_engagement_valid(self):
        dot = graphexport.to_dot(self.store)
        self.assertTrue(dot.startswith("digraph fieldkit {"))
        self.assertTrue(dot.rstrip().endswith("}"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
