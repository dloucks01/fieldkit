#!/usr/bin/env python3
"""Blast-radius path prioritization on the shared asset graph.

Pinned:
  * the scoring primitives (`_score_path`, `_priority_band`, `_downstream_reach`);
  * `escalation_paths` annotates each path with hop_count / blast_radius / score /
    priority and ranks them worst-first (highest score);
  * a short chain onto an admin outranks a longer chain to the same admin;
  * blast radius = distinct principals reachable downstream of the target.

Exercised end-to-end through the k8s dialect (any domain would do — the engine is
shared) plus direct unit tests of the primitives.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import assetgraph, k8s  # noqa: E402
from fieldkit.state import Store  # noqa: E402


class PrimitiveTest(unittest.TestCase):
    def test_score_rewards_short_chains(self):
        one = assetgraph._score_path(1, 0, True)
        two = assetgraph._score_path(2, 0, True)
        self.assertGreater(one, two)

    def test_score_rewards_blast_radius(self):
        narrow = assetgraph._score_path(2, 0, True)
        wide = assetgraph._score_path(2, 20, True)
        self.assertGreater(wide, narrow)

    def test_admin_target_scores_above_non_admin(self):
        self.assertGreater(assetgraph._score_path(2, 0, True),
                           assetgraph._score_path(2, 0, False))

    def test_priority_bands_are_ordered(self):
        self.assertEqual(assetgraph._priority_band(assetgraph._score_path(1, 0, True)),
                         "Critical")
        self.assertEqual(assetgraph._priority_band(assetgraph._score_path(2, 0, True)),
                         "High")
        # a long chain onto a low-reach target falls to the bottom band
        self.assertEqual(assetgraph._priority_band(assetgraph._score_path(5, 0, True)),
                         "Low")

    def test_downstream_reach_counts_transitive_nodes(self):
        adj = {1: [(2, "e")], 2: [(3, "e")], 3: []}
        self.assertEqual(assetgraph._downstream_reach(adj, 1), 2)   # 2 and 3
        self.assertEqual(assetgraph._downstream_reach(adj, 3), 0)

    def test_downstream_reach_survives_cycles(self):
        adj = {1: [(2, "e")], 2: [(1, "e")]}     # 1 <-> 2
        self.assertEqual(assetgraph._downstream_reach(adj, 1), 1)   # just 2, no hang


# A short 1-hop path and a longer 2-hop path onto the SAME admin, which itself
# dominates one downstream node (blast radius 1 for both targets).
GRAPH = {
    "cluster": "prod",
    "subjects": [
        {"id": "s:fast", "name": "fast", "owned": True},
        {"id": "s:slow", "name": "slow", "owned": True},
        {"id": "s:mid", "name": "mid"},
        {"id": "s:admin", "name": "admin", "admin": True},
        {"id": "s:leaf", "name": "leaf"},
    ],
    "edges": [
        {"src": "s:fast", "dst": "s:admin", "kind": "bind"},           # 1 hop
        {"src": "s:slow", "dst": "s:mid", "kind": "pods/create"},      # 2 hops …
        {"src": "s:mid", "dst": "s:admin", "kind": "bind"},
        {"src": "s:admin", "dst": "s:leaf", "kind": "owns"},           # blast radius
    ],
}


class RankingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("RANK")
        k8s.apply_rbac(self.store, json.dumps(GRAPH))
        self.paths = k8s.escalation_paths(self.store)

    def test_every_path_is_annotated(self):
        self.assertEqual(len(self.paths), 2)
        for p in self.paths:
            self.assertIn("priority", p)
            self.assertIn("score", p)
            self.assertIn("hop_count", p)
            self.assertIn("blast_radius", p)

    def test_short_chain_outranks_long_chain(self):
        # worst-first ordering: the 1-hop path leads
        self.assertEqual(self.paths[0]["start"], "fast")
        self.assertEqual(self.paths[0]["hop_count"], 1)
        self.assertEqual(self.paths[1]["start"], "slow")
        self.assertEqual(self.paths[1]["hop_count"], 2)
        self.assertGreater(self.paths[0]["score"], self.paths[1]["score"])

    def test_blast_radius_reflects_downstream(self):
        # admin dominates one further node (leaf)
        for p in self.paths:
            self.assertEqual(p["blast_radius"], 1)

    def test_priority_band_assigned(self):
        self.assertEqual(self.paths[0]["priority"], "Critical")   # 1 hop
        self.assertEqual(self.paths[1]["priority"], "High")       # 2 hops


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
