#!/usr/bin/env python3
"""BloodHound ingest + pathfinding — can what we own reach Domain Admin?

Pinned:

  * load() parses SharpHound JSON into control edges (MemberOf, AdminTo, dangerous
    ACEs) with high-value nodes flagged;
  * owned_paths() BFS-es from a credential fieldkit holds to a high-value target and
    returns the shortest path;
  * a credential we do NOT own yields no path; analyze surfaces the ones we do.

Run:  python3 -m unittest discover -s tests
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit.bloodhound import import_graph, load, owned_paths  # noqa: E402
from fieldkit.creds import Credential  # noqa: E402
from fieldkit.kb import analyze  # noqa: E402
from fieldkit.state import Store  # noqa: E402

DOM = "S-1-5-21-111"
JDOE = f"{DOM}-1001"
ITADMINS = f"{DOM}-1100"
DA = f"{DOM}-512"          # Domain Admins, high-value by RID

# jdoe --MemberOf--> IT Admins --GenericAll--> Domain Admins
USERS = {"meta": {"type": "users"}, "data": [
    {"ObjectIdentifier": JDOE, "Properties": {"name": "JDOE@CORP.LOCAL"}, "Aces": []},
]}
GROUPS = {"meta": {"type": "groups"}, "data": [
    {"ObjectIdentifier": ITADMINS, "Properties": {"name": "IT ADMINS@CORP.LOCAL"},
     "Members": [{"ObjectIdentifier": JDOE, "ObjectType": "User"}],
     "Aces": [{"PrincipalSID": ITADMINS, "PrincipalType": "Group",
               "RightName": "GenericAll", "IsInherited": False}],
     "__note": "the ACE below is on Domain Admins, granting IT Admins GenericAll"},
    {"ObjectIdentifier": DA, "Properties": {"name": "DOMAIN ADMINS@CORP.LOCAL"},
     "Members": [],
     "Aces": [{"PrincipalSID": ITADMINS, "PrincipalType": "Group",
               "RightName": "GenericAll", "IsInherited": False}]},
]}


def write_dir(d):
    with open(os.path.join(d, "users.json"), "w") as fh:
        json.dump(USERS, fh)
    with open(os.path.join(d, "groups.json"), "w") as fh:
        json.dump(GROUPS, fh)
    return d


class LoadTest(unittest.TestCase):
    def test_nodes_and_edges(self):
        with tempfile.TemporaryDirectory() as d:
            nodes, edges = load(write_dir(d))
            by_sid = {n["sid"]: n for n in nodes}
            self.assertTrue(by_sid[DA]["high_value"])          # RID 512
            self.assertFalse(by_sid[JDOE]["high_value"])
            kinds = {(e["src"], e["kind"], e["dst"]) for e in edges}
            self.assertIn((JDOE, "MemberOf", ITADMINS), kinds)
            self.assertIn((ITADMINS, "GenericAll", DA), kinds)


class PathTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME")
        self.dir = write_dir(tempfile.mkdtemp(dir=self.tmp.name))
        import_graph(self.store, self.dir)

    def test_owned_principal_reaches_da(self):
        self.store.add_credential(Credential("jdoe", "pw", domain="corp.local"))
        paths = owned_paths(self.store)
        self.assertEqual(len(paths), 1)
        p = paths[0]
        self.assertEqual(p["owned"], "JDOE@CORP.LOCAL")
        self.assertIn("DOMAIN ADMINS", p["target"])
        self.assertIn("MemberOf", p["path"])
        self.assertIn("GenericAll", p["path"])

    def test_unowned_principal_no_path(self):
        # we own nobody in the graph -> no path
        self.store.add_credential(Credential("stranger", "pw", domain="corp.local"))
        self.assertEqual(owned_paths(self.store), [])

    def test_short_domain_name_matches(self):
        # cred domain "CORP" should match node "JDOE@CORP.LOCAL" on the first label
        self.store.add_credential(Credential("jdoe", "pw", domain="CORP"))
        self.assertEqual(len(owned_paths(self.store)), 1)

    def test_reimport_replaces_graph(self):
        counts = import_graph(self.store, self.dir)
        self.assertEqual(counts["nodes"], 3)  # not doubled
        self.assertEqual(self.store.bh_counts()["nodes"], 3)

    def test_analyze_surfaces_bloodhound_path(self):
        self.store.add_credential(Credential("jdoe", "pw", domain="corp.local"))
        keys = [o.key for o in analyze(self.store) if o.key.startswith("bh:")]
        self.assertEqual(len(keys), 1)

    def test_no_graph_no_paths(self):
        self.store.bh_reset()
        self.store.add_credential(Credential("jdoe", "pw", domain="corp.local"))
        self.assertEqual(owned_paths(self.store), [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
