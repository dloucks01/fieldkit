#!/usr/bin/env python3
"""The v9 asset model — the general target layer (host / endpoint / cloud / …).

An asset is keyed by (kind, key), idempotent + enriching like host/service, and a
finding can attach to one via asset_id. This is what lets non-host domains (web,
cloud, k8s) flow through the same finding → step → report spine as AD.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit.state import SCHEMA_VERSION, Store  # noqa: E402


class AssetTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME")


class SchemaTest(AssetTestCase):
    def test_fresh_db_is_v9_with_asset_table(self):
        self.assertEqual(self.store.schema_version(), SCHEMA_VERSION)
        self.assertGreaterEqual(SCHEMA_VERSION, 9)
        self.assertTrue(self.store.conn.execute(
            "SELECT name FROM sqlite_master WHERE name='asset'").fetchone())
        cols = [r[1] for r in self.store.conn.execute("PRAGMA table_info(finding)")]
        self.assertIn("asset_id", cols)

    def test_v8_database_upgrades_cleanly(self):
        import fieldkit.state as st
        orig, orig_ver = st.MIGRATIONS[:], st.SCHEMA_VERSION
        st.MIGRATIONS = [m for m in orig if m[0] <= 8]
        st.SCHEMA_VERSION = 8
        path = os.path.join(self.tmp.name, "v8.db")
        try:
            old = Store.create(path)
            old.init_engagement("OLD")
            self.assertEqual(old.schema_version(), 8)
            self.assertFalse(old.conn.execute(
                "SELECT name FROM sqlite_master WHERE name='asset'").fetchone())
            old.close()
        finally:
            st.MIGRATIONS, st.SCHEMA_VERSION = orig, orig_ver
        upgraded = Store.open(path)
        self.addCleanup(upgraded.close)
        self.assertEqual(upgraded.schema_version(), SCHEMA_VERSION)
        self.assertTrue(upgraded.conn.execute(
            "SELECT name FROM sqlite_master WHERE name='asset'").fetchone())
        self.assertEqual(upgraded.engagement()["name"], "OLD")   # data preserved


class AddAssetTest(AssetTestCase):
    def test_idempotent_on_kind_key(self):
        a, created = self.store.add_asset("endpoint", "https://x/")
        b, again = self.store.add_asset("endpoint", "https://x/")
        self.assertTrue(created)
        self.assertFalse(again)
        self.assertEqual(a, b)
        # a different kind with the same key is a distinct asset
        c, c_created = self.store.add_asset("cloud_principal", "https://x/")
        self.assertTrue(c_created)
        self.assertNotEqual(a, c)

    def test_enrich_merges_props_and_never_erases(self):
        aid, _ = self.store.add_asset("endpoint", "https://x/", label="X",
                                      props={"status": 200})
        self.store.add_asset("endpoint", "https://x/", props={"title": "Home"})
        self.store.add_asset("endpoint", "https://x/", label=None)   # None must not erase
        row = self.store.asset_by_key("endpoint", "https://x/")
        self.assertEqual(row["label"], "X")
        self.assertEqual(json.loads(row["props_json"]), {"status": 200, "title": "Home"})

    def test_links_to_host(self):
        hid, _ = self.store.add_host("10.0.0.5")
        aid, _ = self.store.add_asset("endpoint", "https://x/", host_id=hid)
        self.assertEqual(self.store.asset_by_id(aid)["host_id"], hid)

    def test_finding_attaches_to_asset(self):
        aid, _ = self.store.add_asset("endpoint", "https://x/")
        fid, created = self.store.add_finding("web_vuln", "CVE on x", asset_id=aid,
                                              proven=True, evidence="e")
        self.assertTrue(created)
        self.assertEqual(self.store.conn.execute(
            "SELECT asset_id FROM finding WHERE id=?", (fid,)).fetchone()[0], aid)
        # idempotent on (asset_id, vector_type, title)
        _, again = self.store.add_finding("web_vuln", "CVE on x", asset_id=aid)
        self.assertFalse(again)

    def test_assets_filter_by_kind(self):
        self.store.add_asset("endpoint", "https://a/")
        self.store.add_asset("endpoint", "https://b/")
        self.store.add_asset("cloud_principal", "arn:aws:iam::1:user/x")
        self.assertEqual(len(self.store.assets("endpoint")), 2)
        self.assertEqual(len(self.store.assets("cloud_principal")), 1)
        self.assertEqual(len(self.store.assets()), 3)


class AssetEdgeTest(AssetTestCase):
    """The v10 asset graph — directed edges between assets (cloud IAM / k8s RBAC / …)."""

    def test_add_edge_idempotent(self):
        a, _ = self.store.add_asset("cloud_principal", "arn:user/dev")
        b, _ = self.store.add_asset("cloud_principal", "arn:role/admin")
        e1, created = self.store.add_asset_edge(a, b, "sts:AssumeRole")
        e2, again = self.store.add_asset_edge(a, b, "sts:AssumeRole")
        self.assertTrue(created)
        self.assertFalse(again)
        self.assertEqual(e1, e2)
        self.assertEqual(len(self.store.asset_edges()), 1)
        # a different kind between the same pair is a distinct edge
        _, c3 = self.store.add_asset_edge(a, b, "iam:PassRole")
        self.assertTrue(c3)
        self.assertEqual(len(self.store.asset_edges()), 2)
        self.assertEqual(len(self.store.asset_edges(kind="iam:PassRole")), 1)

    def test_edge_cascades_on_asset_delete(self):
        a, _ = self.store.add_asset("cloud_principal", "arn:user/dev")
        b, _ = self.store.add_asset("cloud_principal", "arn:role/admin")
        self.store.add_asset_edge(a, b, "sts:AssumeRole")
        self.store.conn.execute("DELETE FROM asset WHERE id=?", (a,))
        self.assertEqual(len(self.store.asset_edges()), 0)   # ON DELETE CASCADE


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
