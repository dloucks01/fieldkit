#!/usr/bin/env python3
"""Bridge AD/host state into the asset graph.

Pinned:
  * hosts → ad_host assets (owned when we admin them, high-value when a DC);
  * recovered credentials → ad_principal assets (owned; admin when admin-on-a-DC),
    carrying UPN / DOMAIN\\user aliases;
  * access rows → principal→host edges (+ host→principal 'dumps credential' on hosts
    we admin); idempotent;
  * end-to-end: a recovered domain account whose UPN matches a cloud principal stitches
    a cross-domain path AD → cloud admin.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import adbridge, assetgraph, cloud_iam  # noqa: E402
from fieldkit.creds import Credential  # noqa: E402
from fieldkit.state import Store  # noqa: E402


class AdBridgeTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("AD")

    def _asset(self, kind, key):
        row = self.store.asset_by_key(kind, key)
        return json.loads(row["props_json"] or "{}") if row else None


class ProjectionTest(AdBridgeTestCase):
    def test_hosts_and_creds_become_assets_with_flags(self):
        ws, _ = self.store.add_host("10.0.0.5", hostname="WS01")
        dc, _ = self.store.add_host("10.0.0.1", hostname="DC01", is_dc=True)
        cred = Credential(username="svc", secret="Pw!", domain="corp.local")
        cid, _ = self.store.add_credential(cred, source="dump")
        da = Credential(username="administrator", secret="aaaa", secret_type="nt",
                        domain="corp.local")
        did, _ = self.store.add_credential(da, source="dcsync")
        # svc is local admin on WS01; administrator is admin on the DC (⇒ domain-admin)
        self.store.add_access(ws, cid, "winrm", admin=True)
        self.store.add_access(dc, did, "smb", admin=True)

        rep = adbridge.bridge_ad(self.store)
        self.assertEqual(rep.hosts_added, 2)
        self.assertEqual(rep.principals_added, 2)

        self.assertTrue(self._asset("ad_host", "10.0.0.5")["owned"])    # we admin WS01
        self.assertFalse(self._asset("ad_host", "10.0.0.5")["admin"])   # not a DC
        self.assertTrue(self._asset("ad_host", "10.0.0.1")["admin"])    # DC → high-value

        svc = self._asset("ad_principal", "corp.local\\svc")
        self.assertTrue(svc["owned"])
        self.assertFalse(svc["admin"])
        self.assertIn("svc@corp.local", svc["aliases"])
        self.assertTrue(self._asset("ad_principal",
                                    "corp.local\\administrator")["admin"])  # admin on DC

    def test_access_becomes_edges(self):
        ws, _ = self.store.add_host("10.0.0.5", hostname="WS01")
        cid, _ = self.store.add_credential(
            Credential(username="svc", secret="Pw!", domain="corp.local"))
        self.store.add_access(ws, cid, "winrm", admin=True)
        adbridge.bridge_ad(self.store)
        kinds = {e["kind"] for e in self.store.asset_edges()}
        # principal -local admin-> host, and (host is admin) host -dumps credential-> principal
        self.assertIn("local admin", kinds)
        self.assertIn("dumps credential", kinds)

    def test_idempotent(self):
        self.store.add_host("10.0.0.5", hostname="WS01")
        cid, _ = self.store.add_credential(
            Credential(username="svc", secret="Pw!", domain="corp.local"))
        self.store.add_access(self.store.host_by_ip("10.0.0.5")["id"], cid, "smb")
        adbridge.bridge_ad(self.store)
        n_assets = len(self.store.assets())
        n_edges = len(self.store.asset_edges())
        rep = adbridge.bridge_ad(self.store)
        self.assertEqual((rep.hosts_added, rep.principals_added, rep.edges_added),
                         (0, 0, 0))
        self.assertEqual(len(self.store.assets()), n_assets)
        self.assertEqual(len(self.store.asset_edges()), n_edges)


class CrossDomainStitchTest(AdBridgeTestCase):
    def test_recovered_ad_account_stitches_into_cloud(self):
        # recovered domain account 'helga' with UPN helga@corp.com; a cloud principal
        # with the same UPN can self-escalate to cloud admin.
        cid, _ = self.store.add_credential(
            Credential(username="helga", secret="Pw!", domain="corp.com"), source="dump")
        cloud_iam.apply_iam(self.store, json.dumps({"provider": "aws", "principals": [
            {"arn": "arn:aws:iam::1:role/helga", "name": "helga@corp.com",
             "permissions": ["iam:CreateAccessKey"]}]}))
        adbridge.bridge_ad(self.store)
        pivots, added, paths = assetgraph.record_cross_domain(self.store)
        self.assertGreaterEqual(pivots, 1)              # AD→cloud federated match
        self.assertEqual(len(paths), 1)
        p = paths[0]
        self.assertEqual(p["domains"], ["ad", "cloud"])
        self.assertIn("[ad]", p["evidence"])
        self.assertIn("[cloud]", p["evidence"])

    def test_no_identity_overlap_no_cross_path(self):
        self.store.add_credential(
            Credential(username="bob", secret="Pw!", domain="corp.com"))
        cloud_iam.apply_iam(self.store, json.dumps({"provider": "aws", "principals": [
            {"arn": "arn:aws:iam::1:user/alice", "name": "alice@corp.com", "owned": True,
             "permissions": ["iam:CreateAccessKey"]}]}))
        adbridge.bridge_ad(self.store)
        assetgraph.derive_pivots(self.store)
        # bob (ad) and alice (cloud) share no identity → no cross-domain stitch
        self.assertEqual(assetgraph.cross_domain_paths(self.store), [])


class EndpointLinkTest(AdBridgeTestCase):
    def test_endpoint_linked_to_host_by_host_id(self):
        hid, _ = self.store.add_host("10.0.0.9", hostname="WEB01")
        self.store.add_asset("endpoint", "https://web01/app", host_id=hid)
        adbridge.bridge(self.store)
        ep = self.store.asset_by_key("endpoint", "https://web01/app")["id"]
        host = self.store.asset_by_key("ad_host", "10.0.0.9")["id"]
        self.assertTrue(any(e["src_id"] == ep and e["dst_id"] == host
                            and e["kind"] == "hosted on"
                            for e in self.store.asset_edges()))

    def test_endpoint_linked_by_ip_literal_without_host_id(self):
        hid, _ = self.store.add_host("10.0.0.20")
        self.store.add_asset("endpoint", "http://10.0.0.20:8080")   # no host_id
        adbridge.bridge(self.store)
        ep = self.store.asset_by_key("endpoint", "http://10.0.0.20:8080")["id"]
        host = self.store.asset_by_key("ad_host", "10.0.0.20")["id"]
        self.assertTrue(any(e["src_id"] == ep and e["dst_id"] == host
                            for e in self.store.asset_edges()))

    def test_proven_rce_owns_endpoint_but_plain_web_vuln_does_not(self):
        hid, _ = self.store.add_host("10.0.0.9", hostname="WEB01")
        shell_ep, _ = self.store.add_asset("endpoint", "https://web01/shell", host_id=hid)
        info_ep, _ = self.store.add_asset("endpoint", "https://web01/info", host_id=hid)
        self.store.add_finding("rce_web", "RCE", asset_id=shell_ep, proven=True,
                               evidence="id=www-data")
        self.store.add_finding("web_vuln", "info leak", asset_id=info_ep, proven=True,
                               evidence="nuclei match")
        adbridge.bridge(self.store)
        shell = json.loads(self.store.asset_by_id(shell_ep)["props_json"])
        info = json.loads(self.store.asset_by_id(info_ep)["props_json"])
        self.assertTrue(shell["owned"])            # code-exec ⇒ foothold
        self.assertFalse(info.get("owned", False))  # a nuclei match is not a shell

    def test_web_rce_to_dc_is_a_cross_domain_path(self):
        # a proven RCE on a web app hosted on a domain controller = web → AD escalation
        dc, _ = self.store.add_host("10.0.0.1", hostname="DC01", is_dc=True)
        ep, _ = self.store.add_asset("endpoint", "https://dc01/app", host_id=dc)
        self.store.add_finding("webshell", "uploaded shell", asset_id=ep, proven=True,
                               evidence="whoami")
        adbridge.bridge(self.store)
        paths = assetgraph.cross_domain_paths(self.store)
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["domains"], ["web", "ad"])
        self.assertIn("hosted on", paths[0]["evidence"])

    def test_idempotent(self):
        hid, _ = self.store.add_host("10.0.0.9", hostname="WEB01")
        ep, _ = self.store.add_asset("endpoint", "https://web01/app", host_id=hid)
        self.store.add_finding("rce_web", "RCE", asset_id=ep, proven=True, evidence="id")
        adbridge.bridge(self.store)
        edges, owned = adbridge.link_endpoints(self.store)
        self.assertEqual((edges, owned), (0, 0))   # nothing new the second time


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
