#!/usr/bin/env python3
"""Recce bridge ingest — recce-bridge.json into fieldkit state.

Pinned:

  * pure ``parse(text) -> RecceIntent`` — no store, no I/O
  * ``apply(store, intent)`` folds into state in one transaction, respects scope
  * only recce-CONFIRMED findings land as fieldkit findings
  * exploit_cmds land as `recce_version_lookup` findings (leads, not proofs)
  * idempotent — re-ingesting doesn't duplicate hosts, services, or findings
  * bridge version mismatch raises a clear operator error, doesn't half-parse
  * `analyze` promotes recce-confirmed findings over unranked opportunities
  * hosts outside `scope_rule` land in ``out_of_scope`` and don't insert
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import kb, recce  # noqa: E402
from fieldkit.state import Store  # noqa: E402


FIXTURE_PATH = os.path.join(os.path.dirname(__file__),
                            "fixtures", "recce-bridge-sample.json")


def _load_fixture():
    with open(FIXTURE_PATH, "r") as fh:
        return fh.read()


class ParseTest(unittest.TestCase):
    def test_valid_bridge_yields_expected_shape(self):
        intent = recce.parse(_load_fixture())
        self.assertEqual(intent.engagement, "ACME Internal")
        self.assertEqual(intent.generated, "2026-08-28T13:45:00Z")
        # 4 hosts in the fixture
        self.assertEqual(len(intent.hosts), 4)
        by_ip = {h.ip: h for h in intent.hosts}
        # WS02 — 3 open ports, 2 confirmed findings, no version routes
        ws02 = by_ip["10.0.0.7"]
        self.assertEqual(ws02.hostname, "WS02")
        self.assertEqual(ws02.os, "Windows 10 Pro 22H2")
        self.assertEqual(sorted(s.port for s in ws02.services), [445, 3389, 5985])
        self.assertEqual(len(ws02.findings), 2)
        self.assertEqual(ws02.findings[0].severity, "critical")
        self.assertIn("CVE-2017-0143", ws02.findings[0].cves)
        # WEB01 — 3 open ports, 1 finding, 2 version routes
        web01 = by_ip["10.0.0.11"]
        self.assertEqual(len(web01.findings), 1)
        self.assertEqual(web01.findings[0].severity, "high")
        self.assertEqual(len(web01.version_routes), 2)
        vr = {v.service: v for v in web01.version_routes}
        self.assertEqual(vr["apache"].version, "2.4.49")
        self.assertEqual(vr["apache"].cves, ["CVE-2021-41773"])
        self.assertEqual(vr["postgres"].cves, [])         # version-lead without CVE

    def test_users_carried_through(self):
        intent = recce.parse(_load_fixture())
        self.assertEqual(sorted(intent.users),
                         ["alice", "bob", "charlie", "svc_backup"])

    def test_missing_bridge_version_raises_clear_error(self):
        payload = json.dumps({"hosts": []})
        with self.assertRaises(recce.RecceBridgeError) as cm:
            recce.parse(payload)
        self.assertIn("_recce_bridge", str(cm.exception))

    def test_unsupported_bridge_version_raises_clear_error(self):
        payload = json.dumps({"_recce_bridge": 999, "hosts": []})
        with self.assertRaises(recce.RecceBridgeError) as cm:
            recce.parse(payload)
        self.assertIn("999", str(cm.exception))
        self.assertIn("major", str(cm.exception))

    def test_potential_findings_are_dropped(self):
        # only confirmed vulns cross into fieldkit — potentials are recce's follow-up.
        payload = json.dumps({
            "_recce_bridge": 1,
            "hosts": [{
                "ip": "10.0.0.5",
                "findings": [
                    {"title": "confirmed one", "severity": "high",
                     "confidence": "confirmed"},
                    {"title": "potential one", "severity": "high",
                     "confidence": "potential"},
                ],
            }],
        })
        intent = recce.parse(payload)
        self.assertEqual(len(intent.hosts[0].findings), 1)
        self.assertEqual(intent.hosts[0].findings[0].title, "confirmed one")

    def test_malformed_json_raises_clear_error(self):
        with self.assertRaises(recce.RecceBridgeError) as cm:
            recce.parse("{not valid json")
        self.assertIn("valid JSON", str(cm.exception))

    def test_bytes_input_decodes(self):
        intent = recce.parse(_load_fixture().encode("utf-8"))
        self.assertEqual(len(intent.hosts), 4)


class ApplyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME")

    def test_end_to_end_hosts_services_findings_persist(self):
        rep = recce.apply(self.store, recce.parse(_load_fixture()))
        self.assertEqual(rep.hosts_added, 4)
        # 3 (WS02) + 3 (WEB01) + 1 (PRINT01) + 1 (JUMPBOX)
        self.assertEqual(rep.services_added, 8)
        self.assertEqual(rep.confirmed_added, 3)         # 2 on WS02 + 1 on WEB01
        self.assertEqual(rep.version_routes_added, 2)    # both on WEB01
        # hosts reachable via state
        ws02 = self.store.host_by_ip("10.0.0.7")
        self.assertIsNotNone(ws02)
        self.assertEqual(ws02["hostname"], "WS02")
        # findings live under vector_type recce_confirmed_vuln
        findings = self.store.findings()
        vtypes = sorted({f["vector_type"] for f in findings})
        self.assertIn(recce.VECTOR_CONFIRMED, vtypes)
        self.assertIn(recce.VECTOR_VERSION_ROUTE, vtypes)
        # severity + cve made it into the evidence line
        conf = [f for f in findings if f["vector_type"] == recce.VECTOR_CONFIRMED]
        titles = [f["title"] for f in conf]
        self.assertTrue(any("EternalBlue" in t for t in titles))
        eb = next(f for f in conf if "EternalBlue" in f["title"])
        self.assertEqual(eb["severity"], "critical")
        self.assertIn("CVE-2017-0143", eb["evidence"])

    def test_idempotent_second_apply_no_duplication(self):
        recce.apply(self.store, recce.parse(_load_fixture()))
        rep2 = recce.apply(self.store, recce.parse(_load_fixture()))
        self.assertEqual(rep2.hosts_added, 0)
        self.assertEqual(rep2.hosts_enriched, 4)
        self.assertEqual(rep2.services_added, 0)
        self.assertEqual(rep2.services_enriched, 8)
        self.assertEqual(rep2.confirmed_added, 0)
        self.assertEqual(rep2.confirmed_seen, 3)
        self.assertEqual(rep2.version_routes_added, 0)
        self.assertEqual(rep2.version_routes_seen, 2)
        # only one row per unique finding despite the second apply
        self.assertEqual(len(self.store.findings()), 3 + 2)

    def test_out_of_scope_hosts_skipped(self):
        # scope narrows to 10.0.0.0/29 (0-7) — WEB01 (.11), PRINT01 (.13), JUMPBOX (.42) all out
        self.store.scope_add("10.0.0.0/29", kind="allow")
        rep = recce.apply(self.store, recce.parse(_load_fixture()))
        self.assertEqual(rep.hosts_added, 1)                       # only WS02 .7 lands
        self.assertEqual(sorted(rep.out_of_scope),
                         ["10.0.0.11", "10.0.0.13", "10.0.0.42"])
        self.assertIsNotNone(self.store.host_by_ip("10.0.0.7"))
        self.assertIsNone(self.store.host_by_ip("10.0.0.11"))

    def test_host_only_bridge_still_enriches(self):
        # bridge with hosts but no findings still writes host/service rows.
        payload = json.dumps({
            "_recce_bridge": 1,
            "hosts": [{
                "ip": "10.0.0.5", "hostname": "ONLY-HOST",
                "ports": [{"port": 22, "product": "OpenSSH", "version": "9.0"}],
                "findings": [], "exploit_cmds": [],
            }],
        })
        rep = recce.apply(self.store, recce.parse(payload))
        self.assertEqual(rep.hosts_added, 1)
        self.assertEqual(rep.services_added, 1)
        self.assertEqual(rep.confirmed_added, 0)
        self.assertEqual(rep.version_routes_added, 0)

    def test_finding_title_prefix_flags_recce_origin(self):
        # operators must see `[recce]` at a glance to distinguish source in status
        recce.apply(self.store, recce.parse(_load_fixture()))
        titles = [f["title"] for f in self.store.findings()]
        self.assertTrue(all(t.startswith("[recce]") for t in titles))


class AnalyzePromotionTest(unittest.TestCase):
    """End-to-end: apply → analyze → recce-confirmed opportunities appear."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME")
        recce.apply(self.store, recce.parse(_load_fixture()))

    def test_recce_confirmed_yields_high_ranked_opportunities(self):
        opps = kb.analyze(self.store)
        recce_conf_keys = [o.key for o in opps if o.key.startswith("recce-conf:")]
        # 3 confirmed findings in the fixture → 3 opportunities
        self.assertEqual(len(recce_conf_keys), 3)
        # critical-severity finding should rank high (exploitability="high")
        eternal_blue = next(o for o in opps if "EternalBlue" in o.title)
        self.assertEqual(eternal_blue.exploitability, "high")
        self.assertGreaterEqual(eternal_blue.score, 320)   # high × config-change × moderate

    def test_recce_version_route_yields_medium_when_cve_known(self):
        opps = kb.analyze(self.store)
        ver = [o for o in opps if o.key.startswith("recce-ver:")]
        # 2 version routes — one with CVE (medium), one without (low)
        self.assertEqual(len(ver), 2)
        with_cve = [o for o in ver if "apache" in o.title.lower()]
        without_cve = [o for o in ver if "postgres" in o.title.lower()]
        self.assertEqual(with_cve[0].exploitability, "medium")
        self.assertEqual(without_cve[0].exploitability, "low")


if __name__ == "__main__":
    unittest.main()
