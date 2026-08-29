#!/usr/bin/env python3
"""status_json — the machine-readable projection of `fieldkit status`.

Pinned:

  * pure function — no printing, no I/O beyond SQLite reads
  * shape is versioned via `_projection`; consumers can refuse unsupported
    versions rather than half-parse
  * every field a human `status` line renders is present in the projection
  * top_moves / phase are opt-in — the projection stays cheap when the caller
    doesn't want the analyze-predicate cost
  * config only surfaces keys with a real value (no Nones cluttering the JSON)
"""
import json
import os
import sys
import tempfile
import unittest
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import status_json  # noqa: E402
from fieldkit.state import Store  # noqa: E402


@dataclass
class _FakeMove:
    """Duck-type an Opportunity for the projection to serialize."""
    key: str
    title: str
    host: str = None
    exploitability: str = "high"
    safety: str = "read-only"
    detection: str = "quiet"
    score: int = 333
    next_step: str = ""
    detail: str = ""
    evidence: str = ""
    manual: bool = False

    @property
    def axes(self):
        return f"{self.exploitability}/{self.safety}/{self.detection}"


class StatusDictTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME")

    def test_empty_engagement_projects_cleanly(self):
        payload = status_json.status_dict(self.store)
        # required keys
        for key in ("_projection", "engagement", "config", "scope", "counts",
                    "os_breakdown", "credential_types", "pwned_hosts",
                    "top_moves", "preflight_missing"):
            self.assertIn(key, payload, key)
        self.assertEqual(payload["_projection"], status_json.PROJECTION_VERSION)
        self.assertEqual(payload["engagement"]["name"], "ACME")
        self.assertEqual(payload["counts"]["hosts"], 0)
        self.assertEqual(payload["pwned_hosts"], [])
        self.assertEqual(payload["top_moves"], [])
        # phase is None when not passed — projection is pure
        self.assertIsNone(payload["phase"])

    def test_serializes_to_json_verbatim(self):
        # every value in the projection must be JSON-safe
        payload = status_json.status_dict(self.store)
        text = json.dumps(payload)      # no default= — will raise on bad types
        self.assertIn('"engagement"', text)
        # round-trips
        self.assertEqual(json.loads(text)["_projection"],
                         status_json.PROJECTION_VERSION)

    def test_counts_reflect_state(self):
        h, _ = self.store.add_host("10.0.0.7", hostname="WS02", os_name="windows")
        self.store.add_service(h, 445, product="Microsoft SMB")
        self.store.add_service(h, 3389)
        payload = status_json.status_dict(self.store)
        self.assertEqual(payload["counts"]["hosts"], 1)
        self.assertEqual(payload["counts"]["services"], 2)
        self.assertEqual(payload["os_breakdown"], {"windows": 1})

    def test_scope_rules_split_by_kind(self):
        self.store.scope_add("10.0.0.0/24", kind="allow")
        self.store.scope_add("10.0.0.13/32", kind="deny")
        payload = status_json.status_dict(self.store)
        self.assertEqual(payload["scope"]["allow"], ["10.0.0.0/24"])
        self.assertEqual(payload["scope"]["deny"], ["10.0.0.13/32"])

    def test_top_moves_are_serialized_when_provided(self):
        moves = [
            _FakeMove(key="recce-conf:1", title="EternalBlue on WS02",
                      host="10.0.0.7", score=333, exploitability="high",
                      safety="config-change", detection="moderate",
                      next_step="fieldkit escalate 10.0.0.7", detail="critical"),
        ]
        payload = status_json.status_dict(self.store, top_moves=moves)
        self.assertEqual(len(payload["top_moves"]), 1)
        m = payload["top_moves"][0]
        self.assertEqual(m["key"], "recce-conf:1")
        self.assertEqual(m["host"], "10.0.0.7")
        self.assertEqual(m["axes"], "high/config-change/moderate")
        self.assertEqual(m["next_step"], "fieldkit escalate 10.0.0.7")

    def test_config_omits_unset_keys(self):
        self.store.set_config({"lhost": "10.10.14.7", "lport": 443})
        payload = status_json.status_dict(self.store)
        self.assertEqual(payload["config"]["lhost"], "10.10.14.7")
        self.assertNotIn("recce_url", payload["config"])
        self.assertNotIn("domain", payload["config"])

    def test_top_moves_are_capped_at_ten(self):
        moves = [_FakeMove(key=f"m{i}", title=f"Move {i}") for i in range(20)]
        payload = status_json.status_dict(self.store, top_moves=moves)
        self.assertEqual(len(payload["top_moves"]), 10)

    def test_pwned_hosts_populated_when_admin_exists(self):
        # set up an admin access record on a host so pwned_hosts is non-empty
        h, _ = self.store.add_host("10.0.0.7", hostname="WS02", os_name="windows",
                                   is_dc=True)
        # need a credential to hang an access row on
        from fieldkit.creds import Credential
        cid, _ = self.store.add_credential(
            Credential(domain="CORP", username="admin", secret="hash",
                       secret_type="nt", local_auth=False))
        self.store.add_access(h, cid, method="smb", admin=True)
        payload = status_json.status_dict(self.store)
        self.assertEqual(len(payload["pwned_hosts"]), 1)
        self.assertEqual(payload["pwned_hosts"][0]["ip"], "10.0.0.7")
        self.assertTrue(payload["pwned_hosts"][0]["is_dc"])


if __name__ == "__main__":
    unittest.main()
