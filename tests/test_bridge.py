#!/usr/bin/env python3
"""The recce bridge (v2) — same wire contract as v1, sourced from state.

This is the compatibility surface recce depends on. It mirrors the v1
test_integration_recce ExportRecceTest, but drives the v2 path: proven findings in
the engagement database -> `fieldkit export-recce` -> the recce-import JSON.

Pinned: source == "fieldkit", each finding gets a `_recce` block with ip/hostname,
lowercased severity, KB CWE + remediation, risk, confidence "confirmed", and CVE ids.

Run:  python3 -m unittest discover -s tests
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit.bridge import export_payload, recce_block  # noqa: E402
from fieldkit.cli import main  # noqa: E402
from fieldkit.state import Store  # noqa: E402


class RecceBlockTest(unittest.TestCase):
    def test_block_resolves_from_kb(self):
        finding = {"vector_type": "unquoted_service", "ip": "10.0.0.5",
                   "hostname": "WIN-SQL01", "references": "CVE-2020-1234"}
        r = recce_block(finding)
        self.assertEqual(r["ip"], "10.0.0.5")
        self.assertEqual(r["hostname"], "WIN-SQL01")
        self.assertEqual(r["severity"], "high")          # KB sev, lowercased
        self.assertEqual(r["cwe"], "CWE-428")            # KB CWE
        self.assertTrue(r["remediation"])                # KB remediation resolved
        self.assertEqual(r["confidence"], "confirmed")
        self.assertIn("CVE-2020-1234", r["ids"])         # finding references folded in

    def test_ids_come_from_kb_refs_too(self):
        r = recce_block({"vector_type": "printnightmare", "ip": "10.0.0.6"})
        self.assertIn("CVE-2021-34527", r["ids"])        # KB refs

    def test_payload_shape(self):
        payload = export_payload({"client": "ACME"},
                                 [{"vector_type": "gtfobins_sudo", "ip": "10.0.0.6",
                                   "hostname": "web01"}])
        self.assertEqual(payload["_recce_import"], 1)
        self.assertEqual(payload["source"], "fieldkit")
        self.assertIn("_recce", payload["findings"][0])
        # original finding fields are preserved alongside _recce
        self.assertEqual(payload["findings"][0]["vector_type"], "gtfobins_sudo")


class ExportRecceCliTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = os.path.join(self.tmp.name, "e.db")

    def run_cli(self, *args, expect=0):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["--db", self.db, *args])
        text = out.getvalue() + err.getvalue()
        self.assertEqual(code, expect, text)
        return text

    def _seed(self):
        store = Store.open(self.db)
        self.addCleanup(store.close)
        hid, _ = store.add_host("10.0.0.5", hostname="WIN-SQL01", os_name="windows")
        fid, _ = store.add_finding("printnightmare", "PrintNightmare RCE", host_id=hid,
                                   proven=True, evidence="spooler loaded our DLL as SYSTEM")
        store.add_step(cmd="Invoke-Nightmare", output="SYSTEM", host_id=hid, finding_id=fid)

    def test_export_recce_end_to_end(self):
        self.run_cli("init", "ACME")
        self._seed()
        out = os.path.join(self.tmp.name, "recce.json")
        text = self.run_cli("export-recce", out)
        self.assertIn("recce fieldkit-import", text)
        data = json.load(open(out))
        self.assertEqual(data["source"], "fieldkit")
        r = data["findings"][0]["_recce"]
        self.assertEqual(r["ip"], "10.0.0.5")
        self.assertEqual(r["hostname"], "WIN-SQL01")
        self.assertEqual(r["severity"], "critical")
        self.assertIn("CVE-2021-34527", r["ids"])

    def test_export_recce_needs_a_proven_finding(self):
        self.run_cli("init", "ACME")
        out = self.run_cli("export-recce", expect=2)
        self.assertIn("no proven findings", out)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
