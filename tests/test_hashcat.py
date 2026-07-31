#!/usr/bin/env python3
"""Hashcat potfile ingest — cracked hashes → promoted credentials.

Pinned:

  * pure `parse_potfile` — text in, list of CrackedEntry out
  * hash type detected from shape (NT, LM:NT, DCC2, krb5tgs, ntlmv2, unknown)
  * plaintext split on the LAST colon (plaintexts may themselves contain colons)
  * `apply` matches cracked NT hashes against SAM/NTDS loot lines and promotes
    the plaintext as a Credential with the recovered principal
  * unmatched cracked hashes are kept as loot (`kind='cracked_hash'`) so a
    later dump ingest can retroactively attribute them
  * source on promoted creds is `hashcat` (audit trail in the report)
  * idempotent — re-ingesting the same potfile doesn't duplicate credentials
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import hashcat  # noqa: E402
from fieldkit.state import Store  # noqa: E402


NT_EMPTY = "31d6cfe0d16ae931b73c59d7e0c089c0"           # NT("")
NT_PW = "8846f7eaee8fb117ad06bdd830b7586c"              # NT("password")
LM_LMPW = "e52cac67419a9a224a3b108f3fa6cb6d"


class ParseTest(unittest.TestCase):
    def test_nt_hash_line(self):
        entries = hashcat.parse_potfile(f"{NT_PW}:password\n")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].hash, NT_PW)
        self.assertEqual(entries[0].plaintext, "password")
        self.assertEqual(entries[0].hash_type, "nt")

    def test_lm_nt_pair_detected(self):
        entries = hashcat.parse_potfile(f"{LM_LMPW}:{NT_PW}:lmpassword\n")
        # 32:32 = LM:NT pair; the plaintext is after the last colon
        self.assertEqual(entries[0].hash_type, "lm:nt")
        self.assertEqual(entries[0].plaintext, "lmpassword")

    def test_dcc2_and_krb_prefixes(self):
        entries = hashcat.parse_potfile(
            "$DCC2$10240#user#a1b2c3d4e5f6:Password1\n"
            "$krb5tgs$23$*svc$corp.local$svc*$xxxxx:CrackMe123!\n"
            "$krb5asrep$23$user@corp.local:xxxxx:HardOne\n")
        self.assertEqual(entries[0].hash_type, "dcc2")
        self.assertEqual(entries[1].hash_type, "krb5tgs")
        self.assertEqual(entries[2].hash_type, "krb5asrep")

    def test_plaintext_with_colons_uses_last_colon(self):
        entries = hashcat.parse_potfile(f"{NT_PW}:pass:word:with:colons\n")
        self.assertEqual(entries[0].plaintext, "pass:word:with:colons")

    def test_blank_and_comment_lines_are_skipped(self):
        entries = hashcat.parse_potfile(
            f"# a comment\n\n{NT_PW}:password\n#another comment\n")
        self.assertEqual(len(entries), 1)

    def test_empty_input_returns_empty_list(self):
        self.assertEqual(hashcat.parse_potfile(""), [])
        self.assertEqual(hashcat.parse_potfile(None), [])


class ApplyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME")
        self.hid, _ = self.store.add_host("10.0.0.7", os_name="windows")

    def _seed_sam(self):
        self.store.add_loot(
            self.hid, "sam_hash",
            value=f"Administrator:500:aad3b435b51404eeaad3b435b51404ee:{NT_EMPTY}:::")
        self.store.add_loot(
            self.hid, "sam_hash",
            value=f"CORP\\svcadmin:1103:aad3b435b51404eeaad3b435b51404ee:{NT_PW}:::")

    def test_matched_hashes_become_credentials(self):
        self._seed_sam()
        entries = hashcat.parse_potfile(
            f"{NT_EMPTY}:(blank)\n{NT_PW}:password\n")
        rep = hashcat.apply(self.store, entries)
        self.assertEqual(rep.matched, 2)
        self.assertEqual(rep.creds_promoted, 2)
        creds = {(c["username"], c["domain"], c["secret"])
                 for c in self.store.credentials()}
        self.assertIn(("Administrator", "", "(blank)"), creds)
        self.assertIn(("svcadmin", "CORP", "password"), creds)
        # source tag survived so the report can show provenance
        for c in self.store.credentials():
            self.assertEqual(c["source"], "hashcat")

    def test_unmatched_cracked_hash_kept_as_loot(self):
        # no SAM loot for this hash → the cracked pair should still be recorded
        entries = hashcat.parse_potfile("deadbeef00112233445566778899aabb:GhostPass\n")
        rep = hashcat.apply(self.store, entries)
        self.assertEqual(rep.matched, 0)
        self.assertEqual(rep.creds_promoted, 0)
        self.assertEqual(rep.unmatched_stored, 1)
        stored = [r for r in self.store.loot() if r["kind"] == "cracked_hash"]
        self.assertEqual(len(stored), 1)
        self.assertIn("GhostPass", stored[0]["value"])

    def test_matches_survive_dump_ingested_later(self):
        # cracked first, THEN the SAM dump lands — a subsequent re-apply attributes
        entries = hashcat.parse_potfile(f"{NT_PW}:password\n")
        r1 = hashcat.apply(self.store, entries)
        self.assertEqual(r1.creds_promoted, 0)   # no loot to match yet
        # dump lands
        self._seed_sam()
        r2 = hashcat.apply(self.store, entries)
        self.assertEqual(r2.matched, 1)
        self.assertEqual(r2.creds_promoted, 1)
        self.assertIn(("svcadmin", "CORP", "password"),
                      {(c["username"], c["domain"], c["secret"])
                       for c in self.store.credentials()})

    def test_idempotent_on_second_apply(self):
        self._seed_sam()
        entries = hashcat.parse_potfile(f"{NT_PW}:password\n")
        hashcat.apply(self.store, entries)
        r2 = hashcat.apply(self.store, entries)
        # matched again but no new cred (add_credential dedupes)
        self.assertEqual(r2.matched, 1)
        self.assertEqual(r2.creds_promoted, 0)
        self.assertEqual(self.store.counts()["credentials"], 1)

    def test_domain_prefix_in_sam_line_splits_correctly(self):
        # DOMAIN\user:RID:LM:NT:::  →  domain=DOMAIN, user=user
        self._seed_sam()
        entries = hashcat.parse_potfile(f"{NT_PW}:password\n")
        hashcat.apply(self.store, entries)
        matched = [c for c in self.store.credentials() if c["username"] == "svcadmin"][0]
        self.assertEqual(matched["domain"], "CORP")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
