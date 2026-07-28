#!/usr/bin/env python3
"""Parsing a credential dump — the ``loot → creds`` promotion rule.

The line that matters: a SAM/NTDS NT hash or an LSA cleartext password becomes a
credential the loop reuses; a cached ``$DCC2$`` blob, a machine account, or a DPAPI
key is loot only. Promoting a ``$DCC2$`` string as a password would poison the next
spray, so that boundary is pinned here.

Run:  python3 -m unittest discover -s tests
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit.dump import parse_dump  # noqa: E402

NT = "31d6cfe0d16ae931b73c59d7e0c089c0"
LM = "e52cac67419a9a224a3b108f3fa6cb6d"

SAM = f"""\
SMB   10.0.0.7   445   WS02   [+] Dumping SAM hashes
SMB   10.0.0.7   445   WS02   Administrator:500:aad3b435b51404eeaad3b435b51404ee:{NT}:::
SMB   10.0.0.7   445   WS02   Guest:501:aad3b435b51404eeaad3b435b51404ee:{NT}:::
SMB   10.0.0.7   445   WS02   [+] Added 2 SAM hashes to the database
"""

LSA = f"""\
SMB   10.0.0.7   445   WS02   [+] Dumping LSA secrets
SMB   10.0.0.7   445   WS02   CORP\\svc_sql:Summer2024!
SMB   10.0.0.7   445   WS02   CORP\\Administrator:$DCC2$10240#Administrator#abcdef0123456789
SMB   10.0.0.7   445   WS02   CORP\\WS02$:aad3b435b51404eeaad3b435b51404ee:{NT}:::
SMB   10.0.0.7   445   WS02   dpapi_machinekey:0x0102030405060708
"""


class SamTest(unittest.TestCase):
    def test_local_hash_promoted_as_local_nt(self):
        entries = parse_dump(SAM)
        admin = [e for e in entries if e.principal == "Administrator"][0]
        self.assertEqual(admin.kind, "sam_hash")
        self.assertTrue(admin.promotable)
        self.assertEqual(admin.credential.secret_type, "nt")
        self.assertEqual(admin.credential.secret, NT)
        self.assertTrue(admin.credential.local_auth)  # SAM = a local account
        self.assertEqual(admin.credential.domain, "")

    def test_headers_and_summaries_skipped(self):
        # Only the two account rows are data, not the "[+] Dumping"/"Added" lines.
        self.assertEqual(len(parse_dump(SAM)), 2)


class LsaTest(unittest.TestCase):
    def test_cleartext_promoted_as_domain_password(self):
        svc = [e for e in parse_dump(LSA) if e.principal.endswith("svc_sql")][0]
        self.assertTrue(svc.promotable)
        self.assertEqual(svc.credential.domain, "CORP")
        self.assertEqual(svc.credential.username, "svc_sql")
        self.assertEqual(svc.credential.secret_type, "password")
        self.assertEqual(svc.credential.secret, "Summer2024!")

    def test_dcc2_is_loot_not_a_password(self):
        dcc2 = [e for e in parse_dump(LSA) if "$DCC2$" in e.raw][0]
        self.assertFalse(dcc2.promotable)  # never sprayed as a password

    def test_machine_account_hash_is_loot_only(self):
        machine = [e for e in parse_dump(LSA) if "WS02$" in e.raw][0]
        self.assertFalse(machine.promotable)

    def test_dpapi_key_is_loot_only(self):
        dpapi = [e for e in parse_dump(LSA) if e.raw.startswith("dpapi")][0]
        self.assertFalse(dpapi.promotable)

    def test_every_line_is_recorded_as_loot(self):
        # promotable or not, the raw secret is always kept as evidence.
        self.assertEqual(len(parse_dump(LSA)), 4)


class NtdsTest(unittest.TestCase):
    def test_domain_hash_not_local(self):
        ntds = ("SMB   10.0.0.6   445   DC01   [+] Dumping the NTDS\n"
                f"SMB   10.0.0.6   445   DC01   CORP.LOCAL\\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:{NT}:::\n")
        e = parse_dump(ntds)[0]
        self.assertEqual(e.kind, "ntds_hash")
        self.assertFalse(e.credential.local_auth)
        self.assertEqual(e.credential.domain, "CORP.LOCAL")
        self.assertEqual(e.credential.username, "krbtgt")


class RawPasteTest(unittest.TestCase):
    def test_secretsdump_without_nxc_prefix(self):
        raw = f"Administrator:500:{LM}:{NT}:::\n"
        e = parse_dump(raw)[0]
        self.assertTrue(e.promotable)
        self.assertEqual(e.credential.secret_type, "lm:nt")  # non-empty LM kept


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
