#!/usr/bin/env python3
"""Folding nxc output back into state — the write half of the credential loop.

Pinned here:

  * classify is pure and lossless — every ``[+]`` becomes a normalized credential
    with the right secret type, every ``[*]`` banner enriches its host;
  * apply is idempotent and monotonic — re-ingesting the same capture adds nothing,
    but a later admin result upgrades an existing non-admin access in place.

Run:  python3 -m unittest discover -s tests
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit.creds import Credential  # noqa: E402
from fieldkit.ingest import apply_nxc, classify_nxc  # noqa: E402
from fieldkit.state import Store  # noqa: E402

NT = "31d6cfe0d16ae931b73c59d7e0c089c0"

CAPTURE = f"""\
SMB   10.0.0.6   445   DC01   [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)
SMB   10.0.0.6   445   DC01   [+] corp.local\\jdoe:Winter2025!
SMB   10.0.0.7   445   WS02   [*] Windows 10 Build 19041 x64 (name:WS02) (domain:corp.local) (signing:False) (SMBv1:False)
SMB   10.0.0.7   445   WS02   [+] corp.local\\Administrator:{NT} (Pwn3d!)
SMB   10.0.0.8   445   WS03   [-] corp.local\\jdoe:Winter2025! STATUS_LOGON_FAILURE
"""


class ClassifyTest(unittest.TestCase):
    """Pure text → intent, no store."""

    def test_only_valid_results_become_creds(self):
        intent = classify_nxc(CAPTURE)
        self.assertEqual(len(intent.creds), 2)  # the [-] failure is dropped
        self.assertEqual(len(intent.hosts), 2)

    def test_password_and_hash_typed_correctly(self):
        by_user = {c.username: c for c, _ in classify_nxc(CAPTURE).creds}
        self.assertEqual(by_user["jdoe"].secret_type, "password")
        self.assertEqual(by_user["jdoe"].secret, "Winter2025!")
        self.assertEqual(by_user["Administrator"].secret_type, "nt")
        self.assertEqual(by_user["Administrator"].secret, NT)

    def test_admin_view(self):
        admin = classify_nxc(CAPTURE).admin
        self.assertEqual([r.ip for _, r in admin], ["10.0.0.7"])


class StoreAccessTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME")

    def _cred(self):
        cid, _ = self.store.add_credential(
            Credential(username="jdoe", secret="pw", domain="corp.local"))
        hid, _ = self.store.add_host("10.0.0.7")
        return hid, cid

    def test_access_is_idempotent(self):
        hid, cid = self._cred()
        _, first = self.store.add_access(hid, cid, "smb", admin=False)
        _, second = self.store.add_access(hid, cid, "smb", admin=False)
        self.assertTrue(first)
        self.assertFalse(second)
        self.assertEqual(self.store.counts()["access"], 1)

    def test_admin_upgrade_in_place(self):
        hid, cid = self._cred()
        self.store.add_access(hid, cid, "smb", admin=False)
        self.store.add_access(hid, cid, "smb", admin=True)  # later Pwn3d
        rows = self.store.access_on(hid)
        self.assertEqual(len(rows), 1)  # not a second row
        self.assertEqual(rows[0]["admin"], 1)
        self.assertEqual(self.store.counts()["admin_access"], 1)

    def test_admin_never_downgrades(self):
        hid, cid = self._cred()
        self.store.add_access(hid, cid, "smb", admin=True)
        self.store.add_access(hid, cid, "smb", admin=False)
        self.assertEqual(self.store.access_on(hid)[0]["admin"], 1)

    def test_different_methods_are_separate_rows(self):
        hid, cid = self._cred()
        self.store.add_access(hid, cid, "smb", admin=False)
        self.store.add_access(hid, cid, "winrm", admin=True)
        self.assertEqual(self.store.counts()["access"], 2)
        self.assertEqual(len(self.store.admin_hosts()), 1)  # still one host

    def test_loot_dedup(self):
        hid, _ = self.store.add_host("10.0.0.7")
        _, first = self.store.add_loot(hid, "nt_hash", value=NT)
        _, second = self.store.add_loot(hid, "nt_hash", value=NT)
        self.assertTrue(first)
        self.assertFalse(second)
        self.assertEqual(self.store.counts()["loot"], 1)


class ApplyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME")

    def test_apply_records_everything(self):
        rep = apply_nxc(self.store, classify_nxc(CAPTURE))
        c = self.store.counts()
        self.assertEqual(rep.creds_added, 2)
        self.assertEqual(c["credentials"], 2)
        self.assertEqual(c["access"], 2)
        self.assertEqual(c["admin_access"], 1)
        self.assertEqual(c["hosts"], 2)

    def test_banner_enriches_host(self):
        apply_nxc(self.store, classify_nxc(CAPTURE))
        dc = self.store.host_by_ip("10.0.0.6")
        self.assertEqual(dc["hostname"], "DC01")
        self.assertEqual(dc["os"], "windows")
        self.assertEqual(dc["is_dc"], 1)

    def test_reingest_is_noop(self):
        apply_nxc(self.store, classify_nxc(CAPTURE))
        rep = apply_nxc(self.store, classify_nxc(CAPTURE))
        self.assertEqual(rep.creds_added, 0)
        self.assertEqual(rep.access_added, 0)
        self.assertEqual(self.store.counts()["credentials"], 2)

    def test_admin_upgrade_across_captures(self):
        first = ("SMB   10.0.0.7   445   WS02   [+] corp.local\\svc:pw\n")
        apply_nxc(self.store, classify_nxc(first))
        self.assertEqual(self.store.counts()["admin_access"], 0)
        later = ("WINRM   10.0.0.7   5985   WS02   [+] corp.local\\svc:pw (Pwn3d!)\n")
        apply_nxc(self.store, classify_nxc(later))
        # winrm is a new method row; the svc cred now holds admin somewhere.
        self.assertEqual(self.store.counts()["admin_access"], 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
