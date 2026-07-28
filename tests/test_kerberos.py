#!/usr/bin/env python3
"""Kerberos roasting — tickets parsed into crackable loot that feeds the loop.

Pinned:

  * the $krb5tgs$/$krb5asrep$ hashes are parsed whole with account + realm;
  * run_roast drives nxc per kind and stores each hash as loot (deduped), so an
    operator cracks offline and re-sprays;
  * the analyze KB surfaces roastable loot as a ranked next move.

Run:  python3 -m unittest discover -s tests
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit.creds import Credential  # noqa: E402
from fieldkit.kb import analyze  # noqa: E402
from fieldkit.kerberos import parse_roast, run_roast  # noqa: E402
from fieldkit.runner import RunResult  # noqa: E402
from fieldkit.state import Store  # noqa: E402

TGS = ("$krb5tgs$23$*svc_sql$CORP.LOCAL$svc_sql*$"
       + "a1b2c3" * 20)
ASREP = "$krb5asrep$23$roastme@CORP.LOCAL:" + "d4e5f6" * 20


class ParseTest(unittest.TestCase):
    def test_parse_tgs(self):
        r = [x for x in parse_roast(f"LDAP  dc  389  DC  {TGS}") if x.kind == "kerberoast"][0]
        self.assertEqual(r.account, "svc_sql")
        self.assertEqual(r.realm, "CORP.LOCAL")
        self.assertEqual(r.hash, TGS)

    def test_parse_asrep(self):
        r = [x for x in parse_roast(ASREP) if x.kind == "asrep_roast"][0]
        self.assertEqual(r.account, "roastme")
        self.assertEqual(r.realm, "CORP.LOCAL")

    def test_dedup(self):
        self.assertEqual(len(parse_roast(TGS + "\n" + TGS)), 1)

    def test_noise_ignored(self):
        self.assertEqual(parse_roast("no hashes here\n[*] done"), [])


class RunRoastTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME")
        self.dc_id, _ = self.store.add_host("10.0.0.10", hostname="DC01", is_dc=True,
                                            os_name="windows")
        cid, _ = self.store.add_credential(Credential("jdoe", "pw", domain="corp.local"))
        self.dc = self.store.host_by_ip("10.0.0.10")
        self.cred = self.store.credential_by_id(cid)

    def _runner(self):
        def run(argv, env=None):
            if "--kerberoasting" in argv:
                return RunResult(argv, 0, stdout=f"LDAP dc 389 DC {TGS}")
            if "--asreproast" in argv:
                return RunResult(argv, 0, stdout=ASREP)
            return RunResult(argv, 0, stdout="")
        return run

    def test_roast_stores_loot(self):
        rep = run_roast(self.store, self.dc, self.cred, run=self._runner())
        self.assertIsNone(rep.aborted)
        self.assertEqual(rep.recovered, 2)
        self.assertEqual(len(self.store.loot(kind="kerberoast")), 1)
        self.assertEqual(len(self.store.loot(kind="asrep_roast")), 1)

    def test_reroast_is_deduped(self):
        run_roast(self.store, self.dc, self.cred, run=self._runner())
        rep = run_roast(self.store, self.dc, self.cred, run=self._runner())
        self.assertEqual(rep.recovered, 0)                       # already in loot
        self.assertEqual(len(self.store.loot(kind="kerberoast")), 1)

    def test_analyze_surfaces_roastable_loot(self):
        run_roast(self.store, self.dc, self.cred, run=self._runner())
        keys = {o.key for o in analyze(self.store)}
        self.assertIn("roast-kerberoast", keys)
        self.assertIn("roast-asrep_roast", keys)

    def test_runner_failure_aborts(self):
        def dead(argv, env=None):
            return RunResult(argv, error="nxc: not found")
        rep = run_roast(self.store, self.dc, self.cred, run=dead)
        self.assertIn("not found", rep.aborted)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
