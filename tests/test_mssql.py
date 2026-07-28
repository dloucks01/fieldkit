#!/usr/bin/env python3
"""MSSQL privilege escalation — low-priv login → sysadmin.

Pinned:

  * EXECUTE AS impersonation on a sysadmin login is proven read-only, then (only with
    config-change) the login is added to the sysadmin role — a proven finding with a
    captured step, the access upgraded to admin, and a reversible cleanup recorded;
  * without config-change it stays gated (surfaced, not changed);
  * linked servers are recorded as observations, not exploited.

The driven `nxc mssql -q` runner is faked; queries carry a `FK:` sentinel.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import mssql  # noqa: E402
from fieldkit.creds import Credential  # noqa: E402
from fieldkit.runner import RunResult  # noqa: E402
from fieldkit.state import Store  # noqa: E402


def fake_run(impersonatable_sysadmin="sa", linked=("SQL02",), starts_sysadmin=False,
             xp_directly=False):
    """A fake nxc mssql -q: routes by SQL content, tracks the role grant statefully.
    ``xp_directly`` = xp_cmdshell runs without being sysadmin (granted rights / already on)."""
    state = {"granted": False}

    def run(argv, env=None):
        sql = argv[argv.index("-q") + 1] if "-q" in argv else ""
        out = ""
        if "echo FK:XPOK" in sql:                       # the xp_cmdshell capability test
            if xp_directly or starts_sysadmin or state["granted"]:
                out = "FK:XPOK"
        elif "sp_configure" in sql:                     # enable/disable — no-op
            out = ""
        elif "sp_addsrvrolemember" in sql:
            state["granted"] = True
        elif "EXECUTE AS" in sql and "IS_SRVROLEMEMBER" in sql:
            out = "FK:1" if impersonatable_sysadmin else "FK:0"
        elif "IS_SRVROLEMEMBER" in sql:
            out = "FK:1" if starts_sysadmin else "FK:0"
        elif "SUSER_NAME" in sql:
            out = "FK:appuser"
        elif "IMPERSONATE" in sql:
            out = f"FK:{impersonatable_sysadmin}" if impersonatable_sysadmin else ""
        elif "is_linked" in sql:
            out = "\n".join(f"FK:{s}" for s in linked)
        return RunResult(argv, exit_code=0, stdout=out)
    return run


class MssqlTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME")
        self.hid, _ = self.store.add_host("10.0.0.9", hostname="SQL01", os_name="windows")
        self.cred = Credential("appuser", "pw", local_auth=True)
        self.cid, _ = self.store.add_credential(self.cred)
        self.store.add_access(self.hid, self.cid, "mssql", admin=False)  # a login, not sa
        self.host = self.store.host_by_ip("10.0.0.9")


class EscalateTest(MssqlTestCase):
    def test_impersonation_escalates_and_upgrades_access(self):
        rep = mssql.escalate_privs(self.store, self.host, self.cred,
                                   run=fake_run(), allow_config_change=True)
        self.assertEqual(rep.status, "escalated")
        self.assertEqual(rep.via, "sa")
        # a proven finding with a captured step
        proven = [f for f in self.store.findings() if f["vector_type"] == "mssql_impersonation"]
        self.assertEqual(len(proven), 1)
        self.assertTrue(proven[0]["proven"])
        self.assertTrue(self.store.steps(finding_id=proven[0]["id"]))
        # the login is now sysadmin (access upgraded to admin)
        self.assertEqual(self.store.counts()["admin_access"], 1)
        # a reversible cleanup was recorded
        self.assertTrue(any("sysadmin" in (a["description"] or "")
                            for a in self.store.artifacts()))
        # the linked server was recorded as an observation
        obs = [f for f in self.store.findings() if f["vector_type"] == "mssql_linked_server"]
        self.assertEqual(len(obs), 1)
        self.assertFalse(obs[0]["proven"])

    def test_gated_without_config_change(self):
        rep = mssql.escalate_privs(self.store, self.host, self.cred,
                                   run=fake_run(), allow_config_change=False)
        self.assertEqual(rep.status, "gated")
        self.assertEqual(rep.impersonatable, ["sa"])
        self.assertEqual(self.store.counts()["admin_access"], 0)   # nothing granted
        self.assertFalse([f for f in self.store.findings()
                          if f["vector_type"] == "mssql_impersonation"])

    def test_xp_cmdshell_directly_without_sysadmin(self):
        # the reported field case: not sysadmin, no impersonatable login, but xp_cmdshell
        # runs (granted rights / already enabled) — must establish exec, not dead-end.
        rep = mssql.escalate_privs(
            self.store, self.host, self.cred,
            run=fake_run(impersonatable_sysadmin=None, linked=(), xp_directly=True),
            allow_config_change=True)
        self.assertEqual(rep.status, "xpcmd")
        proven = [f for f in self.store.findings() if f["vector_type"] == "mssql_xpcmdshell"]
        self.assertEqual(len(proven), 1)
        self.assertTrue(self.store.steps(finding_id=proven[0]["id"]))
        self.assertEqual(self.store.counts()["admin_access"], 1)   # access upgraded → exec
        self.assertTrue(any("xp_cmdshell" in (a["cleanup_cmd"] or "")
                            for a in self.store.artifacts()))       # disable-it cleanup

    def test_sysadmin_establishes_xpcmd_directly(self):
        rep = mssql.escalate_privs(self.store, self.host, self.cred,
                                   run=fake_run(starts_sysadmin=True), allow_config_change=True)
        self.assertEqual(rep.status, "xpcmd")                      # sysadmin runs xp_cmdshell
        self.assertEqual(self.store.counts()["admin_access"], 1)

    def test_read_only_reports_sysadmin_without_touching_anything(self):
        rep = mssql.escalate_privs(self.store, self.host, self.cred,
                                   run=fake_run(starts_sysadmin=True), allow_config_change=False)
        self.assertEqual(rep.status, "already_sysadmin")
        self.assertEqual(self.store.counts()["admin_access"], 0)   # read-only: nothing changed

    def test_no_path_when_no_impersonation_or_linked(self):
        rep = mssql.escalate_privs(self.store, self.host, self.cred,
                                   run=fake_run(impersonatable_sysadmin=None, linked=()),
                                   allow_config_change=True)
        self.assertEqual(rep.status, "none")

    def test_linked_only_when_no_impersonation(self):
        rep = mssql.escalate_privs(self.store, self.host, self.cred,
                                   run=fake_run(impersonatable_sysadmin=None, linked=("SQL02",)),
                                   allow_config_change=True)
        self.assertEqual(rep.status, "linked_only")
        self.assertEqual(rep.linked, ["SQL02"])
        self.assertTrue([f for f in self.store.findings()
                         if f["vector_type"] == "mssql_linked_server"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
