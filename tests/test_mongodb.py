#!/usr/bin/env python3
"""MongoDB privilege enumeration + credential extraction.

Pinned:

  * an anonymous mongosh connection that returns identity data is a Critical
    ``mongodb_unauth`` finding — enumerated anonymously and recorded;
  * an authenticated login that holds ``root`` / ``userAdminAnyDatabase`` / etc. records
    an ``mongodb_admin`` finding and its mongodb access is upgraded to admin;
  * an authenticated login without a privileged role stops at "user" — no finding;
  * ``--allow config-change`` gates the user dump and the field scan;
  * ``--scan-data`` counts credential-field candidates per collection *without*
    capturing values (client-data safeguard);
  * the ``mongosh`` runner is faked — no child process spawns.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import mongodb  # noqa: E402
from fieldkit.creds import Credential  # noqa: E402
from fieldkit.runner import RunResult  # noqa: E402
from fieldkit.state import Store  # noqa: E402


def fake_mongosh(unauth=False, identity="appuser@app", roles=(), databases=("admin", "app"),
                 users=("admin@admin",), field_hits=()):
    """A fake mongosh --eval JS.

    * ``unauth=True`` — an anonymous connection returns identity data; the same fake
      also handles the authenticated call the driver makes after the unauth probe.
    * ``field_hits`` — ``[(coll, field, count)]`` returned by the field-scan pass.
    """
    def run(argv, env=None):
        script = argv[argv.index("--eval") + 1] if "--eval" in argv else ""
        is_unauth_call = "-u" not in argv
        out = ""
        if "listDatabases" in script:
            out = "\n".join(f"FK:{d}" for d in databases)
        elif "system.users" in script:
            out = "\n".join(f'FK:{{"user": "{u.split("@")[0]}", '
                            f'"db": "{u.split("@")[1]}", "roles": []}}' for u in users)
        elif "getCollectionNames" in script:
            # the field-scan script — return synthetic hits
            out = "\n".join(f"FK:{c}|{f}|{n}" for c, f, n in field_hits)
        elif "connectionStatus" in script:
            # unauth probe returns data only when unauth=True; authenticated call
            # always returns the identity.
            if is_unauth_call and not unauth:
                return RunResult(argv, exit_code=1, stdout="",
                                 stderr="Authentication required")
            lines = [f"FK:{identity if not is_unauth_call or unauth else 'anon'}"]
            lines += [f"FKR:{role}@{db}" for role, db in roles]
            out = "\n".join(lines)
        return RunResult(argv, exit_code=0, stdout=out)
    return run


class MongoTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME")
        self.hid, _ = self.store.add_host("10.0.0.11", os_name="linux")
        self.cred = Credential("appuser", "pw")
        self.cid, _ = self.store.add_credential(self.cred)
        self.store.add_access(self.hid, self.cid, "mongodb", admin=False)
        self.host = self.store.host_by_ip("10.0.0.11")


class EnumerateTest(MongoTestCase):
    def test_unauth_connection_is_a_critical_proven_finding(self):
        rep = mongodb.enumerate_privs(
            self.store, self.host, self.cred,
            run=fake_mongosh(unauth=True), allow_config_change=False)
        self.assertEqual(rep.status, "unauth")
        self.assertTrue(rep.is_unauth)
        proven = [f for f in self.store.findings() if f["vector_type"] == "mongodb_unauth"]
        self.assertEqual(len(proven), 1)
        self.assertTrue(proven[0]["proven"])
        self.assertTrue(self.store.steps(finding_id=proven[0]["id"]))

    def test_privileged_role_records_admin_finding_and_upgrades_access(self):
        rep = mongodb.enumerate_privs(
            self.store, self.host, self.cred,
            run=fake_mongosh(identity="admin@admin",
                             roles=[("root", "admin")]),
            allow_config_change=False)
        self.assertEqual(rep.status, "admin")
        self.assertIn("root", rep.privileged_roles)
        # mongodb access upgraded (so enum/escalate can rely on it later)
        self.assertEqual(self.store.counts()["admin_access"], 1)
        proven = [f for f in self.store.findings() if f["vector_type"] == "mongodb_admin"]
        self.assertEqual(len(proven), 1)

    def test_authenticated_user_without_privileged_role_stops_at_user(self):
        rep = mongodb.enumerate_privs(
            self.store, self.host, self.cred,
            run=fake_mongosh(identity="appuser@app",
                             roles=[("readWrite", "app")]),
            allow_config_change=False)
        self.assertEqual(rep.status, "user")
        self.assertEqual(rep.privileged_roles, [])
        self.assertEqual(self.store.counts()["findings"], 0)   # no finding, just enum

    def test_user_dump_gated_by_allow_config_change(self):
        # unauth = we can dump, but only when the operator opts in
        rep = mongodb.enumerate_privs(
            self.store, self.host, self.cred,
            run=fake_mongosh(unauth=True,
                             users=("admin@admin", "svc@app")),
            allow_config_change=False)
        self.assertEqual(rep.users_dumped, 0)   # nothing dumped without --allow

    def test_user_dump_records_loot(self):
        rep = mongodb.enumerate_privs(
            self.store, self.host, self.cred,
            run=fake_mongosh(unauth=True,
                             users=("admin@admin", "svc@app", "reader@app")),
            allow_config_change=True)
        self.assertEqual(rep.users_dumped, 3)
        loot = [row for row in self.store.loot()
                if row["kind"] == "mongodb:user"]
        self.assertEqual(len(loot), 3)

    def test_scan_data_counts_field_candidates_without_capturing_values(self):
        rep = mongodb.enumerate_privs(
            self.store, self.host, self.cred,
            run=fake_mongosh(identity="admin@admin",
                             roles=[("root", "admin")],
                             databases=("admin", "billing"),
                             field_hits=[("users", "password", 42),
                                         ("users", "hashedPassword", 41)]),
            allow_config_change=True, scan_data=True)
        # 2 hits on `billing` (admin/config/local are skipped)
        self.assertEqual(len(rep.cred_candidates), 2)
        self.assertEqual(rep.cred_candidates[0][:3], ("billing", "users", "password"))
        # loot: field + count only, no values
        loot = [row for row in self.store.loot()
                if row["kind"] == "mongodb:cred-field"]
        self.assertEqual(len(loot), 2)
        for row in loot:
            # never contains the string "password=<anything>", only field/counts
            self.assertNotIn("=", row["value"].split("=", 1)[1])  # after `=` is only "N docs"

    def test_scan_data_skips_admin_config_local(self):
        rep = mongodb.enumerate_privs(
            self.store, self.host, self.cred,
            run=fake_mongosh(identity="root@admin", roles=[("root", "admin")],
                             databases=("admin", "config", "local"),
                             field_hits=[("users", "password", 99)]),
            allow_config_change=True, scan_data=True)
        # nothing scanned — the only DBs are system DBs
        self.assertEqual(rep.cred_candidates, [])


class RendererTest(unittest.TestCase):
    """The mongosh renderer (rule 7: canonical argv, not shell strings)."""

    def test_render_mongosh_puts_auth_on_argv(self):
        from fieldkit.creds import render_mongosh
        cred = Credential("appuser", "s3cret")
        r = render_mongosh(cred, "10.0.0.11", port=27017,
                           auth_source="admin", script="print(1)")
        self.assertIsInstance(r.argv, list)
        self.assertIn("--quiet", r.argv)
        self.assertIn("-u", r.argv)
        self.assertIn("appuser", r.argv)
        self.assertIn("s3cret", r.argv)                    # mongo puts pw on argv
        self.assertIn("--authenticationDatabase", r.argv)
        self.assertIn("admin", r.argv)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
