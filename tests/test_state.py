#!/usr/bin/env python3
"""The SQLite store: schema, migrations, and the insert semantics the loop relies on.

The engine re-ingests the same host and the same credential from many sources, so
"add" must be idempotent and enriching rather than duplicating — otherwise the
400-host board double-counts and the credential frontier never converges.
"""
import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit.creds import Credential  # noqa: E402
from fieldkit.state import (  # noqa: E402
    DB_ENV_VAR, SCHEMA_VERSION, StateError, Store, default_db_path,
)


class StoreTestCase(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "engagement.db")
        self.store = Store.create(self.path)
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME")


class SchemaTest(StoreTestCase):

    def test_migrations_run_on_create(self):
        self.assertEqual(self.store.schema_version(), SCHEMA_VERSION)
        tables = {r[0] for r in self.store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertTrue({"engagement", "host", "service", "credential", "access",
                         "finding", "step", "artifact", "loot"} <= tables)

    def test_reopening_is_idempotent(self):
        self.store.close()
        with Store.open(self.path) as store:
            self.assertEqual(store.schema_version(), SCHEMA_VERSION)
            self.assertEqual(store.engagement()["name"], "ACME")

    def test_open_missing_database_is_an_error(self):
        with self.assertRaises(StateError):
            Store.open(os.path.join(self.tmp.name, "nope.db"))

    def test_create_over_an_existing_database_is_refused(self):
        with self.assertRaises(StateError):
            Store.create(self.path)

    def test_a_newer_schema_is_not_silently_downgraded(self):
        self.store.conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 5}")
        with self.assertRaises(StateError):
            self.store.migrate()

    def test_foreign_keys_are_enforced(self):
        with self.assertRaises(sqlite3.IntegrityError):
            with self.store.conn:
                self.store.conn.execute(
                    "INSERT INTO service (host_id, port) VALUES (999, 445)")

    def test_only_one_engagement(self):
        with self.assertRaises(StateError):
            self.store.init_engagement("second")


class HostTest(StoreTestCase):

    def test_add_then_enrich(self):
        host_id, created = self.store.add_host("10.0.0.5", subnet="10.0.0.0/24")
        self.assertTrue(created)
        again, created_again = self.store.add_host(
            "10.0.0.5", hostname="WIN-SQL01", os_name="windows")
        self.assertEqual(host_id, again)
        self.assertFalse(created_again)
        row = self.store.host_by_ip("10.0.0.5")
        self.assertEqual(row["hostname"], "WIN-SQL01")
        self.assertEqual(row["os"], "windows")
        self.assertEqual(row["subnet"], "10.0.0.0/24", "known fields survive re-ingest")

    def test_enrichment_never_erases(self):
        self.store.add_host("10.0.0.5", hostname="WIN-SQL01")
        self.store.add_host("10.0.0.5", hostname=None, os_name="windows")
        self.assertEqual(self.store.host_by_ip("10.0.0.5")["hostname"], "WIN-SQL01")

    def test_subnet_is_derived_when_the_caller_does_not_say(self):
        # Every ingest path (scope file, nxc sweep, recce bridge) must group the same
        # way, or per-subnet lhost overrides quietly stop applying.
        self.store.add_host("10.0.5.20")
        self.assertEqual(self.store.host_by_ip("10.0.5.20")["subnet"], "10.0.5.0/24")

    def test_an_explicit_subnet_wins(self):
        self.store.add_host("10.0.5.20", subnet="dmz")
        self.assertEqual(self.store.host_by_ip("10.0.5.20")["subnet"], "dmz")

    def test_a_non_ip_key_does_not_break_the_insert(self):
        self.store.add_host("dc01.corp.local")
        self.assertIsNone(self.store.host_by_ip("dc01.corp.local")["subnet"])

    def test_ipv6_is_fine(self):
        self.store.add_host("dead:beef::1")
        self.assertIsNotNone(self.store.host_by_ip("dead:beef::1"))

    def test_is_dc_flag(self):
        self.store.add_host("10.0.0.1", is_dc=True)
        self.assertEqual(self.store.host_by_ip("10.0.0.1")["is_dc"], 1)

    def test_hosts_filtered_by_subnet(self):
        self.store.add_host("10.0.0.5", subnet="10.0.0.0/24")
        self.store.add_host("10.0.1.5", subnet="10.0.1.0/24")
        self.assertEqual([h["ip"] for h in self.store.hosts(subnet="10.0.1.0/24")],
                         ["10.0.1.5"])


class CredentialTest(StoreTestCase):

    def cred(self, **kw):
        base = dict(username="jdoe", secret="Winter2025!", secret_type="password",
                    domain="CORP")
        base.update(kw)
        return Credential(**base)

    def test_same_credential_twice_is_one_row(self):
        first, created = self.store.add_credential(self.cred(), source="manual")
        second, created_again = self.store.add_credential(self.cred(), source="spray")
        self.assertEqual(first, second)
        self.assertTrue(created)
        self.assertFalse(created_again)
        self.assertEqual(len(self.store.credentials()), 1)

    def test_identity_is_case_insensitive_on_the_principal(self):
        self.store.add_credential(self.cred())
        _, created = self.store.add_credential(self.cred(username="JDoe", domain="corp"))
        self.assertFalse(created, "AD principals are case-insensitive")

    def test_identity_is_case_sensitive_on_the_secret(self):
        self.store.add_credential(self.cred())
        _, created = self.store.add_credential(self.cred(secret="winter2025!"))
        self.assertTrue(created, "passwords are case-sensitive")

    def test_hash_and_password_for_one_user_are_two_credentials(self):
        self.store.add_credential(self.cred())
        self.store.add_credential(self.cred(secret="a" * 32, secret_type="nt"))
        self.assertEqual(len(self.store.credentials()), 2)

    def test_local_and_domain_are_distinct(self):
        self.store.add_credential(self.cred(domain="", local_auth=False))
        _, created = self.store.add_credential(self.cred(domain="", local_auth=True))
        self.assertTrue(created)

    def test_source_is_recorded(self):
        self.store.add_credential(self.cred(), source="lsa")
        self.assertEqual(self.store.credentials()[0]["source"], "lsa")

    def test_a_stored_credential_round_trips_back_into_the_model(self):
        # Everything downstream renders from a credential read back out of state.
        for original in (self.cred(), self.cred(domain="", local_auth=True),
                         self.cred(secret="a" * 32, secret_type="nt")):
            self.store.add_credential(original)
            row = self.store.conn.execute(
                "SELECT * FROM credential ORDER BY id DESC LIMIT 1").fetchone()
            self.assertEqual(Credential.from_row(row), original)


class BoardTest(StoreTestCase):

    def test_counts_and_breakdowns(self):
        host_id, _ = self.store.add_host("10.0.0.5", os_name="windows")
        self.store.add_host("10.0.0.6", os_name="linux")
        cred_id, _ = self.store.add_credential(
            Credential(username="jdoe", secret="pw", domain="CORP"))
        with self.store.conn:
            self.store.conn.execute(
                "INSERT INTO access (host_id, cred_id, method, admin, proven_at) "
                "VALUES (?, ?, 'nxc', 1, '2026-07-27T00:00:00+00:00')", (host_id, cred_id))
        counts = self.store.counts()
        self.assertEqual(counts["hosts"], 2)
        self.assertEqual(counts["credentials"], 1)
        self.assertEqual(counts["admin_access"], 1)
        self.assertEqual(counts["admin_hosts"], 1)
        self.assertEqual({r["os"]: r["n"] for r in self.store.host_os_breakdown()},
                         {"windows": 1, "linux": 1})
        self.assertEqual([r["secret_type"] for r in self.store.credential_type_breakdown()],
                         ["password"])

    def test_deleting_a_host_takes_its_access_rows(self):
        host_id, _ = self.store.add_host("10.0.0.5")
        cred_id, _ = self.store.add_credential(Credential(username="a", secret="b"))
        with self.store.conn:
            self.store.conn.execute(
                "INSERT INTO access (host_id, cred_id, method, proven_at) "
                "VALUES (?, ?, 'nxc', 'now')", (host_id, cred_id))
            self.store.conn.execute("DELETE FROM host WHERE id = ?", (host_id,))
        self.assertEqual(self.store.counts()["access"], 0)


class ConfigBlobTest(StoreTestCase):

    def test_round_trip(self):
        self.assertEqual(self.store.get_config(), {})
        self.store.set_config({"lhost": "10.10.14.7", "lport": 443})
        self.assertEqual(self.store.get_config()["lport"], 443)

    def test_config_without_an_engagement(self):
        path = os.path.join(self.tmp.name, "empty.db")
        with Store.create(path) as store:
            with self.assertRaises(StateError):
                store.get_config()


class DbPathTest(unittest.TestCase):

    def test_env_var_wins(self):
        os.environ[DB_ENV_VAR] = "/tmp/somewhere/e.db"
        self.addCleanup(os.environ.pop, DB_ENV_VAR, None)
        self.assertEqual(default_db_path(), "/tmp/somewhere/e.db")

    def test_default_is_cwd(self):
        os.environ.pop(DB_ENV_VAR, None)
        self.assertTrue(default_db_path("/srv/eng").endswith("/srv/eng/engagement.db"))


if __name__ == "__main__":
    unittest.main()
