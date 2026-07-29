#!/usr/bin/env python3
"""PostgreSQL low-priv → OS command execution.

Pinned (mirrors `test_mssql.py`):

  * read-only enumeration reports the surface (superuser?, member of a superuser role?,
    pg_execute_server_program?, database list) without changing anything;
  * a superuser or pg_execute_server_program member runs COPY FROM PROGRAM and
    records a proven `postgres_copy_from_program` finding + captured step;
  * a non-superuser member of a superuser role goes SET ROLE → COPY FROM PROGRAM and
    records a proven `postgres_role_grant` finding (via = the role);
  * without --allow config-change it stays gated (surfaced, not run);
  * the `psql` runner is faked — no child process spawns.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import postgres  # noqa: E402
from fieldkit.creds import Credential  # noqa: E402
from fieldkit.runner import RunResult  # noqa: E402
from fieldkit.state import Store  # noqa: E402


def fake_psql(is_super=False, member_of=(), exec_role_member=False, member_supers=(),
              exec_works=True, databases=("postgres", "appdb", "billing")):
    """A fake psql -c: routes by SQL content, returns FK:-prefixed synthetic rows.

    Order-sensitive matching: check the most specific substrings first (e.g.
    ``pg_execute_server_program`` before the generic ``pg_auth_members``, since the
    exec-role EXISTS query contains both).

    * ``is_super`` — the connecting user is superuser;
    * ``member_of`` — every role the user is a (transitive) member of;
    * ``exec_role_member`` — whether pg_execute_server_program covers the user;
    * ``member_supers`` — which of ``member_of`` are themselves superusers;
    * ``exec_works`` — whether COPY FROM PROGRAM produces sentinel output.
    """
    state = {"role_set": None}

    def run(argv, env=None):
        sql = argv[argv.index("-c") + 1] if "-c" in argv else ""
        out = ""
        # SET ROLE (leading in a compound statement): capture role, run the tail.
        if sql.startswith("SET ROLE "):
            role = sql.split('"')[1]
            state["role_set"] = role
            sql = sql.split(";", 1)[1].strip()
        # Order matters — check specific patterns first.
        if 'COPY "fk_exec"' in sql:
            # exec succeeds if: already superuser, or exec-role member, or we did
            # SET ROLE to a role that is itself a superuser.
            can_exec = (is_super or exec_role_member
                        or (state["role_set"] in member_supers))
            out = ("FK:uid=999(postgres) gid=999(postgres) groups=999(postgres)"
                   if (can_exec and exec_works) else "")
        elif "pg_execute_server_program" in sql:                # _HAS_EXEC_ROLE
            out = "FK:1" if exec_role_member else "FK:0"
        elif "rolsuper" in sql and "current_user" in sql:       # _IS_SUPER
            out = "FK:1" if is_super else "FK:0"
        elif "rolsuper" in sql and "WHERE rolname" in sql:      # _ROLE_SUPER (parameterized)
            import re as _re
            m = _re.search(r"rolname\s*=\s*'([^']+)'", sql)
            out = "FK:1" if (m and m.group(1) in member_supers) else "FK:0"
        elif "pg_auth_members" in sql:                          # _MEMBERSHIPS
            out = "\n".join(f"FK:{r}" for r in member_of)
        elif "pg_database" in sql:                              # _LIST_DB
            out = "\n".join(f"FK:{d}" for d in databases)
        elif "current_user" in sql:                             # _WHOAMI
            out = "FK:appuser"
        return RunResult(argv, exit_code=0, stdout=out)
    return run


class PostgresTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME")
        self.hid, _ = self.store.add_host("10.0.0.9", os_name="linux")
        self.cred = Credential("appuser", "pw")
        self.cid, _ = self.store.add_credential(self.cred)
        self.store.add_access(self.hid, self.cid, "postgres", admin=False)
        self.host = self.store.host_by_ip("10.0.0.9")


class EscalateTest(PostgresTestCase):
    def test_superuser_runs_copy_from_program_directly(self):
        rep = postgres.escalate_privs(
            self.store, self.host, self.cred,
            run=fake_psql(is_super=True), allow_config_change=True)
        self.assertEqual(rep.status, "exec")
        proven = [f for f in self.store.findings()
                  if f["vector_type"] == "postgres_copy_from_program"]
        self.assertEqual(len(proven), 1)
        self.assertTrue(proven[0]["proven"])
        self.assertTrue(self.store.steps(finding_id=proven[0]["id"]))
        # postgres access upgraded to admin (enum/escalate can now run through DB)
        self.assertEqual(self.store.counts()["admin_access"], 1)

    def test_pg_execute_server_program_member_runs_directly(self):
        rep = postgres.escalate_privs(
            self.store, self.host, self.cred,
            run=fake_psql(is_super=False, exec_role_member=True),
            allow_config_change=True)
        self.assertEqual(rep.status, "exec")
        self.assertFalse(rep.is_superuser)
        self.assertTrue(rep.exec_role_member)

    def test_role_membership_escalates_via_set_role(self):
        # member of `dbadmin` which is superuser -> SET ROLE dbadmin; COPY FROM PROGRAM
        rep = postgres.escalate_privs(
            self.store, self.host, self.cred,
            run=fake_psql(is_super=False, member_of=["reader", "dbadmin"],
                          member_supers=["dbadmin"]),
            allow_config_change=True)
        self.assertEqual(rep.status, "escalated")
        self.assertEqual(rep.via, "dbadmin")
        proven = [f for f in self.store.findings()
                  if f["vector_type"] == "postgres_role_grant"]
        self.assertEqual(len(proven), 1)
        # a SET ROLE session-scope note is recorded so the report is honest
        self.assertTrue(any("assumed role dbadmin" in (a["description"] or "")
                            for a in self.store.artifacts()))

    def test_gated_without_allow_config_change(self):
        rep = postgres.escalate_privs(
            self.store, self.host, self.cred,
            run=fake_psql(is_super=False, member_of=["dbadmin"],
                          member_supers=["dbadmin"]),
            allow_config_change=False)
        self.assertEqual(rep.status, "gated")
        self.assertEqual(rep.escalatable_via, ["dbadmin"])
        self.assertEqual(self.store.counts()["admin_access"], 0)   # nothing granted
        self.assertFalse([f for f in self.store.findings()])

    def test_read_only_reports_superuser_without_running_anything(self):
        rep = postgres.escalate_privs(
            self.store, self.host, self.cred,
            run=fake_psql(is_super=True), allow_config_change=False)
        self.assertEqual(rep.status, "already_superuser")
        self.assertEqual(self.store.counts()["admin_access"], 0)   # read-only

    def test_no_path_reports_none(self):
        rep = postgres.escalate_privs(
            self.store, self.host, self.cred,
            run=fake_psql(is_super=False, member_of=["reader"], member_supers=[]),
            allow_config_change=True)
        self.assertEqual(rep.status, "none")

    def test_databases_are_enumerated(self):
        rep = postgres.escalate_privs(
            self.store, self.host, self.cred,
            run=fake_psql(databases=("postgres", "appdb", "billing")),
            allow_config_change=False)
        self.assertEqual(rep.databases, ["postgres", "appdb", "billing"])


class RendererTest(unittest.TestCase):
    """The psql renderer (rule 7: canonical Rendered, not shell strings)."""

    def test_render_psql_uses_pgpassword_env_not_flag(self):
        from fieldkit.creds import render_psql
        cred = Credential("appuser", "s3cret")
        r = render_psql(cred, "10.0.0.9", port=5432, database="appdb", sql="SELECT 1")
        self.assertIsInstance(r.argv, list)
        self.assertIn("-w", r.argv)                         # never prompts
        self.assertIn("PGPASSWORD", r.env)                  # secret never on the argv
        self.assertNotIn("s3cret", r.argv)
        self.assertIn("SELECT 1", r.argv)

    def test_render_psql_rejects_non_password_secret_types(self):
        from fieldkit.creds import render_psql
        cred = Credential("appuser", "d34dbeef", secret_type="nt")
        r = render_psql(cred, "10.0.0.9")
        self.assertTrue(any("password only" in n for n in r.notes))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
