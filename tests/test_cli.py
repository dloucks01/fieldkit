#!/usr/bin/env python3
"""End-to-end CLI: init -> config -> add cred -> add hosts -> status.

Drives ``fieldkit.cli.main`` in-process (it is a plain function returning an exit
code, and no fieldkit module does I/O at import) so the whole operator workflow is
covered in milliseconds. The Phase-0 verification from the plan — "create an
engagement, add creds/hosts, status shows them" — is `WorkflowTest`.
"""
import contextlib
import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit.cli import main  # noqa: E402
from fieldkit.creds import EMPTY_LM  # noqa: E402
from fieldkit.state import Store  # noqa: E402

NT = "31d6cfe0d16ae931b73c59d7e0c089c0"


class CliTestCase(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = os.path.join(self.tmp.name, "engagement.db")

    def run_cli(self, *args, expect=0):
        """Run one command; returns stdout+stderr and asserts the exit code."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["--db", self.db, *args])
        text = out.getvalue() + err.getvalue()
        if expect is not None:
            self.assertEqual(code, expect, text)
        return text

    def init(self, name="ACME"):
        return self.run_cli("init", name)

    def write(self, name, text):
        path = os.path.join(self.tmp.name, name)
        with open(path, "w") as fh:
            fh.write(text)
        return path

    def store(self):
        store = Store.open(self.db)
        self.addCleanup(store.close)
        return store


class InitTest(CliTestCase):

    def test_init_creates_the_database(self):
        out = self.init("ACME internal")
        self.assertTrue(os.path.exists(self.db))
        self.assertIn("ACME internal", out)
        self.assertEqual(self.store().engagement()["name"], "ACME internal")

    def test_init_twice_is_refused(self):
        self.init()
        out = self.run_cli("init", expect=2)
        self.assertIn("already exists", out)

    def test_commands_need_an_engagement(self):
        out = self.run_cli("status", expect=2)
        self.assertIn("fieldkit init", out)

    def test_unopenable_database_is_reported_not_raised(self):
        self.db = os.path.join(self.tmp.name, "no-such-dir", "e.db")
        out = self.run_cli("init", expect=2)
        self.assertIn("cannot open", out)

    def test_readonly_database_is_reported_not_raised(self):
        self.init()
        os.chmod(self.db, 0o444)
        self.addCleanup(os.chmod, self.db, 0o644)
        out = self.run_cli("add", "hosts", "10.0.0.5", expect=2)
        self.assertIn("database error", out)


class ConfigCommandTest(CliTestCase):

    def setUp(self):
        super().setUp()
        self.init()

    def test_set_get_show(self):
        self.run_cli("config", "set", "lhost=10.10.14.7", "lport=443", "domain=corp.local")
        self.assertEqual(self.run_cli("config", "get", "lhost").strip(), "10.10.14.7")
        shown = self.run_cli("config", "show")
        self.assertIn("lhost", shown)
        self.assertIn("corp.local", shown)

    def test_bare_config_shows_everything(self):
        self.assertIn("lhost", self.run_cli("config"))

    def test_invalid_value_is_rejected_and_nothing_is_stored(self):
        out = self.run_cli("config", "set", "lhost=attacker.example.com", expect=2)
        self.assertIn("error", out)
        self.assertEqual(self.store().get_config(), {})

    def test_a_bad_key_in_a_batch_applies_nothing(self):
        self.run_cli("config", "set", "lhost=10.10.14.7", "nope=1", expect=2)
        self.assertEqual(self.store().get_config(), {},
                         "a typo must not leave a half-configured engagement")

    def test_unknown_key_on_get(self):
        self.assertIn("unknown config key", self.run_cli("config", "get", "nope", expect=2))

    def test_unset_key_returns_nonzero(self):
        self.run_cli("config", "get", "lhost", expect=1)

    def test_subnet_override(self):
        self.run_cli("config", "set", "lhost=10.10.14.7")
        self.run_cli("config", "set", "lhost=192.168.56.10", "--subnet", "10.0.5.0/24")
        self.assertIn("10.0.5.0/24", self.run_cli("config", "show"))
        self.run_cli("config", "unset", "--subnet", "10.0.5.0/24")
        self.assertNotIn("10.0.5.0/24", self.run_cli("config", "show"))

    def test_unset_needs_a_target(self):
        self.run_cli("config", "unset", expect=2)


class AddCredTest(CliTestCase):

    def setUp(self):
        super().setUp()
        self.init()

    def test_confirm_back_then_store(self):
        out = self.run_cli("add", "cred", "CORP/jdoe:Winter2025!", "--yes")
        self.assertIn("parsed as → domain=CORP  user=jdoe", out)
        self.assertIn("stored 1 credential", out)
        row = self.store().credentials()[0]
        self.assertEqual((row["domain"], row["username"], row["secret_type"]),
                         ("CORP", "jdoe", "password"))

    def test_notes_are_shown(self):
        out = self.run_cli("add", "cred", f"admin:{NT}", "--yes")
        self.assertIn("note:", out)
        self.assertIn("NT hash", out)

    def test_non_interactive_without_yes_stores_nothing(self):
        # stdin is not a tty under the test runner: refuse rather than guess.
        out = self.run_cli("add", "cred", "CORP/jdoe:Winter2025!", expect=2)
        self.assertIn("--yes", out)
        self.assertEqual(len(self.store().credentials()), 0)

    def test_flag_forms(self):
        self.run_cli("add", "cred", "--user", "Administrator", "--hash", NT,
                     "--local", "--source", "sam", "--yes")
        row = self.store().credentials()[0]
        self.assertEqual((row["secret_type"], row["secret"], row["local_auth"],
                          row["source"]), ("nt", NT, 1, "sam"))

    def test_re_adding_is_not_a_duplicate(self):
        self.run_cli("add", "cred", "CORP/jdoe:Winter2025!", "--yes")
        out = self.run_cli("add", "cred", "corp/JDoe:Winter2025!", "--yes")
        self.assertIn("already known", out)
        self.assertEqual(len(self.store().credentials()), 1)

    def test_from_file_reports_bad_lines_and_stores_the_rest(self):
        path = self.write("creds.txt", "\n".join([
            "# from the client",
            "CORP/jdoe:Winter2025!",
            "garbage",
            f"CORP\\svc_sql:1103:{EMPTY_LM}:{NT}:::",
        ]))
        out = self.run_cli("add", "cred", "--from-file", path, "--yes")
        self.assertIn("creds.txt:3", out)
        self.assertIn("stored 2 credentials", out)
        self.assertEqual({r["username"] for r in self.store().credentials()},
                         {"jdoe", "svc_sql"})

    def test_empty_invocation_explains_itself(self):
        self.assertIn("error", self.run_cli("add", "cred", expect=2))

    def test_missing_file(self):
        self.assertIn("no such file",
                      self.run_cli("add", "cred", "--from-file", "/nope/creds.txt", expect=2))


class AddHostsTest(CliTestCase):

    def setUp(self):
        super().setUp()
        self.init()

    def test_literal_targets_and_cidr(self):
        out = self.run_cli("add", "hosts", "10.0.0.5", "10.0.1.0/30", "--os", "windows")
        self.assertIn("added 3 hosts", out)
        rows = self.store().hosts()
        self.assertEqual([r["ip"] for r in rows], ["10.0.0.5", "10.0.1.1", "10.0.1.2"])
        self.assertEqual(rows[0]["subnet"], "10.0.0.0/24", "subnet is derived")
        self.assertEqual(rows[0]["os"], "windows")

    def test_scope_file_positionally_or_by_flag(self):
        path = self.write("scope.txt", "10.0.0.5 WIN-SQL01\n# skip\n10.0.0.6\n")
        self.run_cli("add", "hosts", path)
        self.assertEqual(self.store().host_by_ip("10.0.0.5")["hostname"], "WIN-SQL01")
        path2 = self.write("more.txt", "10.0.0.7\n")
        self.run_cli("add", "hosts", "--file", path2)
        self.assertEqual(self.store().counts()["hosts"], 3)

    def test_re_adding_enriches_instead_of_duplicating(self):
        self.run_cli("add", "hosts", "10.0.0.5")
        out = self.run_cli("add", "hosts", "10.0.0.5", "--os", "linux")
        self.assertIn("already in scope", out)
        self.assertEqual(self.store().counts()["hosts"], 1)
        self.assertEqual(self.store().host_by_ip("10.0.0.5")["os"], "linux")

    def test_dc_flag(self):
        self.run_cli("add", "hosts", "10.0.0.1", "--dc")
        self.assertEqual(self.store().host_by_ip("10.0.0.1")["is_dc"], 1)

    def test_bad_entry_is_reported_but_the_rest_land(self):
        out = self.run_cli("add", "hosts", "10.0.0.5", "dc01.corp.local", expect=1)
        self.assertIn("dc01.corp.local", out)
        self.assertEqual(self.store().counts()["hosts"], 1)

    def test_oversized_cidr_is_refused(self):
        out = self.run_cli("add", "hosts", "10.0.0.0/8", expect=2)
        self.assertIn("limit", out)
        self.assertEqual(self.store().counts()["hosts"], 0)

    def test_max_expand_can_be_raised(self):
        self.run_cli("add", "hosts", "10.0.0.0/22", "--max-expand", "2000")
        self.assertEqual(self.store().counts()["hosts"], 1022)

    def test_nothing_to_add(self):
        self.assertIn("nothing to add", self.run_cli("add", "hosts", expect=2))


class StatusTest(CliTestCase):

    def test_status_reflects_what_was_added(self):
        self.init("ACME internal")
        self.run_cli("config", "set", "lhost=10.10.14.7", "domain=corp.local")
        self.run_cli("add", "cred", "CORP/jdoe:Winter2025!", "--yes")
        self.run_cli("add", "hosts", "10.0.0.5", "--os", "windows")
        out = self.run_cli("status")
        self.assertIn("ACME internal", out)
        self.assertIn("lhost=10.10.14.7", out)
        self.assertIn("hosts            1", out)
        self.assertIn("credentials      1", out)
        self.assertIn("windows 1", out)
        self.assertIn("password 1", out)

    def test_status_listings(self):
        self.init()
        self.run_cli("add", "hosts", "10.0.0.5", "--dc")
        self.run_cli("add", "cred", "CORP/jdoe:Winter2025!", "--yes")
        out = self.run_cli("status", "--hosts", "--creds")
        self.assertIn("10.0.0.5", out)
        self.assertIn("DC", out)
        self.assertIn("CORP\\jdoe", out)
        self.assertNotIn("Winter2025!", out, "the board must not print secrets")

    def test_empty_engagement_points_at_the_next_step(self):
        self.init()
        self.assertIn("add hosts", self.run_cli("status"))


class WorkflowTest(CliTestCase):
    """The Phase-0 acceptance check, start to finish."""

    def test_full_phase0_workflow(self):
        self.init("ACME internal")
        self.run_cli("config", "set", "lhost=10.10.14.7", "lport=443", "domain=corp.local")
        self.run_cli("config", "set", "lhost=192.168.56.10", "--subnet", "10.0.5.0/24")
        creds = self.write("creds.txt", "CORP/jdoe:Winter2025!\n.\\Administrator::%s\n" % NT)
        self.run_cli("add", "cred", "--from-file", creds, "--yes")
        scope = self.write("scope.txt", "10.0.0.5 WIN-SQL01\n10.0.5.0/29\n")
        self.run_cli("add", "hosts", scope)

        out = self.run_cli("status", "--hosts", "--creds")
        self.assertIn("hosts            7", out)
        self.assertIn("credentials      2", out)
        self.assertIn("WIN-SQL01", out)
        self.assertIn(".\\Administrator", out, "a local account renders as .\\user")

        store = self.store()
        self.assertEqual(store.counts(), {
            "hosts": 7, "services": 0, "credentials": 2, "access": 0, "admin_access": 0,
            "admin_hosts": 0, "findings": 0, "proven_findings": 0, "loot": 0})
        from fieldkit.config import load as load_config
        cfg = load_config(store)
        self.assertEqual(cfg.lhost_for("10.0.5.3"), "192.168.56.10")
        self.assertEqual(cfg.lhost_for("10.0.0.5"), "10.10.14.7")


class IngestTest(CliTestCase):

    CAPTURE = f"""\
SMB   10.0.0.6   445   DC01   [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)
SMB   10.0.0.6   445   DC01   [+] corp.local\\jdoe:Winter2025!
SMB   10.0.0.7   445   WS02   [+] corp.local\\Administrator:{NT} (Pwn3d!)
SMB   10.0.0.8   445   WS03   [-] corp.local\\jdoe:Winter2025! STATUS_LOGON_FAILURE
"""

    def test_ingest_records_creds_and_access(self):
        self.init()
        cap = self.write("cap.txt", self.CAPTURE)
        out = self.run_cli("ingest", "nxc", cap, "--yes")
        self.assertIn("2 valid credentials (1 admin)", out)
        self.assertIn("(Pwn3d!)", out)
        counts = self.store().counts()
        self.assertEqual(counts["credentials"], 2)
        self.assertEqual(counts["admin_access"], 1)
        self.assertEqual(counts["admin_hosts"], 1)

    def test_ingest_shows_hash_secret_type(self):
        self.init()
        cap = self.write("cap.txt", self.CAPTURE)
        self.run_cli("ingest", "nxc", cap, "--yes")
        types = {r["username"]: r["secret_type"] for r in self.store().credentials()}
        self.assertEqual(types["Administrator"], "nt")

    def test_ingest_empty_capture_errors(self):
        self.init()
        cap = self.write("noise.txt", "not an nxc line\n\n")
        out = self.run_cli("ingest", "nxc", cap, "--yes", expect=2)
        self.assertIn("nothing recognizable", out)

    def test_ingest_reingest_is_noop(self):
        self.init()
        cap = self.write("cap.txt", self.CAPTURE)
        self.run_cli("ingest", "nxc", cap, "--yes")
        out = self.run_cli("ingest", "nxc", cap, "--yes")
        self.assertIn("0 credentials", out)
        self.assertEqual(self.store().counts()["credentials"], 2)


if __name__ == "__main__":
    unittest.main()
