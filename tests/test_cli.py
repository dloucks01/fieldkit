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
from fieldkit.creds import EMPTY_LM, Credential  # noqa: E402
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

    def test_init_runs_preflight_inline(self):
        # nxc is not installed in the CI env, so the preflight warning must
        # appear right at init — a tester should learn about the missing spine
        # tool now, not five commands later.
        out = self.init("ACME")
        self.assertIn("required tools missing", out)
        self.assertIn("netexec", out)                # tool NAME, not the wordy label
        self.assertNotIn("spray / exec / loot", out)  # the confusing old label form
        self.assertIn("fieldkit preflight", out)      # the follow-up command


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
        self.assertIn("already in the engagement", out)
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


class ScopeTest(CliTestCase):

    def setUp(self):
        super().setUp()
        self.init()

    def test_no_rules_means_no_enforcement(self):
        out = self.run_cli("scope", "show")
        self.assertIn("no scope rules", out)
        # every IP is allowed when no rules exist (backward-compat)
        self.assertTrue(self.store().in_scope("10.0.0.5"))
        self.assertTrue(self.store().in_scope("8.8.8.8"))

    def test_allow_rule_narrows_scope(self):
        self.run_cli("scope", "allow", "10.0.0.0/24")
        self.assertTrue(self.store().in_scope("10.0.0.5"))
        self.assertFalse(self.store().in_scope("10.0.1.5"))
        self.assertFalse(self.store().in_scope("8.8.8.8"))

    def test_deny_carves_exception_out_of_allow(self):
        self.run_cli("scope", "allow", "10.0.0.0/16")
        self.run_cli("scope", "deny", "10.0.10.0/24")
        self.assertTrue(self.store().in_scope("10.0.5.5"))
        self.assertFalse(self.store().in_scope("10.0.10.5"))    # excluded
        self.assertFalse(self.store().in_scope("192.168.1.1"))  # outside allow

    def test_add_hosts_refuses_outside_scope(self):
        self.run_cli("scope", "allow", "10.0.0.0/24")
        out = self.run_cli("add", "hosts", "10.0.0.5", "10.0.1.5", "8.8.8.8", expect=1)
        # only the in-scope IP was added
        self.assertEqual(self.store().counts()["hosts"], 1)
        self.assertIsNotNone(self.store().host_by_ip("10.0.0.5"))
        self.assertIsNone(self.store().host_by_ip("10.0.1.5"))
        self.assertIn("outside the engagement scope", out)
        self.assertIn("10.0.1.5", out)

    def test_scope_show_lists_rules(self):
        self.run_cli("scope", "allow", "10.0.0.0/24", "--notes", "prod segment")
        self.run_cli("scope", "deny", "10.0.0.10/32")
        out = self.run_cli("scope", "show")
        self.assertIn("allow  10.0.0.0/24", out)
        self.assertIn("deny", out)
        self.assertIn("prod segment", out)

    def test_scope_clear_removes_enforcement(self):
        self.run_cli("scope", "allow", "10.0.0.0/24")
        self.run_cli("scope", "clear", "--yes")
        self.assertTrue(self.store().in_scope("192.168.1.1"))   # enforcement OFF
        self.assertEqual(len(self.store().scope_rules()), 0)

    def test_bad_cidr_is_rejected(self):
        out = self.run_cli("scope", "allow", "not-a-cidr", expect=2)
        self.assertIn("not-a-cidr", out)

    def test_normalization(self):
        # /24 given via a host bit gets normalized to the network address
        self.run_cli("scope", "allow", "10.0.0.5/24")
        rules = self.store().scope_rules()
        self.assertEqual(rules[0]["cidr"], "10.0.0.0/24")

    def test_run_on_out_of_scope_reports_scope_not_engagement(self):
        # scope error must be distinct from "not in the engagement"
        self.run_cli("scope", "allow", "10.0.0.0/24")
        # add credential so the credential check doesn't shadow the scope check
        self.run_cli("add", "cred", "svc:pw", "--yes")
        out = self.run_cli("run", "10.9.9.9", "suid:find", "--yes", expect=2)
        self.assertIn("outside the engagement scope", out)


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

    def test_phase_indicator_walks_the_workflow(self):
        # setup -> spraying -> enumeration -> exploitation
        self.init()
        self.assertIn("phase:       setup", self.run_cli("status"))

        self.run_cli("add", "hosts", "10.0.0.5")
        self.assertIn("phase:       setup", self.run_cli("status"))  # no cred yet

        self.run_cli("add", "cred", "svc:pw", "--yes")
        self.assertIn("phase:       spraying", self.run_cli("status"))

        # simulate: a spray proved access
        s = self.store()
        s.add_access(s.host_by_ip("10.0.0.5")["id"], s.credentials()[0]["id"], "ssh")
        self.assertIn("phase:       enumeration", self.run_cli("status"))

    def test_top_moves_appear_once_access_exists(self):
        self.init()
        self.run_cli("add", "hosts", "10.0.0.5", "--os", "linux")
        self.run_cli("add", "cred", "svc:pw", "--yes")
        # simulate proven access + sudo -l enum output → sudo:ALL vector is unlocked
        s = self.store()
        hid = s.host_by_ip("10.0.0.5")["id"]
        s.add_access(hid, s.credentials()[0]["id"], "ssh")
        s.add_step(cmd="id", output="uid=1000(svc) gid=1000(svc)", host_id=hid,
                   label="enum:id")
        s.add_step(cmd="sudo -l",
                   output="(ALL) NOPASSWD: ALL", host_id=hid, label="enum:sudo")
        out = self.run_cli("status")
        self.assertIn("top moves", out)
        self.assertIn("sudo", out.lower())

    def test_scope_rules_appear_in_status(self):
        self.init()
        self.run_cli("scope", "allow", "10.0.0.0/24")
        out = self.run_cli("status")
        self.assertIn("scope:", out)
        self.assertIn("10.0.0.0/24", out)


class WordlistCliTest(CliTestCase):
    """`fieldkit wordlist` — the CLI wrapper over the mutation module.

    No engagement required; wordlist gen is a pre-engagement task.
    """

    def test_positional_seeds_print_to_stdout(self):
        out = self.run_cli("wordlist", "Acme", "--years", "2024")
        self.assertIn("Acme2024", out)
        self.assertIn("Acme2024!", out)

    def test_out_file_gets_written_and_message_points_at_spray(self):
        out_path = os.path.join(self.tmp.name, "p.txt")
        out = self.run_cli("wordlist", "Acme", "--years", "2024",
                            "--out", out_path)
        self.assertTrue(os.path.exists(out_path))
        with open(out_path) as fh:
            words = fh.read().splitlines()
        self.assertIn("Acme2024", words)
        self.assertIn("spray --wordlist", out)  # hints the next command

    def test_from_file_reads_seeds_per_line(self):
        seeds_path = os.path.join(self.tmp.name, "seeds.txt")
        with open(seeds_path, "w") as fh:
            fh.write("# a comment\nAcme\nWidget\n\n")
        out = self.run_cli("wordlist", "--from-file", seeds_path, "--years", "2024")
        self.assertIn("Acme2024", out)
        self.assertIn("Widget2024", out)
        self.assertNotIn("comment2024", out)   # # lines ignored

    def test_from_text_extracts_words(self):
        out = self.run_cli("wordlist", "--from-text",
                            "About Acme Widgets - since 1987", "--years", "2024")
        self.assertIn("Acme2024", out)
        self.assertIn("Widgets2024", out)

    def test_no_seeds_reports_the_three_input_paths(self):
        out = self.run_cli("wordlist", expect=2)
        self.assertIn("--from-file", out)
        self.assertIn("--from-text", out)
        self.assertIn("--rules", out)

    def test_rules_lists_every_mutation(self):
        out = self.run_cli("wordlist", "--rules")
        self.assertIn("cases", out)
        self.assertIn("leet", out)
        self.assertIn("suffix", out)
        self.assertIn("combine", out)
        self.assertIn("walks", out)
        self.assertIn("wrapped", out)

    def test_walks_only_works_without_seeds(self):
        # --walks --min-len 8 produces standalone keyboard walks; no seeds needed
        out = self.run_cli("wordlist", "--walks", "--min-len", "8", "--max-len", "20")
        self.assertIn("qazwsxedc", out)
        self.assertIn("Password2024!", out)

    def test_long_preset_narrows_to_12_16_and_enables_walks_wrapped(self):
        # --long alone: 12-16 char walks only
        out = self.run_cli("wordlist", "--long")
        for w in out.strip().splitlines():
            self.assertGreaterEqual(len(w), 12, f"{w!r} shorter than 12")
            self.assertLessEqual(len(w), 16, f"{w!r} longer than 16")
        # a real 12+ char walk lands
        self.assertIn("1qaz2wsx3edc", out)

    def test_long_with_seeds_produces_wrapped_shapes(self):
        out = self.run_cli("wordlist", "Password", "--long", "--years", "2024")
        # !Password2024! is 14 chars — right in the 12-16 band
        self.assertIn("!Password2024!", out)


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


class AnalyzeTest(CliTestCase):

    CAPTURE = """\
SMB   10.0.0.6   445   DC01   [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)
SMB   10.0.0.6   445   DC01   [+] corp.local\\jdoe:Winter2025! (Pwn3d!)
SMB   10.0.0.7   445   WS02   [+] corp.local\\jdoe:Winter2025! (Pwn3d!)
"""

    def test_analyze_before_any_access(self):
        self.init()
        out = self.run_cli("analyze")
        self.assertIn("nothing to analyze", out)

    def test_analyze_ranks_proven_moves(self):
        self.init()
        cap = self.write("cap.txt", self.CAPTURE)
        # mark the DC so dc-takeover can fire
        self.run_cli("add", "hosts", "10.0.0.6", "--dc")
        self.run_cli("ingest", "nxc", cap, "--yes")
        out = self.run_cli("analyze", "--proof")
        self.assertIn("Domain takeover", out)
        self.assertIn("Password reuse", out)
        self.assertIn("safe proof:", out)
        self.assertIn("high/read-only", out)


class RunCliTest(CliTestCase):
    """The analyze->run wiring around the executor (execution itself is covered with
    injected runners in test_executor/test_hostenum)."""

    def setUp(self):
        super().setUp()
        self.init()
        store = self.store()
        self.hid, _ = store.add_host("10.0.0.8", os_name="linux")
        cid, _ = store.add_credential(Credential("svc", "s3cret", domain="corp"))
        store.add_access(self.hid, cid, "ssh", admin=False)
        # captured enum: a read-only SUID vector + a config-change capability vector
        store.add_step(cmd="find", output="/usr/bin/find\n", host_id=self.hid, label="enum:suid")
        store.add_step(cmd="getcap", output="/usr/bin/tar = cap_dac_override+ep\n",
                       host_id=self.hid, label="enum:caps")

    def test_analyze_lists_privesc_vector_with_run_hint(self):
        out = self.run_cli("analyze")
        self.assertIn("SUID find", out)
        self.assertIn("run: fieldkit run 10.0.0.8 suid:find", out)

    def test_run_unknown_vector_lists_available(self):
        out = self.run_cli("run", "10.0.0.8", "sudo:nope", "--yes", expect=2)
        self.assertIn("no vector", out)
        self.assertIn("suid:find", out)  # suggests what is available

    def test_safety_gate_blocks_config_change_without_allow(self):
        out = self.run_cli("run", "10.0.0.8", "cap:tar", "--yes", expect=2)
        self.assertIn("safety gate", out)
        self.assertIn("--allow config-change", out)
        # nothing executed, so no step for the vector and no finding proven
        store = self.store()
        self.assertEqual(store.counts()["proven_findings"], 0)

    def test_run_on_host_not_in_engagement(self):
        out = self.run_cli("run", "10.9.9.9", "suid:find", "--yes", expect=2)
        self.assertIn("not in the engagement", out)


class ResolveTargetErrorsTest(CliTestCase):
    """The `_resolve_target` failure paths — these are the errors testers see
    most often; they used to be ambiguous. Pinned here so they can't rot."""

    def setUp(self):
        super().setUp()
        self.init()

    def test_zero_credentials_stored_points_at_add_cred(self):
        self.run_cli("add", "hosts", "10.0.0.5")
        out = self.run_cli("enum", "10.0.0.5", "--yes", expect=2)
        self.assertIn("no credentials in the engagement", out)
        self.assertIn("add cred", out)

    def test_credentials_stored_but_not_proven_points_at_spray(self):
        self.run_cli("add", "hosts", "10.0.0.5")
        self.run_cli("add", "cred", "svc:pw", "--yes")
        out = self.run_cli("enum", "10.0.0.5", "--yes", expect=2)
        self.assertIn("stored", out)
        self.assertIn("none is proven", out)
        self.assertIn("fieldkit spray", out)

    def test_escalate_dry_run_does_not_require_proven_cred(self):
        # --dry-run is plan-only: the operator wants to see WHAT escalate would
        # do before committing (and often before running spray to prove a cred).
        # Blocking on "no proven cred" defeats the point.
        self.run_cli("add", "hosts", "10.0.0.5", "--os", "linux")
        self.run_cli("add", "cred", "svc:pw", "--yes")
        # simulate a captured enum showing sudo:ALL — no proven cred yet.
        store = self.store()
        hid = store.host_by_ip("10.0.0.5")["id"]
        store.add_step(cmd="id", output="uid=1000(svc) gid=1000(svc)",
                       host_id=hid, label="enum:id")
        store.add_step(cmd="sudo -l", output="(ALL) NOPASSWD: ALL",
                       host_id=hid, label="enum:sudo")
        out = self.run_cli("escalate", "10.0.0.5", "--dry-run")
        # the plan renders — that's the whole point of dry-run
        self.assertIn("escalation plan", out)
        self.assertIn("sudo:ALL", out)
        # the dry-run note honestly says why cred isn't proven
        self.assertIn("dry-run", out)


class PostureCliTest(CliTestCase):
    def test_posture_defaults_to_assume_caught(self):
        self.init()
        out = self.run_cli("posture")
        self.assertIn("assume-caught", out)
        self.assertIn("RED  untested", out)          # nothing proven yet
        self.assertIn("recommended delivery order", out)
        self.assertIn("native-exe", out)

    def test_posture_shows_green_after_a_clean_lab_result(self):
        self.init()
        self.store().record_evasion("native-exe", "clean", signature="1.401.5")
        out = self.run_cli("posture")
        self.assertIn("GREEN", out)
        self.assertIn("1 technique lab-proven green", out)

    def test_lab_test_without_a_lab_host_errors(self):
        self.init()
        out = self.run_cli("lab", "test", "--yes", expect=2)
        self.assertIn("no lab host", out)


if __name__ == "__main__":
    unittest.main()
