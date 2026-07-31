#!/usr/bin/env python3
"""SMB share spidering + secret scrubbing → loot → creds.

Pinned:

  * every scrubber is pure ``(local, share_path, text) -> [Hit]`` — no I/O, no state;
  * a GPP cpassword decrypts to a plaintext (via a fake openssl runner) and promotes;
  * unattend.xml decodes both PlainText=true and the base64+salt form and promotes;
  * PowerShell / dotenv / -flag / YAML forms of ``user`` + ``password`` promote;
  * filename scrubbers surface sensitive artifacts (KeePass DBs, SSH keys, .env) as
    loot pointers, no credential inferred;
  * spider_and_scrub records a **deletion obligation** for the downloaded corpus —
    that folder is client data, and the report has to say we're holding it;
  * every hit is captured as a `step` (rule 3) and every promotion is a real
    :class:`~fieldkit.creds.Credential` (rule 7);
  * nxc is driven through the injected runner (rule 2) — no real child spawns.

Run:  python3 -m unittest discover -s tests
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import sharespider  # noqa: E402
from fieldkit.creds import Credential  # noqa: E402
from fieldkit.runner import RunResult  # noqa: E402
from fieldkit.state import Store  # noqa: E402


# -------- pure scrubbers (no store, no runner) --------------------------------

class ScrubKvTest(unittest.TestCase):
    def _hit(self, local, share, text):
        return list(sharespider.scrub_kv(local, share, text))

    def test_powershell_variable_form_promotes(self):
        hits = self._hit("/t/a.ps1", "ADMIN$\\a.ps1",
                         "$user='svcadmin'\n$password='Winter2025!'")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].credential.username, "svcadmin")
        self.assertEqual(hits[0].credential.secret, "Winter2025!")
        self.assertNotIn("Winter2025", hits[0].snippet)   # redacted

    def test_dotenv_form_promotes(self):
        h = self._hit("/t/.env", "WWW\\.env",
                      "DB_USER='appsvc'\nDB_PASSWORD='Sp00lService!'")[0]
        self.assertEqual((h.credential.username, h.credential.secret),
                         ("appsvc", "Sp00lService!"))

    def test_powershell_flag_form_promotes(self):
        h = self._hit("/t/deploy.ps1", "IT$\\deploy.ps1",
                      "Connect-DB -User 'appsvc' -Password 'MyDBPass123!'")[0]
        self.assertEqual((h.credential.username, h.credential.secret),
                         ("appsvc", "MyDBPass123!"))

    def test_yaml_form_promotes(self):
        h = self._hit("/t/creds.yaml", "CFG\\creds.yaml",
                      "username: 'appsvc'\npassword: 'YamlSecret!'")[0]
        self.assertEqual((h.credential.username, h.credential.secret),
                         ("appsvc", "YamlSecret!"))

    def test_unquoted_dotenv_secrets_land(self):
        # Real .env files often have UNQUOTED values. The initial pattern only
        # matched quoted values; smoke-audit caught this. All four should hit.
        env = (
            "DB_PASSWORD='S3cret!'\n"                                 # quoted, ends in `password`
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI-K7MDENG-bPxRfiCYEXAMPLEKEY\n"  # unquoted, `secret` in middle
            "GITHUB_TOKEN=ghp_1234567890abcdefghij1234567890abcdef1234\n"       # unquoted, `token` at end
            "X_API_KEY=abcdef123456abcdef\n"                          # unquoted, `api_key` at end
        )
        kinds = [h.snippet for h in self._hit("/t/.env", "APP\\.env", env)]
        # each secret category surfaces
        self.assertTrue(any(s.startswith("DB_PASSWORD") for s in kinds))
        self.assertTrue(any("AWS_SECRET_ACCESS_KEY" in s for s in kinds))
        self.assertTrue(any("GITHUB_TOKEN" in s for s in kinds))
        self.assertTrue(any("X_API_KEY" in s for s in kinds))

    def test_short_placeholder_values_dont_match(self):
        # "changeme" is 8 chars → catches (arguably right — real engagements
        # care about literal changeme). Anything < 8 chars value does not.
        env = "password=xyz\napi_key=short"
        self.assertEqual(self._hit("/t/.env", "APP\\.env", env), [])

    def test_secret_snippet_is_redacted(self):
        # a captured step must not leak the full secret verbatim
        h = self._hit("/t/a.ps1", "A\\a.ps1", "$password='Winter2025!'")[0]
        self.assertNotIn("Winter2025!", h.snippet)
        self.assertIn("Wint", h.snippet)

    def test_binary_extensions_are_skipped(self):
        # only .ps1/.env/.yaml/... — never a .exe/.dll/.png/etc.
        self.assertEqual(self._hit("/t/x.exe", "A\\x.exe",
                                   "password='xyz'"), [])
        self.assertEqual(self._hit("/t/x.png", "A\\x.png",
                                   "password='xyz'"), [])


class ScrubUnattendTest(unittest.TestCase):
    def test_plaintext_password_promotes_local_auth(self):
        text = """<AutoUnattend>
            <AdministratorPassword>
              <Value>Sekret!123</Value>
              <PlainText>true</PlainText>
            </AdministratorPassword>
            <Username>svc</Username>
          </AutoUnattend>"""
        h = list(sharespider.scrub_unattend("/t/u.xml", "IT$\\u.xml", text))[0]
        self.assertEqual((h.credential.username, h.credential.secret),
                         ("svc", "Sekret!123"))
        self.assertTrue(h.credential.local_auth)   # unattend passwords are local

    def test_base64_salted_form_is_decoded(self):
        import base64
        salted = ("StrongPassword1!AdministratorPassword").encode("utf-16-le")
        b64 = base64.b64encode(salted).decode()
        text = (f"<AutoUnattend><UserAccounts><LocalAccount>"
                f"<Password><Value>{b64}</Value><PlainText>false</PlainText></Password>"
                f"<Name>svc</Name></LocalAccount></UserAccounts></AutoUnattend>")
        h = list(sharespider.scrub_unattend("/t/u.xml", "IT$\\u.xml", text))[0]
        self.assertEqual(h.credential.secret, "StrongPassword1!")

    def test_absent_password_yields_nothing(self):
        self.assertEqual(list(sharespider.scrub_unattend(
            "/t/u.xml", "IT$\\u.xml", "<AutoUnattend><Foo/></AutoUnattend>")), [])


class ScrubGppTest(unittest.TestCase):
    def _text(self, cpw="AAAA", user="svcadmin"):
        return (f'<Groups><User><Properties cpassword="{cpw}" '
                f'userName="{user}"/></User></Groups>')

    def test_decrypts_and_promotes_when_openssl_returns_plaintext(self):
        old = sharespider._gpp_decrypt
        sharespider._gpp_decrypt = lambda cpw, run=None: "Password1!"
        try:
            h = list(sharespider.scrub_gpp("/t/G.xml", "SYSVOL\\G.xml", self._text()))[0]
        finally:
            sharespider._gpp_decrypt = old
        self.assertEqual((h.credential.username, h.credential.secret),
                         ("svcadmin", "Password1!"))
        self.assertIn("svcadmin", h.snippet)   # username kept for the operator
        self.assertNotIn("Password1!", h.snippet)   # plaintext redacted

    def test_domain_prefixed_user_splits(self):
        old = sharespider._gpp_decrypt
        sharespider._gpp_decrypt = lambda cpw, run=None: "P@ss"
        try:
            h = list(sharespider.scrub_gpp(
                "/t/G.xml", "SYSVOL\\G.xml",
                self._text(user="CORP\\svcadmin")))[0]
        finally:
            sharespider._gpp_decrypt = old
        self.assertEqual(h.credential.username, "svcadmin")
        self.assertEqual(h.credential.domain, "CORP")

    def test_decrypt_failure_still_records_loot(self):
        # missing openssl / decrypt failure -> hit recorded WITHOUT a credential
        old = sharespider._gpp_decrypt
        sharespider._gpp_decrypt = lambda cpw, run=None: None
        try:
            h = list(sharespider.scrub_gpp("/t/G.xml", "SYSVOL\\G.xml", self._text()))[0]
        finally:
            sharespider._gpp_decrypt = old
        self.assertIsNone(h.credential)
        self.assertEqual(h.kind, "gpp-cpassword")   # still recorded as loot


class ScrubWebconfigTest(unittest.TestCase):
    def test_extracts_db_creds_but_does_not_promote(self):
        # a SQL connection string is loot, not a domain login — the inference would be wrong
        wc = ('<connectionStrings><add name="db" connectionString="Server=sql01;'
              'Database=app;User Id=appsvc;Password=Sp00lService!" /></connectionStrings>')
        h = list(sharespider.scrub_webconfig("/t/w.config", "WWW\\w.config", wc))[0]
        self.assertIsNone(h.credential)
        self.assertIn("appsvc", h.snippet)
        self.assertNotIn("Sp00lService!", h.snippet)   # still redacted


class ScrubFilenameTest(unittest.TestCase):
    def test_kdbx_is_surfaced_as_a_pointer(self):
        h = list(sharespider.scrub_filename(
            "/t/vault.kdbx", "FILES\\vaults\\Team.kdbx", ""))[0]
        self.assertEqual(h.kind, "keepass-db")
        self.assertIsNone(h.credential)             # a pointer, not a login

    def test_ssh_and_env_and_gitcreds_hit(self):
        for name, kind in (
            ("id_rsa", "ssh-key"), (".env", "dotenv"), (".git-credentials", "vcs-creds"),
            ("cert.pfx", "cert-with-key"),
        ):
            hits = list(sharespider.scrub_filename(f"/t/{name}", f"F\\{name}", ""))
            self.assertEqual(hits[0].kind, kind, f"{name} did not classify as {kind}")


# -------- driver: nxc + fold-into-state ---------------------------------------

class DriverTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME")
        self.hid, _ = self.store.add_host("10.0.0.7", os_name="windows")
        self.cid, _ = self.store.add_credential(Credential("jdoe", "pw", domain="corp"))
        self.store.add_access(self.hid, self.cid, "smb", admin=False)
        self.host = self.store.host_by_ip("10.0.0.7")
        self.cred = self.store.credential_by_id(self.cid)
        self.out = os.path.join(self.tmp.name, "spider")

    def _stage_corpus(self):
        os.makedirs(os.path.join(self.out, "10.0.0.7/SYSVOL/Groups"), exist_ok=True)
        os.makedirs(os.path.join(self.out, "10.0.0.7/IT/scripts"), exist_ok=True)
        with open(os.path.join(self.out,
                               "10.0.0.7/SYSVOL/Groups/Groups.xml"), "w") as fh:
            fh.write('<Groups><User><Properties cpassword="AAAA" '
                     'userName="svcadmin"/></User></Groups>')
        with open(os.path.join(self.out, "10.0.0.7/IT/scripts/login.ps1"), "w") as fh:
            fh.write("$user='appadmin'\n$password='Winter2025!'")
        with open(os.path.join(self.out, "10.0.0.7/IT/vault.kdbx"), "w") as fh:
            fh.write("KEEPASS")
        with open(os.path.join(self.out, "10.0.0.7.json"), "w") as fh:
            json.dump({"SYSVOL": {"Groups.xml": {"size": "200 B"}},
                       "IT": {"scripts\\login.ps1": {"size": "50 B"},
                              "vault.kdbx": {"size": "1 KB"}}}, fh)

    def _fake_nxc(self, capture):
        def run(argv, **kw):
            capture.append(argv)
            return RunResult(argv, exit_code=0, stdout="[+] spider_plus done")
        return run

    def test_end_to_end_scrub_and_promote(self):
        self._stage_corpus()
        sharespider._gpp_decrypt = lambda cpw, run=None: "Password1!"
        captured = []
        rep = sharespider.spider_and_scrub(
            self.store, self.host, self.cred,
            run=self._fake_nxc(captured), output_folder=self.out)
        # inventory
        self.assertEqual(rep.shares_readable, 2)
        self.assertEqual(rep.files_inventoried, 3)
        # hits: gpp + ps1 kv + kdbx pointer = 3 kinds
        self.assertEqual({h.kind for h in rep.hits},
                         {"gpp-cpassword", "kv-secret", "keepass-db"})
        # 2 credentials promoted into the loop
        self.assertEqual(rep.creds_promoted, 2)
        promoted = {(c["username"], c["secret"]) for c in self.store.credentials()
                    if c["username"] != "jdoe"}
        self.assertEqual(promoted,
                         {("svcadmin", "Password1!"), ("appadmin", "Winter2025!")})

    def test_nxc_argv_uses_render_nxc_with_spider_plus_options(self):
        self._stage_corpus()
        captured = []
        sharespider.spider_and_scrub(
            self.store, self.host, self.cred,
            run=self._fake_nxc(captured), output_folder=self.out)
        argv = captured[0]
        # argv (rule 7): a list, never a shell string
        self.assertIsInstance(argv, list)
        self.assertEqual(argv[:3], ["nxc", "smb", "10.0.0.7"])
        self.assertIn("-M", argv)
        self.assertIn("spider_plus", argv)
        # spider_plus's DOWNLOAD_FLAG=True idiom: any DOWNLOAD key enables it
        self.assertIn("DOWNLOAD_FLAG=True", argv)
        self.assertIn(f"OUTPUT_FOLDER={self.out}", argv)

    def test_downloaded_corpus_records_a_deletion_obligation(self):
        # holding a bulk copy of the client's shares -> the report must say so,
        # and `report --cleanup` must be able to remove it.
        self._stage_corpus()
        sharespider.spider_and_scrub(
            self.store, self.host, self.cred,
            run=self._fake_nxc([]), output_folder=self.out)
        arts = [a for a in self.store.artifacts()
                if "share corpus" in (a["description"] or "")]
        self.assertEqual(len(arts), 1)
        self.assertIn(self.out, arts[0]["cleanup_cmd"])

    def test_every_hit_captures_a_step_and_a_loot_row(self):
        self._stage_corpus()
        sharespider._gpp_decrypt = lambda cpw, run=None: "P!"
        sharespider.spider_and_scrub(
            self.store, self.host, self.cred,
            run=self._fake_nxc([]), output_folder=self.out)
        # rule 3: every scrub decision has a captured step, and every hit is loot
        steps = [s for s in self.store.steps()
                 if (s["label"] or "").startswith("sharespider:")]
        self.assertEqual(len(steps), 3)
        self.assertEqual(self.store.counts()["loot"], 3)

    def test_nxc_error_is_reported_not_raised(self):
        def run(argv, **kw):
            return RunResult(argv, error="nxc not on PATH")
        rep = sharespider.spider_and_scrub(
            self.store, self.host, self.cred, run=run, output_folder=self.out)
        self.assertIsNotNone(rep.error)
        self.assertEqual(rep.creds_promoted, 0)
        self.assertEqual(rep.hits, [])

    def test_missing_inventory_json_does_not_crash(self):
        # nxc ran but produced no metadata (empty share set) — still a clean report
        os.makedirs(self.out)
        rep = sharespider.spider_and_scrub(
            self.store, self.host, self.cred,
            run=self._fake_nxc([]), output_folder=self.out)
        self.assertIsNone(rep.error)
        self.assertEqual(rep.shares_readable, 0)
        self.assertEqual(rep.creds_promoted, 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
