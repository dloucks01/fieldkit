#!/usr/bin/env python3
"""Credential normalizer + per-tool renderers.

Two things are being pinned down here:

  * **liberal ingest** — every shape an operator actually pastes lands on the same
    canonical model, and anything assumed along the way comes back as a note;
  * **strict output** — renderers emit argv lists, so a password containing quotes,
    backslashes or spaces survives verbatim. v1 built shell strings by hand
    (``:'{pw}'``, ``repr(pw)[1:-1]``) and mangled exactly those.

Run:  python3 -m unittest discover -s tests
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit.creds import (  # noqa: E402
    EMPTY_LM, Credential, CredentialError, describe, parse_credential,
    parse_credential_lines, render_evil_winrm, render_impacket, render_mssqlclient,
    render_nxc,
)

NT = "31d6cfe0d16ae931b73c59d7e0c089c0"
LM = "e52cac67419a9a224a3b108f3fa6cb6d"
AES256 = "a" * 64
AES128 = "b" * 32


def parse(spec, **kw):
    return parse_credential(spec, **kw).credential


class PrincipalFormsTest(unittest.TestCase):
    """The domain/user shapes, however they were typed."""

    def test_slash_form(self):
        cred = parse("CORP/jdoe:Winter2025!")
        self.assertEqual((cred.domain, cred.username, cred.secret_type), ("CORP", "jdoe", "password"))
        self.assertEqual(cred.secret, "Winter2025!")
        self.assertFalse(cred.local_auth)

    def test_backslash_form(self):
        cred = parse("CORP\\jdoe:Winter2025!")
        self.assertEqual((cred.domain, cred.username), ("CORP", "jdoe"))

    def test_upn_form(self):
        cred = parse("jdoe@corp.local:Winter2025!")
        self.assertEqual((cred.domain, cred.username), ("corp.local", "jdoe"))

    def test_fqdn_backslash_form(self):
        cred = parse("corp.local\\jdoe:pw")
        self.assertEqual((cred.domain, cred.username), ("corp.local", "jdoe"))

    def test_bare_user_has_no_domain(self):
        cred = parse("jdoe:Winter2025!")
        self.assertEqual(cred.domain, "")
        self.assertFalse(cred.local_auth)

    def test_dot_backslash_marks_local(self):
        cred = parse(".\\Administrator:Passw0rd")
        self.assertTrue(cred.local_auth)
        self.assertEqual(cred.domain, "")
        self.assertEqual(cred.principal, ".\\Administrator")

    def test_explicit_domain_wins_over_spec(self):
        cred = parse("CORP/jdoe:pw", domain="OTHER")
        self.assertEqual(cred.domain, "OTHER")

    def test_local_flag_wins(self):
        cred = parse("CORP/jdoe:pw", local_auth=True)
        self.assertTrue(cred.local_auth)

    def test_trailing_separator_is_trimmed(self):
        self.assertEqual(parse("jdoe:pw", domain="CORP\\").domain, "CORP")

    def test_pasted_quotes_are_stripped_and_reported(self):
        parsed = parse_credential("'CORP/jdoe:Winter2025!'")
        self.assertEqual(parsed.credential.secret, "Winter2025!")
        self.assertTrue(any("quote" in n for n in parsed.notes))


class SecretFormsTest(unittest.TestCase):
    """password / NT / LM:NT / AES / ccache / key, auto-detected."""

    def test_password_may_contain_colons(self):
        parsed = parse_credential("jdoe:Pa:ss:w0rd")
        self.assertEqual(parsed.credential.secret, "Pa:ss:w0rd")
        self.assertTrue(any("colon" in n for n in parsed.notes))

    def test_password_may_contain_quotes_and_backslashes(self):
        # The v1 shell-string quoting broke on exactly this.
        nasty = "it's a \"trap\"\\ $(id) `id`"
        cred = parse(f"jdoe:{nasty}")
        self.assertEqual(cred.secret, nasty)

    def test_pwdump_pair_drops_the_empty_lm(self):
        cred = parse(f"Administrator:{EMPTY_LM}:{NT}")
        self.assertEqual((cred.secret_type, cred.secret), ("nt", NT))

    def test_pwdump_pair_keeps_a_real_lm(self):
        parsed = parse_credential(f"Administrator:{LM}:{NT}")
        self.assertEqual(parsed.credential.secret_type, "lm:nt")
        self.assertEqual(parsed.credential.secret, f"{LM}:{NT}")
        self.assertEqual(parsed.credential.nt, NT)
        self.assertTrue(any("LM" in n for n in parsed.notes))

    def test_secretsdump_line_with_rid_and_domain(self):
        parsed = parse_credential(f"CORP\\svc_sql:1103:{EMPTY_LM}:{NT}:::")
        cred = parsed.credential
        self.assertEqual((cred.domain, cred.username), ("CORP", "svc_sql"))
        self.assertEqual((cred.secret_type, cred.secret), ("nt", NT))
        self.assertTrue(any("secretsdump" in n for n in parsed.notes))

    def test_hash_only_needs_a_user(self):
        cred = parse(f":{NT}", username="Administrator")
        self.assertEqual((cred.username, cred.secret_type, cred.secret),
                         ("Administrator", "nt", NT))

    def test_single_colon_hex_reads_as_a_hash_but_says_so(self):
        parsed = parse_credential(f"admin:{NT}")
        self.assertEqual(parsed.credential.secret_type, "nt")
        self.assertTrue(any("NT hash" in n for n in parsed.notes),
                        "the operator must be told this was a judgement call")

    def test_double_colon_hash_is_unambiguous(self):
        parsed = parse_credential(f"admin::{NT}")
        self.assertEqual(parsed.credential.secret_type, "nt")
        self.assertFalse(any("NT hash" in n for n in parsed.notes))

    def test_password_flag_forces_a_hex_password(self):
        cred = parse("admin", password=NT)
        self.assertEqual((cred.secret_type, cred.secret), ("password", NT))

    def test_hash_is_lowercased(self):
        self.assertEqual(parse(f"admin::{NT.upper()}").secret, NT)

    def test_kerberos_aes_key_line(self):
        cred = parse(f"svc@corp.local:aes256-cts-hmac-sha1-96:{AES256}")
        self.assertEqual((cred.domain, cred.username), ("corp.local", "svc"))
        self.assertEqual((cred.secret_type, cred.secret), ("aes256", AES256))

    def test_aes_flag_picks_the_size(self):
        self.assertEqual(parse("svc", aes_key=AES256).secret_type, "aes256")
        self.assertEqual(parse("svc", aes_key=AES128).secret_type, "aes128")

    def test_ccache_path_carries_the_user(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "jdoe@CORP.LOCAL.ccache")
            open(path, "w").close()
            parsed = parse_credential(path)
            self.assertEqual(parsed.credential.secret_type, "ccache")
            self.assertEqual(parsed.credential.username, "jdoe")
            self.assertEqual(parsed.credential.secret, path)

    def test_ssh_key_path(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "id_rsa")
            with open(path, "w") as fh:
                fh.write("-----BEGIN OPENSSH PRIVATE KEY-----\n")
            cred = parse(path, username="root")
            self.assertEqual((cred.secret_type, cred.secret), ("ssh_key", path))

    def test_flags_override_the_spec_and_say_so(self):
        parsed = parse_credential("CORP/jdoe:oldpass", password="newpass")
        self.assertEqual(parsed.credential.secret, "newpass")
        self.assertTrue(any("overrode" in n for n in parsed.notes))


class RejectionTest(unittest.TestCase):
    """Bad input is caught at entry, not 40 hosts into a spray."""

    def test_no_username(self):
        with self.assertRaises(CredentialError):
            parse_credential(":pw")

    def test_no_secret(self):
        with self.assertRaises(CredentialError):
            parse_credential("CORP/jdoe")

    def test_two_secrets(self):
        with self.assertRaises(CredentialError):
            parse_credential("jdoe", password="pw", nt_hash=NT)

    def test_malformed_hash_flag(self):
        with self.assertRaises(CredentialError):
            parse_credential("jdoe", nt_hash="not-a-hash")

    def test_malformed_aes_flag(self):
        with self.assertRaises(CredentialError):
            parse_credential("jdoe", aes_key="abc")

    def test_truncated_kerberos_key_is_rejected(self):
        with self.assertRaises(CredentialError):
            parse_credential("svc:aes256-cts-hmac-sha1-96:dead")

    def test_unknown_secret_type(self):
        with self.assertRaises(CredentialError):
            Credential(username="u", secret="s", secret_type="magic")


class FileIngestTest(unittest.TestCase):

    def test_bad_line_does_not_lose_the_good_ones(self):
        text = "\n".join([
            "# creds from the client",
            "CORP/jdoe:Winter2025!",
            "",
            "nonsense-with-no-secret",
            f"CORP/svc_sql:1103:{EMPTY_LM}:{NT}:::",
        ])
        parsed, errors = parse_credential_lines(text)
        self.assertEqual([p.credential.username for p in parsed], ["jdoe", "svc_sql"])
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0][0], 4)


class ConfirmBackTest(unittest.TestCase):

    def test_password_is_shown_in_full(self):
        # A mis-split password is the thing this line exists to catch.
        line = describe(parse("CORP/jdoe:Winter2025!"))
        self.assertIn("domain=CORP", line)
        self.assertIn("user=jdoe", line)
        self.assertIn("'Winter2025!'", line)
        self.assertIn("local_auth=no", line)

    def test_hash_is_fingerprinted_not_dumped(self):
        line = describe(parse(f"admin::{NT}"))
        self.assertIn("NT hash", line)
        self.assertNotIn(NT, line)

    def test_local_is_visible(self):
        self.assertIn("local_auth=yes", describe(parse(".\\admin:pw")))


class RenderNxcTest(unittest.TestCase):

    def test_password_with_domain(self):
        r = render_nxc(parse("CORP/jdoe:Winter2025!"), "smb", "10.0.0.5")
        self.assertEqual(r.argv, ["nxc", "smb", "10.0.0.5", "-u", "jdoe",
                                  "-p", "Winter2025!", "-d", "CORP"])

    def test_hash_and_local_auth(self):
        r = render_nxc(parse(".\\Administrator:" + ":" + NT), "smb", "10.0.0.5")
        self.assertEqual(r.argv, ["nxc", "smb", "10.0.0.5", "-u", "Administrator",
                                  "-H", NT, "--local-auth"])

    def test_nasty_password_is_one_argv_element(self):
        nasty = "p@ss 'w' \"o\"\\rd"
        r = render_nxc(parse(f"jdoe:{nasty}"), "smb", "10.0.0.5")
        self.assertIn(nasty, r.argv)
        self.assertEqual(r.argv.count(nasty), 1)

    def test_extra_flags_come_last(self):
        r = render_nxc(parse("CORP/jdoe:pw"), "smb", "10.0.0.0/24",
                       extra=["--continue-on-success"])
        self.assertEqual(r.argv[-1], "--continue-on-success")

    def test_ccache_goes_through_the_environment(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "jdoe@CORP.LOCAL.ccache")
            open(path, "w").close()
            r = render_nxc(parse(path, domain="CORP"), "smb", "10.0.0.5")
            self.assertIn("-k", r.argv)
            self.assertEqual(r.env["KRB5CCNAME"], path)


class RenderImpacketTest(unittest.TestCase):

    def test_password_target_string(self):
        r = render_impacket(parse("CORP/jdoe:Winter2025!"), "10.0.0.5")
        self.assertEqual(r.argv, ["wmiexec.py", "CORP/jdoe:Winter2025!@10.0.0.5"])

    def test_hash_uses_hashes_flag(self):
        r = render_impacket(parse(f"CORP/jdoe::{NT}"), "10.0.0.5", tool="psexec.py")
        self.assertEqual(r.argv, ["psexec.py", "CORP/jdoe@10.0.0.5", "-hashes", f":{NT}"])

    def test_lm_nt_pair_is_passed_whole(self):
        r = render_impacket(parse(f"admin:{LM}:{NT}"), "10.0.0.5")
        self.assertIn(f"{LM}:{NT}", r.argv)

    def test_at_sign_password_is_not_smuggled_into_the_target(self):
        # impacket's own target parser stops the password at '@'.
        r = render_impacket(parse("CORP/jdoe:pa@ss"), "10.0.0.5")
        self.assertEqual(r.argv, ["wmiexec.py", "CORP/jdoe@10.0.0.5"])
        self.assertTrue(any("@" in n for n in r.notes))

    def test_ccache_is_no_pass(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "jdoe.ccache")
            open(path, "w").close()
            r = render_impacket(parse(path, domain="CORP"), "dc01.corp.local")
            self.assertIn("-k", r.argv)
            self.assertIn("-no-pass", r.argv)
            self.assertEqual(r.env["KRB5CCNAME"], path)


class RenderEvilWinrmTest(unittest.TestCase):

    def test_password(self):
        r = render_evil_winrm(parse("CORP/jdoe:Winter2025!"), "10.0.0.5")
        self.assertEqual(r.argv, ["evil-winrm", "-i", "10.0.0.5", "-u", "jdoe",
                                  "-p", "Winter2025!", "-r", "CORP"])

    def test_hash(self):
        r = render_evil_winrm(parse(f".\\admin::{NT}"), "10.0.0.5")
        self.assertEqual(r.argv, ["evil-winrm", "-i", "10.0.0.5", "-u", "admin", "-H", NT])

    def test_lm_nt_is_reduced_to_the_nt_half(self):
        r = render_evil_winrm(parse(f"admin:{LM}:{NT}"), "10.0.0.5")
        self.assertIn(NT, r.argv)
        self.assertNotIn(f"{LM}:{NT}", r.argv)
        self.assertTrue(r.notes)


class RenderMssqlTest(unittest.TestCase):
    """The -windows-auth rule: domain account or PtH, including a local Windows account."""

    def test_domain_account_gets_windows_auth(self):
        r = render_mssqlclient(parse("CORP/jdoe:Winter2025!"), "10.0.0.5")
        self.assertEqual(r.argv, ["mssqlclient.py", "CORP/jdoe:Winter2025!@10.0.0.5",
                                  "-windows-auth"])

    def test_sql_login_does_not(self):
        r = render_mssqlclient(parse("sa:Password1"), "10.0.0.5")
        self.assertEqual(r.argv, ["mssqlclient.py", "sa:Password1@10.0.0.5"])

    def test_local_windows_account_does(self):
        r = render_mssqlclient(parse(".\\svc_sql:Password1"), "10.0.0.5")
        self.assertIn("-windows-auth", r.argv)

    def test_pth_does(self):
        r = render_mssqlclient(parse(f"sa::{NT}"), "10.0.0.5")
        self.assertIn("-windows-auth", r.argv)
        self.assertIn("-hashes", r.argv)

    def test_non_default_port(self):
        r = render_mssqlclient(parse("sa:pw"), "10.0.0.5", port=14330)
        self.assertIn("-port", r.argv)
        self.assertIn("14330", r.argv)


if __name__ == "__main__":
    unittest.main()
