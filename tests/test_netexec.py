#!/usr/bin/env python3
"""The netexec output parser — the ``(Pwn3d!)`` oracle turned into facts.

Two things are pinned here:

  * the auth verdict is read exactly — ``[+]`` = valid, ``(Pwn3d!)`` = admin,
    ``[-]`` = failed with its status — across nxc's protocol modules and whether or
    not the capture carried ANSI colour;
  * the password policy is read *before* any spray, and a capture with no policy in
    it returns ``None`` so the caller refuses to spray rather than assuming no lockout.

Run:  python3 -m unittest discover -s tests
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit.netexec import (  # noqa: E402
    AuthResult, HostInfo, PassPolicy, parse_line, parse_output, parse_pass_policy,
)


class AuthLineTest(unittest.TestCase):
    """The [+]/[-]/(Pwn3d!) verdict, per protocol."""

    def test_valid_non_admin(self):
        r = parse_line("SMB   10.0.0.5   445   WS01   [+] corp.local\\jdoe:Winter2025!")
        self.assertIsInstance(r, AuthResult)
        self.assertEqual((r.proto, r.ip, r.port), ("SMB", "10.0.0.5", 445))
        self.assertEqual((r.domain, r.username, r.secret), ("corp.local", "jdoe", "Winter2025!"))
        self.assertTrue(r.success)
        self.assertFalse(r.admin)
        self.assertIsNone(r.status)

    def test_pwned_is_admin(self):
        r = parse_line("SMB   10.0.0.6   445   DC01   [+] corp.local\\Administrator:Winter2025! (Pwn3d!)")
        self.assertTrue(r.success)
        self.assertTrue(r.admin)
        self.assertEqual(r.username, "Administrator")
        self.assertEqual(r.secret, "Winter2025!")  # (Pwn3d!) stripped, not folded into the secret

    def test_failure_carries_status(self):
        r = parse_line("SMB   10.0.0.7   445   WS02   [-] corp.local\\jdoe:Winter2025! STATUS_LOGON_FAILURE")
        self.assertFalse(r.success)
        self.assertFalse(r.admin)
        self.assertEqual(r.status, "STATUS_LOGON_FAILURE")
        self.assertEqual(r.secret, "Winter2025!")  # status not folded into the secret

    def test_kerberos_failure_status(self):
        r = parse_line("LDAP   10.0.0.5   389   DC01   [-] corp.local\\svc:Summer2024 KDC_ERR_PREAUTH_FAILED")
        self.assertFalse(r.success)
        self.assertEqual(r.status, "KDC_ERR_PREAUTH_FAILED")

    def test_ssh_has_no_domain(self):
        r = parse_line("SSH   10.0.0.9   22   ubuntu   [+] root:toor (Pwn3d!)")
        self.assertEqual((r.domain, r.username, r.secret), ("", "root", "toor"))
        self.assertTrue(r.admin)
        self.assertEqual(r.principal, "root")

    def test_winrm_pwned(self):
        r = parse_line("WINRM   10.0.0.6   5985   WS01   [+] corp.local\\Administrator:Pass123 (Pwn3d!)")
        self.assertEqual(r.proto, "WINRM")
        self.assertTrue(r.admin)

    def test_hash_secret_is_echoed(self):
        nt = "31d6cfe0d16ae931b73c59d7e0c089c0"
        r = parse_line(f"SMB   10.0.0.6   445   WS01   [+] corp.local\\Administrator:{nt} (Pwn3d!)")
        self.assertEqual(r.secret, nt)

    def test_password_with_colon_keeps_everything_after_first(self):
        r = parse_line("SMB   10.0.0.5   445   WS01   [+] corp.local\\jdoe:pa:ss:word")
        self.assertEqual(r.secret, "pa:ss:word")

    def test_ansi_colour_is_stripped(self):
        line = "SMB   10.0.0.6   445   WS01   \x1b[1m\x1b[32m[+]\x1b[0m corp.local\\Administrator:P (Pwn3d!)"
        r = parse_line(line)
        self.assertTrue(r.success)
        self.assertTrue(r.admin)
        self.assertEqual(r.username, "Administrator")

    def test_principal_property(self):
        r = parse_line("SMB   10.0.0.5   445   WS01   [+] CORP\\jdoe:pw")
        self.assertEqual(r.principal, "CORP\\jdoe")

    def test_ipv6_target(self):
        r = parse_line("SMB   dead:beef::1   445   DC01   [+] corp.local\\jdoe:pw")
        self.assertEqual(r.ip, "dead:beef::1")


class HostInfoTest(unittest.TestCase):
    """The [*] banner: free fingerprinting on every touch."""

    BANNER = ("SMB   10.0.0.6   445   DC01   [*] Windows Server 2019 Build 17763 "
              "x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)")

    def test_banner_fields(self):
        r = parse_line(self.BANNER)
        self.assertIsInstance(r, HostInfo)
        self.assertEqual(r.hostname, "DC01")
        self.assertEqual(r.domain, "corp.local")
        self.assertTrue(r.signing)
        self.assertFalse(r.smbv1)
        self.assertEqual(r.os, "Windows Server 2019 Build 17763 x64")

    def test_signing_domain_reads_as_dc(self):
        self.assertTrue(parse_line(self.BANNER).is_dc)

    def test_member_server_is_not_dc(self):
        line = ("SMB   10.0.0.20   445   WS10   [*] Windows 10 Build 19041 x64 "
                "(name:WS10) (domain:corp.local) (signing:False) (SMBv1:False)")
        self.assertFalse(parse_line(line).is_dc)

    def test_generic_star_line_is_not_a_banner(self):
        # An nxc module status line also starts [*] but names no host fields.
        self.assertIsNone(parse_line("SMB   10.0.0.6   445   DC01   [*] Enumerated shares"))

    def test_all_pairs_kept(self):
        r = parse_line(self.BANNER)
        self.assertEqual(r.fields.get("name"), "DC01")
        self.assertIn("smbv1", r.fields)


class ParseOutputTest(unittest.TestCase):

    CAPTURE = """\
SMB   10.0.0.6   445   DC01   [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)
SMB   10.0.0.6   445   DC01   [+] corp.local\\jdoe:Winter2025!
SMB   10.0.0.7   445   WS02   [*] Windows 10 Build 19041 x64 (name:WS02) (domain:corp.local) (signing:False) (SMBv1:False)
SMB   10.0.0.7   445   WS02   [+] corp.local\\Administrator:Winter2025! (Pwn3d!)
SMB   10.0.0.8   445   WS03   [-] corp.local\\jdoe:Winter2025! STATUS_LOGON_FAILURE
"""

    def test_splits_hosts_and_auth(self):
        out = parse_output(self.CAPTURE)
        self.assertEqual(len(out.hosts), 2)
        self.assertEqual(len(out.auth), 3)

    def test_valid_and_pwned_views(self):
        out = parse_output(self.CAPTURE)
        self.assertEqual({r.ip for r in out.valid}, {"10.0.0.6", "10.0.0.7"})
        self.assertEqual([r.ip for r in out.pwned], ["10.0.0.7"])

    def test_blank_and_noise_lines_ignored(self):
        out = parse_output("\n\nnot an nxc line at all\n" + self.CAPTURE)
        self.assertEqual(len(out.auth), 3)


class PassPolicyTest(unittest.TestCase):

    POLICY = """\
SMB   10.0.0.6   445   DC01   [+] Dumping password info for domain: CORP
SMB   10.0.0.6   445   DC01   Minimum password length: 7
SMB   10.0.0.6   445   DC01   Password history length: 24
SMB   10.0.0.6   445   DC01   Maximum password age: 41 days 23 hours 53 minutes
SMB   10.0.0.6   445   DC01   Reset Account Lockout Counter: 30 minutes
SMB   10.0.0.6   445   DC01   Locked Account Duration: 30 minutes
SMB   10.0.0.6   445   DC01   Account Lockout Threshold: 5
SMB   10.0.0.6   445   DC01   Forced Log off Time: Not Set
"""

    def test_reads_threshold_and_window(self):
        p = parse_pass_policy(self.POLICY)
        self.assertIsInstance(p, PassPolicy)
        self.assertEqual(p.domain, "CORP")
        self.assertEqual(p.threshold, 5)
        self.assertEqual(p.reset_minutes, 30)
        self.assertEqual(p.min_length, 7)
        self.assertTrue(p.has_lockout)
        self.assertEqual(p.safe_attempts, 4)  # one below the threshold

    def test_mixed_unit_duration(self):
        text = self.POLICY.replace("Reset Account Lockout Counter: 30 minutes",
                                   "Reset Account Lockout Counter: 1 day 4 minutes")
        self.assertEqual(parse_pass_policy(text).reset_minutes, 1444)

    def test_lockout_disabled_reads_as_zero_and_safe_attempts_none(self):
        text = self.POLICY.replace("Account Lockout Threshold: 5",
                                   "Account Lockout Threshold: None")
        p = parse_pass_policy(text)
        self.assertEqual(p.threshold, 0)
        self.assertFalse(p.has_lockout)
        self.assertIsNone(p.safe_attempts)

    def test_no_policy_in_capture_returns_none(self):
        # An auth failure (e.g. --pass-pol denied) must not read as "no lockout".
        text = "SMB   10.0.0.6   445   DC01   [-] corp.local\\jdoe:pw STATUS_ACCESS_DENIED"
        self.assertIsNone(parse_pass_policy(text))

    def test_unread_policy_has_none_safe_attempts(self):
        self.assertIsNone(PassPolicy().safe_attempts)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
