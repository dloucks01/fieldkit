#!/usr/bin/env python3
"""Transports — command execution rendered to argv, and honest applicability.

Pinned here:

  * render_exec produces an argv (never a shell string), so a command with quotes
    and pipes reaches the target intact;
  * applicability tells the truth about preconditions — SMB-exec needs admin, WinRM
    and SSH do not — and select picks the least-privileged proven path.

Run:  python3 -m unittest discover -s tests
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit.creds import Credential  # noqa: E402
from fieldkit.transport import (  # noqa: E402
    applicable, by_name, render_exec, render_put, select, select_put,
)


class RenderTest(unittest.TestCase):
    def test_winrm_cmd_argv(self):
        cred = Credential("jdoe", "Winter2025!", domain="corp")
        r = render_exec(by_name("winrm"), cred, "10.0.0.7", "whoami /priv")
        self.assertEqual(r.argv[:3], ["nxc", "winrm", "10.0.0.7"])
        self.assertIn("-x", r.argv)
        # the command is one argv element — pipes/quotes are not re-parsed by a shell
        self.assertEqual(r.argv[r.argv.index("-x") + 1], "whoami /priv")

    def test_powershell_uses_capital_x(self):
        cred = Credential("jdoe", "pw", domain="corp")
        r = render_exec(by_name("winrm-ps"), cred, "10.0.0.7", "Get-Process")
        self.assertIn("-X", r.argv)
        self.assertNotIn("-x", r.argv)

    def test_command_with_pipe_survives_as_one_arg(self):
        cred = Credential("jdoe", "pw", domain="corp")
        cmd = "whoami /priv | findstr SeImpersonate"
        r = render_exec(by_name("winrm"), cred, "10.0.0.7", cmd)
        self.assertIn(cmd, r.argv)

    def test_ssh_key_credential_renders_key_file(self):
        cred = Credential("root", "/home/op/id_rsa", secret_type="ssh_key")
        r = render_exec(by_name("ssh"), cred, "10.0.0.8", "id")
        self.assertIn("--key-file", r.argv)


class ApplicabilityTest(unittest.TestCase):
    def test_smb_exec_needs_admin(self):
        smb = by_name("smb")
        self.assertFalse(applicable(smb, "windows", {"smb"}, is_admin=False))
        self.assertTrue(applicable(smb, "windows", {"smb"}, is_admin=True))

    def test_winrm_needs_no_admin(self):
        self.assertTrue(applicable(by_name("winrm"), "windows", {"winrm"}, is_admin=False))

    def test_proto_must_be_proven(self):
        # We hold SMB but never proved WinRM — WinRM-exec is not applicable.
        self.assertFalse(applicable(by_name("winrm"), "windows", {"smb"}, is_admin=True))

    def test_os_enforced_only_when_known(self):
        ssh = by_name("ssh")
        self.assertFalse(applicable(ssh, "windows", {"ssh"}, is_admin=False))
        self.assertTrue(applicable(ssh, None, {"ssh"}, is_admin=False))  # unknown OS: allowed


class SelectTest(unittest.TestCase):
    def test_non_admin_foothold_picks_winrm_over_smb(self):
        t = select("windows", {"winrm", "smb"}, is_admin=False)
        self.assertEqual(t.name, "winrm")  # smb-exec needs admin, winrm does not

    def test_admin_still_prefers_winrm_quiet_path(self):
        t = select("windows", {"winrm", "smb"}, is_admin=True)
        self.assertEqual(t.name, "winrm")  # quieter, no on-disk service

    def test_smb_used_when_only_admin_smb_proven(self):
        t = select("windows", {"smb"}, is_admin=True)
        self.assertEqual(t.name, "smb")

    def test_no_proven_path_returns_none(self):
        self.assertIsNone(select("windows", {"smb"}, is_admin=False))

    def test_shell_constraint(self):
        t = select("windows", {"winrm"}, is_admin=False, shell="powershell")
        self.assertEqual(t.name, "winrm-ps")

    def test_linux_selects_ssh(self):
        t = select("linux", {"ssh"}, is_admin=False)
        self.assertEqual(t.name, "ssh")


class MssqlTest(unittest.TestCase):
    def test_sysadmin_gets_the_mssql_exec_transport(self):
        # xp_cmdshell exec needs sysadmin (Pwn3d!); it ranks below smb when both exist.
        self.assertEqual(select("windows", {"mssql"}, is_admin=True).name, "mssql")
        self.assertIsNone(select("windows", {"mssql"}, is_admin=False))
        self.assertEqual(select("windows", {"smb", "mssql"}, is_admin=True).name, "smb")

    def test_render_mssql_exec_uses_mssql_proto(self):
        t = by_name("mssql")
        r = render_exec(t, Credential("sa", "pw"), "10.0.0.9", "whoami")
        self.assertEqual(r.argv[0], "nxc")
        self.assertEqual(r.argv[1], "mssql")
        self.assertIn("-x", r.argv)
        self.assertIn("whoami", r.argv)


class PutTest(unittest.TestCase):
    def test_smb_put_needs_admin(self):
        self.assertIsNone(select_put("windows", {"smb"}, is_admin=False))
        self.assertEqual(select_put("windows", {"smb"}, is_admin=True).name, "smb")

    def test_winrm_has_no_put_path(self):
        # winrm can exec but not transfer files — no staging over it.
        self.assertIsNone(select_put("windows", {"winrm"}, is_admin=False))

    def test_ssh_can_put(self):
        self.assertEqual(select_put("linux", {"ssh"}, is_admin=False).name, "ssh")

    def test_render_put_builds_put_file_argv(self):
        t = by_name("smb")
        r = render_put(t, Credential("admin", "pw", domain="corp"), "10.0.0.7",
                       "/arsenal/GodPotato.exe", "C:\\Windows\\Temp\\GodPotato.exe")
        self.assertIn("--put-file", r.argv)
        i = r.argv.index("--put-file")
        self.assertEqual(r.argv[i + 1:i + 3],
                         ["/arsenal/GodPotato.exe", "C:\\Windows\\Temp\\GodPotato.exe"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
