#!/usr/bin/env python3
"""Host enumeration — run every read-only check, then parse it into facts.

Pinned:

  * run_enum executes the whole OS plan through the executor and captures each check;
  * facts_for reparses that captured evidence into HostFacts — the whoami /priv and
    sudo -l signals the privesc predicates key on;
  * a host with no known OS (or no proven path) is reported, not guessed at.

Run:  python3 -m unittest discover -s tests
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit.creds import Credential  # noqa: E402
from fieldkit.hostenum import facts_for, run_enum  # noqa: E402
from fieldkit.runner import RunResult  # noqa: E402
from fieldkit.state import Store  # noqa: E402

LINUX_OUT = {
    "id": "uid=1000(svc) gid=1000(svc) groups=1000(svc),27(sudo),999(docker)",
    "sudo -n -l 2>/dev/null": (
        "Matching Defaults entries for svc on host:\n"
        "    env_reset, env_keep+=LD_PRELOAD\n\n"
        "User svc may run the following commands on host:\n"
        "    (root) NOPASSWD: /usr/bin/find\n"),
    "find / -perm -4000 -type f 2>/dev/null": "/usr/bin/sudo\n/usr/bin/find\n/usr/bin/passwd\n",
    "getcap -r / 2>/dev/null": "/usr/bin/python3.8 = cap_setuid+ep\n",
    "uname -a": "Linux host 5.15.0-72-generic #79-Ubuntu SMP x86_64 GNU/Linux",
}

WIN_OUT = {
    "whoami /priv": (
        "PRIVILEGES INFORMATION\n----------------------\n"
        "Privilege Name                State\n"
        "SeImpersonatePrivilege        Enabled\n"
        "SeChangeNotifyPrivilege       Enabled\n"),
    "whoami /groups": "BUILTIN\\Remote Management Users\nBUILTIN\\Backup Operators\n",
    "services": ("Name     PathName                          StartMode\n"
                 "MyApp    C:\\Program Files\\My App\\svc.exe   Auto\n"
                 "Spooler  C:\\Windows\\System32\\spoolsv.exe   Auto\n"),
    # per-service SDDL + icacls. MyApp: Authenticated Users get change-config (DC) AND the
    # binary/dir are writable by Users. Spooler: neither.
    "svcperms": (
        "SVC|MyApp|C:\\Program Files\\My App\\svc.exe|"
        "O:SYG:SYD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;BU)\n"
        "ACL|MyApp|C:\\Program Files\\My App\\svc.exe|C:\\Program Files\\My App\\svc.exe "
        "BUILTIN\\Users:(F);NT AUTHORITY\\SYSTEM:(F);Successfully processed 1 files.\n"
        "DIR|MyApp|C:\\Program Files\\My App|C:\\Program Files\\My App "
        "BUILTIN\\Users:(M);Successfully processed 1 files.\n"
        "SVC|Spooler|C:\\Windows\\System32\\spoolsv.exe|"
        "O:SYG:SYD:(A;;CCLCSWLOCRRC;;;AU)\n"
        "ACL|Spooler|C:\\Windows\\System32\\spoolsv.exe|C:\\Windows\\System32\\spoolsv.exe "
        "BUILTIN\\Administrators:(F);BUILTIN\\Users:(RX);Successfully processed 1 files.\n"),
}


def make_runner(table, aie_both=True):
    """Fake nxc: return canned output for the command sitting after -x/-X."""
    def run(argv, env=None):
        flag = "-x" if "-x" in argv else "-X"
        command = argv[argv.index(flag) + 1]
        if command.startswith("reg query"):
            hit = "    AlwaysInstallElevated    REG_DWORD    0x1\n"
            return RunResult(argv, exit_code=0, stdout=hit * (2 if aie_both else 1))
        if command.startswith("wmic service"):
            return RunResult(argv, exit_code=0, stdout=table.get("services", ""))
        if "sdshow" in command:
            return RunResult(argv, exit_code=0, stdout=table.get("svcperms", ""))
        return RunResult(argv, exit_code=0, stdout=table.get(command, ""))
    return run


class EnumTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME")

    def linux_host(self):
        hid, _ = self.store.add_host("10.0.0.8", os_name="linux")
        cid, _ = self.store.add_credential(Credential("svc", "s3cret", domain="corp"))
        self.store.add_access(hid, cid, "ssh", admin=False)
        return self.store.host_by_ip("10.0.0.8"), self.store.credential_by_id(cid), hid

    def windows_host(self):
        hid, _ = self.store.add_host("10.0.0.7", os_name="windows")
        cid, _ = self.store.add_credential(Credential("jdoe", "pw", domain="corp"))
        self.store.add_access(hid, cid, "winrm", admin=False)
        return self.store.host_by_ip("10.0.0.7"), self.store.credential_by_id(cid), hid


class LinuxFactsTest(EnumTestCase):
    def test_run_and_parse(self):
        host, cred, hid = self.linux_host()
        report = run_enum(self.store, host, cred, run=make_runner(LINUX_OUT))
        self.assertIsNone(report.blocked)
        self.assertEqual(set(report.ran), {"id", "sudo", "suid", "caps", "kernel"})
        f = facts_for(self.store, hid)
        self.assertEqual((f.user, f.uid), ("svc", 1000))
        self.assertFalse(f.is_root)
        self.assertEqual(f.groups, {"svc", "sudo", "docker"})
        self.assertIn("find", f.sudo_binaries)
        self.assertTrue(f.sudo_nopasswd)
        self.assertEqual(f.sudo_env_keep, {"LD_PRELOAD"})
        self.assertIn("find", f.suid)
        self.assertEqual(f.caps.get("python3.8"), "cap_setuid")
        self.assertEqual(f.kernel, "5.15.0")

    def test_sudo_all_detected(self):
        host, cred, hid = self.linux_host()
        table = dict(LINUX_OUT)
        table["sudo -n -l 2>/dev/null"] = "User svc may run the following commands:\n    (ALL : ALL) ALL\n"
        run_enum(self.store, host, cred, run=make_runner(table))
        self.assertTrue(facts_for(self.store, hid).sudo_all)


class WindowsFactsTest(EnumTestCase):
    def test_run_and_parse(self):
        host, cred, hid = self.windows_host()
        report = run_enum(self.store, host, cred, run=make_runner(WIN_OUT))
        self.assertEqual(set(report.ran), {"priv", "groups", "aie", "services", "svcperms"})
        f = facts_for(self.store, hid)
        self.assertIn("SeImpersonatePrivilege", f.privs)
        self.assertIn("Backup Operators", f.win_groups)
        self.assertIn("Remote Management Users", f.win_groups)
        self.assertTrue(f.always_install_elevated)
        self.assertEqual(len(f.unquoted_services), 1)  # MyApp, not the C:\Windows Spooler
        self.assertEqual(f.unquoted_services[0][0], "MyApp")  # the service name is captured
        # MyApp's ACL grants Authenticated Users change-config; Spooler's does not
        self.assertIn("MyApp", f.reconfigurable_services)
        self.assertNotIn("Spooler", f.reconfigurable_services)
        # MyApp's binary + directory are writable by Users; Spooler's (RX) are not
        self.assertIn("MyApp", f.writable_service_bins)
        self.assertIn("MyApp", f.writable_service_dirs)
        self.assertNotIn("Spooler", f.writable_service_bins)

    def test_aie_needs_both_keys(self):
        host, cred, hid = self.windows_host()
        run_enum(self.store, host, cred, run=make_runner(WIN_OUT, aie_both=False))
        self.assertFalse(facts_for(self.store, hid).always_install_elevated)


class SvcPermsParseTest(unittest.TestCase):
    """The SDDL change-config heuristic — a broad principal with DC/GA/mask is a hijack."""

    def parse(self, sddl):
        from fieldkit.hostenum import HostFacts, _p_svcperms
        f = HostFacts(os="windows")
        _p_svcperms(f, f"SVC|Svc|C:\\svc.exe|{sddl}\n")
        return "Svc" in f.reconfigurable_services

    def test_dc_letter_to_authenticated_users(self):
        self.assertTrue(self.parse("D:(A;;CCDCLCSWRPWP;;;AU)"))

    def test_generic_all_to_users(self):
        self.assertTrue(self.parse("D:(A;;GA;;;BU)"))

    def test_hex_mask_with_change_config_bit(self):
        self.assertTrue(self.parse("D:(A;;0x00000002;;;WD)"))   # 0x2 = SERVICE_CHANGE_CONFIG

    def test_change_config_to_narrow_sid_ignored(self):
        # granting a specific service SID / SYSTEM change-config is normal, not a finding
        self.assertFalse(self.parse("D:(A;;GA;;;S-1-5-80-1234)"))

    def test_broad_sid_without_change_config_ignored(self):
        self.assertFalse(self.parse("D:(A;;CCLCSWRPWPLOCRRC;;;AU)"))  # start/stop, not DC


class IcaclsWritableTest(unittest.TestCase):
    """The icacls heuristic — a broad principal with a write-capable mask, despite the
    drive-letter colon in the leading path."""

    def w(self, acl):
        from fieldkit.hostenum import _icacls_writable
        return _icacls_writable(acl)

    def test_users_full_is_writable(self):
        self.assertTrue(self.w("C:\\svc.exe BUILTIN\\Users:(F);NT AUTHORITY\\SYSTEM:(F)"))

    def test_everyone_modify_is_writable(self):
        self.assertTrue(self.w("C:\\a\\svc.exe Everyone:(M)"))

    def test_users_read_exec_is_not_writable(self):
        self.assertFalse(self.w("C:\\svc.exe BUILTIN\\Users:(RX);BUILTIN\\Administrators:(F)"))

    def test_admins_full_is_not_broad(self):
        self.assertFalse(self.w("C:\\svc.exe BUILTIN\\Administrators:(F);NT SERVICE\\X:(F)"))


class GuardTest(EnumTestCase):
    def test_unknown_os_is_reported(self):
        hid, _ = self.store.add_host("10.0.0.5")  # no os
        cid, _ = self.store.add_credential(Credential("x", "y"))
        self.store.add_access(hid, cid, "smb", admin=True)
        host = self.store.host_by_ip("10.0.0.5")
        report = run_enum(self.store, host, self.store.credential_by_id(cid),
                          run=make_runner({}))
        self.assertIn("OS unknown", report.blocked)

    def test_no_transport_is_reported(self):
        host, cred, _ = self.linux_host()
        # strip the proven access so no transport applies
        self.store.conn.execute("DELETE FROM access")
        self.store.conn.commit()
        report = run_enum(self.store, host, cred, run=make_runner(LINUX_OUT))
        self.assertIn("no proven way", report.blocked)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
