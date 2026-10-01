"""Tests for :mod:`fieldkit.nxc_probes` — the built-in nxc flags/modules that fieldkit
drives beyond the exec transport (``--shares``, ``--loggedon-users``, ``--sessions``,
``-M laps``, ``-M gpp_password``). Each parser is tested against a captured nxc
output snippet, and the ``run_probes`` driver is tested end-to-end with a fake runner
so no subprocess is spawned."""
import unittest
from dataclasses import dataclass

from fieldkit import nxc_probes as np
from fieldkit.runner import RunResult


# ---------------------------------------------------------------- parser tests


class TestParseShares(unittest.TestCase):

    OUTPUT = (
        "SMB   10.0.0.1  445  DC01  [*] Windows Server 2019 (name:DC01) "
        "(domain:corp.local) (signing:True) (SMBv1:False)\n"
        "SMB   10.0.0.1  445  DC01  [+] corp.local\\Administrator:Pass (Pwn3d!)\n"
        "SMB   10.0.0.1  445  DC01  [*] Enumerated shares\n"
        "SMB   10.0.0.1  445  DC01  Share           Permissions     Remark\n"
        "SMB   10.0.0.1  445  DC01  -----           -----------     ------\n"
        "SMB   10.0.0.1  445  DC01  ADMIN$          READ,WRITE      Remote Admin\n"
        "SMB   10.0.0.1  445  DC01  C$              READ,WRITE      Default share\n"
        "SMB   10.0.0.1  445  DC01  IPC$                            IPC Service\n"
        "SMB   10.0.0.1  445  DC01  NETLOGON        READ\n"
        "SMB   10.0.0.1  445  DC01  SYSVOL          READ,WRITE\n")

    def test_write_share_medium(self):
        findings = np.parse_shares(self.OUTPUT)
        writable = [f for f in findings if "WRITE" in f.title]
        self.assertTrue(all(f.severity == "Medium" for f in writable))
        titles = [f.title for f in findings]
        self.assertTrue(any("ADMIN$" in t for t in titles))
        self.assertTrue(any("SYSVOL" in t for t in titles))

    def test_ipc_with_no_perms_is_skipped(self):
        findings = np.parse_shares(self.OUTPUT)
        self.assertFalse(any("IPC$" in f.title for f in findings))


class TestParseLoggedOnUsers(unittest.TestCase):

    OUTPUT = (
        "SMB   10.0.0.1  445  DC01  [+] Enumerated logged-on users\n"
        "SMB   10.0.0.1  445  DC01  CORP\\Administrator     type: interactive\n"
        "SMB   10.0.0.1  445  DC01  CORP\\svc_backup        type: service\n")

    def test_extracts_principals(self):
        findings = np.parse_loggedon_users(self.OUTPUT)
        titles = [f.title for f in findings]
        self.assertTrue(any("CORP\\Administrator" in t for t in titles))
        self.assertTrue(any("CORP\\svc_backup" in t for t in titles))


class TestParseLaps(unittest.TestCase):

    OUTPUT = (
        "SMB   10.0.0.5  445  WS01  [*] LAPS query succeeded\n"
        "SMB   10.0.0.5  445  WS01  Computer: WS01$    Password: 7Wf!q8xL2@zY\n")

    def test_promotes_password(self):
        r = np.parse_laps(self.OUTPUT)
        self.assertEqual(len(r.findings), 1)
        self.assertEqual(r.findings[0].severity, "High")
        self.assertEqual(len(r.credentials), 1)
        self.assertEqual(r.credentials[0].secret, "7Wf!q8xL2@zY")


class TestParseGppPassword(unittest.TestCase):

    OUTPUT = (
        "SMB   10.0.0.10  445  DC01  [*] gpp_password: SYSVOL scanned\n"
        "SMB   10.0.0.10  445  DC01  username: local_admin  password: SuperSecret1\n")

    def test_promotes_cpassword(self):
        r = np.parse_gpp(self.OUTPUT)
        self.assertEqual(len(r.credentials), 1)
        self.assertEqual(r.credentials[0].username, "local_admin")
        self.assertEqual(r.credentials[0].secret, "SuperSecret1")


# ---------------------------------------------------------------- driver test


class _FakeStore:
    """Enough of :class:`fieldkit.state.Store` to exercise ``run_probes``."""

    def __init__(self):
        self.steps, self.findings, self.credentials = [], [], []
        self.access = []       # (host_id, cred_id, method, admin)

    def transaction(self):
        return self  # context manager: __enter__/__exit__ are self

    def __enter__(self): return self
    def __exit__(self, *_): return False

    def add_step(self, cmd, output=None, exit_code=None, host_id=None,
                 finding_id=None, label=None, transport=None):
        self.steps.append({"cmd": cmd, "output": output, "transport": transport,
                           "host_id": host_id})
        return len(self.steps)

    def add_finding(self, vector_type, title, host_id=None, evidence=None,
                    severity=None, risk=None, proven=None, asset_id=None):
        self.findings.append({"vector_type": vector_type, "title": title,
                              "severity": severity, "proven": proven})
        return len(self.findings)

    def add_credential(self, cred, source="manual", notes=None):
        self.credentials.append({"user": cred.username, "secret": cred.secret,
                                 "source": source})
        return len(self.credentials), True

    def add_access(self, host_id, cred_id, method, admin=False, integrity=None):
        self.access.append({"host_id": host_id, "cred_id": cred_id,
                            "method": method, "admin": bool(admin)})
        return len(self.access), True


class TestRunProbes(unittest.TestCase):

    HOST = {"id": 1, "ip": "10.0.0.1", "os": "windows"}

    def _cred_row(self):
        return {"id": 1, "domain": "CORP", "username": "Administrator",
                "secret": "Passw0rd!", "secret_type": "password", "local_auth": 0}

    def test_non_admin_skips_admin_only_probes(self):
        store = _FakeStore()
        calls = []

        def fake_run(argv, env):
            calls.append(argv)
            return RunResult(argv=argv, stdout="", stderr="", exit_code=0)

        r = np.run_probes(store, self.HOST, self._cred_row(), is_admin=False,
                          run=fake_run)
        skipped_keys = {k for k, _ in r.skipped}
        self.assertIn("laps", skipped_keys)
        self.assertIn("loggedon_users", skipped_keys)
        # non-admin probes still ran
        ran_keys = {k for k, _ in r.ran}
        self.assertIn("shares", ran_keys)
        self.assertIn("gpp_password", ran_keys)

    def test_shares_probe_records_finding(self):
        store = _FakeStore()
        # only fire the shares probe for this test
        one = (np.PROBES[0],)

        def fake_run(argv, env):
            return RunResult(
                argv=argv, exit_code=0, stderr="",
                stdout=TestParseShares.OUTPUT)

        np.run_probes(store, self.HOST, self._cred_row(), is_admin=True,
                      run=fake_run, probes=one)
        # step captured
        self.assertEqual(len(store.steps), 1)
        self.assertIn("--shares", store.steps[0]["cmd"])
        # findings written — includes WRITE shares as Medium
        self.assertTrue(any(
            "SYSVOL" in f["title"] and f["severity"] == "Medium"
            for f in store.findings))

    def test_laps_probe_promotes_credential(self):
        store = _FakeStore()
        laps_only = tuple(p for p in np.PROBES if p.key == "laps")

        def fake_run(argv, env):
            return RunResult(
                argv=argv, exit_code=0, stderr="",
                stdout=TestParseLaps.OUTPUT)

        np.run_probes(store, self.HOST, self._cred_row(), is_admin=True,
                      run=fake_run, probes=laps_only)
        self.assertEqual(len(store.credentials), 1)
        self.assertEqual(store.credentials[0]["secret"], "7Wf!q8xL2@zY")

    #: A ``--shares`` capture matching the Samba DC lab: sysvol AND netlogon
    #: are both READ,WRITE (replication-grade = domain admin). This is the
    #: exact shape that nxc's ``(Pwn3d!)`` C$-based oracle misses, and the
    #: shape the heuristic promotes.
    SAMBA_DC_SHARES = (
        "SMB   10.0.0.1  445  DC01  [*] Enumerated shares\n"
        "SMB   10.0.0.1  445  DC01  Share           Permissions     Remark\n"
        "SMB   10.0.0.1  445  DC01  -----           -----------     ------\n"
        "SMB   10.0.0.1  445  DC01  sysvol          READ,WRITE\n"
        "SMB   10.0.0.1  445  DC01  netlogon        READ,WRITE\n"
        "SMB   10.0.0.1  445  DC01  IPC$                            IPC Service\n")

    def test_shares_probe_promotes_admin_on_samba_dc(self):
        """SYSVOL + NETLOGON both writable → promote the SMB access row to admin.
        nxc's ``(Pwn3d!)`` oracle is C$-based and misses Samba DCs; without this
        heuristic a correct domain-admin cred stays flagged "0 admin on 0 hosts"."""
        store = _FakeStore()
        shares_only = tuple(p for p in np.PROBES if p.key == "shares")

        def fake_run(argv, env):
            return RunResult(
                argv=argv, exit_code=0, stderr="",
                stdout=self.SAMBA_DC_SHARES)

        rep = np.run_probes(store, self.HOST, self._cred_row(), is_admin=False,
                            run=fake_run, probes=shares_only)
        self.assertTrue(rep.promoted_admin)
        self.assertEqual(len(store.access), 1)
        self.assertTrue(store.access[0]["admin"])
        self.assertEqual(store.access[0]["method"], "smb")

    def test_shares_probe_does_not_promote_when_already_admin(self):
        """When the cred is already admin, no promotion event (prevents duplicate
        'promoted to admin' event lines)."""
        store = _FakeStore()
        shares_only = tuple(p for p in np.PROBES if p.key == "shares")

        def fake_run(argv, env):
            return RunResult(
                argv=argv, exit_code=0, stderr="",
                stdout=self.SAMBA_DC_SHARES)

        rep = np.run_probes(store, self.HOST, self._cred_row(), is_admin=True,
                            run=fake_run, probes=shares_only)
        self.assertFalse(rep.promoted_admin)

    def test_dc_admin_shares_requires_both_sysvol_and_netlogon_write(self):
        """SYSVOL writable alone (an orphan permission) must NOT promote — only
        the full pair indicates domain-admin."""
        shares_only_sysvol = [
            np.ProbeFinding(kind="smb_share",
                            title="SMB share 'sysvol' — READ,WRITE",
                            evidence="", severity="Medium"),
            np.ProbeFinding(kind="smb_share",
                            title="SMB share 'netlogon' — READ",
                            evidence="", severity="Info"),
        ]
        self.assertFalse(np._is_dc_admin_by_shares(shares_only_sysvol))

        both_writable = shares_only_sysvol + [
            np.ProbeFinding(kind="smb_share",
                            title="SMB share 'netlogon' — READ,WRITE",
                            evidence="", severity="Medium"),
        ]
        self.assertTrue(np._is_dc_admin_by_shares(both_writable))


if __name__ == "__main__":
    unittest.main()
