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

    # --- axis 2: additional probe parsers ------------------------------

    def test_parse_veeam_promotes_discovered_credentials(self):
        out = (
            "SMB   10.0.0.5  445  BAK01  [*] Looking for Veeam creds\n"
            "SMB   10.0.0.5  445  BAK01  [+] Running Veeam credentials dump\n"
            "SMB   10.0.0.5  445  BAK01  CORP\\svc_backup : Winter2025!\n"
            "SMB   10.0.0.5  445  BAK01  Decrypted : vmware_api_token\n")
        r = np.parse_veeam(out)
        self.assertTrue(any(c.secret == "Winter2025!" for c in r.credentials),
                        msg=f"expected to promote CORP\\svc_backup; got {r.credentials}")
        self.assertTrue(any(f.severity == "High" for f in r.findings))

    def test_parse_teams_surfaces_cached_token_as_high_finding(self):
        out = (
            "SMB   10.0.0.5  445  WS02  [+] Found Teams cookies.db for alice@corp.com\n"
            "SMB   10.0.0.5  445  WS02  [+] Token for alice@corp.com: eyJhbGciOi...\n")
        r = np.parse_teams(out)
        self.assertTrue(any("teams_token" in f.kind for f in r.findings),
                        msg=f"expected teams_token finding; got {r.findings}")

    def test_parse_nanodump_records_lsass_dump_as_critical(self):
        out = (
            "SMB   10.0.0.5  445  DC01  [+] Running nanodump\n"
            "SMB   10.0.0.5  445  DC01  [+] Dump saved to C:\\Windows\\Temp\\lsass.dmp\n")
        r = np.parse_nanodump(out)
        self.assertEqual(len(r.findings), 1)
        self.assertEqual(r.findings[0].severity, "Critical")

    def test_parse_ms17_010_distinguishes_vulnerable_from_not(self):
        vuln = ("SMB   10.0.0.5  445  SV01  [+] 10.0.0.5 is vulnerable to MS17-010\n")
        r = np.parse_ms17_010(vuln)
        self.assertEqual(len(r.findings), 1)
        self.assertEqual(r.findings[0].severity, "Critical")
        safe = ("SMB   10.0.0.5  445  SV01  [-] 10.0.0.5 is NOT vulnerable to MS17-010\n")
        r2 = np.parse_ms17_010(safe)
        self.assertEqual(r2.findings, [])

    def test_parse_coerce_plus_flags_coercion_vulnerable_hosts(self):
        out = (
            "SMB   10.0.0.5  445  DC01  [+] Target DC01 is vulnerable to PetitPotam\n"
            "SMB   10.0.0.5  445  DC01  [+] Target DC01 is vulnerable to DFSCoerce\n")
        r = np.parse_coerce_plus(out)
        self.assertGreaterEqual(len(r.findings), 1)
        self.assertTrue(all(f.severity == "High" for f in r.findings))

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

    # --- axis 2 slice 2: 7 more probe parsers --------------------------

    def test_parse_laps_v2_promotes_computer_account_password(self):
        """LAPS v2 output surfaces ``Account: HOST$  Password: <pw>``; must promote
        the pair to a credential and tag the finding ``admin=True`` since reading
        LAPS implies the caller already has the delegated right."""
        out = ("SMB  10.0.0.5  445  DC01  Account: WS07$   Password: Correct-Horse-Battery\n")
        r = np.parse_laps_v2(out)
        self.assertEqual(len(r.credentials), 1)
        self.assertEqual(r.credentials[0].username, "WS07$")
        self.assertEqual(r.credentials[0].secret, "Correct-Horse-Battery")
        self.assertTrue(r.findings[0].admin)

    def test_parse_gpp_autologin_pairs_username_and_password(self):
        """unattend.xml output prints Username / Password on consecutive lines —
        parser must correlate them so a stray Password: line without a preceding
        Username: doesn't promote a hollow credential."""
        out = ("[+] Found /sysvol/CORP.LOCAL/Policies/{G}/MACHINE/unattend.xml\n"
               "Username: localadmin\n"
               "Password: AutoLogon-S3cret\n")
        r = np.parse_gpp_autologin(out)
        self.assertEqual(len(r.credentials), 1)
        self.assertEqual(r.credentials[0].username, "localadmin")

        orphan = "Password: NoPair\n"
        self.assertEqual(np.parse_gpp_autologin(orphan).credentials, [])

    def test_parse_chrome_promotes_decrypted_logins(self):
        out = ("[+] http://portal.corp.local alice BrowserPw!\n"
               "[+] https://sso.corp.local bob N3xt0ne\n")
        r = np.parse_chrome(out)
        self.assertEqual(len(r.credentials), 2)
        secrets = {c.secret for c in r.credentials}
        self.assertEqual(secrets, {"BrowserPw!", "N3xt0ne"})

    def test_parse_firefox_promotes_decrypted_logins(self):
        out = ("[+] https://jira.corp.local eve FxSecret!\n")
        r = np.parse_firefox(out)
        self.assertEqual(len(r.credentials), 1)
        self.assertEqual(r.credentials[0].source, "nxc-probe:firefox")

    def test_parse_keepass_discover_flags_kdbx_findings(self):
        """Must surface .kdbx finds as High (the DB is useless without the master
        key — but discovery alone is a weaponization opportunity)."""
        out = ("[+] Found: \\\\SRV\\Backups\\IT\\passwords.kdbx\n"
               "[+] Found: \\\\SRV\\Shared\\notes.kdbx\n"
               "[-] No KeePass databases on \\\\PRINT01\n")
        r = np.parse_keepass_discover(out)
        self.assertEqual(len(r.findings), 2)
        self.assertTrue(all(f.severity == "High" for f in r.findings))

    def test_parse_masky_promotes_nt_hash_as_critical(self):
        """Masky returns an NT hash of the logged-on user. Parser must extract both
        the username and the hex hash so retest can replay the credential."""
        out = ("[+] Successfully retrieved alice NT hash: aad3b435b51404eeaad3b435b51404ee\n")
        r = np.parse_masky(out)
        self.assertEqual(len(r.credentials), 1)
        self.assertEqual(r.credentials[0].secret_type, "ntlm")
        self.assertEqual(r.findings[0].severity, "Critical")

    def test_parse_masky_ignores_non_hex_tails(self):
        """A log line matching 'NT hash:' pattern but followed by a non-hex value
        must NOT promote — guards against generic log messages or malformed output."""
        out = ("[*] Target has NT hash: unknown\n")
        r = np.parse_masky(out)
        self.assertEqual(r.credentials, [])

    def test_parse_shadowcredentials_flags_write_success(self):
        out = ("[+] Shadow credentials added for CN=alice,OU=users,DC=corp,DC=local\n"
               "[+] Certificate saved to /tmp/alice.pfx\n")
        r = np.parse_shadowcredentials(out)
        self.assertEqual(len(r.findings), 2)
        # First finding (the write success) must be admin-tagged.
        self.assertTrue(r.findings[0].admin)

    # --- axis 2 slice 3: 6 more probe parsers --------------------------

    def test_parse_petitpotam_flags_vulnerable_target(self):
        out = ("SMB   10.0.0.10  445  DC01  [+] DC01 is vulnerable to PetitPotam\n")
        r = np.parse_petitpotam(out)
        self.assertEqual(len(r.findings), 1)
        self.assertEqual(r.findings[0].severity, "High")

    def test_parse_nopac_promotes_dumped_hash(self):
        """noPAC's shape is "DOMAIN\\user:RID:LMhash:NThash" — classic
        secretsdump line. Parser must promote the NT hash as a usable
        credential."""
        out = ("[+] DC01 is vulnerable to noPAC\n"
               "krbtgt:502:aad3b435b51404eeaad3b435b51404ee:"
               "31d6cfe0d16ae931b73c59d7e0c089c0:::\n")
        r = np.parse_nopac(out)
        # Vulnerability finding + credential promoted.
        vulns = [f for f in r.findings if f.kind == "nopac_vulnerable"]
        self.assertTrue(vulns)
        self.assertTrue(vulns[0].admin)
        self.assertEqual(len(r.credentials), 1)
        self.assertEqual(r.credentials[0].username, "krbtgt")

    def test_parse_lsa_backup_keys_flags_pvk_export_as_critical(self):
        out = ("[+] DPAPI domain backup key saved to /tmp/corp.pvk\n")
        r = np.parse_lsa_backup_keys(out)
        self.assertEqual(len(r.findings), 1)
        self.assertEqual(r.findings[0].severity, "Critical")
        self.assertTrue(r.findings[0].admin)

    def test_parse_dpapi_ng_surfaces_decrypted_blobs(self):
        out = ("[+] Decrypted LAPSv2 blob: WORKSTATION-01$ -> SuperSecret!\n"
               "[+] Unprotected KeyCredential for alice: xxxx\n")
        r = np.parse_dpapi_ng(out)
        self.assertEqual(len(r.findings), 2)

    def test_parse_rdcman_promotes_server_user_password(self):
        out = ("[+] WIN-DB01\\sqladmin:DbPassw0rd!\n")
        r = np.parse_rdcman(out)
        self.assertEqual(len(r.credentials), 1)
        c = r.credentials[0]
        self.assertEqual(c.username, "sqladmin")
        self.assertEqual(c.domain, "WIN-DB01")
        self.assertEqual(c.secret, "DbPassw0rd!")

    def test_parse_rdcman_ignores_lines_without_both_parts(self):
        """A line with ":" but no "\\" (plain log output) must not promote."""
        out = ("[+] Starting RDCMan parse: /path/to/file.rdg\n")
        r = np.parse_rdcman(out)
        self.assertEqual(r.credentials, [])

    def test_parse_enum_dns_surfaces_host_records(self):
        out = ("dc01.corp.local  A     10.0.0.10\n"
               "dc01.corp.local  A     10.0.0.10\n"  # duplicate, must dedupe
               "fs01.corp.local  A     10.0.0.20\n"
               "ldap.corp.local  CNAME dc01.corp.local\n")
        r = np.parse_enum_dns(out)
        self.assertEqual(len(r.findings), 3)
        self.assertTrue(all(f.kind == "dns_record" for f in r.findings))

    # --- axis 2 slice 5: 10 more probe parsers -------------------------

    def test_parse_drop_sc_promotes_cached_server_credentials(self):
        out = ("[+] Found config: C:\\ProgramData\\sc.xml\n"
               "URL: wss://sc.corp\n"
               "User: svc_sc\n"
               "Password: ScPw!\n")
        r = np.parse_drop_sc(out)
        self.assertEqual(len(r.credentials), 1)
        self.assertEqual(r.credentials[0].domain, "wss://sc.corp")

    def test_parse_scuffy_flags_scf_write(self):
        out = "[+] File written to \\\\attacker\\share\\loot.scf\n"
        r = np.parse_scuffy(out)
        self.assertEqual(len(r.findings), 1)
        self.assertEqual(r.findings[0].severity, "High")

    def test_parse_spooler_flags_enabled_service(self):
        out = "[+] 10.0.0.1 Print Spooler service is enabled and running\n"
        r = np.parse_spooler(out)
        self.assertEqual(len(r.findings), 1)
        self.assertEqual(r.findings[0].kind, "print_spooler_enabled")

    def test_parse_ldap_checker_flags_relay_candidates(self):
        out = ("[+] dc01 does not require LDAP signing\n"
               "[+] dc02 does not require channel binding\n")
        r = np.parse_ldap_checker(out)
        self.assertEqual(len(r.findings), 2)
        self.assertTrue(all(f.kind == "ldap_relay_candidate" for f in r.findings))

    def test_parse_obsolete_nt_hash_users_flags_pre2004(self):
        out = ("legacyuser   2001-05-01   pre2004\n"
               "modernuser   2024-01-01   nt4\n")
        r = np.parse_obsolete_nt_hash_users(out)
        self.assertEqual(len(r.findings), 1)
        self.assertIn("legacyuser", r.findings[0].title)

    def test_parse_pre2k_promotes_hostname_lowercased_password(self):
        """pre2k shape is: computer account password == lowercased hostname.
        Parser must extract HOST$ and promote `host:host-lowered` as a
        credential so the credential loop replays it."""
        out = ("[+] HOST01$ pre2k auth works\n")
        r = np.parse_pre2k(out)
        self.assertEqual(len(r.credentials), 1)
        self.assertEqual(r.credentials[0].username, "HOST01$")
        self.assertEqual(r.credentials[0].secret, "host01")

    def test_parse_get_network_dedupes_subnet_lines(self):
        out = ("[+] 10.0.0.0/24  Site: HQ\n"
               "[+] 10.0.0.0/24  Site: HQ\n"
               "[+] 10.0.1.0/24  Site: Branch\n")
        r = np.parse_get_network(out)
        self.assertEqual(len(r.findings), 2)

    def test_parse_groupmembership_extracts_member_names(self):
        out = ("[+] Member: alice\n"
               "[+] Member: bob\n"
               "[+] Member: svc_backup\n")
        r = np.parse_groupmembership(out)
        self.assertEqual(len(r.findings), 3)

    def test_parse_rid_brute_classifies_sid_types(self):
        out = ("CORP\\alice (SidTypeUser)\n"
               "CORP\\Domain Admins (SidTypeGroup)\n"
               "CORP\\host01$ (SidTypeUser)\n"
               "CORP\\alice (SidTypeUser)\n"
               )  # last line duplicate, must dedupe
        r = np.parse_rid_brute(out)
        self.assertEqual(len(r.findings), 3)
        kinds = {f.kind for f in r.findings}
        self.assertEqual(kinds, {"domain_user", "domain_group"})

    def test_parse_users_computers_distinguishes_user_vs_computer(self):
        out = ("[*] alice     Senior Engineer\n"
               "[*] WS07$     Windows 11 23H2\n"
               "[*] svc_db    DB service account\n"
               "[*] DC01$     Windows Server 2022\n")
        r = np.parse_users_computers(out)
        kinds = {f.kind for f in r.findings}
        self.assertEqual(kinds, {"domain_user", "domain_computer"})
        users = {f.title.split()[-1] for f in r.findings if f.kind == "domain_user"}
        computers = {f.title.split()[-1] for f in r.findings if f.kind == "domain_computer"}
        self.assertEqual(users, {"alice", "svc_db"})
        self.assertEqual(computers, {"WS07$", "DC01$"})


if __name__ == "__main__":
    unittest.main()
