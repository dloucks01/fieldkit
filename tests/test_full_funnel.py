#!/usr/bin/env python3
"""Full-funnel integration test — one engagement, end to end, through the real CLI.

Drives ``fieldkit.cli.main`` exactly as an operator does — init, add creds/hosts,
spray the credential loop (foothold -> loot -> pivot to DA), enumerate, analyze,
fire a privesc vector, roast, find delegation, enumerate ADCS, ingest BloodHound,
then --check + render the report and export to recce. Unlike the per-module tests
(which inject fake runners), this exercises the *whole* stack including the real
subprocess runner: fake ``nxc`` / ``certipy`` executables are placed on PATH, so
transport selection, argv rendering, capture, the safety gate and the report all run
for real. Mirrors the subprocess style of test_integration_recce.

Run:  python3 -m unittest discover -s tests
"""
import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit.state import Store  # noqa: E402

# --------------------------------------------------------------------- fake tools

FAKE_NXC = r'''#!/usr/bin/env python3
import sys
a = sys.argv[1:]
def val(f): return a[a.index(f) + 1] if f in a else None

if "--pass-pol" in a:
    print("SMB 10.0.0.10 445 DC01 [+] Dumping password info for domain: CORP")
    print("SMB 10.0.0.10 445 DC01 Account Lockout Threshold: 5")
    print("SMB 10.0.0.10 445 DC01 Reset Account Lockout Counter: 30 minutes")
    sys.exit(0)
if "--sam" in a or "--lsa" in a:
    if a[1] == "10.0.0.7":
        print("SMB 10.0.0.7 445 WS02 [+] Dumping LSA secrets")
        print("SMB 10.0.0.7 445 WS02 corp.local\\svc_adm:Sup3rS3cret!")
    sys.exit(0)
if "--kerberoasting" in a:
    print("LDAP 10.0.0.10 389 DC01 $krb5tgs$23$*svc_sql$CORP.LOCAL$svc_sql*$" + "ab" * 40)
    sys.exit(0)
if "--asreproast" in a:
    print("$krb5asrep$23$roastme@CORP.LOCAL:" + "cd" * 40)
    sys.exit(0)
if "--find-delegation" in a:
    print("LDAP 10.0.0.10 389 DC01 AccountName AccountType DelegationType DelegationRightsTo")
    print("LDAP 10.0.0.10 389 DC01 WEB01$ Computer Unconstrained N/A")
    print("LDAP 10.0.0.10 389 DC01 svc_web User Constrained HTTP/dc01.corp.local")
    sys.exit(0)
flag = "-x" if "-x" in a else ("-X" if "-X" in a else None)
if flag:
    cmd = a[a.index(flag) + 1]
    if "GodPotato" in cmd:
        print("nt authority\\system")
    elif "whoami /priv" in cmd:
        print("SeImpersonatePrivilege        Enabled")
        print("SeChangeNotifyPrivilege       Enabled")
    elif "whoami /groups" in cmd:
        print("BUILTIN\\Administrators")
    sys.exit(0)
if "--continue-on-success" in a:
    user, secret, dom = val("-u"), (val("-p") or val("-H")), val("-d")
    principal = (dom + "\\" + user) if dom else user
    targets = a[1:a.index("-u")]
    SPRAY = {"jdoe": {"10.0.0.7": (1, 1), "10.0.0.10": (1, 0)},
             "svc_adm": {"10.0.0.7": (1, 1), "10.0.0.10": (1, 1)}}
    names = {"10.0.0.7": "WS02", "10.0.0.10": "DC01"}
    for ip in targets:
        v, adm = SPRAY.get(user, {}).get(ip, (0, 0))
        h = names.get(ip, "H")
        sign = "True" if ip == "10.0.0.10" else "False"
        print(f"SMB {ip} 445 {h} [*] Windows 10 Build 19041 x64 (name:{h}) "
              f"(domain:corp.local) (signing:{sign}) (SMBv1:False)")
        if v:
            print(f"SMB {ip} 445 {h} [+] {principal}:{secret}" + (" (Pwn3d!)" if adm else ""))
        else:
            print(f"SMB {ip} 445 {h} [-] {principal}:{secret} STATUS_LOGON_FAILURE")
    sys.exit(0)
sys.exit(0)
'''

# a variant where the on-disk GodPotato trips AMSI but the in-memory loader lands SYSTEM,
# so the escalation loop must climb the delivery ladder (native-exe -> inmem-fileless).
FAKE_NXC_CAUGHT = r'''#!/usr/bin/env python3
import sys
a = sys.argv[1:]
def val(f): return a[a.index(f) + 1] if f in a else None
flag = "-x" if "-x" in a else ("-X" if "-X" in a else None)
if flag:
    cmd = a[a.index(flag) + 1]
    if "Reflection.Assembly" in cmd:                   # the in-memory reflective load evades AV
        print("nt authority\\system")
    elif "Potato" in cmd:                              # any native .exe Potato is caught
        print("This script contains malicious content and has been blocked by your antivirus")
    elif "whoami /priv" in cmd:
        print("SeImpersonatePrivilege        Enabled")
    sys.exit(0)
if "--continue-on-success" in a:
    user, secret, dom = val("-u"), (val("-p") or val("-H")), val("-d")
    principal = (dom + "\\" + user) if dom else user
    print("SMB 10.0.0.7 445 WS02 [*] Windows 10 Build 19041 x64 (name:WS02) "
          "(domain:corp.local) (signing:False) (SMBv1:False)")
    print(f"SMB 10.0.0.7 445 WS02 [+] {principal}:{secret} (Pwn3d!)")
    sys.exit(0)
sys.exit(0)
'''

# a stateful variant: GodPotato isn't on the box until --put-file stages it. On the
# first fire the target reports it missing; after the loop auto-stages it, the re-fire
# lands SYSTEM. A sentinel file under $FK_STAGED models the target's disk.
FAKE_NXC_STAGE = r'''#!/usr/bin/env python3
import os, sys
a = sys.argv[1:]
sentinel = os.path.join(os.environ.get("FK_STAGED", "/tmp"), "godpotato.present")
if "--put-file" in a:
    i = a.index("--put-file")
    local, remote = a[i + 1], a[i + 2]
    if "GodPotato" in remote or "GodPotato" in local:
        open(sentinel, "w").close()
    print(f"[+] uploaded {local} to {remote}")
    sys.exit(0)
flag = "-x" if "-x" in a else ("-X" if "-X" in a else None)
if flag:
    cmd = a[a.index(flag) + 1]
    if "GodPotato" in cmd:
        if os.path.exists(sentinel):
            print("nt authority\\system")
        else:
            print("'GodPotato.exe' is not recognized as an internal or external command")
    elif "whoami /priv" in cmd:
        print("SeImpersonatePrivilege        Enabled")
    sys.exit(0)
if "--continue-on-success" in a:
    print("SMB 10.0.0.7 445 WS02 [*] Windows 10 Build 19041 x64 (name:WS02) "
          "(domain:corp.local) (signing:False) (SMBv1:False)")
    print("SMB 10.0.0.7 445 WS02 [+] corp.local\\jdoe:Winter2025! (Pwn3d!)")
    sys.exit(0)
sys.exit(0)
'''

# AlwaysInstallElevated: the SYSTEM .msi doesn't exist until the loop BUILDS it (wixl)
# and stages it. enum reports AIE from the registry; msiexec proves once the msi lands.
FAKE_NXC_BUILD = r'''#!/usr/bin/env python3
import os, sys
a = sys.argv[1:]
sentinel = os.path.join(os.environ.get("FK_STAGED", "/tmp"), "evil.msi.present")
if "--put-file" in a:
    i = a.index("--put-file")
    local, remote = a[i + 1], a[i + 2]
    if "evil.msi" in remote:
        open(sentinel, "w").close()
    print(f"[+] uploaded {local} to {remote}")
    sys.exit(0)
flag = "-x" if "-x" in a else ("-X" if "-X" in a else None)
if flag:
    cmd = a[a.index(flag) + 1]
    if "AlwaysInstallElevated" in cmd:
        print("    AlwaysInstallElevated    REG_DWORD    0x1")
        print("    AlwaysInstallElevated    REG_DWORD    0x1")
    elif "msiexec" in cmd:
        print("nt authority\\system" if os.path.exists(sentinel)
              else "The system cannot find the file specified.")
    sys.exit(0)
if "--continue-on-success" in a:
    print("SMB 10.0.0.7 445 WS02 [*] Windows 10 Build 19041 x64 (name:WS02) "
          "(domain:corp.local) (signing:False) (SMBv1:False)")
    print("SMB 10.0.0.7 445 WS02 [+] corp.local\\jdoe:Winter2025! (Pwn3d!)")
    sys.exit(0)
sys.exit(0)
'''

# a fake wixl that just creates its -o output (a real build isn't the point here).
FAKE_WIXL = r'''#!/usr/bin/env python3
import sys
a = sys.argv[1:]
open(a[a.index("-o") + 1], "w").close()
print("wixl: wrote installer")
'''

FAKE_MSFVENOM = r'''#!/usr/bin/env python3
import sys
a = sys.argv[1:]
open(a[a.index("-o") + 1], "w").close()
print("msfvenom: payload written")
'''

# a service whose binary + dir are writable by Users (but not reconfigurable) -> the
# manual writable-service-binary route.
FAKE_NXC_SVC = r'''#!/usr/bin/env python3
import sys
a = sys.argv[1:]
if "--put-file" in a:
    i = a.index("--put-file")
    print(f"[+] uploaded {a[i+1]} to {a[i+2]}")
    sys.exit(0)
flag = "-x" if "-x" in a else ("-X" if "-X" in a else None)
if flag:
    cmd = a[a.index(flag) + 1]
    if "Win32_Service" in cmd:
        print("SVC|VulnSvc|C:\\Apps\\vuln.exe|O:SYG:SYD:(A;;CCLCSWRPWPLOCRRC;;;AU)")
        print("ACL|VulnSvc|C:\\Apps\\vuln.exe|C:\\Apps\\vuln.exe "
              "BUILTIN\\Users:(F);NT AUTHORITY\\SYSTEM:(F)")
        print("DIR|VulnSvc|C:\\Apps|C:\\Apps BUILTIN\\Users:(M)")
    elif "wmic service" in cmd:
        print("Name      PathName            StartMode")
        print("VulnSvc   C:\\Apps\\vuln.exe    Auto")
    sys.exit(0)
if "--continue-on-success" in a:
    print("SMB 10.0.0.7 445 WS02 [*] Windows 10 Build 19041 x64 (name:WS02) "
          "(domain:corp.local) (signing:False) (SMBv1:False)")
    print("SMB 10.0.0.7 445 WS02 [+] corp.local\\jdoe:Winter2025! (Pwn3d!)")
    sys.exit(0)
sys.exit(0)
'''

# an MSSQL-only sysadmin foothold: no smb/ssh, so a Potato can't be --put-file'd — the loop
# must download-stage it (serve over HTTP, certutil fetches it over xp_cmdshell), then prove.
FAKE_NXC_MSSQL_DL = r'''#!/usr/bin/env python3
import os, re, sys
try:
    import urllib.request
except Exception:
    urllib = None
a = sys.argv[1:]
gp = os.path.join(os.environ.get("FK_STAGED", "/tmp"), "gp.present")
flag = "-x" if "-x" in a else ("-X" if "-X" in a else None)
if flag:
    cmd = a[a.index(flag) + 1]
    if "certutil" in cmd:
        m = re.search(r'https?://[^"\s]+', cmd)
        if m and urllib:
            try:
                urllib.request.urlopen(m.group(0), timeout=5).read()   # really fetch it
            except Exception:
                pass
        open(gp, "w").close()
        print("CertUtil: -URLCache command completed successfully.")
    elif "GodPotato" in cmd:
        print("nt authority\\system" if os.path.exists(gp)
              else "'GodPotato.exe' is not recognized as an internal or external command")
    elif "whoami /priv" in cmd:
        print("SeImpersonatePrivilege        Enabled")
    sys.exit(0)
if "--continue-on-success" in a:   # mssql sysadmin (Pwn3d!)
    print("MSSQL 10.0.0.9 1433 SQL01 [*] Windows Server 2019 (name:SQL01) (domain:corp.local)")
    print("MSSQL 10.0.0.9 1433 SQL01 [+] corp.local\\sa:pw (Pwn3d!)")
    sys.exit(0)
sys.exit(0)
'''

FAKE_CERTIPY = r'''#!/usr/bin/env python3
print("""Certipy v4.8.2
Certificate Templates
  0
    Template Name                       : ESC1-Template
    [!] Vulnerabilities
      ESC1                              : Domain Users can enroll, enrollee supplies subject
""")
'''

DOM = "S-1-5-21-777"
BH_USERS = {"meta": {"type": "users"}, "data": [
    {"ObjectIdentifier": f"{DOM}-1001", "Properties": {"name": "JDOE@CORP.LOCAL"}}]}
BH_GROUPS = {"meta": {"type": "groups"}, "data": [
    {"ObjectIdentifier": f"{DOM}-1100", "Properties": {"name": "IT ADMINS@CORP.LOCAL"},
     "Members": [{"ObjectIdentifier": f"{DOM}-1001"}]},
    {"ObjectIdentifier": f"{DOM}-512", "Properties": {"name": "DOMAIN ADMINS@CORP.LOCAL"},
     "Aces": [{"PrincipalSID": f"{DOM}-1100", "RightName": "GenericAll"}]}]}


class FullFunnelTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name
        self.db = os.path.join(self.dir, "engagement.db")

        # fake nxc + certipy on PATH
        bindir = os.path.join(self.dir, "bin")
        self.bindir = bindir
        os.makedirs(bindir)
        for name, body in (("nxc", FAKE_NXC), ("certipy", FAKE_CERTIPY)):
            p = os.path.join(bindir, name)
            with open(p, "w") as fh:
                fh.write(body)
            os.chmod(p, os.stat(p).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        old_path = os.environ["PATH"]
        os.environ["PATH"] = bindir + os.pathsep + old_path
        self.addCleanup(lambda: os.environ.__setitem__("PATH", old_path))

        # BloodHound data
        self.bh = os.path.join(self.dir, "bh")
        os.makedirs(self.bh)
        with open(os.path.join(self.bh, "users.json"), "w") as fh:
            json.dump(BH_USERS, fh)
        with open(os.path.join(self.bh, "groups.json"), "w") as fh:
            json.dump(BH_GROUPS, fh)

    def cli(self, *args, expect=0):
        from fieldkit.cli import main
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["--db", self.db, *args])
        text = out.getvalue() + err.getvalue()
        self.assertEqual(code, expect, f"`{' '.join(args)}` exited {code}:\n{text}")
        return text

    def store(self):
        s = Store.open(self.db)
        self.addCleanup(s.close)
        return s

    def test_the_whole_funnel(self):
        # 1) set up the engagement
        self.cli("init", "ACME Corp")
        self.cli("config", "set", "client=ACME Corp")
        self.cli("add", "hosts", "10.0.0.10 DC01", "--dc")
        self.cli("add", "hosts", "10.0.0.7 WS02")
        self.cli("add", "cred", "corp.local/jdoe:Winter2025!", "--yes")

        # 2) the credential loop: foothold on WS02 -> loot svc_adm -> pivot to DA on DC01
        spray = self.cli("spray", "smb", "--yes")
        self.assertIn("admin", spray)
        c = self.store().counts()
        self.assertEqual(c["credentials"], 2)            # jdoe + recovered svc_adm
        self.assertEqual(c["admin_hosts"], 2)            # WS02 (jdoe) + DC01 (svc_adm)

        # 3) enumerate the foothold and confirm the privesc signal was captured
        enum = self.cli("enum", "10.0.0.7", "--yes")
        self.assertIn("SeImpersonate", enum)

        # 4) analyze ranks the loop opportunities + the privesc vector together
        analyze = self.cli("analyze")
        self.assertIn("Domain takeover", analyze)
        self.assertIn("SeImpersonate", analyze)

        # 5) fire the privesc vector through the safety gate (config-change -> --allow)
        gated = self.cli("run", "10.0.0.7", "seimpersonate:godpotato", "--yes", expect=2)
        self.assertIn("safety gate", gated)              # blocked without --allow
        run = self.cli("run", "10.0.0.7", "seimpersonate:godpotato",
                       "--allow", "config-change", "--yes")
        self.assertIn("PROVEN", run)
        self.assertEqual(self.store().counts()["proven_findings"], 1)

        # 6) go wide in AD
        self.cli("roast", "--dc", "10.0.0.10", "--yes")
        self.assertEqual(len(self.store().loot(kind="kerberoast")), 1)
        self.assertEqual(len(self.store().loot(kind="asrep_roast")), 1)
        self.cli("delegation", "--dc", "10.0.0.10", "--yes")
        self.cli("adcs", "find", "--dc", "10.0.0.10", "--yes")
        deleg = [f for f in self.store().findings()
                 if f["vector_type"].endswith("delegation") or f["vector_type"] == "rbcd"]
        self.assertTrue(deleg)
        self.assertTrue([f for f in self.store().findings() if f["vector_type"] == "adcs_esc"])

        # 7) BloodHound: an owned principal reaches Domain Admins
        bh = self.cli("bloodhound", "import", self.bh)
        self.assertIn("DOMAIN ADMINS@CORP.LOCAL", bh)

        # the full analyze now spans loop + privesc + roast + delegation + ADCS + BH
        full = self.cli("analyze")
        for signal in ("Domain takeover", "Kerberoastable", "delegation",
                       "ESC1", "BloodHound path"):
            self.assertIn(signal, full, f"analyze missing {signal!r}")

        # 8) report: anti-fabrication passes, the writeup carries the captured proof
        check = self.cli("report", "--check")
        self.assertIn("CHECK OK", check)
        self.cli("report", "--formats", "md", "-o", os.path.join(self.dir, "rpt"))
        md = open(os.path.join(self.dir, "rpt.md")).read()
        self.assertIn("SeImpersonate", md)
        self.assertIn("nt authority\\system", md)        # the captured PoC output
        # the DEFAULT report now includes Observations (delegation/ADCS were not exploited)
        self.assertIn("# Observations (identified, not exploited)", md)
        self.assertIn("delegation", md.lower())
        # --proven-only drops them for the tight deliverable
        self.cli("report", "--proven-only", "--formats", "md", "-o", os.path.join(self.dir, "po"))
        po = open(os.path.join(self.dir, "po.md")).read()
        self.assertNotIn("# Observations (identified, not exploited)", po)
        self.cli("report", "--cleanup", "-o", os.path.join(self.dir, "rpt"))
        cleanup = open(os.path.join(self.dir, "rpt.cleanup.md")).read()
        self.assertIn("INTERNAL", cleanup)
        self.assertIn("GodPotato", cleanup)              # the vector's artifact

        # 9) recce bridge: proven findings fold back, contract intact
        out = os.path.join(self.dir, "recce.json")
        self.cli("export-recce", out)
        payload = json.load(open(out))
        self.assertEqual(payload["source"], "fieldkit")
        self.assertTrue(payload["findings"])
        self.assertEqual(payload["findings"][0]["_recce"]["confidence"], "confirmed")


    def test_escalate_walks_to_proof(self):
        # a minimal engagement, then let the orchestrator walk the ranked vectors
        # instead of naming one by hand (Phase 6).
        self.cli("init", "ACME Corp")
        self.cli("add", "hosts", "10.0.0.7 WS02")
        self.cli("add", "cred", "corp.local/jdoe:Winter2025!", "--yes")
        self.cli("spray", "smb", "--yes")
        self.cli("enum", "10.0.0.7", "--yes")

        # the config-change vector is gated with no --allow — the loop fires nothing
        gated = self.cli("escalate", "10.0.0.7", "--yes", expect=2)
        self.assertIn("above the current --allow", gated)
        self.assertEqual(self.store().counts()["proven_findings"], 0)

        # --dry-run shows the plan but still fires nothing
        dry = self.cli("escalate", "10.0.0.7", "--allow", "config-change", "--dry-run")
        self.assertIn("escalation plan", dry)
        self.assertIn("seimpersonate", dry)
        self.assertEqual(self.store().counts()["proven_findings"], 0)

        # walk it for real: the loop fires seimpersonate, classifies SYSTEM, stops on proof
        run = self.cli("escalate", "10.0.0.7", "--allow", "config-change", "--yes")
        self.assertIn("PROVEN", run)
        self.assertIn("seimpersonate", run)
        self.assertEqual(self.store().counts()["proven_findings"], 1)
        # the finding carries the *captured* PoC output, not a paraphrase
        proven = [f for f in self.store().findings() if f["proven"]]
        self.assertIn("nt authority\\system", proven[0]["evidence"].lower())
        # AND the closing note points at the natural next moves — new SYSTEM
        # context opens up new enum surface (hives, etc.) and re-ranks vectors.
        self.assertIn("next moves opened up", run)
        self.assertIn("enum 10.0.0.7", run)
        self.assertIn("analyze", run)
        self.assertIn("report", run)
        # and the captured step is LINKED to the finding, so anti-fabrication passes for
        # an escalate-proven finding (regression: escalate used to record it unlinked)
        self.assertTrue(self.store().steps(finding_id=proven[0]["id"]))
        self.assertIn("CHECK OK", self.cli("report", "--check"))


    def _install_nxc(self, body):
        p = os.path.join(self.bindir, "nxc")
        with open(p, "w") as fh:
            fh.write(body)
        os.chmod(p, os.stat(p).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    def test_escalate_redelivers_when_delivery_is_caught(self):
        # the on-disk Potatoes are caught -> the loop climbs to the in-memory reflective rung,
        # serves the same GodPotato.exe over HTTP + loads it in memory, records native-exe caught.
        self._install_nxc(FAKE_NXC_CAUGHT)
        arsenal = os.path.join(self.dir, "arsenal")
        os.makedirs(os.path.join(arsenal, "win-potato"))
        open(os.path.join(arsenal, "win-potato", "GodPotato.exe"), "w").close()
        old = os.environ.get("FIELDKIT_ARSENAL")
        os.environ["FIELDKIT_ARSENAL"] = arsenal
        self.addCleanup(lambda: os.environ.__setitem__("FIELDKIT_ARSENAL", old) if old
                        else os.environ.pop("FIELDKIT_ARSENAL", None))

        self.cli("init", "ACME Corp")
        self.cli("config", "set", "lhost=127.0.0.1")       # served-payload callback
        self.cli("config", "set", "amsi_bypass=on")        # patch AMSI before the in-mem load
        self.cli("add", "hosts", "10.0.0.7 WS02")
        self.cli("add", "cred", "corp.local/jdoe:Winter2025!", "--yes")
        self.cli("spray", "smb", "--yes")
        self.cli("enum", "10.0.0.7", "--yes")

        run = self.cli("escalate", "10.0.0.7", "--allow", "config-change", "--yes")
        self.assertIn("caught", run)                       # the native delivery tripped AMSI
        self.assertIn("marked 'native-exe' red", run)      # it was learned red, live
        self.assertIn("serving GodPotato.exe", run)        # in-memory reflective delivery
        self.assertIn("AMSI bypass: built-in", run)        # bypass prepended to the load
        self.assertIn("PROVEN", run)                       # then re-delivered to a win
        self.assertEqual(self.store().counts()["proven_findings"], 1)
        # the bypass actually reached the executed command (captured verbatim in the step)
        god = [s for s in self.store().steps() if "Reflection.Assembly" in (s["cmd"] or "")]
        self.assertTrue(god and "amsiInitFailed" not in god[0]["cmd"]  # split, not literal
                        and "SetValue" in god[0]["cmd"])

        # the live catch persisted: native-exe is now caught in the evasion matrix,
        # so posture (and a future run) will skip it without firing.
        rec = self.store().evasion_result("native-exe")
        self.assertEqual(rec["verdict"], "caught")
        posture = self.cli("posture")
        self.assertIn("native", posture)


    def test_escalate_auto_stages_a_missing_tool(self):
        # Phase 8: the potato isn't on the box -> the loop stages it from the arsenal
        # over smb (--put-file), then re-fires to SYSTEM.
        self._install_nxc(FAKE_NXC_STAGE)

        # a fake arsenal holding GodPotato, and a "target disk" for the sentinel
        arsenal = os.path.join(self.dir, "arsenal")
        os.makedirs(os.path.join(arsenal, "win-postex"))
        open(os.path.join(arsenal, "win-postex", "GodPotato.exe"), "w").close()
        staged = os.path.join(self.dir, "staged")
        os.makedirs(staged)
        for k, v in (("FIELDKIT_ARSENAL", arsenal), ("FK_STAGED", staged)):
            old = os.environ.get(k)
            os.environ[k] = v
            self.addCleanup(lambda k=k, old=old:
                            os.environ.__setitem__(k, old) if old is not None
                            else os.environ.pop(k, None))

        self.cli("init", "ACME Corp")
        self.cli("add", "hosts", "10.0.0.7 WS02")
        self.cli("add", "cred", "corp.local/jdoe:Winter2025!", "--yes")
        self.cli("spray", "smb", "--yes")
        self.cli("enum", "10.0.0.7", "--yes")

        # the plan shows GodPotato resolvable in the arsenal
        plan = self.cli("escalate", "10.0.0.7", "--allow", "config-change", "--dry-run")
        self.assertIn("auto-stage GodPotato (in arsenal)", plan)

        run = self.cli("escalate", "10.0.0.7", "--allow", "config-change", "--yes")
        self.assertIn("stage then retry", run)
        self.assertIn("staged GodPotato", run)
        self.assertIn("PROVEN", run)
        self.assertEqual(self.store().counts()["proven_findings"], 1)
        # the staged binary is on the cleanup manifest
        self.assertTrue(any("GodPotato" in (art["description"] or "")
                            for art in self.store().artifacts()))

        # --no-stage refuses to stage: with a fresh disk the potato stays missing and the
        # native delivery can't prove (it falls through to the other alternates)
        staged2 = os.path.join(self.dir, "staged2")
        os.makedirs(staged2)
        os.environ["FK_STAGED"] = staged2
        nostage = self.cli("escalate", "10.0.0.7", "--allow", "config-change",
                           "--no-stage", "--yes", expect=1)
        self.assertNotIn("staging from the arsenal", nostage)


    def _install(self, name, body):
        p = os.path.join(self.bindir, name)
        with open(p, "w") as fh:
            fh.write(body)
        os.chmod(p, os.stat(p).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    def test_escalate_auto_builds_a_missing_msi(self):
        # Phase 9: no SYSTEM msi exists -> the loop builds one (wixl), stages it, and
        # msiexec proves. The build/rebuild axis, closed.
        self._install("nxc", FAKE_NXC_BUILD)
        self._install("wixl", FAKE_WIXL)             # a builder on PATH -> poc.have('msi')

        staged = os.path.join(self.dir, "staged")
        build = os.path.join(self.dir, "build")
        os.makedirs(staged)
        os.makedirs(build)
        for k, v in (("FK_STAGED", staged), ("FIELDKIT_BUILD", build)):
            old = os.environ.get(k)
            os.environ[k] = v
            self.addCleanup(lambda k=k, old=old:
                            os.environ.__setitem__(k, old) if old is not None
                            else os.environ.pop(k, None))

        self.cli("init", "ACME Corp")
        self.cli("add", "hosts", "10.0.0.7 WS02")
        self.cli("add", "cred", "corp.local/jdoe:Winter2025!", "--yes")
        self.cli("spray", "smb", "--yes")
        self.cli("enum", "10.0.0.7", "--yes")

        # `poc --check` sees the (fake) wixl; the plan says the msi is buildable
        self.assertIn("wixl", self.cli("poc", "--check"))
        plan = self.cli("escalate", "10.0.0.7", "--allow", "config-change", "--dry-run")
        self.assertIn("auto-build msi (wixl ready)", plan)

        run = self.cli("escalate", "10.0.0.7", "--allow", "config-change", "--yes")
        self.assertIn("build then retry", run)
        self.assertIn("built+staged", run)
        self.assertIn("PROVEN", run)
        self.assertEqual(self.store().counts()["proven_findings"], 1)
        # the built artifact is on the cleanup manifest
        self.assertTrue(any("evil.msi" in (art["cleanup_cmd"] or "")
                            for art in self.store().artifacts()))

    def test_poc_check_runs_without_an_engagement(self):
        out = self.cli("poc", "--check")
        self.assertIn("build toolchain", out)

    def test_multiple_stage_dirs_expand_into_per_dir_alternates(self):
        # a comma-separated stage_win → each provisioned tool is tried in each dir, so a
        # 'didn't land' miss rolls to the same tool in the next writable dir.
        self.cli("init", "ACME")
        self.cli("config", "set",
                 "stage_win=C:\\Windows\\Temp,C:\\Users\\Public,C:\\ProgramData")
        self.cli("add", "hosts", "10.0.0.7 WS02")
        self.cli("add", "cred", "corp.local/jdoe:Winter2025!", "--yes")
        self.cli("spray", "smb", "--yes")
        self.cli("enum", "10.0.0.7", "--yes")
        plan = self.cli("escalate", "10.0.0.7", "--allow", "config-change", "--dry-run")
        for suffix in ("seimpersonate:godpotato@Temp", "seimpersonate:godpotato@Public",
                       "seimpersonate:godpotato@ProgramData"):
            self.assertIn(suffix, plan)

    def test_escalate_download_stages_a_potato_over_mssql(self):
        # MSSQL-only sysadmin: no --put-file path, so the loop download-stages GodPotato
        # (serve over HTTP, certutil fetches it over xp_cmdshell), then proves SYSTEM.
        self._install("nxc", FAKE_NXC_MSSQL_DL)
        arsenal = os.path.join(self.dir, "arsenal")
        os.makedirs(os.path.join(arsenal, "win-postex"))
        open(os.path.join(arsenal, "win-postex", "GodPotato.exe"), "w").close()
        staged = os.path.join(self.dir, "staged")
        os.makedirs(staged)
        for k, v in (("FIELDKIT_ARSENAL", arsenal), ("FK_STAGED", staged)):
            old = os.environ.get(k)
            os.environ[k] = v
            self.addCleanup(lambda k=k, old=old:
                            os.environ.__setitem__(k, old) if old is not None
                            else os.environ.pop(k, None))

        self.cli("init", "ACME")
        self.cli("config", "set", "lhost=127.0.0.1")   # the callback the target fetches from
        self.cli("add", "hosts", "10.0.0.9 SQL01")
        self.cli("add", "cred", "corp.local/sa:pw", "--yes")
        self.cli("spray", "mssql", "--yes")
        self.cli("enum", "10.0.0.9", "--yes")

        run = self.cli("escalate", "10.0.0.9", "--allow", "config-change", "--yes")
        self.assertIn("serving", run)                  # download-staging kicked in
        self.assertIn("PROVEN", run)
        self.assertEqual(self.store().counts()["proven_findings"], 1)

    def test_prep_builds_and_playbooks_a_manual_route(self):
        # a writable service binary can't be one-shot (overwrite a running exe) -> fieldkit
        # builds the payload and hands over the placement steps.
        self._install("nxc", FAKE_NXC_SVC)
        self._install("msfvenom", FAKE_MSFVENOM)
        build = os.path.join(self.dir, "build")
        os.makedirs(build)
        old = os.environ.get("FIELDKIT_BUILD")
        os.environ["FIELDKIT_BUILD"] = build
        self.addCleanup(lambda: os.environ.__setitem__("FIELDKIT_BUILD", old) if old
                        else os.environ.pop("FIELDKIT_BUILD", None))

        self.cli("init", "ACME")
        self.cli("add", "hosts", "10.0.0.7 WS02")
        self.cli("add", "cred", "corp.local/jdoe:Winter2025!", "--yes")
        self.cli("spray", "smb", "--yes")
        self.cli("enum", "10.0.0.7", "--yes")

        # escalate surfaces the manual route but never fires it
        plan = self.cli("escalate", "10.0.0.7", "--allow", "config-change", "--dry-run")
        self.assertIn("writablesvc:VulnSvc", plan)
        self.assertIn("manual", plan)

        # prep builds the payload and prints where to place it + the steps
        out = self.cli("prep", "10.0.0.7", "writablesvc:VulnSvc")
        self.assertIn("artifacts (attacker-side)", out)
        self.assertIn("place at: C:\\Apps\\vuln.exe", out)
        self.assertIn("sc stop VulnSvc", out)
        self.assertIn("restore", out.lower())

        # --stage also uploads it to the target
        staged = self.cli("prep", "10.0.0.7", "writablesvc:VulnSvc", "--stage", "--yes")
        self.assertIn("staged on target", staged)

    def test_kernel_cve_is_matched_ranked_and_never_auto_fired(self):
        """A matched local-CVE is explained and prepared — never blind-fired at a client host.

        Safety-critical: even with `--allow crash-risk` (the widest gate there is), a kernel
        exploit that can panic the box must stay a prepared route.
        """
        self.cli("init", "ACME Corp")
        self.cli("add", "hosts", "10.0.0.5 app01")
        self.cli("add", "cred", "svc:pw", "--yes")
        hid = self.store().host_by_ip("10.0.0.5")["id"]
        cid = self.store().credentials()[0]["id"]
        self.store().add_host("10.0.0.5", os_name="linux")
        self.store().add_access(hid, cid, "ssh", admin=False)
        for label, cmd, out in (
            ("enum:id", "id", "uid=1000(svc) gid=1000(svc) groups=1000(svc)"),
            ("enum:kernel", "uname -a", "Linux app01 5.15.0-72-generic #79-Ubuntu x86_64"),
            ("enum:suid", "find / -perm -4000", "/usr/bin/pkexec\n/usr/bin/passwd"),
            ("enum:versions", "sudo -V", "Sudo version 1.8.31\npkexec version 0.105"),
        ):
            self.store().add_step(cmd, output=out, exit_code=0, host_id=hid, label=label)

        # analyze matches on the captured version and says *why*
        an = self.cli("analyze")
        self.assertIn("CVE-2022-0847", an)                    # kernel 5.15.0 in range
        self.assertIn("kernel 5.15.0 in 5.8", an)             # the evidence, not a guess
        self.assertIn("CVE-2021-4034", an)                    # SUID pkexec present
        self.assertIn("prep 10.0.0.5 cve:dirtypipe", an)      # routed to prep, not run

        # even at the widest safety gate, nothing kernel-related is fired
        esc = self.cli("escalate", "10.0.0.5", "--allow", "crash-risk", "--yes")
        self.assertIn("manual", esc)
        self.assertIn("cve:dirtypipe", esc)
        self.assertEqual(self.store().counts()["proven_findings"], 0)   # nothing fired
        self.assertFalse([s for s in self.store().steps()
                          if "dirtypipe" in (s["cmd"] or "")])          # never executed

        # prep renders concrete steps (and names the arsenal artifact it needs)
        prep = self.cli("prep", "10.0.0.5", "cve:dirtypipe")
        self.assertIn("place at:", prep)
        self.assertIn("dirtypipe", prep)
        self.assertIn("restore", prep.lower())

    def test_patched_host_matches_no_local_cve(self):
        """No false positives: a current kernel/sudo/glibc matches nothing."""
        self.cli("init", "ACME Corp")
        self.cli("add", "hosts", "10.0.0.6 app02")
        self.cli("add", "cred", "svc:pw", "--yes")
        hid = self.store().host_by_ip("10.0.0.6")["id"]
        cid = self.store().credentials()[0]["id"]
        self.store().add_host("10.0.0.6", os_name="linux")
        self.store().add_access(hid, cid, "ssh", admin=False)
        for label, cmd, out in (
            ("enum:id", "id", "uid=1000(svc) gid=1000(svc) groups=1000(svc)"),
            ("enum:kernel", "uname -a", "Linux app02 6.11.0-9-generic #9-Ubuntu x86_64"),
            ("enum:suid", "find / -perm -4000", "/usr/bin/passwd"),
            ("enum:versions", "sudo -V", "Sudo version 1.9.15p5\nldd (GNU libc) 2.39"),
        ):
            self.store().add_step(cmd, output=out, exit_code=0, host_id=hid, label=label)
        an = self.cli("analyze")
        self.assertNotIn("CVE-", an)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
