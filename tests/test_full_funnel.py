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
    if "GodPotato" in cmd:
        print("This script contains malicious content and has been blocked by your antivirus")
    elif "loader.exe" in cmd:
        print("nt authority\\system")
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
        gated = self.cli("run", "10.0.0.7", "seimpersonate:native", "--yes", expect=2)
        self.assertIn("safety gate", gated)              # blocked without --allow
        run = self.cli("run", "10.0.0.7", "seimpersonate:native",
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


    def _install_nxc(self, body):
        p = os.path.join(self.bindir, "nxc")
        with open(p, "w") as fh:
            fh.write(body)
        os.chmod(p, os.stat(p).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    def test_escalate_redelivers_when_delivery_is_caught(self):
        # Phase 7: the on-disk potato is caught -> the loop climbs to the in-memory
        # delivery, proves there, and records native-exe as caught (live evidence).
        self._install_nxc(FAKE_NXC_CAUGHT)
        self.cli("init", "ACME Corp")
        self.cli("add", "hosts", "10.0.0.7 WS02")
        self.cli("add", "cred", "corp.local/jdoe:Winter2025!", "--yes")
        self.cli("spray", "smb", "--yes")
        self.cli("enum", "10.0.0.7", "--yes")

        run = self.cli("escalate", "10.0.0.7", "--allow", "config-change", "--yes")
        self.assertIn("caught", run)                       # the native delivery tripped AMSI
        self.assertIn("marked 'native-exe' red", run)      # it was learned red, live
        self.assertIn("PROVEN", run)                       # then re-delivered to a win
        self.assertIn("in-memory", run)                    # the winning alternate's title
        self.assertEqual(self.store().counts()["proven_findings"], 1)

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
        self.assertIn("staging from the arsenal", run)
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


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
