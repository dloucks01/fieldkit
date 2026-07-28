#!/usr/bin/env python3
"""Smoke tests for the recce <-> fieldkit integration seams.

The v1 generators are print-only scripts (no importable API), so these drive them
the way an operator does — via subprocess — and assert on exit code + printed output.
They now live under archive/ (v2 migration); the recce JSON contract they define is
the compatibility surface v2 must keep green, so these tests stay as-is until
report.py/bridge.py port them (Phase 3).

  * report/gen_report.py --export-recce            (fieldkit findings -> recce_findings.json)
  * report/gen_report.py --check                   (anti-fabrication gate still gates)
  * archive/access/network/sweep.py triage --recce (recce bridge -> ranked scoreboard)
  * archive/access/network/sweep.py triage --nmap  (classic greppable path unbroken)
  * archive/access/network/sweep.py plan           (classic plan path unbroken)

Stdlib only; no pandoc/nmap/network needed (both flags run before any of that).

Run:  python3 -m unittest discover -s tests      (from the repo root)
  or: python3 tests/test_integration_recce.py
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GEN_REPORT = os.path.join(ROOT, "report", "gen_report.py")
SWEEP = os.path.join(ROOT, "archive", "access", "network", "sweep.py")


def run(script, *args):
    """Run a fieldkit script by path (its own dir lands on sys.path[0], so local
    imports like _report_kb resolve). Returns (returncode, stdout+stderr)."""
    p = subprocess.run([sys.executable, script, *args],
                       capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def _write(path, obj):
    with open(path, "w") as fh:
        json.dump(obj, fh)


class ExportRecceTest(unittest.TestCase):

    def test_export_recce_enriches_from_kb(self):
        with tempfile.TemporaryDirectory() as d:
            findings = os.path.join(d, "findings.json")
            out = os.path.join(d, "recce_findings.json")
            _write(findings, {"engagement": {"client": "ACME"}, "findings": [{
                "title": "Unquoted service path",
                "vector_type": "unquoted_service",
                "affected_host": "10.0.0.5 (WIN-SQL01)",
                "references": "CVE-2020-1234",
                "steps": [{"cmd": "sc qc MyApp", "output": "BINARY_PATH_NAME : C:\\x y\\s.exe"}],
            }]})
            rc, o = run(GEN_REPORT, findings, "--export-recce", out)
            self.assertEqual(rc, 0, o)
            self.assertTrue(os.path.exists(out))
            data = json.load(open(out))
            self.assertEqual(data.get("source"), "fieldkit")
            f = data["findings"][0]
            self.assertIn("_recce", f)
            r = f["_recce"]
            self.assertEqual(r["ip"], "10.0.0.5")            # IP parsed out of affected_host
            self.assertEqual(r["hostname"], "WIN-SQL01")
            self.assertEqual(r["severity"], "high")          # from the KB, lowercased for recce
            self.assertEqual(r["cwe"], "CWE-428")            # KB CWE
            self.assertTrue(r["remediation"])                # KB remediation resolved
            self.assertIn("CVE-2020-1234", r["ids"])         # references folded in

    def test_export_recce_default_filename(self):
        with tempfile.TemporaryDirectory() as d:
            findings = os.path.join(d, "findings.json")
            _write(findings, {"findings": [{
                "title": "sudo find", "vector_type": "gtfobins_sudo",
                "affected_host": "10.0.0.6 (web01)",
                "steps": [{"cmd": "sudo -l", "output": "(root) NOPASSWD: /usr/bin/find"}],
            }]})
            # default output is recce_findings.json in the cwd
            p = subprocess.run([sys.executable, GEN_REPORT, findings, "--export-recce"],
                               capture_output=True, text=True, cwd=d)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertTrue(os.path.exists(os.path.join(d, "recce_findings.json")))

    def test_check_gate_still_works(self):
        with tempfile.TemporaryDirectory() as d:
            good = os.path.join(d, "good.json")
            bad = os.path.join(d, "bad.json")
            _write(good, {"findings": [{
                "title": "ok", "vector_type": "gtfobins_sudo",
                "affected_host": "10.0.0.6 (web01)",
                "steps": [{"cmd": "sudo -l", "output": "(root) NOPASSWD: /usr/bin/find"}],
            }]})
            _write(bad, {"findings": [{                       # step with no captured output
                "title": "bad", "vector_type": "gtfobins_sudo",
                "affected_host": "10.0.0.6",
                "steps": [{"cmd": "sudo -l", "output": ""}],
            }]})
            self.assertEqual(run(GEN_REPORT, good, "--check")[0], 0)
            self.assertEqual(run(GEN_REPORT, bad, "--check")[0], 2)


class SweepRecceTest(unittest.TestCase):

    def _bridge(self, path):
        _write(path, {"_recce_bridge": 1, "engagement": "T", "users": ["jdoe"],
                      "creds_count": 1, "hosts": [{
            "ip": "10.0.10.10", "hostname": "dc01", "os": "Windows Server 2019 (96%)",
            "roles": ["Domain Controller"], "smb_signing": "required",
            "null_smb": False, "access_gained": False, "access_detail": "",
            "ports": [{"port": 445, "service": "microsoft-ds", "product": "", "version": ""}],
            "findings": [{"title": "ms17-010", "severity": "critical",
                          "confidence": "confirmed", "cves": ["CVE-2017-0143"]}],
            "suggested": [{"port": 445, "service": "smb", "label": "smb",
                           "module": "services/gen_smb", "juiciness": 1}],
            "exploit_cmds": [{"port": 445, "service": "apache", "version": "2.4.41",
                              "cmd": "python3 access/network/gen_exploit.py find "
                                     "--service apache --version \"2.4.41\"",
                              "cves": ["CVE-2021-41773"]}],
            "access_cmds": ["python3 access/network/gen_shell.py --target 10.0.10.10 "
                            "--user jdoe --pass 'x' --proto smb"],
        }]})

    def test_triage_recce_prints_findings_and_commands(self):
        with tempfile.TemporaryDirectory() as d:
            bridge = os.path.join(d, "recce-bridge.json")
            self._bridge(bridge)
            rc, o = run(SWEEP, "triage", "--recce", bridge)
            self.assertEqual(rc, 0, o)
            self.assertIn("10.0.10.10", o)
            self.assertIn("CONFIRM", o)
            self.assertIn("CVE-2017-0143", o)
            self.assertIn("gen_exploit.py find --service apache", o)   # ver->cve line
            self.assertIn("gen_shell.py --target 10.0.10.10", o)       # cred line
            self.assertIn("services/gen_smb", o)                       # WINS route

    def test_triage_recce_only_needs_the_bridge(self):
        # --recce works with no --nmap (recce already knows the ports).
        with tempfile.TemporaryDirectory() as d:
            bridge = os.path.join(d, "b.json")
            self._bridge(bridge)
            rc, o = run(SWEEP, "triage", "--recce", bridge)
            self.assertEqual(rc, 0, o)
            self.assertIn("SCOREBOARD", o)

    def test_triage_nmap_classic_path_unbroken(self):
        with tempfile.TemporaryDirectory() as d:
            gnmap = os.path.join(d, "ports.gnmap")
            with open(gnmap, "w") as fh:
                fh.write("Host: 10.0.0.9 (redisbox)\tPorts: 6379/open/tcp//redis///"
                         "\tIgnored State: closed\n")
            rc, o = run(SWEEP, "triage", "--nmap", gnmap)
            self.assertEqual(rc, 0, o)
            self.assertIn("10.0.0.9", o)
            self.assertIn("gen_db.py --db redis", o)          # WINS mapping intact

    def test_triage_requires_an_input(self):
        rc, o = run(SWEEP, "triage")
        self.assertEqual(rc, 1)                                # neither --nmap nor --recce
        self.assertIn("--recce", o)

    def test_plan_path_unbroken(self):
        with tempfile.TemporaryDirectory() as d:
            tf = os.path.join(d, "targets.txt")
            with open(tf, "w") as fh:
                fh.write("10.0.0.0/24\n")
            rc, o = run(SWEEP, "plan", "--targets", tf)
            self.assertEqual(rc, 0, o)
            self.assertIn("nmap", o)


if __name__ == "__main__":
    unittest.main()
