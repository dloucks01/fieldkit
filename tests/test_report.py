#!/usr/bin/env python3
"""The report — a projection of state, with anti-fabrication by construction.

Pinned:

  * build() pulls proven findings + their captured steps + artifacts out of state;
  * check() is the gate — a step with no captured output is an error, so a finding
    cannot reach the report without the proof that made it;
  * render_markdown auto-fills severity/CWE/remediation from the KB and reproduces
    the PoC trail; cleanup_manifest lists the artifacts with their removal commands.

Run:  python3 -m unittest discover -s tests
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit.config import load as load_config  # noqa: E402
from fieldkit.report import (  # noqa: E402
    build, check, cleanup_manifest, render_markdown,
)
from fieldkit.state import Store  # noqa: E402


class ReportTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME")
        self.cfg = load_config(self.store)
        self.hid, _ = self.store.add_host("10.0.0.7", hostname="WS02", os_name="windows")

    def proven_finding(self):
        fid, _ = self.store.add_finding(
            "seimpersonate", "SeImpersonate → SYSTEM (Potato)", host_id=self.hid,
            proven=True, evidence="whoami returned nt authority\\system")
        self.store.add_step(cmd="GodPotato.exe -cmd \"cmd /c whoami\"",
                            output="nt authority\\system", host_id=self.hid,
                            finding_id=fid, transport="winrm")
        self.store.add_artifact("staged GodPotato.exe", cleanup_cmd="del C:\\Windows\\Temp\\GodPotato.exe",
                                host_id=self.hid, finding_id=fid)
        return fid


class BuildTest(ReportTestCase):
    def test_build_pulls_proven_findings_with_evidence(self):
        self.proven_finding()
        eng, findings = build(self.store, self.cfg)
        self.assertEqual(eng["client"], "ACME")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["vector_type"], "seimpersonate")
        self.assertEqual(f["affected_host"], "10.0.0.7 (WS02, windows)")
        self.assertEqual(f["ip"], "10.0.0.7")
        self.assertEqual(len(f["steps"]), 1)
        self.assertEqual(f["steps"][0]["output"], "nt authority\\system")
        self.assertEqual(f["artifacts"][0]["remove"], "del C:\\Windows\\Temp\\GodPotato.exe")

    def test_unproven_findings_excluded_by_default(self):
        self.store.add_finding("gtfobins_sudo", "sudo find", host_id=self.hid)  # not proven
        _, findings = build(self.store, self.cfg)
        self.assertEqual(findings, [])
        _, all_findings = build(self.store, self.cfg, proven_only=False)
        self.assertEqual(len(all_findings), 1)


class CheckTest(ReportTestCase):
    def test_clean_finding_passes(self):
        self.proven_finding()
        _, findings = build(self.store, self.cfg)
        errors, _ = check(findings)
        self.assertEqual(errors, [])

    def test_step_without_output_is_an_error(self):
        fid, _ = self.store.add_finding("gtfobins_sudo", "sudo find", host_id=self.hid,
                                        proven=True)
        self.store.add_step(cmd="sudo find . -exec id \\;", output="", host_id=self.hid,
                            finding_id=fid)
        _, findings = build(self.store, self.cfg)
        errors, _ = check(findings)
        self.assertTrue(any("NO output" in m for _, m in errors))

    def test_finding_with_no_steps_is_an_error(self):
        self.store.add_finding("gtfobins_sudo", "sudo find", host_id=self.hid, proven=True)
        _, findings = build(self.store, self.cfg)
        errors, _ = check(findings)
        self.assertTrue(any("no proof-of-concept" in m for _, m in errors))

    def test_observation_without_steps_is_not_an_error(self):
        # an unproven finding (observation) is not a claim of compromise, so a missing
        # PoC is a note, not an anti-fabrication error — this is what lets --all render.
        self.store.add_finding("unconstrained_delegation", "Unconstrained delegation",
                               host_id=self.hid)  # proven defaults False
        _, findings = build(self.store, self.cfg, proven_only=False)
        errors, warns = check(findings)
        self.assertEqual(errors, [])
        self.assertTrue(any("observation" in m for _, m in warns))


class RenderTest(ReportTestCase):
    def test_markdown_has_writeup_and_kb_content(self):
        self.proven_finding()
        eng, findings = build(self.store, self.cfg)
        md = render_markdown(eng, findings)
        self.assertIn("# Penetration Test Report — ACME", md)
        self.assertIn("SeImpersonate", md)
        self.assertIn("**Severity:** High", md)          # from the KB
        self.assertIn("CWE-250", md)                     # KB CWE for seimpersonate
        self.assertIn("nt authority\\system", md)        # the captured PoC output
        self.assertIn("Changes made during testing", md)  # artifact section
        self.assertIn("Remediation", md)
        # proven finding: labelled a FINDING, with a walkthrough + screenshot placeholder
        self.assertIn("FINDING — proven", md)
        self.assertIn("Technical walkthrough", md)
        self.assertIn("Screenshot for the report", md)
        self.assertIn("Proof of compromise", md)

    def test_observations_render_distinctly_from_findings(self):
        self.proven_finding()
        self.store.add_finding("unconstrained_delegation", "Unconstrained delegation on WEB01$",
                               host_id=self.hid, evidence="LDAP: WEB01$ Unconstrained")
        eng, findings = build(self.store, self.cfg, proven_only=False)
        md = render_markdown(eng, findings)
        # the two are separated and defined, and the observation is clearly not a finding
        self.assertIn("How to read this report", md)
        self.assertIn("# Findings (proven)", md)
        self.assertIn("# Observations (identified, not exploited)", md)
        self.assertIn("OBSERVATION — identified, not exploited", md)
        self.assertIn("Potential impact (if exploited)", md)
        self.assertIn("Observations at a glance", md)
        # the observation is NOT dressed up with a proven-style money shot
        obs = md.split("# Observations (identified")[1]
        self.assertNotIn("Proof of compromise", obs)

    def test_empty_report_is_honest(self):
        eng, findings = build(self.store, self.cfg)
        md = render_markdown(eng, findings)
        self.assertIn("No privilege-escalation", md)
        self.assertIn("absence of findings is not proof", md.lower())


class CleanupTest(ReportTestCase):
    def test_manifest_lists_artifact_and_removal(self):
        self.proven_finding()
        eng, findings = build(self.store, self.cfg)
        man = cleanup_manifest(eng, findings)
        self.assertIn("INTERNAL", man)
        self.assertIn("staged GodPotato.exe", man)
        self.assertIn("del C:\\Windows\\Temp\\GodPotato.exe", man)
        self.assertIn("Host: 10.0.0.7", man)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
