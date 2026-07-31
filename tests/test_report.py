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

from fieldkit import report  # noqa: E402
from fieldkit.config import load as load_config  # noqa: E402
from fieldkit.report import (  # noqa: E402
    build, check, cleanup_manifest, render_markdown,
)
from fieldkit.runner import RunResult  # noqa: E402
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

    def test_recovered_credentials_render_as_audit_trail(self):
        # add creds recovered by different mechanisms; manual creds should NOT appear
        from fieldkit.creds import Credential
        self.store.add_credential(Credential("jdoe", "manual", domain="corp"),
                                  source="manual")
        self.store.add_credential(Credential("svcadmin", "S3cret!", domain="corp"),
                                  source="sharespider:gpp-cpassword")
        self.store.add_credential(Credential("app", "deadbeef00", secret_type="nt"),
                                  source="dump:sam")
        eng, findings = build(self.store, self.cfg)
        self.assertEqual(len(eng["recovered_credentials"]), 2)
        md = render_markdown(eng, findings)
        self.assertIn("Credentials recovered during testing", md)
        self.assertIn("sharespider:gpp-cpassword", md)
        self.assertIn("dump:sam", md)
        self.assertIn("corp\\svcadmin", md.lower())          # domain\user shown
        self.assertNotIn("| `jdoe`", md.lower())              # manual creds excluded
        self.assertNotIn("manual", md.lower().split("credentials recovered")[1][:400])

    def test_no_credentials_section_when_nothing_recovered(self):
        from fieldkit.creds import Credential
        self.store.add_credential(Credential("jdoe", "manual"), source="manual")
        eng, findings = build(self.store, self.cfg)
        md = render_markdown(eng, findings)
        self.assertNotIn("Credentials recovered during testing", md)

    def test_reached_via_line_names_the_authenticating_credential(self):
        from fieldkit.creds import Credential
        cid, _ = self.store.add_credential(
            Credential("svcadmin", "S3cret!", domain="corp"),
            source="sharespider:gpp-cpassword")
        self.store.add_access(self.hid, cid, "smb", admin=True)
        self.proven_finding()
        eng, findings = build(self.store, self.cfg)
        # build() attaches reached_via
        self.assertEqual(findings[0]["reached_via"]["principal"], "corp\\svcadmin")
        self.assertEqual(findings[0]["reached_via"]["source"],
                         "sharespider:gpp-cpassword")
        md = render_markdown(eng, findings)
        self.assertIn("### Reached via", md)
        self.assertIn("corp\\svcadmin", md)
        self.assertIn("sharespider:gpp-cpassword", md)
        # exec summary carries the chain sentence
        self.assertIn("Demonstrated attack chain", md)

    def test_reached_via_manual_cred_does_not_claim_a_chain(self):
        # a proven finding via an operator-provided cred is NOT a chain
        from fieldkit.creds import Credential
        cid, _ = self.store.add_credential(
            Credential("jdoe", "pw", domain="corp"), source="manual")
        self.store.add_access(self.hid, cid, "smb", admin=True)
        self.proven_finding()
        eng, findings = build(self.store, self.cfg)
        md = render_markdown(eng, findings)
        # per-finding line still there and honest
        self.assertIn("### Reached via", md)
        self.assertIn("operator-provided", md)
        # BUT the exec summary chain sentence is skipped (no recovery happened)
        self.assertNotIn("Demonstrated attack chain", md)


class CleanupTest(ReportTestCase):
    def test_manifest_lists_artifact_and_removal(self):
        self.proven_finding()
        eng, findings = build(self.store, self.cfg)
        man = cleanup_manifest(eng, findings)
        self.assertIn("INTERNAL", man)
        self.assertIn("staged GodPotato.exe", man)
        self.assertIn("del C:\\Windows\\Temp\\GodPotato.exe", man)
        self.assertIn("Host: 10.0.0.7", man)


class ExportTest(unittest.TestCase):
    """docx/pdf conversion — pandoc is driven through the injected runner, never spawned
    here directly (rule 2), so this runs with or without pandoc installed."""

    def runner(self, exit_code=0, stderr="", error=None):
        seen = []

        def run(argv):
            seen.append(argv)
            return RunResult(argv, exit_code=exit_code, stderr=stderr, error=error)
        return run, seen

    def test_docx_drives_pandoc_with_an_argv_list(self):
        run, seen = self.runner()
        lines = report.export("r.md", "r", ["docx"], run=run, have=lambda t: True)
        self.assertEqual(lines, ["wrote r.docx"])
        self.assertEqual(seen[0], ["pandoc", "r.md", "-o", "r.docx"])   # argv, not a string

    def test_pdf_passes_the_engine_flag(self):
        run, seen = self.runner()
        report.export("r.md", "r", ["pdf"], run=run, have=lambda t: True)
        self.assertIn("--pdf-engine=weasyprint", seen[0])

    def test_missing_pandoc_prints_the_manual_command_and_runs_nothing(self):
        run, seen = self.runner()
        lines = report.export("r.md", "r", ["docx", "pdf"], run=run, have=lambda t: False)
        self.assertEqual(seen, [])                       # nothing spawned
        self.assertTrue(all(ln.startswith("#") for ln in lines))
        self.assertIn("install pandoc", lines[0])

    def test_pdf_needs_weasyprint_too(self):
        run, seen = self.runner()
        lines = report.export("r.md", "r", ["pdf"], run=run,
                              have=lambda t: t == "pandoc")   # pandoc yes, weasyprint no
        self.assertEqual(seen, [])
        self.assertIn("weasyprint", lines[0])

    def test_a_failed_conversion_is_reported_not_raised(self):
        run, _ = self.runner(exit_code=1, stderr="pandoc: boom")
        lines = report.export("r.md", "r", ["docx"], run=run, have=lambda t: True)
        self.assertIn("docx FAILED", lines[0])
        self.assertIn("boom", lines[0])

    def test_a_missing_binary_is_reported_not_raised(self):
        run, _ = self.runner(error="pandoc not found")
        lines = report.export("r.md", "r", ["docx"], run=run, have=lambda t: True)
        self.assertIn("docx FAILED", lines[0])
        self.assertIn("not found", lines[0])


class ArchitectureTest(unittest.TestCase):
    """The load-bearing invariants from ARCHITECTURE.md, checked mechanically so they can't rot."""

    def _package_files(self):
        pkg = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "fieldkit")
        return [os.path.join(pkg, f) for f in sorted(os.listdir(pkg)) if f.endswith(".py")]

    def test_runner_is_the_only_child_process_spawn(self):
        """Rule 2 — every tool goes through `runner.run`, so tests can inject a fake."""
        import ast
        offenders = []
        for path in self._package_files():
            if os.path.basename(path) == "runner.py":
                continue
            tree = ast.parse(open(path).read())
            for node in ast.walk(tree):
                # `import subprocess` / `from subprocess import ...`
                if isinstance(node, ast.Import):
                    offenders += [(path, node.lineno, a.name) for a in node.names
                                  if a.name == "subprocess"]
                elif isinstance(node, ast.ImportFrom) and node.module == "subprocess":
                    offenders.append((path, node.lineno, "from subprocess"))
                # os.system / os.popen / os.exec*
                elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                    if node.value.id == "os" and (node.attr in ("system", "popen")
                                                  or node.attr.startswith("exec")):
                        offenders.append((path, node.lineno, f"os.{node.attr}"))
        self.assertEqual(offenders, [], f"child-process spawn outside runner.py: {offenders}")

    def test_no_module_does_io_at_import_time(self):
        """Importing the package must be free of disk/network work — `fieldkit --help`
        (and every test) imports everything."""
        import ast
        forbidden = {"open", "urlopen", "mkdir", "makedirs", "remove", "rmtree", "connect"}
        offenders = []
        for path in self._package_files():
            tree = ast.parse(open(path).read())
            for node in tree.body:            # module level only, not inside a def/class
                for sub in ast.walk(node) if not isinstance(
                        node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) else ():
                    if isinstance(sub, ast.Call):
                        name = getattr(sub.func, "id", None) or getattr(sub.func, "attr", None)
                        if name in forbidden:
                            offenders.append((os.path.basename(path), sub.lineno, name))
        self.assertEqual(offenders, [], f"I/O at import time: {offenders}")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
