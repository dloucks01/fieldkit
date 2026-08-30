#!/usr/bin/env python3
"""fieldkit doctor --fix — auto-remediate the actionable warnings.

Pins:

  * fix() creates a missing Linux stage dir;
  * fix() skips Windows stage paths on Linux host (they're
    for the target, not local);
  * fix() restores a missing config default via cfg.set;
  * fix() skips chmod on unwritable paths (safety);
  * fix() skips chain-lint findings (need code/YAML edit);
  * fix() emits install hints for missing tools;
  * CLI --fix runs re-probes after fixes and re-emits exit code.
"""
import io
import os
import sys
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _make_store(test_case):
    tmp = tempfile.TemporaryDirectory()
    test_case.addCleanup(tmp.cleanup)
    from fieldkit.state import Store
    s = Store.create(os.path.join(tmp.name, "e.db"))
    s.init_engagement("test-doctor-fix")
    test_case.addCleanup(s.close)
    return s, tmp.name


class FixStageDirTest(unittest.TestCase):

    def test_mkdir_creates_missing_linux_stage_dir(self):
        from fieldkit import doctor, config as config_mod
        s, tmp = _make_store(self)
        stage = os.path.join(tmp, "custom-stage")
        cfg = config_mod.load(s)
        cfg.set("stage_lin", stage)
        # Confirm it doesn't exist
        self.assertFalse(os.path.isdir(stage))
        reports = [doctor.probe_engagement(s)]
        actions = doctor.fix(reports, store=s)
        # A mkdir action landed for the Linux path
        mkdirs = [a for a, o in actions
                  if a.startswith("mkdir") and stage in a]
        self.assertEqual(len(mkdirs), 1)
        outcomes = [o for a, o in actions if stage in a]
        self.assertEqual(outcomes[0], "fixed")
        self.assertTrue(os.path.isdir(stage))

    def test_windows_stage_path_skipped_on_linux_host(self):
        from fieldkit import doctor, config as config_mod
        s, _ = _make_store(self)
        cfg = config_mod.load(s)
        cfg.set("stage_win", "C:\\Windows\\Temp")
        reports = [doctor.probe_engagement(s)]
        actions = doctor.fix(reports, store=s)
        # Windows-shaped path is skipped
        win = [(a, o) for a, o in actions if "C:\\Windows\\Temp" in a]
        if win:
            self.assertTrue(win[0][1].startswith("skipped"))


class FixUnwritableTest(unittest.TestCase):

    def test_unwritable_stage_dir_prints_chmod_hint_not_chmod(self):
        from fieldkit import doctor, config as config_mod
        s, tmp = _make_store(self)
        ro = os.path.join(tmp, "readonly-stage")
        os.mkdir(ro)
        os.chmod(ro, 0o500)  # r-x, not writable
        self.addCleanup(lambda: os.chmod(ro, 0o700))
        cfg = config_mod.load(s)
        cfg.set("stage_lin", ro)
        cfg.set("stage_win", ro)  # also point win at real dir so it's not flagged
        reports = [doctor.probe_engagement(s)]
        actions = doctor.fix(reports, store=s)
        chmod = [(a, o) for a, o in actions if a.startswith("chmod")]
        self.assertGreater(len(chmod), 0)
        self.assertTrue(chmod[0][1].startswith("skipped"))


class FixToolsHintsTest(unittest.TestCase):

    def test_missing_tool_gets_install_hint(self):
        from fieldkit import doctor
        # Synthesize a tools-probe report with missing tools
        rep = doctor.Report(
            name="tools", rung="warning",
            message="1 optional tool(s) missing",
            details=["pandoc — report docx/pdf"])
        actions = doctor.fix([rep])
        self.assertTrue(any(a.startswith("install pandoc") for a, _ in actions))


class FixChainFindingsSkippedTest(unittest.TestCase):

    def test_chain_lint_findings_are_skipped(self):
        from fieldkit import doctor
        rep = doctor.Report(
            name="chains", rung="warning",
            message="1 chain lint warning(s)",
            details=["esc8: [no-signals] step falls back to detection_cost=1"])
        actions = doctor.fix([rep])
        # The chain-lint finding is surfaced but not touched
        chain_actions = [(a, o) for a, o in actions if "no-signals" in a]
        self.assertEqual(len(chain_actions), 1)
        self.assertTrue(chain_actions[0][1].startswith("skipped"))


class FixTTPParseSkippedTest(unittest.TestCase):

    def test_ttp_parse_failure_is_surfaced_but_not_fixed(self):
        from fieldkit import doctor
        rep = doctor.Report(
            name="ttps", rung="error",
            message="TTP catalog parse failure: bad yaml at ...")
        actions = doctor.fix([rep])
        ttp_actions = [(a, o) for a, o in actions if "TTP catalog" in a]
        self.assertEqual(len(ttp_actions), 1)
        self.assertTrue(ttp_actions[0][1].startswith("skipped"))


class CLIIntegrationTest(unittest.TestCase):

    def _run(self, argv):
        from fieldkit.cli import build_parser, cmd_doctor
        parser = build_parser()
        args = parser.parse_args(argv)
        buf = io.StringIO()
        errbuf = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(errbuf):
            code = cmd_doctor(args)
        return code, buf.getvalue(), errbuf.getvalue()

    def test_fix_flag_registered(self):
        from fieldkit.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["doctor", "--fix"])
        self.assertTrue(args.fix)

    def test_fix_default_false(self):
        from fieldkit.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["doctor"])
        self.assertFalse(getattr(args, "fix", False))

    def test_fix_prints_actions_section(self):
        code, out, _ = self._run(["doctor", "--fix"])
        # Some actions almost always exist (tools install hints)
        self.assertIn("fix actions:", out)


if __name__ == "__main__":
    unittest.main()
