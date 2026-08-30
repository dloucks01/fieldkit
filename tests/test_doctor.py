#!/usr/bin/env python3
"""fieldkit doctor — one health-check for tools + chains + TTPs +
engagement.

Pins each probe in isolation + the top-level run() composition +
the CLI exit-code semantics (0 clean, 1 warnings, 2 errors).
"""
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _make_store(test_case, init=True):
    tmp = tempfile.TemporaryDirectory()
    test_case.addCleanup(tmp.cleanup)
    from fieldkit.state import Store
    s = Store.create(os.path.join(tmp.name, "e.db"))
    if init:
        s.init_engagement("test-doctor")
    test_case.addCleanup(s.close)
    return s


class ProbeToolsTest(unittest.TestCase):
    """probe_tools uses the shared preflight module. Monkey-patch
    preflight.check to drive different outcomes deterministically."""

    def test_all_present_returns_ok(self):
        from fieldkit import doctor, preflight
        original = preflight.check
        preflight.check = lambda: [
            ("netexec", "spray", "nxc", ["nxc"], True),
            ("impacket", "dump", "impacket-secretsdump", ["impacket-secretsdump"], True),
            ("pandoc", "report", "pandoc", ["pandoc"], False),
        ]
        try:
            r = doctor.probe_tools()
            self.assertEqual(r.rung, "ok")
        finally:
            preflight.check = original

    def test_missing_required_returns_error(self):
        from fieldkit import doctor, preflight
        original = preflight.check
        preflight.check = lambda: [
            ("netexec", "spray", None, ["nxc"], True),
            ("impacket", "dump", "impacket-secretsdump", ["impacket-secretsdump"], True),
        ]
        try:
            r = doctor.probe_tools()
            self.assertEqual(r.rung, "error")
            self.assertIn("netexec", r.details[0])
        finally:
            preflight.check = original

    def test_missing_optional_returns_warning(self):
        from fieldkit import doctor, preflight
        original = preflight.check
        preflight.check = lambda: [
            ("netexec", "spray", "nxc", ["nxc"], True),
            ("impacket", "dump", "impacket-secretsdump", ["impacket-secretsdump"], True),
            ("pandoc", "report", None, ["pandoc"], False),
        ]
        try:
            r = doctor.probe_tools()
            self.assertEqual(r.rung, "warning")
            self.assertIn("pandoc", r.details[0])
        finally:
            preflight.check = original


class ProbeChainsTest(unittest.TestCase):
    """probe_chains runs chainlint.audit_all() — real registry."""

    def test_shipped_catalog_is_ok(self):
        # C12 slice 1 landed all shipped profiles clean.
        # A leaked synthetic profile from a prior test could
        # break this — scope to a fresh registry.
        from fieldkit import doctor, chain as chain_mod
        snap = dict(chain_mod._PROFILES)
        # Keep only the shipped set for this test
        shipped = {"esc8", "rbcd", "smb-relay-exec", "esc1"}
        chain_mod._PROFILES = {k: v for k, v in snap.items()
                                if k in shipped}
        try:
            r = doctor.probe_chains()
            self.assertEqual(r.rung, "ok", f"details: {r.details}")
        finally:
            chain_mod._PROFILES.clear()
            chain_mod._PROFILES.update(snap)

    def test_lint_error_bubbles_up_as_error(self):
        from fieldkit import doctor, chain as chain_mod
        from fieldkit.chain import Chain
        snap = dict(chain_mod._PROFILES)
        chain_mod._PROFILES["_doctor_test_empty"] = \
            lambda t: Chain(profile="_doctor_test_empty",
                             target=t, steps=())
        try:
            r = doctor.probe_chains()
            self.assertEqual(r.rung, "error")
        finally:
            chain_mod._PROFILES.clear()
            chain_mod._PROFILES.update(snap)


class ProbeEngagementTest(unittest.TestCase):

    def test_no_engagement_returns_warning(self):
        from fieldkit import doctor
        s = _make_store(self, init=False)
        r = doctor.probe_engagement(s)
        self.assertEqual(r.rung, "warning")
        self.assertIn("no engagement", r.message)

    def test_engagement_without_stage_dirs_warns(self):
        from fieldkit import doctor
        s = _make_store(self)
        r = doctor.probe_engagement(s)
        self.assertEqual(r.rung, "warning")
        # stage_win + stage_lin not configured → warning
        self.assertTrue(any("stage_win" in d for d in r.details))

    def test_engagement_with_hosts_but_no_creds_warns(self):
        from fieldkit import doctor, config as config_mod
        import tempfile
        s = _make_store(self)
        # Configure stage dirs so those don't trip the warning
        stage_dir = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(
            stage_dir, ignore_errors=True))
        cfg = config_mod.load(s)
        cfg.set("stage_win", stage_dir)
        cfg.set("stage_lin", stage_dir)
        s.add_host("10.0.0.1", os_name="linux")
        r = doctor.probe_engagement(s)
        self.assertEqual(r.rung, "warning")
        self.assertTrue(any("credential" in d for d in r.details))

    def test_clean_engagement_returns_ok(self):
        from fieldkit import doctor, config as config_mod
        from fieldkit.creds import Credential
        import tempfile
        s = _make_store(self)
        stage_dir = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(
            stage_dir, ignore_errors=True))
        cfg = config_mod.load(s)
        cfg.set("stage_win", stage_dir)
        cfg.set("stage_lin", stage_dir)
        s.add_host("10.0.0.1", os_name="linux")
        s.add_credential(Credential(username="u", secret="p"))
        r = doctor.probe_engagement(s)
        self.assertEqual(r.rung, "ok")


class ProbeTTPsTest(unittest.TestCase):

    def test_ttp_catalog_loads(self):
        from fieldkit import doctor
        r = doctor.probe_ttps()
        self.assertEqual(r.rung, "ok")
        self.assertIn("loaded", r.message)


class RunCompositionTest(unittest.TestCase):

    def test_run_without_store_skips_engagement_probe(self):
        from fieldkit import doctor
        reports, code = doctor.run()
        names = [r.name for r in reports]
        self.assertNotIn("engagement", names)
        # tools/chains/ttps always run
        self.assertIn("tools", names)
        self.assertIn("chains", names)
        self.assertIn("ttps", names)

    def test_run_with_store_adds_engagement_probe(self):
        from fieldkit import doctor
        s = _make_store(self)
        reports, _ = doctor.run(store=s)
        names = [r.name for r in reports]
        self.assertIn("engagement", names)

    def test_exit_code_ok(self):
        from fieldkit import doctor
        reports = [doctor.Report("a", "ok", "m"),
                    doctor.Report("b", "ok", "m")]
        self.assertEqual(doctor._worst(reports), "ok")

    def test_exit_code_error_beats_warning(self):
        from fieldkit import doctor
        reports = [doctor.Report("a", "warning", "m"),
                    doctor.Report("b", "error", "m")]
        self.assertEqual(doctor._worst(reports), "error")


class CLITest(unittest.TestCase):

    def _run(self, argv):
        from fieldkit.cli import build_parser, cmd_doctor
        parser = build_parser()
        args = parser.parse_args(argv)
        buf = io.StringIO()
        errbuf = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(errbuf):
            code = cmd_doctor(args)
        return code, buf.getvalue(), errbuf.getvalue()

    def test_doctor_prints_expected_sections(self):
        # Scope the chain registry to the shipped set — other tests
        # may leak synthetic broken profiles into the process-wide
        # registry, which would trip chain-lint errors and bump the
        # doctor exit to 2.
        from fieldkit import chain as chain_mod
        snap = dict(chain_mod._PROFILES)
        shipped = {"esc8", "rbcd", "smb-relay-exec", "esc1"}
        chain_mod._PROFILES = {k: v for k, v in snap.items()
                                if k in shipped}
        try:
            code, out, _ = self._run(["doctor"])
        finally:
            chain_mod._PROFILES.clear()
            chain_mod._PROFILES.update(snap)
        # tools, chains, ttps always render
        self.assertIn("tools", out)
        self.assertIn("chains", out)
        self.assertIn("ttps", out)
        self.assertIn("summary:", out)
        # Optional-tool absence keeps this ≤ 1 on the shipped set.
        self.assertIn(code, (0, 1))

    def test_doctor_json_output_parses(self):
        import json as _json
        code, out, _ = self._run(["doctor", "--json"])
        doc = _json.loads(out)
        self.assertIn("reports", doc)
        self.assertIn("exit_code", doc)
        self.assertEqual(doc["exit_code"], code)
        self.assertTrue(any(r["name"] == "tools" for r in doc["reports"]))


if __name__ == "__main__":
    unittest.main()
