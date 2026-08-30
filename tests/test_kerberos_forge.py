#!/usr/bin/env python3
"""fieldkit kerberos forge — Golden/Silver ticket generation.

C18 gap-slice C. Wraps impacket-ticketer; monkey-patches
shutil.which + runner.run for isolation.
"""
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _patch(canned_result, tool_present=True):
    """Common monkey-patch fixture for shutil.which + runner.run."""
    import shutil as _shutil
    from fieldkit import runner as runner_mod
    orig_which = _shutil.which
    orig_run = runner_mod.run
    _shutil.which = (lambda name: f"/fake/{name}") if tool_present \
        else (lambda _: None)
    runner_mod.run = lambda argv, timeout=None: canned_result
    return lambda: (setattr(_shutil, "which", orig_which),
                    setattr(runner_mod, "run", orig_run))


def _fake_run(stdout="", stderr="", exit_code=0, timed_out=False, error=None):
    class _R: pass
    r = _R()
    r.stdout = stdout
    r.stderr = stderr
    r.exit_code = exit_code
    r.timed_out = timed_out
    r.error = error
    return r


class GoldenForgeTest(unittest.TestCase):

    def test_no_tool_returns_no_tool(self):
        from fieldkit import kerberos_forge as kf
        undo = _patch(_fake_run(), tool_present=False)
        self.addCleanup(undo)
        r = kf.forge_golden("aabbcc" * 5 + "aa", "CORP.LOCAL",
                              "S-1-5-21-1", "Administrator")
        self.assertEqual(r.kind, "no-tool")

    def test_success_returns_ok_with_ccache_path(self):
        from fieldkit import kerberos_forge as kf
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        undo = _patch(_fake_run(
            stdout="[*] Creating basic skeleton ticket\n"
                    "[*] Saving ticket in Administrator.ccache"))
        self.addCleanup(undo)
        r = kf.forge_golden("aabbcc" * 5 + "aa", "CORP.LOCAL",
                              "S-1-5-21-1", "Administrator",
                              out_dir=tmp.name)
        self.assertEqual(r.kind, "ok")
        self.assertTrue(r.ccache_path.endswith("Administrator.ccache"))

    def test_failure_returns_fail(self):
        from fieldkit import kerberos_forge as kf
        undo = _patch(_fake_run(
            stdout="", stderr="[-] Invalid domain SID format"))
        self.addCleanup(undo)
        r = kf.forge_golden("aabbcc" * 5 + "aa", "CORP.LOCAL",
                              "bogus-sid", "Administrator")
        self.assertEqual(r.kind, "fail")


class SilverForgeTest(unittest.TestCase):

    def test_silver_requires_spn(self):
        # Ensured at CLI layer, not module — but the module accepts
        # the spn positionally so verify the argv shape.
        from fieldkit import kerberos_forge as kf
        undo = _patch(_fake_run(stdout="[*] Saving ticket in x.ccache"))
        self.addCleanup(undo)
        r = kf.forge_silver("hash", "CORP.LOCAL", "S-1-5-21-1",
                              "Administrator", spn="cifs/dc01.corp.local")
        self.assertEqual(r.kind, "ok")


class CLITest(unittest.TestCase):

    def _run(self, argv):
        from fieldkit.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(argv)
        buf = io.StringIO()
        errbuf = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(errbuf):
            code = args.func(args)
        return code, buf.getvalue(), errbuf.getvalue()

    def test_golden_subparser_registered(self):
        from fieldkit.cli import build_parser
        parser = build_parser()
        args = parser.parse_args([
            "kerberos", "forge", "golden",
            "--user", "Administrator",
            "--hash", "a" * 32,
            "--domain", "CORP.LOCAL",
            "--domain-sid", "S-1-5-21-1"])
        self.assertEqual(args.kind, "golden")

    def test_silver_missing_spn_exits_2(self):
        # Silver needs --spn; without it the handler returns 2.
        undo = _patch(_fake_run(), tool_present=True)
        self.addCleanup(undo)
        code, _, err = self._run([
            "kerberos", "forge", "silver",
            "--user", "Administrator",
            "--hash", "a" * 32,
            "--domain", "CORP.LOCAL",
            "--domain-sid", "S-1-5-21-1"])
        self.assertEqual(code, 2)
        self.assertIn("--spn is required", err)


if __name__ == "__main__":
    unittest.main()
