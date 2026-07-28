#!/usr/bin/env python3
"""The failure classifier — the inspectable ruleset that drives fallback.

Pinned:

  * structural signals (timeout, tool-missing, build exit) win before string matching;
  * a relayed elevation marker is SUCCESS even if the output also mentions e.g. AMSI;
  * the AV/AMSI, denied, delivery, arch and build signatures map to the right outcome
    and fallback axis; anything unrecognized is UNKNOWN (surfaced), never a false pass.

Run:  python3 -m unittest discover -s tests
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit.classify import (  # noqa: E402
    BAD_BUILD, BUILD_ERROR, CAUGHT, DELIVERY, DENIED, NO_TOOL, RAN_NO_PROOF, SUCCESS,
    TIMEOUT, UNKNOWN, classify, describe_rules, looks_elevated,
)
from fieldkit.runner import RunResult  # noqa: E402


def res(stdout="", exit_code=0, stderr="", error=None, timed_out=False):
    return RunResult(argv=["x"], exit_code=exit_code, stdout=stdout, stderr=stderr,
                     error=error, timed_out=timed_out)


class SuccessTest(unittest.TestCase):
    def test_windows_system(self):
        v = classify(res("nt authority\\system"), os_name="windows")
        self.assertEqual(v.outcome, SUCCESS)
        self.assertTrue(v.ok)
        self.assertEqual(v.axis, "done")

    def test_linux_root(self):
        self.assertEqual(classify(res("uid=0(root) gid=0(root)"), os_name="linux").outcome,
                         SUCCESS)

    def test_explicit_marker(self):
        self.assertEqual(classify(res("...FK-PWN-9...", ), expect_marker="FK-PWN-9").outcome,
                         SUCCESS)

    def test_marker_beats_noise(self):
        # proof present wins even if the output also trips an AMSI signature
        v = classify(res("amsi blah\nnt authority\\system"), os_name="windows")
        self.assertEqual(v.outcome, SUCCESS)


class StructuralTest(unittest.TestCase):
    def test_no_tool(self):
        v = classify(res(error="certipy: not found — is it installed?"))
        self.assertEqual(v.outcome, NO_TOOL)
        self.assertEqual(v.axis, "stage")

    def test_timeout_beats_error_string(self):
        # a real timeout carries both timed_out and an error string
        v = classify(res(error="timed out after 600s", timed_out=True))
        self.assertEqual(v.outcome, TIMEOUT)

    def test_build_nonzero_exit(self):
        v = classify(res(stderr="cc1: some noise", exit_code=1), context="build")
        self.assertEqual(v.outcome, BUILD_ERROR)


class SignatureTest(unittest.TestCase):
    def test_amsi_caught(self):
        v = classify(res("This script contains malicious content and has been blocked"))
        self.assertEqual(v.outcome, CAUGHT)
        self.assertEqual(v.axis, "evasion")

    def test_defender_virus_caught(self):
        self.assertEqual(classify(res("Operation did not complete successfully because "
                                      "the file contains a virus")).outcome, CAUGHT)

    def test_access_denied(self):
        v = classify(res("Access is denied."))
        self.assertEqual(v.outcome, DENIED)
        self.assertEqual(v.axis, "vector")

    def test_needs_elevation(self):
        self.assertEqual(classify(res("The requested operation requires elevation.")).outcome,
                         DENIED)

    def test_wrong_arch(self):
        v = classify(res("%1 is not a valid Win32 application"))
        self.assertEqual(v.outcome, BAD_BUILD)
        self.assertEqual(v.axis, "rebuild")

    def test_dotnet_mismatch(self):
        self.assertEqual(classify(res("Could not load file or assembly")).outcome, BAD_BUILD)

    def test_delivery_not_found(self):
        self.assertEqual(classify(res("The system cannot find the file specified.")).outcome,
                         DELIVERY)

    def test_command_absent(self):
        self.assertEqual(classify(res("'GodPotato.exe' is not recognized as an internal or "
                                      "external command")).outcome, DELIVERY)

    def test_compiler_error(self):
        self.assertEqual(classify(res("payload.c:5: error: expected ';'")).outcome, BUILD_ERROR)


class FallthroughTest(unittest.TestCase):
    def test_clean_run_no_marker(self):
        v = classify(res("some benign output", exit_code=0), os_name="linux")
        self.assertEqual(v.outcome, RAN_NO_PROOF)
        self.assertEqual(v.axis, "vector")

    def test_unrecognized_nonzero(self):
        v = classify(res("weird gibberish", exit_code=3), os_name="linux")
        self.assertEqual(v.outcome, UNKNOWN)
        self.assertEqual(v.axis, "surface")


class InspectTest(unittest.TestCase):
    def test_rules_describe(self):
        text = describe_rules()
        self.assertIn("caught", text)
        self.assertIn("amsi", text)

    def test_looks_elevated(self):
        self.assertTrue(looks_elevated("NT AUTHORITY\\SYSTEM", "windows"))
        self.assertFalse(looks_elevated("just a user", "windows"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
