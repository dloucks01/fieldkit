#!/usr/bin/env python3
"""The Defender lab harness — honest verdicts, no false greens.

Pinned:

  * the EICAR control gates the run — if the lab does not remove it, the harness
    aborts rather than reporting greens from an unprotected lab;
  * a probe is clean only when its marker comes back with no detection; a blocked
    probe (no marker) or a logged detection is caught;
  * techniques with no self-contained probe are skipped, not faked, and results are
    recorded per technique for `posture`.

Run:  python3 -m unittest discover -s tests
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit.creds import Credential  # noqa: E402
from fieldkit.lab import (  # noqa: E402
    control_is_live, interpret, parse_status, run_tests,
)
from fieldkit.runner import RunResult  # noqa: E402
from fieldkit.state import Store  # noqa: E402

STATUS = ("RealTimeProtectionEnabled : True\nAMSIEnabled : True\n"
          "AntivirusSignatureVersion : 1.401.123.0")
STATUS_RTP_OFF = STATUS.replace("RealTimeProtectionEnabled : True",
                                "RealTimeProtectionEnabled : False")
STATUS_DETECTED = STATUS + "\n\nThreatID : 2147519003\nResources : {file:_C:\\Temp\\x}"


class InterpretTest(unittest.TestCase):
    def test_clean_when_marker_returns(self):
        v, sig, _ = interpret("...FK-PROBE-x...", STATUS, "FK-PROBE-x")
        self.assertEqual(v, "clean")
        self.assertEqual(sig, "1.401.123.0")

    def test_caught_when_marker_absent(self):
        v, _, _ = interpret("", STATUS, "FK-PROBE-x")
        self.assertEqual(v, "caught")

    def test_caught_when_detection_logged(self):
        v, _, _ = interpret("FK-PROBE-x", STATUS_DETECTED, "FK-PROBE-x")
        self.assertEqual(v, "caught")  # detection overrides a returned marker

    def test_error_when_rtp_off(self):
        v, _, detail = interpret("FK-PROBE-x", STATUS_RTP_OFF, "FK-PROBE-x")
        self.assertEqual(v, "error")
        self.assertIn("protection is off", detail)

    def test_parse_status(self):
        sig, rtp, det = parse_status(STATUS)
        self.assertEqual(sig, "1.401.123.0")
        self.assertTrue(rtp)
        self.assertFalse(det)

    def test_control_liveness(self):
        self.assertTrue(control_is_live("FK-EICAR-REMOVED"))
        self.assertFalse(control_is_live("FK-EICAR-SURVIVED"))


def make_lab(control="FK-EICAR-REMOVED"):
    def run(argv, env=None):
        flag = "-x" if "-x" in argv else ("-X" if "-X" in argv else None)
        cmd = argv[argv.index(flag) + 1] if flag else " ".join(argv)
        if "Get-MpComputerStatus" in cmd:
            return RunResult(argv, 0, stdout=STATUS)
        if "fk.txt" in cmd:                         # the EICAR control
            return RunResult(argv, 0, stdout=control)
        if "AMSI Test Sample" in cmd:               # script/AMSI probes: blocked
            return RunResult(argv, 0, stdout="")
        if "net user fkprobe" in cmd:               # add-admin: ran
            return RunResult(argv, 0, stdout="FK-PROBE-add-admin")
        return RunResult(argv, 0, stdout="")
    return run


class HarnessTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME")
        hid, _ = self.store.add_host("10.13.13.5", os_name="windows")
        cid, _ = self.store.add_credential(Credential("adm", "pw", domain="corp"))
        self.store.add_access(hid, cid, "winrm", admin=True)
        self.host = self.store.host_by_ip("10.13.13.5")
        self.cred = self.store.credential_by_id(cid)

    def test_full_run_records_greens_and_reds(self):
        rep = run_tests(self.store, self.host, self.cred, run=make_lab())
        self.assertIsNone(rep.aborted)
        self.assertEqual(rep.signature, "1.401.123.0")
        verdicts = dict((t, v) for t, v, _ in rep.results)
        self.assertEqual(verdicts["add-admin"], "clean")       # marker returned
        self.assertEqual(verdicts["ps-amsi-revshell"], "caught")  # AMSI blocked it
        self.assertEqual(rep.green, ["add-admin"])

    def test_results_persist_per_technique(self):
        run_tests(self.store, self.host, self.cred, run=make_lab())
        self.assertEqual(self.store.evasion_result("add-admin")["verdict"], "clean")
        self.assertEqual(self.store.evasion_result("ps-amsi-revshell")["verdict"], "caught")

    def test_native_pe_techniques_are_skipped_not_faked(self):
        rep = run_tests(self.store, self.host, self.cred, run=make_lab())
        self.assertIn("native-exe", rep.skipped)
        self.assertIsNone(self.store.evasion_result("native-exe"))  # no faked row

    def test_dead_lab_aborts_with_no_records(self):
        rep = run_tests(self.store, self.host, self.cred,
                        run=make_lab(control="FK-EICAR-SURVIVED"))
        self.assertIn("EICAR control survived", rep.aborted)
        self.assertEqual(self.store.evasion_results(), [])  # nothing recorded

    def test_add_admin_probe_records_cleanup_artifact(self):
        run_tests(self.store, self.host, self.cred, run=make_lab())
        arts = [a["description"] for a in self.store.artifacts()]
        self.assertTrue(any("fkprobe" in a for a in arts))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
