#!/usr/bin/env python3
"""Confidence scoring — direct_capture > inferred_version > predicted_pattern
> unverified. Score is PURE: no I/O, no state."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import confidence


class TestScoreStep(unittest.TestCase):

    def test_uid_zero_is_direct_capture(self):
        c = confidence.score_step({"output": "uid=0(root) gid=0(root) groups=0(root)", "exit_code": 0})
        self.assertEqual(c.label, "direct_capture")
        self.assertEqual(c.score, 1.0)

    def test_pwn3d_marker_is_direct_capture(self):
        c = confidence.score_step({"output": "SMB  10.0.0.1  445  DC01  [+] CORP\\admin:P@ssw (Pwn3d!)",
                                   "exit_code": 0})
        self.assertEqual(c.label, "direct_capture")

    def test_nt_authority_system_is_direct(self):
        c = confidence.score_step({"output": "NT AUTHORITY\\SYSTEM", "exit_code": 0})
        self.assertEqual(c.label, "direct_capture")

    def test_k8s_allowed_true_is_direct(self):
        c = confidence.score_step({"output": '{"status":{"allowed":true}}', "exit_code": 0})
        self.assertEqual(c.label, "direct_capture")

    def test_kerberos_tgs_dump_is_direct(self):
        c = confidence.score_step({"output": "$krb5tgs$23$*admin$DOM$svc*$aa$ff...", "exit_code": 0})
        self.assertEqual(c.label, "direct_capture")

    def test_exit_zero_with_output_but_no_proof_is_predicted(self):
        c = confidence.score_step({"output": "scanned 10 hosts, no match", "exit_code": 0})
        self.assertEqual(c.label, "predicted_pattern")
        self.assertEqual(c.score, 0.4)

    def test_non_zero_exit_is_unverified(self):
        c = confidence.score_step({"output": "", "exit_code": 1})
        self.assertEqual(c.label, "unverified")

    def test_empty_output_is_unverified(self):
        c = confidence.score_step({"output": None, "exit_code": 0})
        self.assertEqual(c.label, "unverified")

    def test_object_shape_also_accepted(self):
        class Row:
            output = "uid=0(root)"
            exit_code = 0
        c = confidence.score_step(Row())
        self.assertEqual(c.label, "direct_capture")


class TestScoreFinding(unittest.TestCase):

    def test_direct_proof_in_steps_wins(self):
        f = {"key": "sudo:ALL", "exploitability": "high"}
        steps = [{"output": "sudo -l confirmed", "exit_code": 0},
                 {"output": "uid=0(root)", "exit_code": 0}]
        c = confidence.score_finding(f, steps)
        self.assertEqual(c.label, "direct_capture")

    def test_cve_without_proof_is_inferred_version(self):
        f = {"key": "cve:cve-2022-0847", "exploitability": "high"}
        c = confidence.score_finding(f, steps=None)
        self.assertEqual(c.label, "inferred_version")
        self.assertEqual(c.score, 0.6)

    def test_cve_with_direct_proof_still_wins_direct(self):
        f = {"key": "cve:cve-2022-0847", "exploitability": "high"}
        steps = [{"output": "uid=0(root)", "exit_code": 0}]
        c = confidence.score_finding(f, steps)
        self.assertEqual(c.label, "direct_capture")

    def test_high_exploitability_without_proof_is_predicted(self):
        f = {"key": "privesc:writable-sudoers", "exploitability": "high"}
        c = confidence.score_finding(f, steps=None)
        self.assertEqual(c.label, "predicted_pattern")

    def test_medium_exploitability_without_proof_is_unverified(self):
        f = {"key": "loot:cloud-credentials", "exploitability": "medium"}
        c = confidence.score_finding(f, steps=None)
        self.assertEqual(c.label, "unverified")


class TestScoreOrdering(unittest.TestCase):
    """The point of confidence: a reader can rank findings by (ranking,
    confidence) and the ordering must respect the four tiers."""

    def test_scores_ordered_correctly(self):
        self.assertGreater(confidence.DIRECT_CAPTURE,
                           confidence.INFERRED_VERSION)
        self.assertGreater(confidence.INFERRED_VERSION,
                           confidence.PREDICTED_PATTERN)
        self.assertGreater(confidence.PREDICTED_PATTERN,
                           confidence.UNVERIFIED)


if __name__ == "__main__":
    unittest.main()
