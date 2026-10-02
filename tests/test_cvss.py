#!/usr/bin/env python3
"""CVSS v3.1 derivation — vector string + base score + severity label."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import cvss


class TestDeriveShapes(unittest.TestCase):

    def test_critical_crashrisk_scope_U_default(self):
        r = cvss.derive("Critical", "high", "crash-risk", "moderate")
        self.assertIn("CVSS:3.1", r.vector)
        self.assertIn("S:U", r.vector)
        self.assertGreaterEqual(r.score, 7.0)

    def test_critical_crashrisk_scope_C(self):
        """Scope-changed must score higher than the same shape unchanged."""
        u = cvss.derive("Critical", "high", "crash-risk", "moderate", scope="U")
        c = cvss.derive("Critical", "high", "crash-risk", "moderate", scope="C")
        self.assertGreater(c.score, u.score)
        self.assertIn("S:C", c.vector)

    def test_high_readonly_quiet(self):
        """sudo:ALL shape — should land High (7.0-8.9)."""
        r = cvss.derive("High", "high", "read-only", "quiet")
        self.assertEqual(r.severity, "High")

    def test_medium_loot_hunt(self):
        """Loot family shape — Medium."""
        r = cvss.derive("Medium", "medium", "read-only", "quiet")
        self.assertEqual(r.severity, "Medium")

    def test_loud_detection_adds_user_interaction(self):
        """Loud detection → UI:R (user must click something) → lower score."""
        quiet = cvss.derive("High", "high", "config-edit", "quiet")
        loud = cvss.derive("High", "high", "config-edit", "loud")
        self.assertIn("UI:R", loud.vector)
        self.assertIn("UI:N", quiet.vector)
        self.assertLess(loud.score, quiet.score)


class TestScoreMath(unittest.TestCase):

    def test_vector_is_v3_1(self):
        r = cvss.derive("Medium", "medium", "read-only", "quiet")
        self.assertTrue(r.vector.startswith("CVSS:3.1/"))

    def test_score_is_rounded_to_one_decimal(self):
        r = cvss.derive("High", "high", "crash-risk", "moderate", scope="C")
        self.assertEqual(round(r.score * 10), r.score * 10)

    def test_score_capped_at_10(self):
        """No shape in the mapping should produce > 10.0."""
        for sev in ("Critical", "High"):
            for safe in ("crash-risk", "config-edit"):
                for scope in ("U", "C"):
                    r = cvss.derive(sev, "high", safe, "quiet", scope=scope)
                    self.assertLessEqual(r.score, 10.0)

    def test_info_sev_scores_low_or_none(self):
        r = cvss.derive("Info", "low", "read-only", "quiet")
        self.assertIn(r.severity, {"None", "Low"})


class TestSeverityLabel(unittest.TestCase):

    def test_label_bands(self):
        from fieldkit.cvss import _severity_label
        self.assertEqual(_severity_label(9.5), "Critical")
        self.assertEqual(_severity_label(8.0), "High")
        self.assertEqual(_severity_label(5.0), "Medium")
        self.assertEqual(_severity_label(2.0), "Low")
        self.assertEqual(_severity_label(0.0), "None")

    def test_boundary_values(self):
        from fieldkit.cvss import _severity_label
        self.assertEqual(_severity_label(9.0), "Critical")
        self.assertEqual(_severity_label(8.9), "High")
        self.assertEqual(_severity_label(7.0), "High")
        self.assertEqual(_severity_label(6.9), "Medium")
        self.assertEqual(_severity_label(4.0), "Medium")
        self.assertEqual(_severity_label(3.9), "Low")
        self.assertEqual(_severity_label(0.1), "Low")
        self.assertEqual(_severity_label(0.0), "None")


class TestDeriveFromKb(unittest.TestCase):

    def test_combines_kb_entry_and_ranking(self):
        class R:
            exploitability = "high"
            safety = "config-edit"
            detection = "quiet"
        r = cvss.derive_from_kb({"sev": "High"}, R())
        self.assertEqual(r.severity, "High")

    def test_crashrisk_safety_is_scope_changing(self):
        class R:
            exploitability = "high"
            safety = "crash-risk"
            detection = "moderate"
        r = cvss.derive_from_kb({"sev": "Critical"}, R())
        self.assertIn("S:C", r.vector)

    def test_missing_sev_falls_back_to_medium(self):
        class R:
            exploitability = "medium"
            safety = "read-only"
            detection = "quiet"
        r = cvss.derive_from_kb({}, R())
        self.assertEqual(r.vector.split("CVSS:3.1/")[1].count("/"), 7)


class TestResultIsFrozen(unittest.TestCase):

    def test_cvss_result_is_immutable(self):
        r = cvss.derive("High", "high", "read-only", "quiet")
        with self.assertRaises(Exception):
            r.score = 0


if __name__ == "__main__":
    unittest.main()
