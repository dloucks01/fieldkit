#!/usr/bin/env python3
"""Preflight — which driven tools are on PATH.

Pinned: check() resolves the first candidate that exists per tool; netexec + impacket are
required (missing_required flags them); alt names (nxc/netexec) both satisfy.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import preflight  # noqa: E402


def which_of(present):
    return lambda name: ("/usr/bin/" + name) if name in present else None


class PreflightTest(unittest.TestCase):
    def test_all_present(self):
        every = {a for _, alts, _ in preflight.CHECKS for a in alts}
        rows = preflight.check(which=which_of(every))
        self.assertTrue(all(found for _, found, _, _ in rows))
        self.assertEqual(preflight.missing_required(rows), [])

    def test_alt_names_both_satisfy(self):
        # netexec via either `nxc` or `netexec`
        self.assertTrue(preflight.check(which=which_of({"nxc", "secretsdump.py"}))[0][1])
        self.assertTrue(preflight.check(which=which_of({"netexec", "secretsdump.py"}))[0][1])

    def test_missing_netexec_is_a_required_gap(self):
        rows = preflight.check(which=which_of({"secretsdump.py", "certipy"}))
        missing = preflight.missing_required(rows)
        self.assertEqual([m[0] for m in missing], ["netexec — spray / exec / loot"])

    def test_optional_tools_are_not_required(self):
        rows = preflight.check(which=which_of({"nxc", "secretsdump.py"}))  # spine only
        self.assertEqual(preflight.missing_required(rows), [])   # no required gap
        self.assertFalse([r for r in rows if r[0].startswith("certipy")][0][1])  # certipy absent


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
