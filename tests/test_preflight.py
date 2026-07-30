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
        every = {a for _, _p, alts, _r in preflight.CHECKS for a in alts}
        rows = preflight.check(which=which_of(every))
        self.assertTrue(all(found for _n, _p, found, _a, _r in rows))
        self.assertEqual(preflight.missing_required(rows), [])

    def test_alt_names_both_satisfy(self):
        # netexec via either `nxc` or `netexec`
        self.assertTrue(preflight.check(which=which_of({"nxc", "secretsdump.py"}))[0][2])
        self.assertTrue(preflight.check(which=which_of({"netexec", "secretsdump.py"}))[0][2])

    def test_missing_netexec_is_a_required_gap(self):
        rows = preflight.check(which=which_of({"secretsdump.py", "certipy"}))
        missing = preflight.missing_required(rows)
        # missing_required returns the full row; the name is r[0], purpose is r[1]
        self.assertEqual([m[0] for m in missing], ["netexec"])

    def test_optional_tools_are_not_required(self):
        rows = preflight.check(which=which_of({"nxc", "secretsdump.py"}))  # spine only
        self.assertEqual(preflight.missing_required(rows), [])   # no required gap
        # certipy row has name at [0], found at [2]
        certipy_row = [r for r in rows if r[0] == "certipy"][0]
        self.assertFalse(certipy_row[2])

    def test_row_shape_is_name_purpose_found_alts_required(self):
        # regression guard: the 5-tuple shape is load-bearing (cli.py + status
        # depend on r[0] = name; the old shape had r[0] = "netexec — spray / exec / loot"
        # which read badly in a comma-joined warning).
        rows = preflight.check(which=which_of({"nxc"}))
        name, purpose, found, alts, required = rows[0]
        self.assertEqual(name, "netexec")
        self.assertIn("spray", purpose)
        self.assertEqual(found, "nxc")   # `which` returned the found binary name
        self.assertIn("nxc", alts)
        self.assertTrue(required)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
