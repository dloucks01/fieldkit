#!/usr/bin/env python3
"""Evasion catalog + the assume-caught model.

The one rule that must not bend: a technique is red unless a *fresh* lab result says
otherwise. Pinned here:

  * no lab record -> untested (assumed caught), never a silent pass;
  * a caught record is red; a clean record is green only while fresh, then stale;
  * recommend() puts a fresh green first and, among the red majority, quiet native
    no-AMSI paths before AMSI-scanned scripts and the loud add_admin.

Run:  python3 -m unittest discover -s tests
"""
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit.evasion import (  # noqa: E402
    CAUGHT, GREEN, STALE, UNTESTED, by_key, for_os, recommend, resolve,
)

NOW = datetime(2026, 7, 27, tzinfo=timezone.utc)


def record(verdict, days_ago=0, signature="1.400.1"):
    ts = (NOW - timedelta(days=days_ago)).isoformat()
    return {"verdict": verdict, "signature": signature, "tested_at": ts}


class CatalogTest(unittest.TestCase):
    def test_windows_and_linux_present(self):
        self.assertTrue(for_os("windows"))
        self.assertTrue(for_os("linux"))

    def test_native_pe_has_no_amsi_surface(self):
        self.assertFalse(by_key("native-exe").amsi_surface)

    def test_script_path_needs_amsi_bypass(self):
        t = by_key("ps-amsi-revshell")
        self.assertTrue(t.amsi_surface)
        self.assertTrue(t.needs_amsi_bypass)


class ResolveTest(unittest.TestCase):
    def test_no_record_is_untested_not_pass(self):
        s = resolve(by_key("native-exe"), None, now=NOW)
        self.assertEqual(s.verdict, UNTESTED)
        self.assertFalse(s.usable)

    def test_caught_is_red(self):
        s = resolve(by_key("native-exe"), record("caught"), now=NOW)
        self.assertEqual(s.verdict, CAUGHT)
        self.assertFalse(s.usable)

    def test_fresh_clean_is_green(self):
        s = resolve(by_key("native-exe"), record("clean", days_ago=1), now=NOW)
        self.assertEqual(s.verdict, GREEN)
        self.assertTrue(s.usable)
        self.assertEqual(s.signature, "1.400.1")

    def test_stale_clean_is_red(self):
        s = resolve(by_key("native-exe"), record("clean", days_ago=30), now=NOW)
        self.assertEqual(s.verdict, STALE)
        self.assertFalse(s.usable)

    def test_stale_boundary(self):
        self.assertEqual(resolve(by_key("native-exe"), record("clean", days_ago=13),
                                 now=NOW).verdict, GREEN)
        self.assertEqual(resolve(by_key("native-exe"), record("clean", days_ago=20),
                                 now=NOW).verdict, STALE)


class RecommendTest(unittest.TestCase):
    def _statuses(self, mapping):
        # mapping: key -> record|None
        return [resolve(t, mapping.get(t.key), now=NOW) for t in for_os("windows")]

    def test_untested_prefers_native_no_amsi(self):
        order = [s.technique.key for s in recommend(self._statuses({}))]
        # among all-untested, a native no-AMSI exe beats an AMSI script and add_admin
        self.assertLess(order.index("native-exe"), order.index("ps-amsi-revshell"))
        self.assertLess(order.index("native-exe"), order.index("add-admin"))

    def test_fresh_green_beats_untested_native(self):
        order = [s.technique.key for s in
                 recommend(self._statuses({"ps-amsi-revshell": record("clean", 1)}))]
        # a lab-proven script now outranks an untested native path
        self.assertEqual(order[0], "ps-amsi-revshell")

    def test_caught_sinks_to_bottom(self):
        statuses = self._statuses({"native-exe": record("caught")})
        order = [s.technique.key for s in recommend(statuses)]
        self.assertEqual(order[-1], "native-exe")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
