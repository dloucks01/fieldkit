#!/usr/bin/env python3
"""TUI chain-plan screen — data + rendering (C9 slice 4).

New Textual screen `ChainPlanScreen` shows every registered chain
profile + its step plan + aggregate detection debt. The rendering
math is verified via the data-layer helper `tui_data.chain_profiles()`
so the tests stay dependency-free (no Textual runtime needed).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class ChainProfilesDataTest(unittest.TestCase):

    def test_returns_every_shipped_profile(self):
        # C-arc D5 shipped esc8 + rbcd + smb-relay-exec + esc1.
        # Later slices may add more; the test asserts the shipped
        # set is a subset.
        from fieldkit.tui.data import chain_profiles
        names = {p["name"] for p in chain_profiles()}
        self.assertTrue({"esc8", "rbcd", "smb-relay-exec", "esc1"}
                          .issubset(names))

    def test_each_profile_has_shape(self):
        # Scope to the shipped profiles only — other test modules
        # register transient profiles (dup-test, test-filter-profile,
        # etc.) with intentionally-empty step lists to exercise
        # walker edge cases; those pollute the module-scoped registry
        # for the full-suite run. See tests/test_chain_profiles.py's
        # RegistryTest which uses the same subset pattern.
        from fieldkit.tui.data import chain_profiles
        shipped = {"esc8", "rbcd", "smb-relay-exec", "esc1"}
        for p in chain_profiles():
            if p["name"] not in shipped:
                continue
            self.assertIn("name", p)
            self.assertIn("step_count", p)
            self.assertIn("total_cost", p)
            self.assertIn("steps", p)
            self.assertGreater(p["step_count"], 0)
            self.assertEqual(len(p["steps"]), p["step_count"])
            for s in p["steps"]:
                self.assertIn("name", s)
                self.assertIn("kind", s)
                self.assertIn("cost", s)

    def test_profiles_sorted_quietest_first(self):
        # Operator preference: pick lowest-debt applicable profile.
        # The data helper sorts by total_cost ascending.
        from fieldkit.tui.data import chain_profiles
        costs = [p["total_cost"] for p in chain_profiles()]
        self.assertEqual(costs, sorted(costs))

    def test_esc1_is_quieter_than_esc8(self):
        # Load-bearing story: ESC1 (no coerce, no listener) is
        # quieter than ESC8 (both). The dashboard/plan sort should
        # place esc1 above esc8 in the ranked list.
        from fieldkit.tui.data import chain_profiles
        by_name = {p["name"]: p for p in chain_profiles()}
        self.assertLess(by_name["esc1"]["total_cost"],
                          by_name["esc8"]["total_cost"])


class ChainProfilesRenderingTest(unittest.TestCase):

    def test_render_lists_every_profile(self):
        from fieldkit.tui.chain_plan import _render_profiles
        from fieldkit.tui.data import chain_profiles
        text = _render_profiles(chain_profiles())
        for name in ("esc8", "rbcd", "smb-relay-exec", "esc1"):
            with self.subTest(name=name):
                self.assertIn(name, text)

    def test_render_shows_step_names(self):
        from fieldkit.tui.chain_plan import _render_profiles
        from fieldkit.tui.data import chain_profiles
        text = _render_profiles(chain_profiles())
        # A shipped step name should appear (esc8 has preflight:
        # reachability, coerce:petitpotam, etc.).
        self.assertIn("preflight:reachability", text)
        self.assertIn("post:dcsync", text)

    def test_render_shows_running_totals(self):
        from fieldkit.tui.chain_plan import _render_profiles
        from fieldkit.tui.data import chain_profiles
        text = _render_profiles(chain_profiles())
        # Running-total lines are formatted "running=<N>"
        self.assertIn("running=", text)

    def test_empty_profiles_renders_placeholder(self):
        from fieldkit.tui.chain_plan import _render_profiles
        text = _render_profiles([])
        self.assertIn("no chain profiles", text)


class AppScreenRegistrationTest(unittest.TestCase):
    """The chain-plan screen is registered on the App SCREENS map +
    bound to the `c` key for keyboard navigation."""

    def test_screen_registered(self):
        from fieldkit.tui.app import FieldkitTUI
        self.assertIn("chain-plan", FieldkitTUI.SCREENS)

    def test_c_key_bound_to_chain_plan_switch(self):
        from fieldkit.tui.app import FieldkitTUI
        found = False
        for b in FieldkitTUI.BINDINGS:
            key = b.key if hasattr(b, "key") else b[0]
            action = b.action if hasattr(b, "action") else b[1]
            if key == "c" and "chain-plan" in action:
                found = True
                break
        self.assertTrue(found, "no 'c' → chain-plan binding found")


if __name__ == "__main__":
    unittest.main()
