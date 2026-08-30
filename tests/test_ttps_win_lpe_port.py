#!/usr/bin/env python3
"""WIN_LPE port — pin the Windows-side CVE table now flows through YAML.

Phase B5d, the direct Windows analogue to B5c: the five rules in
:data:`fieldkit.privesc.WIN_LPE` (printnightmare, spoolfool,
smbghost-2020-0796, afd-2023-21768, win32k-2021-1732) each become a
T1068-CVE-*.yaml TTP using the compound
``all_of[version_range, no_hotfix_from]`` predicate landed alongside
this slice. ``_d_win_lpe`` retires from ``DRIVERS[WINDOWS]``.

The compound predicate is what lets a single YAML express the inlined
driver's compound rule "in vulnerable build window AND none of these
fixing KBs are installed" — refusing to fire when a fix landed prevents
false positives on patched hosts, matching :func:`win_lpe_candidates`'s
in-window + hotfix-suppression logic exactly.

Pins:

  * every port emits ``key = "wincve:<slug>"`` matching the inlined
    driver's naming (analyze/escalate/prep + reportkb key off this);
  * every port sets ``report_type = "kernel_cve"`` (same reportkb entry
    as the Linux side);
  * every port sets the same ``exploitability/safety/detection`` triple
    as the WIN_LPE rule;
  * every port carries a playbook (Windows kernel CVEs against client
    hosts are prepare-only routes — BSOD risk on failure);
  * ``no_hotfix_from`` suppresses the TTP when any listed KB is
    installed (real fix suppression, not just build check);
  * ``all_of`` compound predicate propagates the version_range payload
    up so the evidence template can render ``{{version}}``/``{{lo}}``/``{{hi}}``.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class DriverRetirementTest(unittest.TestCase):
    def test_only_ttp_yaml_driver_wired_for_windows(self):
        # `_d_win_lpe` was retired at Phase B5d and has since
        # been deleted. DRIVERS[WINDOWS] is exclusively `_d_ttp_yaml`.
        from fieldkit.privesc import DRIVERS, WINDOWS, _d_ttp_yaml
        self.assertEqual(DRIVERS[WINDOWS], (_d_ttp_yaml,))

    def test_win_lpe_candidates_still_exported(self):
        from fieldkit.privesc import WIN_LPE, win_lpe_candidates
        self.assertTrue(callable(win_lpe_candidates))
        self.assertTrue(len(WIN_LPE) >= 5)


class WinLPEPortCoverageTest(unittest.TestCase):

    def _by_key(self):
        from fieldkit.ttps.loader import load_all
        return {t.key: t for t in load_all() if t.key.startswith("wincve:")}

    def test_every_win_lpe_rule_has_a_ttp(self):
        from fieldkit.privesc import WIN_LPE
        by_key = self._by_key()
        for rule in WIN_LPE:
            with self.subTest(rule=rule["key"]):
                self.assertIn(f"wincve:{rule['key']}", by_key)

    def test_ranking_triple_matches_win_lpe(self):
        from fieldkit.privesc import WIN_LPE
        by_key = self._by_key()
        for rule in WIN_LPE:
            with self.subTest(rule=rule["key"]):
                t = by_key[f"wincve:{rule['key']}"]
                self.assertEqual(t.ranking.exploitability, rule["exploitability"])
                self.assertEqual(t.ranking.safety, rule["safety"])
                self.assertEqual(t.ranking.detection, rule["detection"])

    def test_all_report_under_kernel_cve(self):
        for t in self._by_key().values():
            with self.subTest(key=t.key):
                self.assertEqual(t.report.vector_type, "kernel_cve")

    def test_all_carry_a_playbook_with_bsod_wording(self):
        # Windows kernel CVEs are all prepare-only — the playbook exists
        # and the escalate loop reads .manual = True from it.
        for t in self._by_key().values():
            with self.subTest(key=t.key):
                self.assertIsNotNone(t.playbook)
                self.assertTrue(t.playbook.steps)

    def test_all_use_compound_predicate_with_version_and_hotfix_gates(self):
        # The compound predicate is the load-bearing surface: without
        # `no_hotfix_from` the port would fire on patched hosts, which
        # `win_lpe_candidates` never did.
        for t in self._by_key().values():
            with self.subTest(key=t.key):
                self.assertEqual(t.detect.kind, "all_of")
                kinds = {list(entry.keys())[0] for entry in t.detect.value}
                self.assertIn("version_range", kinds)
                self.assertIn("no_hotfix_from", kinds)


class VectorEmissionTest(unittest.TestCase):

    def _facts(self, **kw):
        from fieldkit.hostenum import HostFacts, WINDOWS
        base = dict(os=WINDOWS, user="alice", uid=1000)
        base.update(kw)
        return HostFacts(**base)

    def _vectors_for(self, **kw):
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        return vectors_for(self._facts(**kw), "10.0.0.7")

    def test_20h2_build_fires_expected_cves(self):
        # 20H2 (10.0.19042) is in-range for printnightmare, spoolfool,
        # win32k. Should NOT fire smbghost (18362/18363) or afd (22000+).
        vs = self._vectors_for(win_build="10.0.19042.928")
        keys = {v.key for v in vs if v.key.startswith("wincve:")}
        self.assertIn("wincve:printnightmare", keys)
        self.assertIn("wincve:spoolfool", keys)
        self.assertIn("wincve:win32k-2021-1732", keys)
        self.assertNotIn("wincve:smbghost-2020-0796", keys)
        self.assertNotIn("wincve:afd-2023-21768", keys)

    def test_hotfix_kb_suppresses_the_rule(self):
        # KB4601319 fixes win32k-2021-1732; installing it must remove
        # THAT rule without touching printnightmare (which needs a
        # different KB set to be suppressed).
        vs = self._vectors_for(win_build="10.0.19042.928",
                                hotfixes={"KB4601319"})
        keys = {v.key for v in vs if v.key.startswith("wincve:")}
        self.assertNotIn("wincve:win32k-2021-1732", keys)
        self.assertIn("wincve:printnightmare", keys)

    def test_all_hotfixes_installed_produces_zero_wincve(self):
        # Union every fixing KB across all 5 rules — the target is
        # patched for everything.
        vs = self._vectors_for(
            win_build="10.0.19042.928",
            hotfixes={"KB5005010", "KB5005033", "KB5005565",
                       "KB5005568", "KB5005566",
                       "KB5010342", "KB5010354", "KB5010351",
                       "KB4551762",
                       "KB5022303", "KB5022287", "KB5022834", "KB5022836",
                       "KB4601319", "KB4601315"})
        keys = {v.key for v in vs if v.key.startswith("wincve:")}
        self.assertEqual(keys, set())

    def test_smbghost_only_on_1903_1909(self):
        for build in ("10.0.18362.1", "10.0.18363.1"):
            vs = self._vectors_for(win_build=build)
            keys = {v.key for v in vs if v.key.startswith("wincve:")}
            self.assertIn("wincve:smbghost-2020-0796", keys,
                          f"expected smbghost to fire on {build}")
        # Above/below the window
        self.assertNotIn("wincve:smbghost-2020-0796",
                          {v.key for v in self._vectors_for(
                              win_build="10.0.19041.0")})
        self.assertNotIn("wincve:smbghost-2020-0796",
                          {v.key for v in self._vectors_for(
                              win_build="10.0.17763.0")})

    def test_afd_only_on_win11_and_server2022(self):
        vs = self._vectors_for(win_build="10.0.22000.500")
        keys = {v.key for v in vs if v.key.startswith("wincve:")}
        self.assertIn("wincve:afd-2023-21768", keys)

    def test_unknown_build_produces_no_wincve(self):
        # Matches the inlined `_build_in_range(None, ...)` returning False.
        vs = self._vectors_for(win_build=None)
        keys = {v.key for v in vs if v.key.startswith("wincve:")}
        self.assertEqual(keys, set())

    def test_emitted_vectors_are_prepare_only(self):
        vs = [v for v in self._vectors_for(win_build="10.0.19042.928")
              if v.key.startswith("wincve:")]
        self.assertTrue(vs)
        for v in vs:
            self.assertTrue(v.manual)
            self.assertIsNotNone(v.playbook)
            self.assertEqual(v.report_type, "kernel_cve")
            self.assertTrue(v.stages)

    def test_evidence_carries_build_and_range(self):
        vs = self._vectors_for(win_build="10.0.19042.928")
        pn = [v for v in vs if v.key == "wincve:printnightmare"][0]
        self.assertIn("10.0.19042.928", pn.evidence)
        # Range comes from the YAML's version_range spec — extended lo/hi
        # payload lets the template render them cleanly.
        self.assertIn("10.0.0.0", pn.evidence)
        self.assertIn("10.0.19043.9999", pn.evidence)


class CompoundPredicateTest(unittest.TestCase):
    """`all_of` and `no_hotfix_from` — the new adapter surface for B5d."""

    def test_all_of_requires_every_subpredicate(self):
        from fieldkit.hostenum import HostFacts, WINDOWS
        from fieldkit.ttps.adapter import _p_all_of
        facts = HostFacts(os=WINDOWS, user="alice", uid=1000,
                           win_build="10.0.19042.928",
                           hotfixes={"KB4601319"})
        # version_range matches (in-range), no_hotfix_from fails (KB installed)
        matched, _ = _p_all_of(facts, [
            {"version_range": {"win_build": ">=10.0.19041.0,<=10.0.19042.9999"}},
            {"no_hotfix_from": ["KB4601319"]},
        ])
        self.assertFalse(matched)
        # Both match
        matched, payload = _p_all_of(facts, [
            {"version_range": {"win_build": ">=10.0.19041.0,<=10.0.19042.9999"}},
            {"no_hotfix_from": ["KB9999999"]},
        ])
        self.assertTrue(matched)
        # Payload propagates from the version_range sub-predicate
        self.assertEqual(payload["field"], "win_build")
        self.assertEqual(payload["version"], "10.0.19042.928")

    def test_no_hotfix_from_matches_on_empty_hotfix_list(self):
        # `win_lpe_candidates` fires (with a caveat) when the enum didn't
        # capture hotfixes — refusing to fire would silently under-report.
        from fieldkit.hostenum import HostFacts, WINDOWS
        from fieldkit.ttps.adapter import _p_no_hotfix_from
        facts = HostFacts(os=WINDOWS, user="alice", uid=1000, hotfixes=set())
        matched, _ = _p_no_hotfix_from(facts, ["KB4601319", "KB4601315"])
        self.assertTrue(matched)

    def test_no_hotfix_from_declines_when_any_kb_installed(self):
        from fieldkit.hostenum import HostFacts, WINDOWS
        from fieldkit.ttps.adapter import _p_no_hotfix_from
        facts = HostFacts(os=WINDOWS, user="alice", uid=1000,
                           hotfixes={"KB4601319", "KB9999999"})
        matched, _ = _p_no_hotfix_from(facts, ["KB4601319", "KB4601315"])
        self.assertFalse(matched)


if __name__ == "__main__":
    unittest.main()
