#!/usr/bin/env python3
"""KERNEL_LPE port — pin every entry now flows through YAML + adapter.

Phase B5c: the eight rules in :data:`fieldkit.privesc.KERNEL_LPE` (pwnkit,
baronsamedit, looneytunables, dirtypipe, nftables, stackrot,
cve-2021-22555, dirtycow) each become a T1068-CVE-*.yaml TTP using either
the ``version_range`` predicate (7 of them) or ``suid`` (pwnkit — its
lo/hi in KERNEL_LPE were None, meaning "any polkit build with SUID
pkexec"). ``_d_kernel_lpe`` retires from ``DRIVERS[LINUX]`` after all
eight port cleanly.

This test file locks in the contract that lets the inlined driver be
retired without regressing the CLI:

  * every port emits ``key = "cve:<slug>"`` matching the inlined driver's
    naming, so downstream code that keys off `cve:*` (analyze, escalate,
    prep, reports) doesn't change;
  * every port sets ``report_type = "kernel_cve"`` so :mod:`reportkb`
    finds the entry via the same key it always used;
  * every port sets ``exploitability/safety/detection`` to the same
    triple the inlined driver used (verified rule-by-rule against
    KERNEL_LPE), so ranking output stays stable;
  * every port carries a ``playbook`` — kernel CVEs against client hosts
    are prepare-only routes, so ``vector.manual`` must be True;
  * the ``evidence`` template reproduces the inlined driver's
    "<component> <version> in <lo>-<hi>" (or "SUID pkexec present")
    format, so the analyze/prep report text stays legible;
  * the ``sudo_version`` p-suffix survives parsing so baronsamedit's
    hi=1.9.5p1 fires on 1.9.5p1 but not on 1.9.5p2 (the fix).

The pure-Python :data:`KERNEL_LPE` tuple + :func:`kernel_candidates`
function stay exported (they're the coverage-pin used by the reportkb
sanity tests), just no longer wired into ``DRIVERS`` — they're now the
authoritative lookup that the YAML ports mirror.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class DriverRetirementTest(unittest.TestCase):
    """`_d_kernel_lpe` was retired at Phase B5c and its function has
    since been deleted. Every kernel-CVE vector emitted by
    `vectors_for` now comes from the TTP adapter (`_d_ttp_yaml`).
    Test pins the stronger post-condition: DRIVERS[LINUX] is
    exclusively `_d_ttp_yaml`."""

    def test_only_ttp_yaml_driver_wired_for_linux(self):
        from fieldkit.privesc import DRIVERS, LINUX, _d_ttp_yaml
        self.assertEqual(DRIVERS[LINUX], (_d_ttp_yaml,))

    def test_kernel_candidates_still_exported(self):
        # The pure-Python lookup stays available for the reportkb sanity
        # test + any operator-side introspection. Only the DRIVER wiring
        # was retired.
        from fieldkit.privesc import KERNEL_LPE, kernel_candidates
        self.assertTrue(callable(kernel_candidates))
        self.assertTrue(len(KERNEL_LPE) >= 8)


class KernelCVEPortCoverageTest(unittest.TestCase):
    """Every KERNEL_LPE rule now has a matching TTP with the same key,
    report_type, and ranking triple as the inlined driver used to emit."""

    def _load_by_key(self):
        from fieldkit.ttps.loader import load_all
        return {t.key: t for t in load_all() if t.key.startswith("cve:")}

    def test_every_kernel_lpe_rule_has_a_ttp(self):
        from fieldkit.privesc import KERNEL_LPE
        by_key = self._load_by_key()
        for rule in KERNEL_LPE:
            with self.subTest(rule=rule["key"]):
                self.assertIn(f"cve:{rule['key']}", by_key,
                              f"KERNEL_LPE rule {rule['key']!r} has no port")

    def test_ranking_triple_matches_kernel_lpe(self):
        # Same three-axis ranking as the inlined driver, so `vectors_for`'s
        # score-sort produces the same order (dirtypipe/pwnkit above
        # nftables, etc.).
        from fieldkit.privesc import KERNEL_LPE
        by_key = self._load_by_key()
        for rule in KERNEL_LPE:
            with self.subTest(rule=rule["key"]):
                t = by_key[f"cve:{rule['key']}"]
                self.assertEqual(t.ranking.exploitability, rule["exploitability"])
                self.assertEqual(t.ranking.safety, rule["safety"])
                self.assertEqual(t.ranking.detection, rule["detection"])

    def test_all_report_under_kernel_cve(self):
        from fieldkit.privesc import KERNEL_LPE
        by_key = self._load_by_key()
        for rule in KERNEL_LPE:
            with self.subTest(rule=rule["key"]):
                t = by_key[f"cve:{rule['key']}"]
                self.assertEqual(t.report.vector_type, "kernel_cve")

    def test_all_carry_a_playbook(self):
        # Kernel CVEs against client hosts are prepare-only — never
        # blind-fired even under `--allow crash-risk`.
        from fieldkit.privesc import KERNEL_LPE
        by_key = self._load_by_key()
        for rule in KERNEL_LPE:
            with self.subTest(rule=rule["key"]):
                t = by_key[f"cve:{rule['key']}"]
                self.assertIsNotNone(t.playbook,
                                     f"cve:{rule['key']} lacks a playbook")
                self.assertTrue(t.playbook.steps)
                self.assertTrue(t.playbook.place)


class VectorEmissionTest(unittest.TestCase):
    """End-to-end: HostFacts → vectors_for → the emitted kernel-CVE Vector
    has all the properties the CLI + reports rely on."""

    def _fire_dirtypipe(self, kernel="5.15.0"):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=LINUX, user="alice", uid=1000, kernel=kernel),
            "10.0.0.7")
        return [v for v in vs if v.key == "cve:dirtypipe"]

    def _fire_pwnkit(self):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=LINUX, user="alice", uid=1000, suid={"pkexec"}),
            "10.0.0.7")
        return [v for v in vs if v.key == "cve:pwnkit"]

    def _fire_baronsamedit(self, sudo_version):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=LINUX, user="alice", uid=1000, sudo_version=sudo_version),
            "10.0.0.7")
        return [v for v in vs if v.key == "cve:baronsamedit"]

    def test_dirtypipe_fires_in_window(self):
        vs = self._fire_dirtypipe("5.15.0")
        self.assertEqual(len(vs), 1)
        v = vs[0]
        self.assertEqual(v.report_type, "kernel_cve")
        self.assertTrue(v.manual)
        self.assertIsNotNone(v.playbook)
        self.assertTrue(v.stages)  # arsenal artifact to push
        # Evidence carries the same shape as the inlined driver used to.
        # The `–` separator is a Unicode en-dash from the YAML template.
        self.assertIn("kernel", v.evidence)
        self.assertIn("5.15.0", v.evidence)

    def test_dirtypipe_does_not_fire_on_patched(self):
        self.assertEqual(self._fire_dirtypipe("6.1.0"), [])
        self.assertEqual(self._fire_dirtypipe("5.16.12"), [])

    def test_pwnkit_fires_on_suid_pkexec(self):
        vs = self._fire_pwnkit()
        self.assertEqual(len(vs), 1)
        v = vs[0]
        self.assertEqual(v.report_type, "kernel_cve")
        self.assertTrue(v.manual)
        self.assertEqual(v.evidence, "SUID pkexec present")

    def test_baronsamedit_p_suffix_boundary(self):
        # `1.9.5p1` = last vulnerable, `1.9.5p2` = first patched. The
        # adapter's version parser must preserve the p-suffix (via
        # `_parse_version` returning `(1,9,5,N)`), otherwise both would
        # collapse to `(1,9,5,0)` and the port would fire on the fix.
        self.assertEqual(len(self._fire_baronsamedit("1.9.5p1")), 1)
        self.assertEqual(len(self._fire_baronsamedit("1.9.5p2")), 0)
        # Deep in the window
        self.assertEqual(len(self._fire_baronsamedit("1.8.20")), 1)
        # Below the window
        self.assertEqual(len(self._fire_baronsamedit("1.8.1")), 0)

    def test_reliable_dirtypipe_outranks_crash_risk_nftables(self):
        # Same ordering the inlined driver produced (high/config-change
        # ranks above medium/crash-risk).
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=LINUX, user="alice", uid=1000, kernel="5.15.0",
                       suid={"pkexec"}),
            "10.0.0.7")
        keys = [v.key for v in vs if v.key.startswith("cve:")]
        self.assertIn("cve:dirtypipe", keys)
        self.assertIn("cve:pwnkit", keys)
        # nftables may or may not fire depending on window overlap; if it
        # does, it MUST rank below the safer routes.
        if "cve:nftables" in keys:
            self.assertLess(keys.index("cve:dirtypipe"), keys.index("cve:nftables"))
            self.assertLess(keys.index("cve:pwnkit"), keys.index("cve:nftables"))

    def test_no_false_positive_on_patched_host(self):
        # Modern kernel + modern sudo + modern glibc + no SUID pkexec →
        # zero cve:* vectors. Matches the inlined-driver "no false
        # positives" pin at :meth:`FullFunnelTest.test_patched_host_matches_no_local_cve`.
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=LINUX, user="alice", uid=1000,
                       kernel="6.11.0", sudo_version="1.9.15p5",
                       glibc_version="2.39", suid=set()),
            "10.0.0.7")
        cves = [v.key for v in vs if v.key.startswith("cve:")]
        self.assertEqual(cves, [])


class AdapterEvidenceTemplateTest(unittest.TestCase):
    """The adapter's evidence-template renderer — new surface for B5c."""

    def test_derive_lo_hi_from_range_spec(self):
        from fieldkit.ttps.adapter import _derive_lo_hi
        self.assertEqual(_derive_lo_hi(">=5.8,<=5.16.11"), ("5.8", "5.16.11"))
        self.assertEqual(_derive_lo_hi("<=4.8.2"), ("*", "4.8.2"))
        self.assertEqual(_derive_lo_hi(">=2.6.19"), ("2.6.19", "*"))
        self.assertEqual(_derive_lo_hi("==1.9.5p1"), ("1.9.5p1", "1.9.5p1"))

    def test_p_version_range_payload_carries_field_and_version(self):
        # The payload shape is `{"field": str, "version": str, "lo": str,
        # "hi": str}` so the evidence template can render lo/hi without
        # walking `ttp.detect.value` — important for compound predicates
        # (`all_of`) where the version_range spec lives one level down.
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.ttps.adapter import _p_version_range
        facts = HostFacts(os=LINUX, user="alice", uid=1000, kernel="5.15.0")
        matched, payload = _p_version_range(facts, {"kernel": ">=5.8,<=5.16.11"})
        self.assertTrue(matched)
        self.assertEqual(payload, {"field": "kernel", "version": "5.15.0",
                                    "lo": "5.8", "hi": "5.16.11"})

    def test_p_version_range_returns_none_payload_on_miss(self):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.ttps.adapter import _p_version_range
        facts = HostFacts(os=LINUX, user="alice", uid=1000, kernel="6.11.0")
        matched, payload = _p_version_range(facts, {"kernel": ">=5.8,<=5.16.11"})
        self.assertFalse(matched)
        self.assertIsNone(payload)

    def test_evidence_template_renders_lo_hi_from_spec(self):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=LINUX, user="alice", uid=1000, kernel="5.15.0"),
            "10.0.0.7")
        dp = [v for v in vs if v.key == "cve:dirtypipe"]
        self.assertEqual(len(dp), 1)
        # Reproduces the inlined driver's `f"{component} {got} in {lo}–{hi}"`.
        self.assertEqual(dp[0].evidence, "kernel 5.15.0 in 5.8–5.16.11")

    def test_evidence_template_default_when_absent(self):
        # A TTP without a `report.evidence` template falls back to the
        # generic "detected via TTP T… (kind)" string, so shipping
        # existing TTPs don't regress.
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        # A sudo TTP with sudo_allows kind — no custom evidence template.
        vs = vectors_for(
            HostFacts(os=LINUX, user="alice", uid=1000,
                       sudo_binaries={"find"}),
            "10.0.0.7")
        sudo_find = [v for v in vs if v.key == "sudo:find"]
        self.assertTrue(sudo_find)
        self.assertIn("detected via TTP", sudo_find[0].evidence)


class AdapterPlaybookEmissionTest(unittest.TestCase):
    """Adapter builds a runtime Playbook from the YAML `playbook:` block."""

    def test_playbook_substitutes_stage(self):
        # `{{stage}}` in playbook.place / .steps / .restore is filled with
        # ctx.stage_lin (linux) at emit time.
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=LINUX, user="alice", uid=1000, kernel="5.15.0"),
            "10.0.0.7", stage_lin="/dev/shm")
        dp = [v for v in vs if v.key == "cve:dirtypipe"][0]
        self.assertEqual(dp.playbook.place, "/dev/shm/dirtypipe")
        self.assertIn("/dev/shm/dirtypipe", dp.playbook.restore)
        for step in dp.playbook.steps:
            self.assertNotIn("{{stage}}", step)

    def test_playbook_substitutes_binary_for_suid_ports(self):
        # pwnkit's playbook doesn't use {{binary}} in its steps, but the
        # summary carries "{{binary}} present" — check that the adapter
        # doesn't leave a `{{binary}}` template variable in the output
        # when payload IS a matched binary string.
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=LINUX, user="alice", uid=1000, suid={"pkexec"}),
            "10.0.0.7")
        pk = [v for v in vs if v.key == "cve:pwnkit"][0]
        # Evidence uses {{binary}} — must have rendered "pkexec".
        self.assertEqual(pk.evidence, "SUID pkexec present")


if __name__ == "__main__":
    unittest.main()
