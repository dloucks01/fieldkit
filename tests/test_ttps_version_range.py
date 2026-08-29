#!/usr/bin/env python3
"""fieldkit.ttps — `version_range` predicate + first CVE TTP (B5b tail).

Pinned:

  * version parser normalizes to a 4-tuple, ignoring trailing suffixes
    (`5.15.0-generic` → `(5,15,0,0)`) so real-world uname output compares
    correctly against clean version strings;
  * short versions pad zeros so `5.15` == `5.15.0` == `5.15.0.0`;
  * all six comparison operators (`<`, `<=`, `>`, `>=`, `==`, `!=`) work
    and inclusive/exclusive boundaries land where the shipped TTPs expect;
  * comma-separated constraints in a spec are AND-ed;
  * multiple fields in the predicate dict are AND-ed;
  * missing / unparseable host version = no match (don't fire a
    version-gated exploit on a host we can't safely place in the window);
  * dirty COW TTP fires for `[2.6.22, 4.8.4)` and refuses outside.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class VersionParseTest(unittest.TestCase):
    def test_normal_version(self):
        from fieldkit.ttps.adapter import _parse_version
        self.assertEqual(_parse_version("5.15.0"), (5, 15, 0, 0))
        self.assertEqual(_parse_version("2.6.22"), (2, 6, 22, 0))

    def test_short_version_pads_zeros(self):
        from fieldkit.ttps.adapter import _parse_version
        self.assertEqual(_parse_version("5.15"), (5, 15, 0, 0))
        self.assertEqual(_parse_version("5"), (5, 0, 0, 0))

    def test_trailing_suffix_ignored(self):
        # Real-world uname/apt output carries suffixes; the parser should
        # strip them so `4.8.3-generic-hwe-16` == `4.8.3`.
        from fieldkit.ttps.adapter import _parse_version
        self.assertEqual(_parse_version("4.8.3-generic-hwe-16"), (4, 8, 3, 0))
        self.assertEqual(_parse_version("5.15.0-134-generic"), (5, 15, 0, 0))

    def test_unparseable_returns_none(self):
        from fieldkit.ttps.adapter import _parse_version
        self.assertIsNone(_parse_version(""))
        self.assertIsNone(_parse_version(None))
        self.assertIsNone(_parse_version("not-a-version"))


class ConstraintParseTest(unittest.TestCase):
    def test_all_operators_parse(self):
        from fieldkit.ttps.adapter import _parse_constraint
        for spec, expected_tuple in [
            (">=5.4", (5, 4, 0, 0)),
            ("<=4.8.3", (4, 8, 3, 0)),
            ("<5.15", (5, 15, 0, 0)),
            (">2.6.22", (2, 6, 22, 0)),
            ("==5.15.0", (5, 15, 0, 0)),
            ("!=5.15", (5, 15, 0, 0)),
        ]:
            parsed = _parse_constraint(spec)
            self.assertIsNotNone(parsed, f"{spec!r} parsed as None")
            _, v = parsed
            self.assertEqual(v, expected_tuple)

    def test_two_char_op_wins_over_prefix(self):
        # `>=` must be tried before `>` (else `>=5.4` gets shortened to `>`).
        from fieldkit.ttps.adapter import _parse_constraint
        op_fn, _ = _parse_constraint(">=5.15")
        self.assertTrue(op_fn(_parse_version_helper("5.15"), (5, 15, 0, 0)))
        self.assertFalse(op_fn(_parse_version_helper("5.14"), (5, 15, 0, 0)))

    def test_invalid_constraint_returns_none(self):
        from fieldkit.ttps.adapter import _parse_constraint
        self.assertIsNone(_parse_constraint("garbage"))
        self.assertIsNone(_parse_constraint(""))
        self.assertIsNone(_parse_constraint("<not-a-version"))


def _parse_version_helper(s):
    from fieldkit.ttps.adapter import _parse_version
    return _parse_version(s)


class VersionRangePredicateTest(unittest.TestCase):
    def _facts(self, **kw):
        from fieldkit.hostenum import HostFacts, LINUX
        defaults = dict(os=LINUX, user="alice", uid=1000)
        defaults.update(kw)
        return HostFacts(**defaults)

    def test_single_constraint_within_range(self):
        from fieldkit.ttps.adapter import _p_version_range
        facts = self._facts(kernel="4.4.0")
        matched, _ = _p_version_range(facts, {"kernel": ">=2.6.22,<4.8.4"})
        self.assertTrue(matched)

    def test_single_constraint_outside_range(self):
        from fieldkit.ttps.adapter import _p_version_range
        facts = self._facts(kernel="5.15.0")
        matched, _ = _p_version_range(facts, {"kernel": ">=2.6.22,<4.8.4"})
        self.assertFalse(matched)

    def test_boundary_inclusive_and_exclusive(self):
        # >=2.6.22 includes 2.6.22; <4.8.4 excludes 4.8.4.
        from fieldkit.ttps.adapter import _p_version_range
        self.assertTrue(_p_version_range(self._facts(kernel="2.6.22"),
                                          {"kernel": ">=2.6.22,<4.8.4"})[0])
        self.assertFalse(_p_version_range(self._facts(kernel="2.6.21"),
                                           {"kernel": ">=2.6.22,<4.8.4"})[0])
        self.assertTrue(_p_version_range(self._facts(kernel="4.8.3"),
                                          {"kernel": ">=2.6.22,<4.8.4"})[0])
        self.assertFalse(_p_version_range(self._facts(kernel="4.8.4"),
                                           {"kernel": ">=2.6.22,<4.8.4"})[0])

    def test_multi_field_conjunction(self):
        # Both fields must match — a compound like "old kernel AND old sudo".
        from fieldkit.ttps.adapter import _p_version_range
        matched, _ = _p_version_range(
            self._facts(kernel="4.4.0", sudo_version="1.8.20"),
            {"kernel": "<4.8.4", "sudo_version": "<1.9.0"})
        self.assertTrue(matched)
        # One field fails → whole predicate fails
        matched, _ = _p_version_range(
            self._facts(kernel="4.4.0", sudo_version="1.9.5"),
            {"kernel": "<4.8.4", "sudo_version": "<1.9.0"})
        self.assertFalse(matched)

    def test_missing_field_declines_to_match(self):
        # A partially-enumerated host must NOT spuriously fire a version-
        # gated exploit — if we can't parse the version, we can't safely
        # place the host in the window.
        from fieldkit.ttps.adapter import _p_version_range
        facts = self._facts(kernel=None)   # no enum data
        matched, _ = _p_version_range(facts, {"kernel": "<4.8.4"})
        self.assertFalse(matched)


class DirtyCowTTPTest(unittest.TestCase):
    """The shipped Dirty COW TTP — first version_range TTP in the library.
    Proves the whole chain: YAML load → adapter → predicate → Vector."""

    def _dirty_cow_fires_on(self, kernel):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=LINUX, user="alice", uid=1000, kernel=kernel),
            "10.0.0.7")
        return any(v.key == "kernel_lpe:dirtycow" for v in vs)

    def test_fires_on_ancient_kernel(self):
        self.assertTrue(self._dirty_cow_fires_on("2.6.32"))
        self.assertTrue(self._dirty_cow_fires_on("3.10.0"))
        self.assertTrue(self._dirty_cow_fires_on("4.4.0"))

    def test_fires_at_last_vulnerable_version(self):
        # 4.8.3 is the last vulnerable upstream; mainline fix landed at 4.8.4.
        self.assertTrue(self._dirty_cow_fires_on("4.8.3"))

    def test_does_not_fire_at_first_patched_version(self):
        self.assertFalse(self._dirty_cow_fires_on("4.8.4"))

    def test_does_not_fire_on_modern_kernel(self):
        self.assertFalse(self._dirty_cow_fires_on("5.15.0"))
        self.assertFalse(self._dirty_cow_fires_on("6.1.0"))

    def test_does_not_fire_on_ancient_pre_bug_kernel(self):
        # Pre-2.6.22 kernels didn't have the COW code path that introduced
        # the race. Refusing to fire below the lower bound is honest.
        self.assertFalse(self._dirty_cow_fires_on("2.6.20"))

    def test_missing_kernel_fact_doesnt_fire(self):
        # A host we haven't enum'd → no dirty cow claim.
        self.assertFalse(self._dirty_cow_fires_on(None))


if __name__ == "__main__":
    unittest.main()
