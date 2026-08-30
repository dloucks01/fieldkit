#!/usr/bin/env python3
"""SUID GTFO port — pin the 15 GTFO suid entries now flow through YAML.

Phase B5e: `_d_suid_gtfo` (inlined) retires from DRIVERS[LINUX] and the
15 GTFO entries with a `suid` variant (bash, sh, dash, find, python,
perl, ruby, php, awk, gawk, env, tar, gdb, make, docker) each become a
T1548.001-suid-*.yaml TTP. Mirrors the B2 sudo port pattern that
retired `_d_sudo_gtfo`.

The port required one adapter change: `_p_suid` is now `_canon`-aware,
so `suid: python` in a TTP still fires against a host that reports
`suid: {"python3.8"}` (the actual basename lands in `{{binary}}` and
the vector key ends `suid:python3.8`). Without that, retiring the
inlined driver would regress test_privesc.py::test_python3_variant.

Pins:
  * every GTFO entry with a `suid` form has a matching YAML;
  * every port emits `key = "suid:<binary>"` matching the inlined
    driver's naming, so downstream code (analyze, escalate, reportkb)
    keys off the same shape;
  * canon-aware match: python3.8 fires suid:python (as suid:python3.8);
  * `_d_suid_gtfo` is no longer wired into DRIVERS[LINUX].
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

#: Every GTFO entry with a `suid` variant — the port target for B5e. If
#: a new SUID form ever lands in privesc.GTFO, this list wants a new
#: T1548.001-suid-*.yaml alongside it and the test below flags the gap.
SUID_GTFO_KEYS = (
    "bash", "sh", "dash", "find", "python", "perl", "ruby", "php",
    "awk", "gawk", "env", "tar", "gdb", "make", "docker",
)


class DriverRetirementTest(unittest.TestCase):

    def test_only_ttp_yaml_driver_wired_for_linux(self):
        # `_d_suid_gtfo` was retired at Phase B5e and has since
        # been deleted. DRIVERS[LINUX] is exclusively `_d_ttp_yaml`.
        from fieldkit.privesc import DRIVERS, LINUX, _d_ttp_yaml
        self.assertEqual(DRIVERS[LINUX], (_d_ttp_yaml,))


class GTFOPortCoverageTest(unittest.TestCase):

    def _load_suid_ttps(self):
        from fieldkit.ttps.loader import load_all
        return [t for t in load_all()
                if t.technique == "T1548.001" and t.detect.kind == "suid"]

    def test_every_suid_gtfo_entry_has_a_ttp(self):
        # A TTP exists for every SUID form declared in GTFO. Uses the
        # detect.value (which the loader keeps verbatim) as the key.
        ttps = self._load_suid_ttps()
        by_bin = {t.detect.value: t for t in ttps}
        for key in SUID_GTFO_KEYS:
            with self.subTest(key=key):
                self.assertIn(key, by_bin, f"no SUID GTFO TTP for {key!r}")

    def test_no_stray_suid_ports_beyond_gtfo_coverage(self):
        # Guardrails: every T1548.001+suid TTP that shipped is one of the
        # 15 GTFO keys — no accidental port beyond what the inlined
        # driver used to emit. Catches a copy-paste mistake at review time.
        ttps = self._load_suid_ttps()
        for t in ttps:
            with self.subTest(source=os.path.basename(t.source_path)):
                self.assertIn(t.detect.value, SUID_GTFO_KEYS,
                              f"{t.source_path} declares suid:{t.detect.value!r} "
                              "which is not in GTFO's SUID form list")

    def test_all_report_under_gtfobins_suid(self):
        for t in self._load_suid_ttps():
            with self.subTest(source=t.source_path):
                self.assertEqual(t.report.vector_type, "gtfobins_suid")


class VectorEmissionTest(unittest.TestCase):

    def _facts(self, **kw):
        from fieldkit.hostenum import HostFacts, LINUX
        base = dict(os=LINUX, user="alice", uid=1000)
        base.update(kw)
        return HostFacts(**base)

    def _vectors_for(self, **kw):
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        return vectors_for(self._facts(**kw), "10.0.0.7")

    def test_direct_match_fires_expected_key(self):
        vs = self._vectors_for(suid={"find"})
        keys = {v.key for v in vs if v.key.startswith("suid:")}
        self.assertEqual(keys, {"suid:find"})

    def test_canon_match_python3_variant_fires(self):
        # The load-bearing case: python3.8 on the host, TTP declares
        # `suid: python` — must fire, key must carry the actual basename
        # (so reports say what file to look at), and command must invoke
        # the real binary via {{binary}} substitution.
        vs = self._vectors_for(suid={"python3.8"})
        py_vecs = [v for v in vs if v.key.startswith("suid:")]
        self.assertEqual(len(py_vecs), 1)
        v = py_vecs[0]
        self.assertEqual(v.key, "suid:python3.8")
        self.assertIn("python3.8 -c", v.command)
        self.assertNotIn("{{binary}}", v.command)

    def test_all_15_gtfo_suid_binaries_fire(self):
        vs = self._vectors_for(suid=set(SUID_GTFO_KEYS))
        keys = {v.key for v in vs if v.key.startswith("suid:")}
        expected = {f"suid:{b}" for b in SUID_GTFO_KEYS}
        self.assertEqual(keys, expected)

    def test_non_gtfo_suid_binary_produces_no_vector(self):
        # `passwd` is legitimately SUID root on every distro; it's not a
        # GTFO primitive so no vector. The inlined driver's shape.
        vs = self._vectors_for(suid={"passwd"})
        suid_vecs = [v for v in vs if v.key.startswith("suid:")]
        self.assertEqual(suid_vecs, [])

    def test_command_starts_with_matched_basename(self):
        # {{binary}} substitution puts the actual host basename first —
        # matches privesc._use_binary's shape.
        vs = self._vectors_for(suid={"awk"})
        v = [x for x in vs if x.key == "suid:awk"][0]
        self.assertTrue(v.command.startswith("awk "))

    def test_suid_report_type_gtfobins_suid(self):
        vs = self._vectors_for(suid={"find"})
        v = [x for x in vs if x.key == "suid:find"][0]
        self.assertEqual(v.report_type, "gtfobins_suid")


class CanonAwareSuidPredicateTest(unittest.TestCase):
    """Direct tests on the adapter's _p_suid — the load-bearing bit."""

    def _facts(self, **kw):
        from fieldkit.hostenum import HostFacts, LINUX
        base = dict(os=LINUX, user="alice", uid=1000)
        base.update(kw)
        return HostFacts(**base)

    def test_direct_match_returns_that_binary(self):
        from fieldkit.ttps.adapter import _p_suid
        matched, payload = _p_suid(self._facts(suid={"find"}), "find")
        self.assertTrue(matched)
        self.assertEqual(payload, "find")

    def test_canon_match_returns_actual_basename(self):
        # `python` matches `python3.8` via _canon; the payload MUST be the
        # actual host basename, not the abstract `python`, so
        # {{binary}} substitution renders correctly.
        from fieldkit.ttps.adapter import _p_suid
        matched, payload = _p_suid(self._facts(suid={"python3.8"}), "python")
        self.assertTrue(matched)
        self.assertEqual(payload, "python3.8")

    def test_no_match_returns_none(self):
        from fieldkit.ttps.adapter import _p_suid
        matched, payload = _p_suid(self._facts(suid={"passwd"}), "find")
        self.assertFalse(matched)
        self.assertIsNone(payload)

    def test_python3_matches_python(self):
        from fieldkit.ttps.adapter import _p_suid
        matched, payload = _p_suid(self._facts(suid={"python3"}), "python")
        self.assertTrue(matched)
        self.assertEqual(payload, "python3")


if __name__ == "__main__":
    unittest.main()
