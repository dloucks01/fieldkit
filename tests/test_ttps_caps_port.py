#!/usr/bin/env python3
"""CAPS port — the interpreter+cap_setuid case + _d_caps retirement.

Phase B5f: the last hole in the CAPS port (deferred from B3) closes.
The inlined `_cap_vector` handled three cases:

  * cap_setuid / cap_setgid on the 4 GTFO interpreters (python / perl /
    ruby / php) — reuses the GTFO suid template body;
  * cap_dac_read_search — read arbitrary files (typically /etc/shadow);
  * cap_dac_override — write arbitrary files (append UID-0 line).

Cases 2 and 3 shipped as T1548.001-cap_dac_*.yaml in an earlier slice.
Case 1 was deferred because the plain `capability:` predicate can't
express "cap X on a specific set of binaries" — a naive port would fire
the python TTP against openssl-with-cap_setuid.

The new `capability_on_binary` predicate takes `{binary: <canon>, cap:
<name>}`, matches _canon-aware (so `python` fires on `python3.8` but
not on `openssl`), and returns the actual host basename as payload —
so `{{binary}}` substitutes correctly and the vector key ends
`cap:python3.8`.

With all cases covered, `_d_caps` retires from DRIVERS[LINUX]. The
GTFO dict + `_cap_vector` helper stay exported for tests and operator
introspection.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

#: The 4 GTFO interpreters that carry a cap_setuid port. Node isn't in
#: the set because its GTFO entry lacks a `suid` variant (interactive-
#: only shell), so the setuid-then-exec pattern doesn't apply.
CAP_SETUID_INTERPRETERS = ("python", "perl", "ruby", "php")


class DriverRetirementTest(unittest.TestCase):

    def test_only_ttp_yaml_driver_wired_for_linux(self):
        # `_d_caps` was retired at Phase B5f and has since been
        # deleted. DRIVERS[LINUX] is exclusively `_d_ttp_yaml`.
        from fieldkit.privesc import DRIVERS, LINUX, _d_ttp_yaml
        self.assertEqual(DRIVERS[LINUX], (_d_ttp_yaml,))


class CapSetuidPortCoverageTest(unittest.TestCase):

    def _load(self):
        from fieldkit.ttps.loader import load_all
        return [t for t in load_all()
                if t.detect.kind == "capability_on_binary"]

    def test_every_gtfo_interpreter_has_a_cap_setuid_ttp(self):
        by_binary = {t.detect.value["binary"]: t for t in self._load()}
        for interp in CAP_SETUID_INTERPRETERS:
            with self.subTest(interp=interp):
                self.assertIn(interp, by_binary,
                              f"no cap_setuid TTP for {interp!r}")

    def test_all_report_under_capability(self):
        # Same vector_type as the inlined _cap_vector emitted — reportkb
        # entry stays stable.
        for t in self._load():
            with self.subTest(source=t.source_path):
                self.assertEqual(t.report.vector_type, "capability")

    def test_evidence_template_matches_inlined_getcap_shape(self):
        # Inlined _cap_vector's evidence was `f"getcap: {basename} {cap}"`.
        # The port's evidence template preserves that shape via
        # {{binary}} substitution.
        for t in self._load():
            with self.subTest(source=t.source_path):
                self.assertIn("getcap:", t.report.evidence)
                self.assertIn("{{binary}}", t.report.evidence)


class VectorEmissionTest(unittest.TestCase):

    def _facts(self, **kw):
        from fieldkit.hostenum import HostFacts, LINUX
        base = dict(os=LINUX, user="alice", uid=1000)
        base.update(kw)
        return HostFacts(**base)

    def _vs(self, **kw):
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        return vectors_for(self._facts(**kw), "10.0.0.7")

    def test_python3_variant_fires_with_actual_basename(self):
        vs = self._vs(caps={"python3.8": "cap_setuid"})
        cap_vecs = [v for v in vs if v.key.startswith("cap:")]
        self.assertEqual(len(cap_vecs), 1)
        v = cap_vecs[0]
        self.assertEqual(v.key, "cap:python3.8")
        self.assertIn("python3.8 -c", v.command)
        self.assertNotIn("{{binary}}", v.command)
        self.assertEqual(v.evidence, "getcap: python3.8 cap_setuid")

    def test_each_interpreter_fires_only_its_own_ttp(self):
        # perl-with-cap_setuid must NOT fire the python TTP, and so on.
        for interp in CAP_SETUID_INTERPRETERS:
            with self.subTest(interp=interp):
                vs = self._vs(caps={interp: "cap_setuid"})
                cap_vecs = [v for v in vs if v.key.startswith("cap:")]
                self.assertEqual(len(cap_vecs), 1)
                self.assertEqual(cap_vecs[0].key, f"cap:{interp}")

    def test_non_interpreter_with_cap_setuid_produces_no_interpreter_vector(self):
        # openssl-with-cap_setuid must NOT fire python/perl/ruby/php TTPs.
        vs = self._vs(caps={"openssl": "cap_setuid"})
        cap_setuid_interpreter_titles = [
            v.title for v in vs
            if v.key.startswith("cap:") and "setuid on " in v.title]
        self.assertEqual(cap_setuid_interpreter_titles, [])

    def test_cap_dac_read_search_still_fires_via_ttp(self):
        # Case 2 from _cap_vector — ported earlier; must still land now
        # that _d_caps is retired.
        vs = self._vs(caps={"openssl": "cap_dac_read_search"})
        openssl = [v for v in vs if v.key == "cap:openssl"]
        self.assertEqual(len(openssl), 1)
        self.assertIn("shadow", openssl[0].command)

    def test_cap_dac_override_still_fires_via_ttp(self):
        # Case 3 from _cap_vector — ported earlier.
        vs = self._vs(caps={"cp": "cap_dac_override"})
        cp = [v for v in vs if v.key == "cap:cp"]
        self.assertEqual(len(cp), 1)
        self.assertIn("/etc/passwd", cp[0].command)


class CapabilityOnBinaryPredicateTest(unittest.TestCase):
    """Direct tests on the new predicate — the load-bearing surface."""

    def _facts(self, **kw):
        from fieldkit.hostenum import HostFacts, LINUX
        base = dict(os=LINUX, user="alice", uid=1000)
        base.update(kw)
        return HostFacts(**base)

    def test_direct_binary_match(self):
        from fieldkit.ttps.adapter import _p_capability_on_binary
        matched, payload = _p_capability_on_binary(
            self._facts(caps={"python": "cap_setuid"}),
            {"binary": "python", "cap": "cap_setuid"})
        self.assertTrue(matched)
        self.assertEqual(payload, "python")

    def test_canon_binary_match_returns_actual_basename(self):
        from fieldkit.ttps.adapter import _p_capability_on_binary
        matched, payload = _p_capability_on_binary(
            self._facts(caps={"python3.8": "cap_setuid"}),
            {"binary": "python", "cap": "cap_setuid"})
        self.assertTrue(matched)
        self.assertEqual(payload, "python3.8")

    def test_wrong_binary_declines(self):
        from fieldkit.ttps.adapter import _p_capability_on_binary
        matched, _ = _p_capability_on_binary(
            self._facts(caps={"openssl": "cap_setuid"}),
            {"binary": "python", "cap": "cap_setuid"})
        self.assertFalse(matched)

    def test_wrong_cap_declines(self):
        from fieldkit.ttps.adapter import _p_capability_on_binary
        matched, _ = _p_capability_on_binary(
            self._facts(caps={"python": "cap_dac_override"}),
            {"binary": "python", "cap": "cap_setuid"})
        self.assertFalse(matched)

    def test_missing_dict_keys_declines(self):
        from fieldkit.ttps.adapter import _p_capability_on_binary
        facts = self._facts(caps={"python": "cap_setuid"})
        # Not a dict
        self.assertFalse(_p_capability_on_binary(facts, "cap_setuid")[0])
        # Missing binary
        self.assertFalse(_p_capability_on_binary(
            facts, {"cap": "cap_setuid"})[0])
        # Missing cap
        self.assertFalse(_p_capability_on_binary(
            facts, {"binary": "python"})[0])


if __name__ == "__main__":
    unittest.main()
