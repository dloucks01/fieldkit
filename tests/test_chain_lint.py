#!/usr/bin/env python3
"""Chain lint — coverage audit for the shipped chain-profile catalog.

Pins:

  * audit_profile returns Findings for a synthetic profile with
    each defect (empty catalog, factory raises, preflight not first,
    duplicate step names, no-signals fallback, coerce without
    rpc-call signal);
  * audit_all iterates every registered profile;
  * summarize buckets profiles by ok/warn/err;
  * live shipped catalog audit — the current known state — pinned
    so a regression (e.g. dropping the preflight from esc8) trips
    a test rather than shipping silently;
  * CLI cmd_chain_lint exit codes: 0 clean, 1 warnings, 2 errors;
  * CLI --profile filter scopes correctly.
"""
import io
import os
import sys
import unittest
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _fresh_profile_registry():
    """Snapshot the registry so tests that register synthetic
    profiles can restore it cleanly."""
    from fieldkit import chain as chain_mod
    return dict(chain_mod._PROFILES)


def _restore_registry(snap):
    from fieldkit import chain as chain_mod
    chain_mod._PROFILES.clear()
    chain_mod._PROFILES.update(snap)


def _register_synthetic(test_case, name, factory):
    """Register a one-shot profile that auto-cleans."""
    from fieldkit import chain as chain_mod
    snap = _fresh_profile_registry()
    test_case.addCleanup(_restore_registry, snap)
    chain_mod._PROFILES[name] = factory


class SyntheticProfileTest(unittest.TestCase):

    def test_factory_raise_surfaces_factory_fails(self):
        from fieldkit import chainlint
        def _broken(_target):
            raise RuntimeError("kaboom")
        _register_synthetic(self, "lint-broken", _broken)
        fs = chainlint.audit_profile("lint-broken")
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0].code, "factory-fails")
        self.assertEqual(fs[0].severity, "error")

    def test_empty_catalog_surfaces_error(self):
        from fieldkit import chainlint
        from fieldkit.chain import Chain
        def _empty(target):
            return Chain(profile="lint-empty", target=target, steps=())
        _register_synthetic(self, "lint-empty", _empty)
        fs = chainlint.audit_profile("lint-empty")
        # exactly one finding, and it should be empty-catalog
        codes = [f.code for f in fs]
        self.assertIn("empty-catalog", codes)
        self.assertEqual(fs[0].severity, "error")

    def test_preflight_not_first_surfaces_error(self):
        from fieldkit import chainlint
        from fieldkit.chain import Chain, Step, Outcome
        def _act(*_):
            return Outcome(kind="ok", evidence="fake")
        def _bad(target):
            return Chain(profile="lint-noprefl", target=target, steps=(
                Step(name="coerce:x", kind="target-side",
                     action=_act, detection_cost=1),
                Step(name="preflight:reachability", kind="preflight",
                     action=_act, detection_cost=0),
            ))
        _register_synthetic(self, "lint-noprefl", _bad)
        fs = chainlint.audit_profile("lint-noprefl")
        codes = {f.code for f in fs}
        self.assertIn("preflight-not-first", codes)

    def test_duplicate_step_names_surfaces_warning(self):
        from fieldkit import chainlint
        from fieldkit.chain import Chain, Step, Outcome, DetectionSignal
        def _act(*_):
            return Outcome(kind="ok", evidence="fake")
        rpc = DetectionSignal(kind="rpc-call", identifier="fake", count=1)
        def _dup(target):
            return Chain(profile="lint-dup", target=target, steps=(
                Step(name="preflight:reachability", kind="preflight",
                     action=_act, detection_cost=0, signals=(rpc,)),
                Step(name="dupe-name", kind="attacker-side",
                     action=_act, detection_cost=1, signals=(rpc,)),
                Step(name="dupe-name", kind="attacker-side",
                     action=_act, detection_cost=1, signals=(rpc,)),
            ))
        _register_synthetic(self, "lint-dup", _dup)
        fs = chainlint.audit_profile("lint-dup")
        codes = [f.code for f in fs]
        self.assertIn("duplicate-step-names", codes)
        dup = [f for f in fs if f.code == "duplicate-step-names"][0]
        self.assertEqual(dup.severity, "warning")
        self.assertEqual(dup.step_name, "dupe-name")

    def test_no_signals_with_nonzero_cost_surfaces_warning(self):
        from fieldkit import chainlint
        from fieldkit.chain import Chain, Step, Outcome, DetectionSignal
        def _act(*_):
            return Outcome(kind="ok", evidence="fake")
        rpc = DetectionSignal(kind="rpc-call", identifier="fake", count=1)
        def _mix(target):
            return Chain(profile="lint-nosig", target=target, steps=(
                Step(name="preflight:reachability", kind="preflight",
                     action=_act, detection_cost=0, signals=(rpc,)),
                Step(name="silent-step", kind="attacker-side",
                     action=_act, detection_cost=2),   # cost > 0, no signals
            ))
        _register_synthetic(self, "lint-nosig", _mix)
        fs = chainlint.audit_profile("lint-nosig")
        no_sig = [f for f in fs if f.code == "no-signals"]
        self.assertEqual(len(no_sig), 1)
        self.assertEqual(no_sig[0].step_name, "silent-step")
        self.assertEqual(no_sig[0].severity, "warning")

    def test_no_signals_with_zero_cost_is_honest_zero(self):
        # A step with cost=0 AND empty signals is honest — a local-
        # only step (like post:cert-request's cert validation) or an
        # attacker-side action with no target-visible signals. The
        # lint should NOT flag it.
        from fieldkit import chainlint
        from fieldkit.chain import Chain, Step, Outcome, DetectionSignal
        def _act(*_):
            return Outcome(kind="ok", evidence="fake")
        rpc = DetectionSignal(kind="rpc-call", identifier="fake", count=1)
        def _honest(target):
            return Chain(profile="lint-honest-zero", target=target, steps=(
                Step(name="preflight:reachability", kind="preflight",
                     action=_act, detection_cost=0, signals=(rpc,)),
                Step(name="local-validation", kind="attacker-side",
                     action=_act, detection_cost=0),   # cost=0, empty ok
            ))
        _register_synthetic(self, "lint-honest-zero", _honest)
        fs = chainlint.audit_profile("lint-honest-zero")
        no_sig = [f for f in fs if f.code == "no-signals"]
        self.assertEqual(no_sig, [],
                         "cost=0 + empty signals should not warn")

    def test_coerce_without_rpc_signal_surfaces_warning(self):
        from fieldkit import chainlint
        from fieldkit.chain import Chain, Step, Outcome, DetectionSignal
        def _act(*_):
            return Outcome(kind="ok", evidence="fake")
        rpc = DetectionSignal(kind="rpc-call", identifier="fake", count=1)
        smb = DetectionSignal(kind="smb-conn", identifier="0.0.0.0", count=1)
        def _wrong(target):
            return Chain(profile="lint-coerce-smb", target=target, steps=(
                Step(name="preflight:reachability", kind="preflight",
                     action=_act, detection_cost=0, signals=(rpc,)),
                # coerce:* with only smb-conn — missing rpc-call
                Step(name="coerce:smb-only", kind="target-side",
                     action=_act, detection_cost=1, signals=(smb,)),
            ))
        _register_synthetic(self, "lint-coerce-smb", _wrong)
        fs = chainlint.audit_profile("lint-coerce-smb")
        codes = [f.code for f in fs]
        self.assertIn("coerce-without-rpc-signal", codes)


class AllProfilesTest(unittest.TestCase):
    """Audit the live shipped catalog. These are honest pins of the
    current state — they document what the lint SHOULD find without
    passing/failing based on total finding count."""

    def test_audit_all_returns_list(self):
        from fieldkit import chainlint
        fs = chainlint.audit_all()
        self.assertIsInstance(fs, list)

    def test_shipped_catalog_is_clean(self):
        # Stronger pin than "no errors" — after C12 slice 1, the
        # shipped catalog has ZERO findings (errors OR warnings).
        # Regressing this means either a real gap was introduced or
        # the lint became noisier; either warrants a look.
        # Scoped to shipped-in-source profiles because other tests
        # may register synthetic profiles that leak into the process
        # registry.
        from fieldkit import chainlint
        shipped = {"esc8", "rbcd", "smb-relay-exec", "esc1"}
        fs = [f for f in chainlint.audit_all() if f.profile in shipped]
        self.assertEqual(fs, [], f"shipped catalog has findings: {fs}")

    def test_summarize_matches_findings(self):
        from fieldkit import chainlint
        shipped = ["esc8", "rbcd", "smb-relay-exec", "esc1"]
        fs = [f for name in shipped for f in chainlint.audit_profile(name)]
        ok, warn, err = chainlint.summarize(fs, shipped)
        self.assertEqual(ok + warn + err, len(shipped))


class CLITest(unittest.TestCase):

    def _run(self, argv):
        from fieldkit.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(argv)
        buf = io.StringIO()
        errbuf = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(errbuf):
            code = args.func(args)
        return code, buf.getvalue(), errbuf.getvalue()

    def test_lint_returns_1_when_only_warnings(self):
        # Register a synthetic profile with a warnings-only defect
        # (no-signals on a cost>0 step) and scope the lint to it.
        # Not using a shipped profile — after C12 slice 1, all four
        # shipped profiles are clean.
        from fieldkit.chain import Chain, Step, Outcome, DetectionSignal
        rpc = DetectionSignal(kind="rpc-call", identifier="fake", count=1)
        def _act(*_):
            return Outcome(kind="ok", evidence="fake")
        def _warn(target):
            return Chain(profile="lint-cli-warn", target=target, steps=(
                Step(name="preflight:reachability", kind="preflight",
                     action=_act, detection_cost=0, signals=(rpc,)),
                Step(name="silent", kind="attacker-side",
                     action=_act, detection_cost=2),
            ))
        _register_synthetic(self, "lint-cli-warn", _warn)
        code, out, _ = self._run(["chain", "lint",
                                    "--profile", "lint-cli-warn"])
        self.assertEqual(code, 1)
        self.assertIn("chain lint:", out)
        self.assertIn("summary:", out)
        self.assertIn("no-signals", out)

    def test_lint_scoped_to_esc1_returns_0(self):
        # esc1 has full signal coverage → no findings → exit 0
        code, out, _ = self._run(["chain", "lint", "--profile", "esc1"])
        self.assertEqual(code, 0)
        self.assertIn("esc1", out)
        self.assertIn("no findings", out)

    def test_lint_unknown_profile_returns_2(self):
        code, _, err = self._run(["chain", "lint", "--profile", "not-a-profile"])
        self.assertEqual(code, 2)
        self.assertIn("unknown", err)

    def test_lint_json_output_parses(self):
        # --json emits a single parseable JSON object with profiles,
        # findings, summary. Scope to a clean shipped profile so
        # the assertions don't depend on registry pollution.
        import json as _json
        code, out, _ = self._run(["chain", "lint",
                                    "--profile", "esc1", "--json"])
        self.assertEqual(code, 0)
        doc = _json.loads(out)
        self.assertEqual(doc["profiles"], ["esc1"])
        self.assertEqual(doc["findings"], [])
        self.assertEqual(doc["summary"], {"ok": 1, "warn": 0, "err": 0})

    def test_lint_json_output_carries_findings(self):
        # Register a synthetic profile with a warning; --json output
        # should include the finding with all its structured fields.
        import json as _json
        from fieldkit.chain import Chain, Step, Outcome, DetectionSignal
        rpc = DetectionSignal(kind="rpc-call", identifier="fake", count=1)
        def _act(*_):
            return Outcome(kind="ok", evidence="fake")
        def _warn(target):
            return Chain(profile="lint-json-warn", target=target, steps=(
                Step(name="preflight:reachability", kind="preflight",
                     action=_act, detection_cost=0, signals=(rpc,)),
                Step(name="silent", kind="attacker-side",
                     action=_act, detection_cost=2),
            ))
        _register_synthetic(self, "lint-json-warn", _warn)
        code, out, _ = self._run(["chain", "lint",
                                    "--profile", "lint-json-warn",
                                    "--json"])
        self.assertEqual(code, 1)
        doc = _json.loads(out)
        self.assertEqual(len(doc["findings"]), 1)
        f = doc["findings"][0]
        self.assertEqual(f["code"], "no-signals")
        self.assertEqual(f["severity"], "warning")
        self.assertEqual(f["step_index"], 1)
        self.assertEqual(f["step_name"], "silent")
        self.assertIn("detection_cost", f["message"])
        self.assertEqual(doc["summary"], {"ok": 0, "warn": 1, "err": 0})

    def test_lint_json_error_returns_2(self):
        import json as _json
        from fieldkit.chain import Chain
        def _empty(target):
            return Chain(profile="lint-json-err", target=target, steps=())
        _register_synthetic(self, "lint-json-err", _empty)
        code, out, _ = self._run(["chain", "lint",
                                    "--profile", "lint-json-err",
                                    "--json"])
        self.assertEqual(code, 2)
        doc = _json.loads(out)
        self.assertEqual(doc["summary"]["err"], 1)
        self.assertEqual(doc["findings"][0]["code"], "empty-catalog")

    def test_lint_with_synthetic_error_returns_2(self):
        # Register a profile that will trip an error, run scoped
        # lint against it → exit 2.
        from fieldkit.chain import Chain
        def _empty(target):
            return Chain(profile="lint-cli-err", target=target, steps=())
        _register_synthetic(self, "lint-cli-err", _empty)
        code, out, _ = self._run(["chain", "lint",
                                    "--profile", "lint-cli-err"])
        self.assertEqual(code, 2)
        self.assertIn("empty-catalog", out)


if __name__ == "__main__":
    unittest.main()
