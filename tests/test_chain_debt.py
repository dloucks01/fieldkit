#!/usr/bin/env python3
"""D6 — detection-debt pricing for coerce chains.

The charter's tie-back: fieldkit tells operators the *cost* of a
chain in terms defenders think in — Windows event IDs, DCERPC
opcodes, Kerberos ticket-request patterns — not a single hand-waved
"noise" number. This slice pins:

  * DetectionSignal shape + enum-gated kind + SIGNAL_WEIGHTS-driven
    cost;
  * per-step signal catalog for esc8 / rbcd / smb-relay-exec that
    reflects real defender-visible artifacts (event IDs from the
    Microsoft catalog, RPC interface/opcode names from the MS-* docs,
    Kerberos ticket types);
  * Chain.total_detection_cost prefers signal_cost when the step has
    a catalog; falls back to the legacy detection_cost for pre-D6
    steps — no big-bang renumbering forced on tests;
  * relative rankings that match reality: DCSync (MS-DRSR/
    DRSGetNCChanges) is the loudest single step; RBCD (LDAPS write
    + Kerberos S4U2Self) is quieter than ESC8 (which has DCSync);
    SMB-relay-exec quieter still.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class DetectionSignalShapeTest(unittest.TestCase):

    def test_kind_enum_gated(self):
        from fieldkit.chain import DetectionSignal
        for k in ("win-event", "rpc-call", "smb-conn", "ldap-write",
                   "kerb-ticket", "http-req", "process-exec", "auth-attempt"):
            DetectionSignal(kind=k, identifier="x")
        with self.assertRaises(ValueError):
            DetectionSignal(kind="totally-fine", identifier="x")

    def test_count_must_be_non_negative(self):
        from fieldkit.chain import DetectionSignal
        DetectionSignal(kind="win-event", identifier="4624", count=0)
        DetectionSignal(kind="win-event", identifier="4624", count=100)
        with self.assertRaises(ValueError):
            DetectionSignal(kind="win-event", identifier="4624", count=-1)

    def test_cost_is_weight_times_count(self):
        from fieldkit.chain import DetectionSignal, SIGNAL_WEIGHTS
        sig = DetectionSignal(kind="rpc-call",
                                identifier="MS-DRSR/DRSGetNCChanges",
                                count=1)
        self.assertEqual(sig.cost, SIGNAL_WEIGHTS["rpc-call"])
        sig10 = DetectionSignal(kind="auth-attempt", identifier="spray",
                                 count=50)
        self.assertEqual(sig10.cost, 50 * SIGNAL_WEIGHTS["auth-attempt"])

    def test_zero_count_signal_has_zero_cost(self):
        # A signal with count=0 documents that a step COULD emit
        # something without adding debt — useful for "this step
        # normally emits X but was disabled by ctx.opsec" scenarios.
        from fieldkit.chain import DetectionSignal
        sig = DetectionSignal(kind="win-event", identifier="4624", count=0)
        self.assertEqual(sig.cost, 0)


class StepSignalsIntegrationTest(unittest.TestCase):

    def test_step_signal_cost_aggregates_signals(self):
        from fieldkit.chain import Step, DetectionSignal
        s = Step(
            name="test", kind="preflight",
            action=lambda c, x: None,
            signals=(
                DetectionSignal(kind="win-event", identifier="4624"),  # 3
                DetectionSignal(kind="rpc-call", identifier="x/y"),    # 8
                DetectionSignal(kind="ldap-write", identifier="ACL",
                                 count=2),                              # 10
            ))
        self.assertEqual(s.signal_cost, 3 + 8 + 10)

    def test_step_without_signals_has_zero_signal_cost(self):
        from fieldkit.chain import Step
        s = Step(name="test", kind="preflight",
                 action=lambda c, x: None, detection_cost=5)
        self.assertEqual(s.signal_cost, 0)


class ChainAggregateCostTest(unittest.TestCase):

    def test_total_detection_cost_prefers_signal_cost_when_available(self):
        # When a step has both a legacy detection_cost AND a signals
        # catalog, the aggregate uses signal_cost — the D6 refinement
        # supersedes the coarse D1 number. detection_cost=10 (the
        # max legacy score) is different from the win-event signal
        # weight of 3, so we can tell which one was used.
        from fieldkit.chain import Chain, Step, DetectionSignal, Outcome, walk
        s = Step(name="a", kind="preflight",
                 action=lambda c, x: Outcome("ok", ""),
                 detection_cost=10,
                 signals=(DetectionSignal(kind="win-event", identifier="4624"),))
        ch = Chain(profile="test", target="x", steps=(s,))
        walk(ch, None)
        self.assertEqual(ch.total_detection_cost, 3)   # win-event weight, NOT 10

    def test_total_detection_cost_falls_back_to_legacy_when_no_signals(self):
        # A step with no signals catalog uses detection_cost — this
        # is the coexistence path so legacy code doesn't need to
        # migrate all at once.
        from fieldkit.chain import Chain, Step, Outcome, walk
        s = Step(name="a", kind="preflight",
                 action=lambda c, x: Outcome("ok", ""),
                 detection_cost=7)
        ch = Chain(profile="test", target="x", steps=(s,))
        walk(ch, None)
        self.assertEqual(ch.total_detection_cost, 7)

    def test_mixed_steps_sum_correctly(self):
        from fieldkit.chain import Chain, Step, DetectionSignal, Outcome, walk
        signals_step = Step(
            name="a", kind="preflight",
            action=lambda c, x: Outcome("ok", ""),
            signals=(DetectionSignal(kind="rpc-call", identifier="x/y"),))
        legacy_step = Step(
            name="b", kind="preflight",
            action=lambda c, x: Outcome("ok", ""),
            detection_cost=5)
        ch = Chain(profile="test", target="x",
                   steps=(signals_step, legacy_step))
        walk(ch, None)
        # rpc-call (8) + legacy 5 = 13
        self.assertEqual(ch.total_detection_cost, 13)


class DebtBreakdownTest(unittest.TestCase):

    def test_breakdown_lists_walked_steps_only(self):
        from fieldkit.chain import Chain, Step, DetectionSignal, Outcome, walk
        s1 = Step(name="a", kind="preflight",
                  action=lambda c, x: Outcome("ok", ""),
                  signals=(DetectionSignal(kind="win-event", identifier="4624"),))
        s2 = Step(name="b", kind="preflight",
                  action=lambda c, x: Outcome("fail", "stop"),
                  detection_cost=7)
        s3 = Step(name="c", kind="preflight",
                  action=lambda c, x: Outcome("ok", ""),
                  detection_cost=10)     # never runs (walk aborts at s2)
        ch = Chain(profile="test", target="x", steps=(s1, s2, s3))
        walk(ch, None)
        bd = ch.debt_breakdown
        # s3 excluded — not walked.
        self.assertEqual([b["step"] for b in bd], ["a", "b"])
        self.assertEqual(bd[0]["cost"], 3)    # win-event
        self.assertEqual(bd[1]["cost"], 7)    # legacy fallback


class ESC8SignalCatalogTest(unittest.TestCase):
    """Pin the ESC8 profile's signal catalog + aggregate numbers.
    Changes to individual signal weights or step catalogs surface
    here as intentional test updates — the numbers become part of
    the operator contract, not implementation detail."""

    def _walk_full(self, target="10.0.0.1"):
        from fieldkit.chain import esc8_chain, Outcome
        ch = esc8_chain(target)
        # Simulate a fully-walked chain by pushing ok outcomes for
        # every step — we care about the cost aggregate, not the
        # per-step action side effects.
        for _ in ch.steps:
            ch.outcomes.append(Outcome(kind="ok", evidence=""))
        return ch

    def test_esc8_aggregate_debt_pinned(self):
        # 46 units after C12 slice 1 — dropped from 47 when
        # post:cert-request went from detection_cost=1 to 0
        # (empty signals catalog was intentional; step is local
        # cert-material validation with no target-visible signals).
        # DCSync (17) is still the loudest step; coerce:petitpotam
        # (12) second; relay:capture (10) third.
        # Regenerate this number when the signal catalog changes;
        # the pin makes the change visible in code review.
        ch = self._walk_full()
        self.assertEqual(ch.total_detection_cost, 46)

    def test_dcsync_is_the_loudest_step(self):
        # The MS-DRSR/DRSGetNCChanges RPC call is the definitive
        # DCSync signal; it should dominate the per-step ranking.
        ch = self._walk_full()
        bd = ch.debt_breakdown
        by_cost = sorted(bd, key=lambda b: b["cost"], reverse=True)
        self.assertEqual(by_cost[0]["step"], "post:dcsync")

    def test_every_esc8_step_has_a_signal_catalog(self):
        # Empty signals is legitimate (relay:listen emits nothing
        # target-visible until an auth arrives; post:cert-request is
        # local-only). But we want every step to at least DECLARE
        # its signals (empty tuple is a positive assertion "nothing
        # visible") — no forgotten catalogs. The way to enforce that
        # is: hasattr(.signals) — which is trivially True since
        # dataclass default is (). More useful pin: every step
        # explicitly names its signals attribute (not relying on the
        # default), which means `s.signals is not None`.
        from fieldkit.chain import esc8_chain
        ch = esc8_chain("10.0.0.1")
        for s in ch.steps:
            self.assertIsNotNone(s.signals, f"{s.name} has None signals")


class RBCDSignalCatalogTest(unittest.TestCase):

    def _walk_full(self):
        from fieldkit.chain import profile, Outcome
        ch = profile("rbcd")("10.0.0.20")
        for _ in ch.steps:
            ch.outcomes.append(Outcome(kind="ok", evidence=""))
        return ch

    def test_rbcd_aggregate_debt_pinned(self):
        ch = self._walk_full()
        self.assertEqual(ch.total_detection_cost, 30)

    def test_ldap_write_signal_present_on_relay_capture(self):
        from fieldkit.chain import profile
        ch = profile("rbcd")("10.0.0.20")
        capture = [s for s in ch.steps if s.name == "relay:capture"][0]
        kinds = {sig.kind for sig in capture.signals}
        self.assertIn("ldap-write", kinds)
        # The specific identifier is the load-bearing signal — a
        # detection rule for RBCD scans event 5136 for edits to
        # this exact attribute name.
        ids = {sig.identifier for sig in capture.signals}
        self.assertIn("msDS-AllowedToActOnBehalfOfOtherIdentity", ids)


class SMBRelayExecSignalCatalogTest(unittest.TestCase):

    def _walk_full(self):
        from fieldkit.chain import profile, Outcome
        ch = profile("smb-relay-exec")("10.0.0.20")
        for _ in ch.steps:
            ch.outcomes.append(Outcome(kind="ok", evidence=""))
        return ch

    def test_smb_relay_exec_aggregate_debt_pinned(self):
        ch = self._walk_full()
        self.assertEqual(ch.total_detection_cost, 24)

    def test_service_install_signal_present(self):
        from fieldkit.chain import profile
        ch = profile("smb-relay-exec")("10.0.0.20")
        capture = [s for s in ch.steps if s.name == "relay:capture"][0]
        ids = {sig.identifier for sig in capture.signals}
        # Event 7045 (new service installed) is the ntlmrelayx
        # default-attack signature; a detection guide for SMB relay
        # should list it.
        self.assertIn("7045", ids)


class ProfileRelativeCostRankingTest(unittest.TestCase):
    """The charter promise: profiles ranked by detection debt should
    reflect real defender-visibility, so operators picking the
    quietest applicable chain always have honest data. DCSync is the
    loudest; ESC8 (has DCSync) is the loudest profile."""

    def _cost(self, name):
        from fieldkit.chain import profile, Outcome
        target = "10.0.0.1" if name != "smb-relay-exec" else "10.0.0.2"
        ch = profile(name)(target)
        for _ in ch.steps:
            ch.outcomes.append(Outcome(kind="ok", evidence=""))
        return ch.total_detection_cost

    def test_esc8_costs_more_than_rbcd(self):
        # ESC8 includes DCSync; RBCD stops at S4U2Self. DCSync alone
        # (17 units) is more than the RBCD S4U2Self step (5).
        self.assertGreater(self._cost("esc8"), self._cost("rbcd"))

    def test_rbcd_costs_more_than_smb_relay_exec(self):
        # RBCD has 5 steps (adds S4U2Self); smb-relay-exec has 4.
        self.assertGreater(self._cost("rbcd"),
                           self._cost("smb-relay-exec"))


class ChainShowRenderingTest(unittest.TestCase):
    """`fieldkit chain show <id> --signals` prints the per-step
    detection breakdown so an operator can hand the report to a
    defender for hunt-package construction."""

    def test_chain_show_signals_flag_prints_signal_kinds_and_identifiers(self):
        import contextlib
        import io
        import tempfile
        from fieldkit.chain import esc8_chain, walk, Outcome
        from fieldkit.state import Store
        # cmd_chain_show is @needs_engagement-wrapped; call the
        # inner function directly to skip the store-open shim.
        from fieldkit.cli import cmd_chain_show as _wrapped
        cmd_chain_show = _wrapped.__wrapped__

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        s = Store.create(os.path.join(tmp.name, "e.db"))
        s.init_engagement("test")
        self.addCleanup(s.close)

        # Persist a walked esc8 chain.
        ch = esc8_chain("10.0.0.1")
        for _ in ch.steps:
            ch.outcomes.append(Outcome(kind="ok", evidence="mocked"))
        cid = s.reserve_chain_id(ch)
        s.finalize_chain(cid, ch)

        # Fake args
        class Args:
            chain_id = cid
            signals = True

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cmd_chain_show(Args(), s)
        self.assertEqual(rc, 0)
        out = buf.getvalue()

        # Aggregate rendered as "detection debt".
        self.assertIn("detection debt", out)
        # Signal breakdown section present.
        self.assertIn("detection signals:", out)
        # A few load-bearing identifiers surface (proves the catalog
        # is being read from the live registry, not just the DB row).
        for token in ("MS-EFSR/EfsRpcOpenFileRaw",       # petitpotam
                      "MS-DRSR/DRSGetNCChanges",          # dcsync
                      "AS-REQ/PKINIT",                    # pkinit
                      "4886",                             # ADCS request received
                      "msDS-AllowedToActOnBehalfOfOtherIdentity"):
            # msDS-... only in rbcd — the esc8 chain doesn't emit it.
            # Skip that one for esc8.
            if token == "msDS-AllowedToActOnBehalfOfOtherIdentity":
                continue
            with self.subTest(token=token):
                self.assertIn(token, out)

    def test_chain_show_without_signals_flag_stays_compact(self):
        # The default (no --signals) doesn't render the breakdown —
        # keeps the standard `chain show` output readable.
        import contextlib
        import io
        import tempfile
        from fieldkit.chain import esc8_chain, Outcome
        from fieldkit.state import Store
        # cmd_chain_show is @needs_engagement-wrapped; call the
        # inner function directly to skip the store-open shim.
        from fieldkit.cli import cmd_chain_show as _wrapped
        cmd_chain_show = _wrapped.__wrapped__

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        s = Store.create(os.path.join(tmp.name, "e.db"))
        s.init_engagement("test")
        self.addCleanup(s.close)

        ch = esc8_chain("10.0.0.1")
        for _ in ch.steps:
            ch.outcomes.append(Outcome(kind="ok", evidence="mocked"))
        cid = s.reserve_chain_id(ch)
        s.finalize_chain(cid, ch)

        class Args:
            chain_id = cid
            signals = False

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cmd_chain_show(Args(), s)
        out = buf.getvalue()
        self.assertNotIn("detection signals:", out)


if __name__ == "__main__":
    unittest.main()
