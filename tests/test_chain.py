#!/usr/bin/env python3
"""Coerce chain — D1 skeleton.

Pins the state-machine surface + esc8 profile shape + Store
persistence for chain runs. The primitives themselves (PetitPotam
coerce, ntlmrelayx wrap, post-relay actions) land in D2/D3/D4;
this slice ships the walkable-end-to-end plan so those primitives
have a place to plug in.
"""
import os
import socket
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _open_listener(port_hint=0):
    """Bind an ephemeral listener socket and return (port, close-fn).
    Used to give the reachability probe a real reachable target
    without dependence on the network."""
    s = socket.socket()
    s.bind(("127.0.0.1", port_hint))
    s.listen(1)
    port = s.getsockname()[1]

    def _accept_loop():
        try:
            while True:
                c, _ = s.accept()
                c.close()
        except OSError:
            return
    t = threading.Thread(target=_accept_loop, daemon=True)
    t.start()
    return port, s.close


class OutcomeShapeTest(unittest.TestCase):
    """Outcome + Step are frozen dataclasses with validated kinds."""

    def test_outcome_kinds_are_enum_gated(self):
        from fieldkit.chain import Outcome
        for k in ("ok", "skip", "fail", "manual"):
            Outcome(kind=k, evidence="x")   # no raise
        with self.assertRaises(ValueError):
            Outcome(kind="totally-fine", evidence="x")

    def test_step_kinds_are_enum_gated(self):
        from fieldkit.chain import Step
        for k in ("preflight", "target-side", "attacker-side"):
            Step(name="s", kind=k, action=lambda c, x: None)
        with self.assertRaises(ValueError):
            Step(name="s", kind="unknown", action=lambda c, x: None)

    def test_step_detection_cost_must_be_0_to_10(self):
        from fieldkit.chain import Step
        Step(name="s", kind="preflight", action=lambda c, x: None,
             detection_cost=0)
        Step(name="s", kind="preflight", action=lambda c, x: None,
             detection_cost=10)
        with self.assertRaises(ValueError):
            Step(name="s", kind="preflight", action=lambda c, x: None,
                 detection_cost=-1)
        with self.assertRaises(ValueError):
            Step(name="s", kind="preflight", action=lambda c, x: None,
                 detection_cost=11)


class RegistryTest(unittest.TestCase):

    def test_esc8_is_registered_out_of_the_box(self):
        from fieldkit.chain import known_profiles, profile
        self.assertIn("esc8", known_profiles())
        factory = profile("esc8")
        ch = factory("10.0.0.1")
        self.assertEqual(ch.profile, "esc8")
        self.assertEqual(ch.target, "10.0.0.1")

    def test_unknown_profile_raises(self):
        from fieldkit.chain import profile
        with self.assertRaises(KeyError):
            profile("does-not-exist")

    def test_duplicate_registration_raises(self):
        from fieldkit.chain import register
        # register a first time
        @register("dup-test")
        def _f(t):    # noqa: E306
            from fieldkit.chain import Chain
            return Chain(profile="dup-test", target=t, steps=())
        # register a second time under the same name → refuse
        with self.assertRaises(ValueError):
            @register("dup-test")
            def _g(t):    # noqa: E306
                from fieldkit.chain import Chain
                return Chain(profile="dup-test", target=t, steps=())


class ESC8ProfileTest(unittest.TestCase):

    def test_esc8_has_seven_steps_in_expected_order(self):
        from fieldkit.chain import esc8_chain
        ch = esc8_chain("10.0.0.1")
        names = [s.name for s in ch.steps]
        self.assertEqual(names, [
            "preflight:reachability",
            "coerce:petitpotam",
            "relay:listen",
            "relay:capture",
            "post:cert-request",
            "post:pkinit-tgt",
            "post:dcsync",
        ])

    def test_esc8_step_kinds_match_charter(self):
        # Preflight is safe; coerce hits the target; the rest all
        # run attacker-side (fieldkit host).
        from fieldkit.chain import esc8_chain
        ch = esc8_chain("10.0.0.1")
        by_name = {s.name: s for s in ch.steps}
        self.assertEqual(by_name["preflight:reachability"].kind, "preflight")
        self.assertEqual(by_name["coerce:petitpotam"].kind, "target-side")
        for name in ("relay:listen", "relay:capture", "post:cert-request",
                      "post:pkinit-tgt", "post:dcsync"):
            self.assertEqual(by_name[name].kind, "attacker-side")

    def test_esc8_aggregate_detection_cost_is_9(self):
        # Pin the C12-slice-1 baseline. Dropped from 10 to 9 when
        # post:cert-request went from detection_cost=1 to 0 — that
        # step's a local cert-material validation with zero target-
        # visible signals; the empty SIGNALS_CERT_REQUEST_VALIDATE
        # catalog and cost=0 now match honestly, and `chain lint`
        # stops flagging it. Update when a future slice refines
        # further.
        from fieldkit.chain import esc8_chain
        ch = esc8_chain("10.0.0.1")
        self.assertEqual(sum(s.detection_cost for s in ch.steps), 9)


class WalkerTest(unittest.TestCase):

    def test_walk_stops_at_first_fail_and_records_reason(self):
        from fieldkit.chain import Chain, Step, Outcome, walk

        def _ok(c, x):
            return Outcome(kind="ok", evidence="step-ok")

        def _fail(c, x):
            return Outcome(kind="fail", evidence="broke")

        def _never(c, x):
            raise AssertionError("this step must not run — chain aborted before it")

        ch = Chain(profile="test", target="t",
                   steps=(Step("s1", "preflight", _ok),
                          Step("s2", "preflight", _fail),
                          Step("s3", "preflight", _never)))
        walk(ch, None)
        self.assertEqual(ch.status, "aborted")
        self.assertEqual(len(ch.outcomes), 2)   # s3 skipped
        self.assertIn("broke", ch.aborted_reason)

    def test_walk_advances_through_manual_outcomes(self):
        # Manual outcomes don't abort — the chain plans through, so
        # the trail records the whole handoff picture.
        from fieldkit.chain import Chain, Step, Outcome, walk

        def _manual(c, x):
            return Outcome(kind="manual", evidence="needs operator")

        def _ok(c, x):
            return Outcome(kind="ok", evidence="done")

        ch = Chain(profile="test", target="t",
                   steps=(Step("s1", "preflight", _manual),
                          Step("s2", "preflight", _ok)))
        walk(ch, None)
        self.assertEqual(ch.status, "proven")
        self.assertEqual(len(ch.outcomes), 2)
        self.assertEqual(ch.outcomes[0].kind, "manual")

    def test_walk_catches_action_exceptions_as_fail(self):
        from fieldkit.chain import Chain, Step, walk

        def _boom(c, x):
            raise RuntimeError("intentional")

        ch = Chain(profile="test", target="t",
                   steps=(Step("s1", "preflight", _boom),))
        walk(ch, None)
        self.assertEqual(ch.status, "aborted")
        self.assertIn("RuntimeError", ch.outcomes[0].evidence)

    def test_walk_threads_data_into_artifacts(self):
        # Downstream steps read what upstream produced.
        from fieldkit.chain import Chain, Step, Outcome, walk

        def _make_cert(c, x):
            return Outcome(kind="ok", evidence="", data={"cert": b"MOCK"})

        def _use_cert(c, x):
            assert c.artifacts.get("cert") == b"MOCK"
            return Outcome(kind="ok", evidence="cert consumed")

        ch = Chain(profile="test", target="t",
                   steps=(Step("s1", "preflight", _make_cert),
                          Step("s2", "preflight", _use_cert)))
        walk(ch, None)
        self.assertEqual(ch.status, "proven")

    def test_walk_stamps_started_and_finished(self):
        from fieldkit.chain import Chain, Step, Outcome, walk
        ch = Chain(profile="t", target="x",
                   steps=(Step("s", "preflight", lambda c, x: Outcome("ok", "")),))
        walk(ch, None)
        self.assertIsNotNone(ch.started_at)
        self.assertIsNotNone(ch.finished_at)

    def test_total_detection_cost_sums_walked_steps(self):
        from fieldkit.chain import Chain, Step, Outcome, walk
        ch = Chain(profile="t", target="x",
                   steps=(Step("a", "preflight",
                                lambda c, x: Outcome("ok", ""),
                                detection_cost=2),
                          Step("b", "preflight",
                                lambda c, x: Outcome("fail", "stop"),
                                detection_cost=3),
                          Step("c", "preflight",
                                lambda c, x: Outcome("ok", ""),
                                detection_cost=5)))
        walk(ch, None)
        # a + b walked (cost 2 + 3 = 5); c skipped
        self.assertEqual(ch.total_detection_cost, 5)


class ReachabilityPreflightTest(unittest.TestCase):

    def test_reachable_target_produces_ok_outcome(self):
        from fieldkit.chain import REACHABILITY_STEP, Chain
        port, close = _open_listener()
        try:
            ch = Chain(profile="test", target="127.0.0.1",
                       steps=(REACHABILITY_STEP,))
            class Ctx: probe_port = port; probe_timeout = 1.0    # noqa: E701
            out = REACHABILITY_STEP.action(ch, Ctx())
            self.assertEqual(out.kind, "ok")
            self.assertTrue(out.data["probe"]["ok"])
        finally:
            close()

    def test_unreachable_target_produces_fail_outcome(self):
        from fieldkit.chain import REACHABILITY_STEP, Chain
        ch = Chain(profile="test", target="127.0.0.1",
                   steps=(REACHABILITY_STEP,))
        # Port 1 (echo) is almost never listening on modern hosts.
        class Ctx: probe_port = 1; probe_timeout = 0.3           # noqa: E701
        out = REACHABILITY_STEP.action(ch, Ctx())
        self.assertEqual(out.kind, "fail")


class ChainStorePersistenceTest(unittest.TestCase):

    def _make_store(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        from fieldkit.state import Store
        s = Store.create(os.path.join(tmp.name, "e.db"))
        s.init_engagement("test")
        self.addCleanup(s.close)
        return s

    def test_add_chain_persists_chain_and_step_trail(self):
        from fieldkit.chain import esc8_chain, walk
        class Ctx: probe_port = 1; probe_timeout = 0.3           # noqa: E701
        ch = esc8_chain("127.0.0.1")
        walk(ch, Ctx())     # aborts at reachability step against port 1
        s = self._make_store()
        cid = s.add_chain(ch)
        row = s.chain_by_id(cid)
        self.assertEqual(row["profile"], "esc8")
        self.assertEqual(row["target"], "127.0.0.1")
        self.assertEqual(row["status"], "aborted")
        trail = s.chain_step_trail(cid)
        self.assertEqual(len(trail), 1)
        self.assertEqual(trail[0]["step_name"], "preflight:reachability")
        self.assertEqual(trail[0]["outcome_kind"], "fail")

    def test_chains_lists_newest_first(self):
        from fieldkit.chain import esc8_chain, walk
        class Ctx: probe_port = 1; probe_timeout = 0.3           # noqa: E701
        s = self._make_store()
        ids = []
        for target in ("127.0.0.1", "127.0.0.2", "127.0.0.3"):
            ch = esc8_chain(target)
            walk(ch, Ctx())
            ids.append(s.add_chain(ch))
        listing = s.chains()
        # newest first: reverse insertion order
        self.assertEqual([r["id"] for r in listing], list(reversed(ids)))

    def test_chains_filter_by_profile(self):
        from fieldkit.chain import esc8_chain, walk, register, Chain, Step, Outcome
        class Ctx: probe_port = 1; probe_timeout = 0.3           # noqa: E701

        @register("test-filter-profile")
        def _mk(target):
            return Chain(profile="test-filter-profile", target=target,
                         steps=(Step("ok", "preflight",
                                     lambda c, x: Outcome("ok", "")),))

        s = self._make_store()
        esc = esc8_chain("127.0.0.1")
        walk(esc, Ctx())
        s.add_chain(esc)
        other = _mk("127.0.0.2")
        walk(other, None)
        s.add_chain(other)

        esc_only = s.chains(profile="esc8")
        self.assertEqual([r["profile"] for r in esc_only], ["esc8"])
        other_only = s.chains(profile="test-filter-profile")
        self.assertEqual([r["profile"] for r in other_only],
                         ["test-filter-profile"])


if __name__ == "__main__":
    unittest.main()
