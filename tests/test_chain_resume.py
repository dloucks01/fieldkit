#!/usr/bin/env python3
"""Chain resume — pick up an in_progress chain from persisted trail.

Pins:

  * chain.resume raises KeyError on unknown chain id;
  * chain.resume raises ValueError on non-in_progress chains
    (proven/aborted are terminal);
  * chain.resume raises KeyError when the profile has been dropped;
  * chain.resume raises ValueError on profile-drift (persisted step
    name != current profile's step name at that index);
  * a resumed chain is walkable from where the prior walk stopped
    (chain.current == previously-persisted step count);
  * a resumed chain preserves the original started_at;
  * a resumed chain stamps _persisted_id so mid-walk artifact
    writes keep landing on the same chain row;
  * finalize_chain on a resumed walk appends only the new step
    rows (idx >= existing) — no duplicate, no wipe of prior;
  * end-to-end: run 2 steps, stop, resume + run 2 more, chain
    has all 4 outcomes in the store.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _make_store(test_case):
    tmp = tempfile.TemporaryDirectory()
    test_case.addCleanup(tmp.cleanup)
    from fieldkit.state import Store
    s = Store.create(os.path.join(tmp.name, "e.db"))
    s.init_engagement("test-resume")
    test_case.addCleanup(s.close)
    return s


def _make_chain(target="10.0.0.5"):
    from fieldkit.chain import esc8_chain
    return esc8_chain(target)


def _persist_prefix(store, chain, n_steps):
    """Reserve a chain_id and persist the first n outcomes as
    ok, then finalize with status=in_progress so it's resumable."""
    from fieldkit.chain import Outcome
    for i in range(n_steps):
        chain.outcomes.append(Outcome(kind="ok", evidence=f"ok-{i}"))
    chain.current = n_steps
    # Simulate a walker stop mid-way — need in_progress status
    chain.finished_at = None
    # DO NOT set aborted_reason; leaving status property as
    # in_progress
    cid = store.reserve_chain_id(chain)
    store.finalize_chain(cid, chain)
    return cid


class ResumeErrorsTest(unittest.TestCase):

    def test_unknown_chain_id_raises_keyerror(self):
        from fieldkit import chain as chain_mod
        s = _make_store(self)
        with self.assertRaises(KeyError):
            chain_mod.resume(s, 9999)

    def test_proven_chain_is_not_resumable(self):
        from fieldkit import chain as chain_mod
        s = _make_store(self)
        ch = _make_chain()
        # Persist a full walk with ok outcomes → status "proven"
        for step in ch.steps:
            from fieldkit.chain import Outcome
            ch.outcomes.append(Outcome(kind="ok", evidence="ok"))
        ch.current = len(ch.steps)
        cid = s.reserve_chain_id(ch)
        s.finalize_chain(cid, ch)
        # Status should be proven now
        row = s.chain_by_id(cid)
        self.assertEqual(row["status"], "proven")
        with self.assertRaises(ValueError):
            chain_mod.resume(s, cid)

    def test_aborted_chain_is_not_resumable(self):
        from fieldkit import chain as chain_mod
        from fieldkit.chain import Outcome
        s = _make_store(self)
        ch = _make_chain()
        ch.outcomes.append(Outcome(kind="fail", evidence="boom"))
        ch.aborted_reason = "step failed"
        ch.current = 1
        cid = s.reserve_chain_id(ch)
        s.finalize_chain(cid, ch)
        row = s.chain_by_id(cid)
        self.assertEqual(row["status"], "aborted")
        with self.assertRaises(ValueError):
            chain_mod.resume(s, cid)

    def test_dropped_profile_raises_keyerror(self):
        from fieldkit import chain as chain_mod
        s = _make_store(self)
        # Fake a persisted chain row referencing a profile that
        # doesn't exist in the current registry.
        ch = _make_chain()
        cid = _persist_prefix(s, ch, 2)
        # Corrupt the profile column
        s.conn.execute("UPDATE coerce_chain SET profile = 'imaginary' "
                       "WHERE id = ?", (cid,))
        s.conn.commit()
        with self.assertRaises(KeyError):
            chain_mod.resume(s, cid)

    def test_step_drift_raises_valueerror(self):
        from fieldkit import chain as chain_mod
        s = _make_store(self)
        ch = _make_chain()
        cid = _persist_prefix(s, ch, 2)
        # Corrupt the persisted step_name so it no longer matches
        # the live profile's step at that index.
        s.conn.execute(
            "UPDATE chain_step SET step_name = 'gone-step' "
            "WHERE chain_id = ? AND idx = 0", (cid,))
        s.conn.commit()
        with self.assertRaises(ValueError):
            chain_mod.resume(s, cid)


class ResumeReconstructionTest(unittest.TestCase):

    def test_resumed_chain_current_equals_persisted_count(self):
        from fieldkit import chain as chain_mod
        s = _make_store(self)
        ch = _make_chain()
        cid = _persist_prefix(s, ch, 3)
        r = chain_mod.resume(s, cid)
        self.assertEqual(r.current, 3)
        self.assertEqual(len(r.outcomes), 3)

    def test_resumed_chain_preserves_started_at(self):
        from fieldkit import chain as chain_mod
        s = _make_store(self)
        ch = _make_chain()
        ch.started_at = "2026-01-15T10:00:00+00:00"
        cid = _persist_prefix(s, ch, 2)
        r = chain_mod.resume(s, cid)
        self.assertEqual(r.started_at, "2026-01-15T10:00:00+00:00")

    def test_resumed_chain_stamps_persisted_id(self):
        from fieldkit import chain as chain_mod
        s = _make_store(self)
        ch = _make_chain()
        cid = _persist_prefix(s, ch, 2)
        r = chain_mod.resume(s, cid)
        self.assertEqual(r._persisted_id, cid)

    def test_resumed_chain_uses_current_profile_step_catalog(self):
        # The reconstructed chain uses the CURRENT factory's step
        # catalog, so any updated signals cost applies to remaining
        # steps.
        from fieldkit import chain as chain_mod
        s = _make_store(self)
        ch = _make_chain()
        cid = _persist_prefix(s, ch, 2)
        r = chain_mod.resume(s, cid)
        # Same profile → same step count
        self.assertEqual(len(r.steps), len(ch.steps))
        # First 2 outcomes seeded; steps 2..end will be walked next
        self.assertEqual(r.outcomes[0].kind, "ok")
        self.assertEqual(r.outcomes[0].evidence, "ok-0")


class FinalizeAppendsOnlyNewStepsTest(unittest.TestCase):

    def test_finalize_after_resume_appends_only_new_outcomes(self):
        from fieldkit import chain as chain_mod
        from fieldkit.chain import Outcome
        s = _make_store(self)
        ch = _make_chain()
        cid = _persist_prefix(s, ch, 2)
        r = chain_mod.resume(s, cid)
        # Simulate walking 2 more steps.
        r.outcomes.append(Outcome(kind="ok", evidence="ok-2"))
        r.outcomes.append(Outcome(kind="ok", evidence="ok-3"))
        r.current = 4
        s.finalize_chain(cid, r)
        # Now the persisted trail should have all 4 outcomes.
        trail = s.chain_step_trail(cid)
        self.assertEqual(len(trail), 4)
        # And no duplicate first 2 (idx 0, 1 kept exactly once each)
        idxs = [t["idx"] for t in trail]
        self.assertEqual(sorted(idxs), [0, 1, 2, 3])
        # First 2 evidence strings unchanged
        self.assertEqual(trail[0]["evidence"], "ok-0")
        self.assertEqual(trail[1]["evidence"], "ok-1")
        # Last 2 evidence strings from the resumed walk
        self.assertEqual(trail[2]["evidence"], "ok-2")
        self.assertEqual(trail[3]["evidence"], "ok-3")


class ArgparseTest(unittest.TestCase):

    def test_chain_resume_subparser_registered(self):
        from fieldkit.cli import build_parser
        parser = build_parser()
        # `fieldkit chain resume 3` should parse cleanly
        args = parser.parse_args(["chain", "resume", "3"])
        self.assertEqual(args.chain_command, "resume")
        self.assertEqual(args.chain_id, 3)


if __name__ == "__main__":
    unittest.main()
