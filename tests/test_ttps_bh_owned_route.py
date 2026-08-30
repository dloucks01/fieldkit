#!/usr/bin/env python3
"""BloodHound owned-set intake — Store-fed HostFacts + TTP surface.

Slice 4 of the 4-slice arc: pipe fieldkit's existing BloodHound
path-finding into the ranked TOP MOVES surface. Before this
slice, `fieldkit bloodhound path` ran in isolation — operators
had to know to check it. Now `fieldkit escalate` on a domain-
joined host with ingested BloodHound data automatically shows
`adroute:bh-owned-to-hv-path` as a route (playbook renders the
walk).

Load-bearing pieces:

  * HostFacts.bh_owned_reaches_hv — new boolean field, populated
    by facts_for via a lazy call to bloodhound.owned_paths().
    Zero-cost when no graph is loaded (bh_node table empty → the
    query returns [] fast).
  * T1078-adroute-bh-owned-to-hv-path.yaml — the new TTP. Gates
    on the flag; playbook composes with the C6 per-edge routes
    (adroute:generic-all-user / writeowner-group / etc.).

Test surface pins:
  * facts_for sets the flag to True when the graph exists AND a
    path is reachable;
  * facts_for defaults to False when no graph is loaded;
  * facts_for stays False when a graph is loaded but no owned
    principal reaches a high-value target;
  * facts_for degrades gracefully on bloodhound import/query
    failure (returns facts with the flag=False, no traceback);
  * the TTP fires iff the flag is True.
"""
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class FactsForBHFlagTest(unittest.TestCase):
    """facts_for populates bh_owned_reaches_hv via lazy bloodhound call."""

    def _make_store(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        from fieldkit.state import Store
        s = Store.create(os.path.join(tmp.name, "e.db"))
        s.init_engagement("test")
        self.addCleanup(s.close)
        return s

    def test_no_graph_loaded_yields_flag_false(self):
        from fieldkit.hostenum import facts_for
        s = self._make_store()
        hid, _ = s.add_host("10.0.0.1", os_name="windows")
        facts = facts_for(s, hid)
        self.assertFalse(facts.bh_owned_reaches_hv)

    def test_graph_but_no_reachable_hv_yields_flag_false(self):
        # bloodhound.owned_paths() returns [] when no owned
        # credential reaches a high-value target — even with a
        # graph loaded.
        from fieldkit.hostenum import facts_for
        from fieldkit import bloodhound as bh_mod
        s = self._make_store()
        hid, _ = s.add_host("10.0.0.1", os_name="windows")
        with patch.object(bh_mod, "owned_paths", return_value=[]):
            facts = facts_for(s, hid)
        self.assertFalse(facts.bh_owned_reaches_hv)

    def test_graph_with_reachable_hv_yields_flag_true(self):
        from fieldkit.hostenum import facts_for
        from fieldkit import bloodhound as bh_mod
        s = self._make_store()
        hid, _ = s.add_host("10.0.0.1", os_name="windows")
        # owned_paths returns a list-of-dicts on success; any non-
        # empty list flips the flag.
        with patch.object(bh_mod, "owned_paths",
                    return_value=[{"owned": "USER@CORP.LOCAL",
                                    "target": "Domain Admins",
                                    "hops": 2}]):
            facts = facts_for(s, hid)
        self.assertTrue(facts.bh_owned_reaches_hv)

    def test_bloodhound_exception_degrades_gracefully(self):
        # If bloodhound.owned_paths raises (e.g. schema mismatch on
        # an in-flight migration), facts_for should return a
        # useable facts object with the flag defaulting to False —
        # not propagate the exception. Every non-BH-gated TTP still
        # works.
        from fieldkit.hostenum import facts_for
        from fieldkit import bloodhound as bh_mod
        s = self._make_store()
        hid, _ = s.add_host("10.0.0.1", os_name="windows")
        with patch.object(bh_mod, "owned_paths",
                    side_effect=RuntimeError("simulated graph read error")):
            facts = facts_for(s, hid)
        self.assertFalse(facts.bh_owned_reaches_hv)
        # And the rest of the facts populated normally.
        self.assertEqual(facts.os, "windows")


class BHOwnedPathTTPTest(unittest.TestCase):
    """The adroute:bh-owned-to-hv-path TTP fires iff the flag is True."""

    def _fire(self, **kw):
        from fieldkit.hostenum import HostFacts, WINDOWS
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        base = dict(os=WINDOWS, user="alice", uid=1000)
        base.update(kw)
        return vectors_for(HostFacts(**base), "10.0.0.7")

    def test_fires_when_flag_set(self):
        vs = self._fire(bh_owned_reaches_hv=True)
        self.assertTrue(any(v.key == "adroute:bh-owned-to-hv-path"
                             for v in vs))

    def test_does_not_fire_when_flag_unset(self):
        vs = self._fire()   # default False
        self.assertFalse(any(v.key == "adroute:bh-owned-to-hv-path"
                              for v in vs))

    def test_ranks_high_read_only_quiet(self):
        # 333 — should top the AD-escalation family on hosts where
        # the flag is set. It's a definitive claim ("path exists")
        # rather than a speculative one ("check for edges").
        vs = self._fire(bh_owned_reaches_hv=True,
                         win_groups={"Domain Users"})
        by_key = {v.key: v for v in vs}
        bh_route = by_key["adroute:bh-owned-to-hv-path"]
        self.assertEqual(bh_route.score, 333)

    def test_ttp_is_windows_only(self):
        # bh-owned-to-hv-path is an AD concept; Linux hosts don't
        # fire it even with the flag artificially set.
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(HostFacts(os=LINUX, user="alice", uid=1000,
                                       bh_owned_reaches_hv=True),
                          "10.0.0.7")
        self.assertFalse(any(v.key == "adroute:bh-owned-to-hv-path"
                              for v in vs))


class EndToEndFactsForToTTPTest(unittest.TestCase):
    """The full pipeline: Store with a BH graph → facts_for populates
    the flag → vectors_for surfaces the TTP. Proves each piece
    hooks into the next."""

    def test_bh_ingest_to_ranked_route(self):
        import tempfile
        from fieldkit.hostenum import facts_for
        from fieldkit.state import Store
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        from fieldkit import bloodhound as bh_mod

        with tempfile.TemporaryDirectory() as tmp:
            s = Store.create(os.path.join(tmp, "e.db"))
            s.init_engagement("test")
            hid, _ = s.add_host("10.0.0.1", os_name="windows",
                                 hostname="WS01")

            # Simulate a graph with a reachable path (mock the
            # owned_paths call — the actual SharpHound ingest +
            # BFS is exercised by test_bloodhound.py already).
            with patch.object(bh_mod, "owned_paths",
                        return_value=[{"owned": "svc@CORP.LOCAL",
                                        "target": "Domain Admins",
                                        "hops": 3}]):
                facts = facts_for(s, hid)

            self.assertTrue(facts.bh_owned_reaches_hv)

            _reset_ttp_cache_for_tests()
            vs = vectors_for(facts, "10.0.0.1")
            bh_route = [v for v in vs
                        if v.key == "adroute:bh-owned-to-hv-path"]
            self.assertEqual(len(bh_route), 1)
            self.assertEqual(bh_route[0].score, 333)
            s.close()


if __name__ == "__main__":
    unittest.main()
