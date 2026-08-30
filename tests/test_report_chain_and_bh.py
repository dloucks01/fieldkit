#!/usr/bin/env python3
"""Report renderer — chain history + BloodHound path sections (C8 slice 2).

Two new report sections land: `## Coerce chain history` (per-chain
step trail + aggregate detection debt) and `## BloodHound — owned →
high-value control paths` (ranked shortest paths). Both are read-
only reporting slots — they surface work fieldkit's chain +
bloodhound modules already did, without changing the finding set.

Test surface pins:

  * build() populates engagement["chain_history"] +
    engagement["bh_paths"] from Store + bloodhound module;
  * both sections render nothing when empty (no chains run, no
    graph ingested) — the report stays clean on minimal
    engagements;
  * both sections render tables + per-chain step trails when
    populated;
  * bloodhound module import failure degrades gracefully to
    empty paths list (report doesn't crash).
"""
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _make_store():
    tmp = tempfile.TemporaryDirectory()
    from fieldkit.state import Store
    s = Store.create(os.path.join(tmp.name, "e.db"))
    s.init_engagement("test-client")
    return s, tmp


class BuildChainHistoryTest(unittest.TestCase):

    def test_no_chains_yields_empty_history(self):
        from fieldkit.report import build
        s, tmp = _make_store()
        try:
            engagement, _ = build(s, {})
            self.assertEqual(engagement["chain_history"], [])
        finally:
            s.close()
            tmp.cleanup()

    def test_walked_chain_appears_in_history_with_trail(self):
        from fieldkit.chain import esc8_chain, Outcome
        from fieldkit.report import build
        s, tmp = _make_store()
        try:
            ch = esc8_chain("10.0.0.1")
            # simulate a full-walk chain — push outcomes AND advance
            # current so the derived status property reports "proven".
            for step in ch.steps:
                ch.outcomes.append(Outcome(kind="ok", evidence=f"{step.name} fired"))
            ch.current = len(ch.steps)
            cid = s.reserve_chain_id(ch)
            s.finalize_chain(cid, ch)

            engagement, _ = build(s, {})
            history = engagement["chain_history"]
            self.assertEqual(len(history), 1)
            entry = history[0]
            self.assertEqual(entry["profile"], "esc8")
            self.assertEqual(entry["target"], "10.0.0.1")
            self.assertEqual(entry["status"], "proven")
            self.assertGreater(entry["detection_debt"], 0)
            self.assertEqual(len(entry["steps"]), len(ch.steps))
            self.assertEqual(entry["steps"][0]["name"],
                              "preflight:reachability")
        finally:
            s.close()
            tmp.cleanup()

    def test_multiple_chains_appear_newest_first(self):
        from fieldkit.chain import esc8_chain, Outcome
        from fieldkit.report import build
        s, tmp = _make_store()
        try:
            for target in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
                ch = esc8_chain(target)
                for step in ch.steps:
                    ch.outcomes.append(Outcome(kind="ok", evidence=""))
                cid = s.reserve_chain_id(ch)
                s.finalize_chain(cid, ch)
            engagement, _ = build(s, {})
            targets = [c["target"] for c in engagement["chain_history"]]
            # Store.chains() returns newest-first (largest id first);
            # reserve_chain_id insertion order → 10.0.0.3 is newest.
            self.assertEqual(targets, ["10.0.0.3", "10.0.0.2", "10.0.0.1"])
        finally:
            s.close()
            tmp.cleanup()


class BuildBHPathsTest(unittest.TestCase):

    def test_no_graph_yields_empty_paths(self):
        from fieldkit.report import build
        s, tmp = _make_store()
        try:
            engagement, _ = build(s, {})
            self.assertEqual(engagement["bh_paths"], [])
        finally:
            s.close()
            tmp.cleanup()

    def test_bh_paths_populated_from_bloodhound_module(self):
        from fieldkit.report import build
        from fieldkit import bloodhound as bh_mod
        s, tmp = _make_store()
        try:
            fake_paths = [
                {"owned": "svc@CORP.LOCAL", "target": "Domain Admins",
                 "hops": 2},
                {"owned": "web@CORP.LOCAL", "target": "Enterprise Admins",
                 "hops": 4},
            ]
            with patch.object(bh_mod, "owned_paths", return_value=fake_paths):
                engagement, _ = build(s, {})
            self.assertEqual(engagement["bh_paths"], fake_paths)
        finally:
            s.close()
            tmp.cleanup()

    def test_bh_module_exception_degrades_to_empty_list(self):
        # A schema mismatch during migration in the bloodhound query
        # should NOT crash the report renderer. Empty paths list +
        # section renders as absent — same as no graph ingested.
        from fieldkit.report import build
        from fieldkit import bloodhound as bh_mod
        s, tmp = _make_store()
        try:
            with patch.object(bh_mod, "owned_paths",
                              side_effect=RuntimeError("simulated")):
                engagement, _ = build(s, {})
            self.assertEqual(engagement["bh_paths"], [])
        finally:
            s.close()
            tmp.cleanup()


class RenderChainHistoryTest(unittest.TestCase):

    def test_empty_history_produces_no_section(self):
        from fieldkit.report import _render_chain_history
        L = []
        _render_chain_history(L.append, [])
        self.assertEqual(L, [])

    def test_history_renders_summary_table_and_per_chain_trail(self):
        from fieldkit.report import _render_chain_history
        L = []
        chains = [
            {
                "id": 1, "profile": "esc8", "target": "10.0.0.1",
                "status": "proven", "detection_debt": 47,
                "aborted_reason": "", "started_at": "2026-08-29T12:00:00+00:00",
                "steps": [
                    {"name": "preflight:reachability", "kind": "preflight",
                     "outcome": "ok", "cost": 1, "evidence": "tcp reachable"},
                    {"name": "post:dcsync", "kind": "attacker-side",
                     "outcome": "ok", "cost": 17, "evidence": "DCSync ok — 42 accounts"},
                ],
            }
        ]
        _render_chain_history(L.append, chains)
        output = "\n".join(L)
        # Section header + summary table + per-chain trail.
        self.assertIn("# Coerce chain history", output)
        self.assertIn("| # | Profile |", output)   # summary
        self.assertIn("| 1 | `esc8` |", output)
        self.assertIn("### Chain #1 — esc8 against 10.0.0.1", output)
        self.assertIn("Detection debt: 47", output)
        self.assertIn("`post:dcsync`", output)
        self.assertIn("**ok**", output)

    def test_history_escapes_pipes_in_evidence(self):
        # Evidence text containing | breaks Markdown tables — the
        # renderer must escape.
        from fieldkit.report import _render_chain_history
        L = []
        chains = [{
            "id": 1, "profile": "esc8", "target": "10.0.0.1",
            "status": "proven", "detection_debt": 1,
            "aborted_reason": "", "started_at": "",
            "steps": [{"name": "s", "kind": "attacker-side",
                       "outcome": "ok", "cost": 1,
                       "evidence": "a | b | c"}],
        }]
        _render_chain_history(L.append, chains)
        output = "\n".join(L)
        # `a | b | c` → `a \| b \| c` in the table row
        self.assertIn("a \\| b \\| c", output)

    def test_history_truncates_long_evidence(self):
        from fieldkit.report import _render_chain_history
        L = []
        long_ev = "x" * 200
        chains = [{
            "id": 1, "profile": "esc8", "target": "10.0.0.1",
            "status": "proven", "detection_debt": 1,
            "aborted_reason": "", "started_at": "",
            "steps": [{"name": "s", "kind": "attacker-side",
                       "outcome": "ok", "cost": 1,
                       "evidence": long_ev}],
        }]
        _render_chain_history(L.append, chains)
        output = "\n".join(L)
        # 77 chars + "..." in the table
        self.assertIn("x" * 77 + "...", output)
        # 200-char raw evidence NOT verbatim in output
        self.assertNotIn("x" * 200, output)


class RenderBHPathsTest(unittest.TestCase):

    def test_empty_paths_produces_no_section(self):
        from fieldkit.report import _render_bh_paths
        L = []
        _render_bh_paths(L.append, [])
        self.assertEqual(L, [])

    def test_paths_render_as_ranked_table(self):
        from fieldkit.report import _render_bh_paths
        L = []
        paths = [
            {"owned": "svc@CORP.LOCAL", "target": "Domain Admins",
             "hops": 2},
            {"owned": "web@CORP.LOCAL", "target": "Enterprise Admins",
             "hops": 4},
        ]
        _render_bh_paths(L.append, paths)
        output = "\n".join(L)
        self.assertIn("# BloodHound", output)
        self.assertIn("| # | Owned principal | High-value target | Hops |", output)
        self.assertIn("`svc@CORP.LOCAL`", output)
        self.assertIn("**Domain Admins**", output)
        self.assertIn("| 2 |", output)   # hops for first path


class FullReportIntegrationTest(unittest.TestCase):
    """render_markdown output includes both new sections when data
    is populated, and stays clean when it isn't."""

    def test_full_render_with_chain_and_bh_data(self):
        from fieldkit.chain import esc8_chain, Outcome
        from fieldkit.report import build, render_markdown
        from fieldkit import bloodhound as bh_mod
        s, tmp = _make_store()
        try:
            ch = esc8_chain("10.0.0.1")
            for step in ch.steps:
                ch.outcomes.append(Outcome(kind="ok", evidence=""))
            cid = s.reserve_chain_id(ch)
            s.finalize_chain(cid, ch)
            fake_paths = [{"owned": "svc@CORP.LOCAL",
                            "target": "Domain Admins", "hops": 3}]
            with patch.object(bh_mod, "owned_paths",
                              return_value=fake_paths):
                engagement, findings = build(s, {})
                md = render_markdown(engagement, findings)
            self.assertIn("# Coerce chain history", md)
            self.assertIn("# BloodHound", md)
            self.assertIn("`esc8`", md)
            self.assertIn("Domain Admins", md)
        finally:
            s.close()
            tmp.cleanup()

    def test_full_render_without_new_data_stays_clean(self):
        from fieldkit.report import build, render_markdown
        s, tmp = _make_store()
        try:
            engagement, findings = build(s, {})
            md = render_markdown(engagement, findings)
            # Sections should NOT appear when their data is empty.
            self.assertNotIn("# Coerce chain history", md)
            self.assertNotIn("# BloodHound", md)
        finally:
            s.close()
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
