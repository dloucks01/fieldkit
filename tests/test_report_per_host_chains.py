#!/usr/bin/env python3
"""Report per-host summary — chain-history cross-reference.

C12 slice 5. When any recorded chain targeted a host in the
per-host summary, cite the chain (id, profile, target, status,
debt) in that host's block. Ties the report's separately-rendered
chain-history section to the per-host block so a reader answering
"what happened on X" sees both the finding writeups and the
chain runs that targeted X.

Pins:

  * no chain_history → per-host block unchanged;
  * chain targeting the host by IP → cited in that host's block;
  * chain targeting a different host → NOT cited;
  * multiple chains on same host → all cited, ordered as passed;
  * proven / in_progress / aborted status all render;
  * aborted chains show the aborted_reason;
  * cross-ref only fires when per-host summary renders at all
    (no findings → no summary → no cross-ref).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _mk_finding(*, title, sev, host, proven=True):
    return {
        "title": title,
        "severity": sev,
        "vector_type": "local_priv_esc",
        "affected_host": host,
        "ip": host.split(" ")[0] if " " in host else host,
        "hostname": "",
        "proven": proven,
        "evidence": "e",
        "steps": [{"cmd": "true", "output": "ok"}],
        "artifacts": [],
        "reached_via": None,
        "related_ttps": [],
    }


def _render(engagement, findings):
    from fieldkit.report import render_markdown
    return render_markdown(engagement, findings)


class NoChainHistoryTest(unittest.TestCase):

    def test_no_chains_omits_cross_ref(self):
        f = _mk_finding(title="A", sev="High",
                          host="10.0.0.5 (dc01, windows)")
        md = _render({"client": "c", "date": "2026-01-01",
                       "scope": "s", "targets": []}, [f])
        # Per-host section renders but no chain cross-ref.
        seg = md.split("### 10.0.0.5")[1].split("# Findings")[0]
        self.assertNotIn("Chains targeting", seg)


class MatchingChainTest(unittest.TestCase):

    def test_chain_targeting_host_ip_is_cited(self):
        f = _mk_finding(title="A", sev="High",
                          host="10.0.0.5 (dc01, windows)")
        eng = {
            "client": "c", "date": "2026-01-01", "scope": "s",
            "targets": [],
            "chain_history": [
                {"id": 12, "profile": "esc8", "target": "10.0.0.5",
                 "status": "proven", "detection_debt": 9,
                 "aborted_reason": "", "started_at": "", "steps": []},
            ],
        }
        md = _render(eng, [f])
        seg = md.split("### 10.0.0.5")[1].split("# Findings")[0]
        self.assertIn("Chains targeting this host:", seg)
        self.assertIn("Chain #12", seg)
        self.assertIn("esc8", seg)
        self.assertIn("proven", seg)
        self.assertIn("detection debt 9", seg)

    def test_chain_targeting_hostname_is_cited(self):
        f = _mk_finding(title="A", sev="High",
                          host="10.0.0.5 (dc01, windows)")
        eng = {
            "client": "c", "date": "2026-01-01", "scope": "s",
            "targets": [],
            "chain_history": [
                # target is the hostname, not the IP
                {"id": 13, "profile": "rbcd", "target": "dc01",
                 "status": "in_progress", "detection_debt": 5,
                 "aborted_reason": "", "started_at": "", "steps": []},
            ],
        }
        md = _render(eng, [f])
        seg = md.split("### 10.0.0.5")[1].split("# Findings")[0]
        self.assertIn("Chain #13", seg)
        self.assertIn("in_progress", seg)


class NonMatchingChainTest(unittest.TestCase):

    def test_chain_on_different_host_not_cited(self):
        f = _mk_finding(title="A", sev="High",
                          host="10.0.0.5 (dc01, windows)")
        eng = {
            "client": "c", "date": "2026-01-01", "scope": "s",
            "targets": [],
            "chain_history": [
                {"id": 44, "profile": "esc8", "target": "10.0.0.9",
                 "status": "proven", "detection_debt": 9,
                 "aborted_reason": "", "started_at": "", "steps": []},
            ],
        }
        md = _render(eng, [f])
        seg = md.split("### 10.0.0.5")[1].split("# Findings")[0]
        self.assertNotIn("Chain #44", seg)


class MultipleChainsTest(unittest.TestCase):

    def test_multiple_chains_on_same_host_all_cited(self):
        f = _mk_finding(title="A", sev="High",
                          host="10.0.0.5 (dc01, windows)")
        eng = {
            "client": "c", "date": "2026-01-01", "scope": "s",
            "targets": [],
            "chain_history": [
                {"id": 12, "profile": "esc8", "target": "10.0.0.5",
                 "status": "proven", "detection_debt": 9,
                 "aborted_reason": "", "started_at": "", "steps": []},
                {"id": 13, "profile": "esc1", "target": "10.0.0.5",
                 "status": "aborted", "detection_debt": 3,
                 "aborted_reason": "step 'exploit:esc1-enroll' returned fail: bad template",
                 "started_at": "", "steps": []},
            ],
        }
        md = _render(eng, [f])
        seg = md.split("### 10.0.0.5")[1].split("# Findings")[0]
        self.assertIn("Chain #12", seg)
        self.assertIn("Chain #13", seg)


class AbortedChainTest(unittest.TestCase):

    def test_aborted_chain_shows_reason(self):
        f = _mk_finding(title="A", sev="High",
                          host="10.0.0.5 (dc01, windows)")
        eng = {
            "client": "c", "date": "2026-01-01", "scope": "s",
            "targets": [],
            "chain_history": [
                {"id": 20, "profile": "rbcd", "target": "10.0.0.5",
                 "status": "aborted", "detection_debt": 4,
                 "aborted_reason": "step 'relay:capture' returned fail: no auth caught within timeout",
                 "started_at": "", "steps": []},
            ],
        }
        md = _render(eng, [f])
        seg = md.split("### 10.0.0.5")[1].split("# Findings")[0]
        self.assertIn("Chain #20", seg)
        self.assertIn("aborted", seg)
        self.assertIn("no auth caught within timeout", seg)


class ScopeTest(unittest.TestCase):

    def test_no_findings_omits_entire_per_host_summary(self):
        # Cross-ref only fires when per-host summary renders.
        # With no findings, the section is skipped entirely.
        eng = {
            "client": "c", "date": "2026-01-01", "scope": "s",
            "targets": [],
            "chain_history": [
                {"id": 5, "profile": "esc8", "target": "10.0.0.5",
                 "status": "proven", "detection_debt": 9,
                 "aborted_reason": "", "started_at": "", "steps": []},
            ],
        }
        md = _render(eng, [])
        self.assertNotIn("# Per-host summary", md)
        # Chain history still renders in its own section
        self.assertIn("# Coerce chain history", md)


if __name__ == "__main__":
    unittest.main()
