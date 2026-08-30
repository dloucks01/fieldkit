#!/usr/bin/env python3
"""Report per-host cover section — condensed host-centric writeup.

Rendered between the severity "at a glance" tables and the full
per-finding writeups, so a reader who cares about "what happened
on host X" doesn't need to page through every finding to find
out. Pins:

  * empty findings + observations → helper renders nothing;
  * unspecified-host entries excluded (empty host label filtered);
  * multi-host engagement renders one section per real host;
  * highest-severity picked from proven findings when both present;
  * finding numbering matches the later per-finding sections;
  * host-scoped recovered creds surface via source-string match;
  * observation-only host still renders with "unconfirmed" tag;
  * severity ordering — worst host first.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _mk_finding(*, title, sev, vector_type="local_priv_esc",
                 host, proven=True, reached_via=None):
    """Build a minimal finding dict — same shape build() produces."""
    return {
        "title": title,
        "severity": sev,
        "vector_type": vector_type,
        "affected_host": host,
        "ip": host.split(" ")[0] if " " in host else host,
        "hostname": "",
        "proven": proven,
        "evidence": "e",
        "steps": [{"cmd": "true", "output": "ok"}],
        "artifacts": [],
        "reached_via": reached_via,
        "related_ttps": [],
    }


def _render(engagement, findings):
    from fieldkit.report import render_markdown
    return render_markdown(engagement, findings)


class EmptyTest(unittest.TestCase):

    def test_no_findings_or_observations_omits_section(self):
        md = _render({"client": "c", "date": "2026-01-01",
                       "scope": "s", "targets": []}, [])
        self.assertNotIn("Per-host summary", md)


class BasicRenderingTest(unittest.TestCase):

    def test_single_host_renders_section(self):
        f = _mk_finding(title="ADCS ESC1", sev="Critical",
                          host="10.0.0.5 (dc01, windows)")
        md = _render({"client": "c", "date": "2026-01-01",
                       "scope": "s", "targets": []}, [f])
        self.assertIn("# Per-host summary", md)
        self.assertIn("### 10.0.0.5 (dc01, windows)", md)
        self.assertIn("Highest proven severity:** Critical", md)
        self.assertIn("Findings proven:** 1", md)

    def test_multi_host_renders_one_section_each(self):
        fs = [
            _mk_finding(title="A", sev="Critical",
                          host="10.0.0.5 (dc01, windows)"),
            _mk_finding(title="B", sev="Medium",
                          host="10.0.0.7 (fs01, windows)"),
        ]
        md = _render({"client": "c", "date": "2026-01-01",
                       "scope": "s", "targets": []}, fs)
        self.assertIn("### 10.0.0.5 (dc01, windows)", md)
        self.assertIn("### 10.0.0.7 (fs01, windows)", md)

    def test_unspecified_host_excluded(self):
        f = _mk_finding(title="ghost", sev="High",
                          host="(unspecified host)")
        md = _render({"client": "c", "date": "2026-01-01",
                       "scope": "s", "targets": []}, [f])
        # The empty-host entry doesn't get a per-host section
        self.assertNotIn("### (unspecified host)", md)

    def test_severity_worst_host_first(self):
        # Critical host should render before Medium host
        fs = [
            _mk_finding(title="med", sev="Medium",
                          host="10.0.0.7 (fs01, windows)"),
            _mk_finding(title="crit", sev="Critical",
                          host="10.0.0.5 (dc01, windows)"),
        ]
        md = _render({"client": "c", "date": "2026-01-01",
                       "scope": "s", "targets": []}, fs)
        i_crit = md.index("### 10.0.0.5")
        i_med = md.index("### 10.0.0.7")
        self.assertLess(i_crit, i_med)


class ObservationsTest(unittest.TestCase):

    def test_observation_only_host_renders_with_unconfirmed_tag(self):
        f = _mk_finding(title="weak-acl", sev="Medium",
                          host="10.0.0.9 (ws01, windows)",
                          proven=False)
        md = _render({"client": "c", "date": "2026-01-01",
                       "scope": "s", "targets": []}, [f])
        self.assertIn("### 10.0.0.9 (ws01, windows)", md)
        self.assertIn("Highest observation severity:** Medium", md)
        self.assertIn("(unconfirmed)", md)
        # Proven count = 0, observations = 1
        # The per-host section should show 1 observation row.
        seg = md.split("### 10.0.0.9")[1].split("###")[0]
        self.assertIn("observation", seg)

    def test_mixed_host_shows_both_counts(self):
        fs = [
            _mk_finding(title="crit", sev="Critical",
                          host="10.0.0.5 (dc01, windows)"),
            _mk_finding(title="obs1", sev="Low",
                          host="10.0.0.5 (dc01, windows)",
                          proven=False),
        ]
        md = _render({"client": "c", "date": "2026-01-01",
                       "scope": "s", "targets": []}, fs)
        seg = md.split("### 10.0.0.5")[1].split("###")[0]
        self.assertIn("Findings proven:** 1", seg)
        self.assertIn("Observations:** 1", seg)


class ReachedViaTest(unittest.TestCase):

    def test_reached_via_recovered_shows_source(self):
        f = _mk_finding(
            title="A", sev="High",
            host="10.0.0.5 (dc01, windows)",
            reached_via={"principal": "CORP\\svc_x",
                          "method": "smb", "admin": True,
                          "source": "kerberoast"})
        md = _render({"client": "c", "date": "2026-01-01",
                       "scope": "s", "targets": []}, [f])
        seg = md.split("### 10.0.0.5")[1].split("###")[0]
        self.assertIn("Reached via:", seg)
        self.assertIn("CORP\\svc_x", seg)
        self.assertIn("(admin)", seg)
        self.assertIn("recovered", seg)
        self.assertIn("kerberoast", seg)

    def test_reached_via_manual_shows_operator_provided(self):
        f = _mk_finding(
            title="A", sev="High",
            host="10.0.0.5 (dc01, windows)",
            reached_via={"principal": "svc_x", "method": "smb",
                          "admin": False, "source": "manual"})
        md = _render({"client": "c", "date": "2026-01-01",
                       "scope": "s", "targets": []}, [f])
        seg = md.split("### 10.0.0.5")[1].split("###")[0]
        self.assertIn("operator-provided", seg)


class RecoveredCredsTest(unittest.TestCase):

    def test_creds_with_matching_source_surface_per_host(self):
        f = _mk_finding(title="A", sev="High",
                          host="10.0.0.5 (dc01, windows)")
        eng = {
            "client": "c", "date": "2026-01-01", "scope": "s",
            "targets": [],
            "recovered_credentials": [
                {"principal": "CORP\\admin", "kind": "NT hash",
                 "source": "dumped-hive:10.0.0.5"},
                {"principal": "svc_x", "kind": "kerberos",
                 "source": "kerberoast"},
            ],
        }
        md = _render(eng, [f])
        # Slice from this host's section start to the end of the
        # per-host block (marked by the "# Findings (proven)"
        # header). Splitting on "---" collides with the "|---|"
        # separators of markdown tables.
        seg = md.split("### 10.0.0.5")[1].split("# Findings")[0]
        # 10.0.0.5 matches "dumped-hive:10.0.0.5" but not
        # "kerberoast" — first cred should appear in the host
        # section, second should not.
        self.assertIn("Recovered on this host:", seg)
        self.assertIn("CORP\\admin", seg)
        # svc_x has no host-substring match — the general table
        # at the bottom of the report still shows it, but not in
        # this host's block.
        self.assertNotIn("svc_x", seg)


class FindingNumberingTest(unittest.TestCase):
    """Per-host finding numbers must match the numbering used in
    the later per-finding sections."""

    def test_numbering_matches_per_finding_section(self):
        fs = [
            _mk_finding(title="A", sev="Critical",
                          host="10.0.0.5 (dc01, windows)"),
            _mk_finding(title="B", sev="High",
                          host="10.0.0.7 (fs01, windows)"),
            _mk_finding(title="C", sev="Medium",
                          host="10.0.0.5 (dc01, windows)"),
        ]
        md = _render({"client": "c", "date": "2026-01-01",
                       "scope": "s", "targets": []}, fs)
        # Per-finding writeup uses "Finding N. Title" — numbers
        # 1, 2, 3 in original order.
        self.assertIn("## Finding 1. A", md)
        self.assertIn("## Finding 2. B", md)
        self.assertIn("## Finding 3. C", md)
        # Per-host section should list the same numbers in its
        # table rows.
        seg_dc = md.split("### 10.0.0.5 (dc01, windows)")[1].split("###")[0]
        # dc01 owns findings 1 (A) and 3 (C)
        self.assertIn("| 1 | A |", seg_dc)
        self.assertIn("| 3 | C |", seg_dc)
        seg_fs = md.split("### 10.0.0.7 (fs01, windows)")[1].split("###")[0]
        # fs01 owns finding 2 (B)
        self.assertIn("| 2 | B |", seg_fs)


if __name__ == "__main__":
    unittest.main()
