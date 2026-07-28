#!/usr/bin/env python3
"""ADCS — certipy ESC findings parsed and recorded for analyze/report.

Pinned:

  * parse_certipy associates each ESCn with its template/CA and de-dupes;
  * run_find records each ESC as an (unproven) adcs_esc finding via the injected
    runner, and re-running does not duplicate;
  * analyze surfaces the templates as ranked opportunities with the abuse next-step.

Run:  python3 -m unittest discover -s tests
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit.adcs import parse_certipy, run_find  # noqa: E402
from fieldkit.creds import Credential  # noqa: E402
from fieldkit.kb import analyze  # noqa: E402
from fieldkit.runner import RunResult  # noqa: E402
from fieldkit.state import Store  # noqa: E402

CERTIPY = """\
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
Certificate Authorities
  0
    CA Name                             : CORP-CA
    DNS Name                            : dc01.corp.local
    [!] Vulnerabilities
      ESC8                              : Web Enrollment is enabled and Request Disposition is set to Issue
Certificate Templates
  0
    Template Name                       : ESC1-Template
    Display Name                        : ESC1 Template
    [!] Vulnerabilities
      ESC1                              : 'CORP.LOCAL\\\\Domain Users' can enroll, enrollee supplies subject and client auth
  1
    Template Name                       : UserAuth
    [!] Vulnerabilities
      ESC2                              : Template can be used for any purpose
"""


class ParseTest(unittest.TestCase):
    def test_parses_esc_per_target(self):
        vulns = parse_certipy(CERTIPY)
        by = {(v.esc, v.target) for v in vulns}
        self.assertIn(("ESC1", "ESC1-Template"), by)
        self.assertIn(("ESC2", "UserAuth"), by)
        self.assertIn(("ESC8", "CORP-CA"), by)

    def test_ca_name_tracked(self):
        esc1 = [v for v in parse_certipy(CERTIPY) if v.esc == "ESC1"][0]
        self.assertEqual(esc1.ca, "CORP-CA")

    def test_dedup(self):
        self.assertEqual(len(parse_certipy(CERTIPY + CERTIPY)), len(parse_certipy(CERTIPY)))

    def test_empty(self):
        self.assertEqual(parse_certipy("no PKI found"), [])


class RunFindTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME")
        self.dc_id, _ = self.store.add_host("10.0.0.10", hostname="DC01", is_dc=True,
                                            os_name="windows")
        cid, _ = self.store.add_credential(Credential("jdoe", "pw", domain="corp.local"))
        self.dc = self.store.host_by_ip("10.0.0.10")
        self.cred = self.store.credential_by_id(cid)

    def runner(self):
        return lambda argv, env=None: RunResult(argv, 0, stdout=CERTIPY)

    def test_records_findings(self):
        rep = run_find(self.store, self.dc, self.cred, run=self.runner())
        self.assertIsNone(rep.aborted)
        self.assertEqual(rep.found, 3)
        vts = [f["vector_type"] for f in self.store.findings()]
        self.assertEqual(vts, ["adcs_esc"] * 3)

    def test_certipy_argv_uses_upn_and_password(self):
        captured = {}

        def run(argv, env=None):
            captured["argv"] = argv
            return RunResult(argv, 0, stdout=CERTIPY)
        run_find(self.store, self.dc, self.cred, run=run)
        self.assertIn("jdoe@corp.local", captured["argv"])
        self.assertIn("-vulnerable", captured["argv"])
        self.assertIn("-p", captured["argv"])

    def test_rerun_does_not_duplicate(self):
        run_find(self.store, self.dc, self.cred, run=self.runner())
        rep = run_find(self.store, self.dc, self.cred, run=self.runner())
        self.assertEqual(rep.found, 0)
        self.assertEqual(len(self.store.findings()), 3)

    def test_analyze_surfaces_adcs(self):
        run_find(self.store, self.dc, self.cred, run=self.runner())
        titles = [o.title for o in analyze(self.store) if o.key.startswith("adcs:")]
        self.assertEqual(len(titles), 3)
        self.assertTrue(any("ESC1" in t for t in titles))

    def test_missing_certipy_aborts(self):
        rep = run_find(self.store, self.dc, self.cred,
                       run=lambda a, env=None: RunResult(a, error="certipy: not found"))
        self.assertIn("not found", rep.aborted)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
