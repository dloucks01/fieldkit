#!/usr/bin/env python3
"""Delegation detection — the three flavors parsed and recorded.

Pinned:

  * parse_delegation maps Unconstrained/Constrained/Resource-Based to the right
    reportkb vector_type and keeps the rights-to target;
  * run_find records each as a finding via the injected runner (deduped);
  * analyze surfaces them as ranked opportunities.

Run:  python3 -m unittest discover -s tests
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit.creds import Credential  # noqa: E402
from fieldkit.delegation import parse_delegation, run_find  # noqa: E402
from fieldkit.kb import analyze  # noqa: E402
from fieldkit.runner import RunResult  # noqa: E402
from fieldkit.state import Store  # noqa: E402

FIND = """\
LDAP        10.0.0.10       389    DC01             [*] Total of records returned 3
LDAP        10.0.0.10       389    DC01             AccountName   AccountType  DelegationType          DelegationRightsTo
LDAP        10.0.0.10       389    DC01             WEB01$        Computer     Unconstrained           N/A
LDAP        10.0.0.10       389    DC01             svc_web       User         Constrained             HTTP/dc01.corp.local
LDAP        10.0.0.10       389    DC01             SQL01$        Computer     Resource-Based Constrained   DC01$
"""


class ParseTest(unittest.TestCase):
    def test_types_mapped(self):
        by = {d.account: d.kind for d in parse_delegation(FIND)}
        self.assertEqual(by["WEB01$"], "unconstrained_delegation")
        self.assertEqual(by["svc_web"], "constrained_delegation")
        self.assertEqual(by["SQL01$"], "rbcd")

    def test_rights_to_captured(self):
        svc = [d for d in parse_delegation(FIND) if d.account == "svc_web"][0]
        self.assertEqual(svc.rights_to, "HTTP/dc01.corp.local")

    def test_na_rights_blanked(self):
        web = [d for d in parse_delegation(FIND) if d.account == "WEB01$"][0]
        self.assertEqual(web.rights_to, "")

    def test_header_row_skipped(self):
        self.assertEqual(len(parse_delegation(FIND)), 3)


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
        return lambda argv, env=None: RunResult(argv, 0, stdout=FIND)

    def test_records_findings(self):
        rep = run_find(self.store, self.dc, self.cred, run=self.runner())
        self.assertEqual(rep.found, 3)
        vts = sorted(f["vector_type"] for f in self.store.findings())
        self.assertEqual(vts, ["constrained_delegation", "rbcd", "unconstrained_delegation"])

    def test_rerun_dedupes(self):
        run_find(self.store, self.dc, self.cred, run=self.runner())
        rep = run_find(self.store, self.dc, self.cred, run=self.runner())
        self.assertEqual(rep.found, 0)

    def test_analyze_surfaces_delegation(self):
        run_find(self.store, self.dc, self.cred, run=self.runner())
        keys = [o.key for o in analyze(self.store) if o.key.startswith("deleg:")]
        self.assertEqual(len(keys), 3)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
