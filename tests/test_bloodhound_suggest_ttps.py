#!/usr/bin/env python3
"""bloodhound suggest cross-references shipped CVE TTPs.

C14 slice 4. For each path with a chain-profile suggestion, look
up the fieldkit host that matches the suggested chain target,
gather its services, and cite every shipped TTP whose
`detect.version_range` predicate names one of those services.

Pins:

  * suggest_chains attaches matching_ttps to each entry;
  * empty when target host isn't in fieldkit's host list;
  * empty when host has no services;
  * matches by product name via _canon_product;
  * matches by IP OR hostname substring (BH FQDN, fieldkit
    short hostname);
  * CLI surfaces "also check" line + `fieldkit ttps show` cmd
    for each matching TTP.
"""
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _make_store(test_case):
    tmp = tempfile.TemporaryDirectory()
    test_case.addCleanup(tmp.cleanup)
    from fieldkit.state import Store
    s = Store.create(os.path.join(tmp.name, "e.db"))
    s.init_engagement("test-bh-ttps")
    test_case.addCleanup(s.close)
    return s


def _seed_owned_path(store, owned_name, target_name, high_value=True,
                      target_ntype="Computer"):
    """Register credential + BH nodes so owned_paths returns one entry
    landing at (target_name)."""
    from fieldkit.creds import Credential
    from_ = owned_name.split("@")[0]
    dom = owned_name.split("@")[1] if "@" in owned_name else ""
    store.add_credential(Credential(username=from_, secret="x", domain=dom),
                          source="spray")
    store.bh_add_node("S-1-1", name=owned_name, ntype="User")
    store.bh_add_node("S-1-2", name=target_name, ntype=target_ntype,
                       high_value=high_value)
    store.bh_add_edge("S-1-1", "S-1-2", "AdminTo")


class MatchingTTPsAttachmentTest(unittest.TestCase):

    def test_no_matching_host_returns_empty_ttps(self):
        # BH target has no corresponding fieldkit host record.
        from fieldkit import bloodhound as bh
        s = _make_store(self)
        _seed_owned_path(s, "ADMIN@CORP.LOCAL", "DC01.CORP.LOCAL")
        paths = bh.suggest_chains(s)
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["matching_ttps"], [])

    def test_matches_by_ip(self):
        from fieldkit import bloodhound as bh
        s = _make_store(self)
        # Register a fieldkit host with a service that matches a
        # shipped TTP (services.fortigate → CVE-2024-55591).
        hid, _ = s.add_host("10.0.0.5", hostname="fw01")
        s.add_service(host_id=hid, port=443,
                       proto="tcp", product="FortiGate",
                       version="7.0.10")
        # BH graph names the host by IP so the substring match hits.
        _seed_owned_path(s, "ADMIN@CORP.LOCAL", "10.0.0.5")
        paths = bh.suggest_chains(s)
        self.assertGreater(len(paths[0]["matching_ttps"]), 0)
        # The FortiGate CVE key should be in the list
        self.assertIn("service_cve:2024-55591", paths[0]["matching_ttps"])

    def test_matches_by_hostname_substring(self):
        from fieldkit import bloodhound as bh
        s = _make_store(self)
        # fieldkit hostname "fw01" — BH graph uses FQDN "fw01.CORP.LOCAL"
        hid, _ = s.add_host("10.0.0.5", hostname="fw01")
        s.add_service(host_id=hid, port=443,
                       proto="tcp", product="FortiGate",
                       version="7.0.10")
        _seed_owned_path(s, "ADMIN@CORP.LOCAL", "fw01.CORP.LOCAL")
        paths = bh.suggest_chains(s)
        self.assertGreater(len(paths[0]["matching_ttps"]), 0)

    def test_no_services_yields_empty_ttps(self):
        from fieldkit import bloodhound as bh
        s = _make_store(self)
        hid, _ = s.add_host("10.0.0.5", hostname="dc01")
        # No services added — no TTPs can match.
        _seed_owned_path(s, "ADMIN@CORP.LOCAL", "10.0.0.5")
        paths = bh.suggest_chains(s)
        self.assertEqual(paths[0]["matching_ttps"], [])

    def test_no_suggestion_still_produces_empty_ttps_field(self):
        # A path with no fitting chain profile gets matching_ttps=[]
        # so downstream renderers always see the key.
        from fieldkit import bloodhound as bh
        from fieldkit.creds import Credential
        s = _make_store(self)
        # Register a MemberOf-only path to a Group — none of the
        # chain heuristics fit (target isn't a Computer, no RBCD
        # edge, no AdminTo edge).
        s.add_credential(Credential(username="ADMIN", secret="x",
                                      domain="CORP.LOCAL"), source="spray")
        s.bh_add_node("S-1-1", name="ADMIN@CORP.LOCAL", ntype="User")
        s.bh_add_node("S-1-2", name="DA_GROUP", ntype="Group",
                       high_value=True)
        s.bh_add_edge("S-1-1", "S-1-2", "MemberOf")
        paths = bh.suggest_chains(s)
        self.assertIsNone(paths[0]["suggestion"])
        self.assertEqual(paths[0]["matching_ttps"], [])


class CLITest(unittest.TestCase):

    def _run(self, argv, store):
        from fieldkit.cli import build_parser, cmd_bloodhound_suggest
        parser = build_parser()
        args = parser.parse_args(argv)
        buf = io.StringIO()
        errbuf = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(errbuf):
            code = cmd_bloodhound_suggest.__wrapped__(args, store)
        return code, buf.getvalue(), errbuf.getvalue()

    def test_cli_surfaces_matching_ttps(self):
        s = _make_store(self)
        hid, _ = s.add_host("10.0.0.5", hostname="fw01")
        s.add_service(host_id=hid, port=443,
                       proto="tcp", product="FortiGate", version="7.0.10")
        _seed_owned_path(s, "ADMIN@CORP.LOCAL", "10.0.0.5")
        code, out, _ = self._run(["bloodhound", "suggest"], s)
        self.assertEqual(code, 0)
        self.assertIn("also check", out)
        self.assertIn("fieldkit ttps show service_cve:2024-55591", out)

    def test_cli_omits_line_when_no_matching_ttps(self):
        s = _make_store(self)
        _seed_owned_path(s, "ADMIN@CORP.LOCAL", "DC01.CORP.LOCAL")
        code, out, _ = self._run(["bloodhound", "suggest"], s)
        self.assertEqual(code, 0)
        # esc8 gets suggested, but no fieldkit host exists → no matches.
        self.assertNotIn("also check", out)


if __name__ == "__main__":
    unittest.main()
