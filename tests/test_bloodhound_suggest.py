#!/usr/bin/env python3
"""BloodHound → chain-profile suggestion.

C13 slice 1. For each owned→high-value path the ingested BH
graph surfaces, suggest the best-fit shipped chain profile +
target from a small edge-kind heuristic table.

Pins:

  * empty graph → suggest_chains returns [];
  * high-value Computer target → esc8 (canonical DC pwn);
  * RBCD/AllowedToDelegate edge → rbcd;
  * dangerous ACE (WriteDacl/GenericAll/GenericWrite) on a
    Computer → rbcd;
  * AdminTo edge to Computer → smb-relay-exec;
  * path with none of the above → no suggestion (None);
  * suggestion carries profile + target + rationale;
  * CLI cmd_bloodhound_suggest surfaces the suggested command
    line; empty-graph engagement returns exit 2 with a hint.
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
    s.init_engagement("test-bh-suggest")
    test_case.addCleanup(s.close)
    return s


class SuggestChainHeuristicsTest(unittest.TestCase):
    """Direct unit tests on suggest_chain(path_entry, nodes_by_sid)."""

    def _nodes(self, *entries):
        """Fake nodes_by_sid dict from (sid, name, ntype, high_value) tuples."""
        return {sid: {"sid": sid, "name": name, "ntype": ntype,
                        "high_value": high_value}
                for sid, name, ntype, high_value in entries}

    def test_target_high_value_computer_suggests_esc8(self):
        from fieldkit.bloodhound import suggest_chain
        nodes = self._nodes(
            ("S-1-1", "USER01@CORP.LOCAL", "User", 0),
            ("S-1-2", "DC01.CORP.LOCAL", "Computer", 1),
        )
        p = {"owned": "USER01@CORP.LOCAL", "target": "DC01.CORP.LOCAL",
             "hops": 2,
             "path": "USER01@CORP.LOCAL -MemberOf-> DA_GROUP "
                     "-AdminTo-> DC01.CORP.LOCAL"}
        s = suggest_chain(p, nodes)
        self.assertIsNotNone(s)
        self.assertEqual(s["profile"], "esc8")
        self.assertEqual(s["target"], "DC01.CORP.LOCAL")
        self.assertIn("ADCS", s["rationale"])

    def test_high_value_computer_also_suggests_nopac_alternative(self):
        # C15: same high-value-Computer target should carry nopac as
        # an alternative, so the operator picks the profile whose
        # precondition (ADCS vs MAQ+unpatched-KDC) their environment
        # actually meets.
        from fieldkit.bloodhound import suggest_chain
        nodes = self._nodes(
            ("S-1-1", "USER01@CORP.LOCAL", "User", 0),
            ("S-1-2", "DC01.CORP.LOCAL", "Computer", 1),
        )
        p = {"owned": "USER01@CORP.LOCAL", "target": "DC01.CORP.LOCAL",
             "hops": 1, "path": "USER01@CORP.LOCAL -AdminTo-> DC01.CORP.LOCAL"}
        s = suggest_chain(p, nodes)
        alts = s.get("alternatives") or []
        self.assertEqual(len(alts), 1)
        self.assertEqual(alts[0]["profile"], "nopac")
        self.assertIn("MachineAccountQuota", alts[0]["rationale"])
        self.assertIn("DC01.CORP.LOCAL", alts[0]["rationale"])

    def test_rbcd_edge_suggests_rbcd(self):
        from fieldkit.bloodhound import suggest_chain
        nodes = self._nodes(
            ("S-1-1", "USER01", "User", 0),
            ("S-1-2", "TARGETWS", "Computer", 0),
        )
        p = {"owned": "USER01", "target": "TARGETWS", "hops": 1,
             "path": "USER01 -AllowedToActOnBehalfOfOtherIdentity-> TARGETWS"}
        s = suggest_chain(p, nodes)
        self.assertIsNotNone(s)
        self.assertEqual(s["profile"], "rbcd")
        self.assertEqual(s["target"], "TARGETWS")

    def test_dangerous_ace_on_computer_suggests_rbcd(self):
        from fieldkit.bloodhound import suggest_chain
        nodes = self._nodes(
            ("S-1-1", "USER01", "User", 0),
            ("S-1-2", "WS01", "Computer", 0),
        )
        p = {"owned": "USER01", "target": "WS01", "hops": 1,
             "path": "USER01 -WriteDacl-> WS01"}
        s = suggest_chain(p, nodes)
        self.assertEqual(s["profile"], "rbcd")
        self.assertEqual(s["target"], "WS01")

    def test_admin_to_computer_suggests_smb_relay_exec(self):
        from fieldkit.bloodhound import suggest_chain
        nodes = self._nodes(
            ("S-1-1", "USER01", "User", 0),
            ("S-1-2", "FILES01", "Computer", 0),
        )
        p = {"owned": "USER01", "target": "FILES01", "hops": 1,
             "path": "USER01 -AdminTo-> FILES01"}
        s = suggest_chain(p, nodes)
        self.assertEqual(s["profile"], "smb-relay-exec")
        self.assertEqual(s["target"], "FILES01")

    def test_generic_path_no_match_returns_none(self):
        from fieldkit.bloodhound import suggest_chain
        nodes = self._nodes(
            ("S-1-1", "USER01", "User", 0),
            ("S-1-2", "DA_GROUP", "Group", 1),
        )
        p = {"owned": "USER01", "target": "DA_GROUP", "hops": 1,
             "path": "USER01 -MemberOf-> DA_GROUP"}
        s = suggest_chain(p, nodes)
        self.assertIsNone(s)

    def test_esc8_wins_over_admin_to_when_target_is_high_value(self):
        # A path with an AdminTo edge that lands at a high-value
        # Computer should still prefer esc8 (target-based rule
        # runs first) rather than smb-relay-exec (edge-based).
        from fieldkit.bloodhound import suggest_chain
        nodes = self._nodes(
            ("S-1-1", "USER01", "User", 0),
            ("S-1-2", "DC01", "Computer", 1),
        )
        p = {"owned": "USER01", "target": "DC01", "hops": 1,
             "path": "USER01 -AdminTo-> DC01"}
        s = suggest_chain(p, nodes)
        self.assertEqual(s["profile"], "esc8")


class SuggestChainsStoreTest(unittest.TestCase):
    """suggest_chains iterates over the actual owned_paths + attaches
    a suggestion field to each entry."""

    def test_empty_graph_returns_empty_list(self):
        from fieldkit import bloodhound as bh
        s = _make_store(self)
        self.assertEqual(bh.suggest_chains(s), [])

    def test_populated_graph_attaches_suggestion(self):
        from fieldkit import bloodhound as bh
        s = _make_store(self)
        # Register an owned credential + the BH nodes + edge from
        # the owned principal to a high-value Computer.
        from fieldkit.creds import Credential
        s.add_credential(Credential(username="ADMIN", secret="x",
                                      domain="CORP.LOCAL"),
                          source="spray")
        s.bh_add_node("S-1-1", name="ADMIN@CORP.LOCAL", ntype="User")
        s.bh_add_node("S-1-2", name="DC01.CORP.LOCAL", ntype="Computer",
                       high_value=True)
        s.bh_add_edge("S-1-1", "S-1-2", "AdminTo")
        paths = bh.suggest_chains(s)
        self.assertEqual(len(paths), 1)
        self.assertIn("suggestion", paths[0])
        self.assertEqual(paths[0]["suggestion"]["profile"], "esc8")


class CLITest(unittest.TestCase):

    def _run(self, argv, store):
        # Call the un-wrapped handler with (args, store) — the
        # @needs_engagement wrapper opens its own store from
        # args.db, but tests want the fixture-store injected.
        from fieldkit.cli import build_parser, cmd_bloodhound_suggest
        parser = build_parser()
        args = parser.parse_args(argv)
        buf = io.StringIO()
        errbuf = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(errbuf):
            code = cmd_bloodhound_suggest.__wrapped__(args, store)
        return code, buf.getvalue(), errbuf.getvalue()

    def test_no_graph_returns_2_with_hint(self):
        s = _make_store(self)
        code, _, err = self._run(["bloodhound", "suggest"], s)
        self.assertEqual(code, 2)
        self.assertIn("no BloodHound graph", err)
        self.assertIn("import", err)

    def test_suggest_prints_chain_command(self):
        s = _make_store(self)
        from fieldkit.creds import Credential
        s.add_credential(Credential(username="ADMIN", secret="x",
                                      domain="CORP.LOCAL"),
                          source="spray")
        s.bh_add_node("S-1-1", name="ADMIN@CORP.LOCAL", ntype="User")
        s.bh_add_node("S-1-2", name="DC01.CORP.LOCAL", ntype="Computer",
                       high_value=True)
        s.bh_add_edge("S-1-1", "S-1-2", "AdminTo")
        code, out, _ = self._run(["bloodhound", "suggest"], s)
        self.assertEqual(code, 0)
        self.assertIn("fieldkit chain run esc8 DC01.CORP.LOCAL", out)
        self.assertIn("why:", out)

    def test_suggest_shows_no_chain_fits_line(self):
        # Path with no fitting edge kind gets an explicit "no chain
        # fits" line rather than being silently omitted.
        s = _make_store(self)
        from fieldkit.creds import Credential
        s.add_credential(Credential(username="ADMIN", secret="x",
                                      domain="CORP.LOCAL"),
                          source="spray")
        s.bh_add_node("S-1-1", name="ADMIN", ntype="User")
        s.bh_add_node("S-1-2", name="DA_GROUP", ntype="Group",
                       high_value=True)
        s.bh_add_edge("S-1-1", "S-1-2", "MemberOf")
        code, out, _ = self._run(["bloodhound", "suggest"], s)
        self.assertEqual(code, 0)
        self.assertIn("no shipped chain profile fits", out)


if __name__ == "__main__":
    unittest.main()
