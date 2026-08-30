#!/usr/bin/env python3
"""BloodHound multi-path enumeration — owned_paths_all + suggest --all-paths.

C16 gaps slice 3. owned_paths (shortest-per-source) leaves the
operator blind to alternative destinations. owned_paths_all
surfaces every distinct high-value target reachable from each
owned principal.

Pins:

  * owned_paths_all empty when no graph;
  * owned_paths_all returns one entry per distinct target reached;
  * max_paths_per_start caps the enumeration per source;
  * high-value nodes aren't traversed past (avoid DA→DA loops);
  * suggest_chains(all_paths=True) plumbs through;
  * CLI --all-paths / --max-paths flags registered.
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
    s.init_engagement("test-bh-multipath")
    test_case.addCleanup(s.close)
    return s


def _seed_owned(store, name="ADMIN", domain="CORP.LOCAL"):
    from fieldkit.creds import Credential
    store.add_credential(Credential(username=name, secret="x",
                                       domain=domain),
                          source="spray")


class EmptyGraphTest(unittest.TestCase):

    def test_empty_graph_returns_empty(self):
        from fieldkit import bloodhound as bh
        s = _make_store(self)
        self.assertEqual(bh.owned_paths_all(s), [])


class MultiTargetTest(unittest.TestCase):

    def test_one_owned_reaching_two_targets_surfaces_both(self):
        # ADMIN -AdminTo-> DC01 (high-value)
        # ADMIN -AdminTo-> FS01 (high-value)
        # owned_paths would surface only DC01 (first BFS hit);
        # owned_paths_all should surface BOTH.
        from fieldkit import bloodhound as bh
        s = _make_store(self)
        _seed_owned(s)
        s.bh_add_node("S-1-1", name="ADMIN@CORP.LOCAL", ntype="User")
        s.bh_add_node("S-1-2", name="DC01", ntype="Computer",
                       high_value=True)
        s.bh_add_node("S-1-3", name="FS01", ntype="Computer",
                       high_value=True)
        s.bh_add_edge("S-1-1", "S-1-2", "AdminTo")
        s.bh_add_edge("S-1-1", "S-1-3", "AdminTo")
        paths = bh.owned_paths_all(s)
        targets = {p["target"] for p in paths}
        self.assertEqual(targets, {"DC01", "FS01"})

    def test_max_paths_per_start_caps_enumeration(self):
        from fieldkit import bloodhound as bh
        s = _make_store(self)
        _seed_owned(s)
        s.bh_add_node("S-1-1", name="ADMIN@CORP.LOCAL", ntype="User")
        # Own 5 admin-to edges from the same principal
        for i in range(1, 6):
            s.bh_add_node(f"S-1-{i+1}", name=f"H{i}",
                           ntype="Computer", high_value=True)
            s.bh_add_edge("S-1-1", f"S-1-{i+1}", "AdminTo")
        paths = bh.owned_paths_all(s, max_paths_per_start=3)
        # Only 3 targets surface even though 5 exist
        self.assertEqual(len(paths), 3)

    def test_owned_paths_still_returns_shortest_only(self):
        # Regression pin: adding owned_paths_all didn't change
        # the behavior of owned_paths (existing callers unchanged).
        from fieldkit import bloodhound as bh
        s = _make_store(self)
        _seed_owned(s)
        s.bh_add_node("S-1-1", name="ADMIN@CORP.LOCAL", ntype="User")
        s.bh_add_node("S-1-2", name="DC01", ntype="Computer",
                       high_value=True)
        s.bh_add_node("S-1-3", name="FS01", ntype="Computer",
                       high_value=True)
        s.bh_add_edge("S-1-1", "S-1-2", "AdminTo")
        s.bh_add_edge("S-1-1", "S-1-3", "AdminTo")
        paths = bh.owned_paths(s)
        # Only one path returned even with two viable targets
        self.assertEqual(len(paths), 1)


class SuggestChainsIntegrationTest(unittest.TestCase):

    def test_suggest_chains_all_paths_returns_multi_target(self):
        from fieldkit import bloodhound as bh
        s = _make_store(self)
        _seed_owned(s)
        s.bh_add_node("S-1-1", name="ADMIN@CORP.LOCAL", ntype="User")
        s.bh_add_node("S-1-2", name="DC01", ntype="Computer",
                       high_value=True)
        s.bh_add_node("S-1-3", name="DC02", ntype="Computer",
                       high_value=True)
        s.bh_add_edge("S-1-1", "S-1-2", "AdminTo")
        s.bh_add_edge("S-1-1", "S-1-3", "AdminTo")
        # Default (all_paths=False) → 1 suggestion
        default = bh.suggest_chains(s)
        self.assertEqual(len(default), 1)
        # all_paths=True → 2
        every = bh.suggest_chains(s, all_paths=True)
        self.assertEqual(len(every), 2)
        # Both should have esc8 suggestions (high-value Computer)
        for p in every:
            self.assertEqual(p["suggestion"]["profile"], "esc8")


class CLIFlagTest(unittest.TestCase):

    def _run(self, argv, store):
        from fieldkit.cli import build_parser, cmd_bloodhound_suggest
        parser = build_parser()
        args = parser.parse_args(argv)
        buf = io.StringIO()
        errbuf = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(errbuf):
            code = cmd_bloodhound_suggest.__wrapped__(args, store)
        return code, buf.getvalue(), errbuf.getvalue()

    def test_all_paths_flag_registered(self):
        from fieldkit.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["bloodhound", "suggest", "--all-paths"])
        self.assertTrue(args.all_paths)

    def test_max_paths_flag_registered(self):
        from fieldkit.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["bloodhound", "suggest",
                                     "--all-paths", "--max-paths", "3"])
        self.assertEqual(args.max_paths, 3)

    def test_default_flags(self):
        from fieldkit.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["bloodhound", "suggest"])
        self.assertFalse(getattr(args, "all_paths", False))
        self.assertEqual(getattr(args, "max_paths", None), 5)

    def test_cli_all_paths_surfaces_multiple_targets(self):
        s = _make_store(self)
        _seed_owned(s)
        s.bh_add_node("S-1-1", name="ADMIN@CORP.LOCAL", ntype="User")
        s.bh_add_node("S-1-2", name="DC01", ntype="Computer",
                       high_value=True)
        s.bh_add_node("S-1-3", name="FS01", ntype="Computer",
                       high_value=True)
        s.bh_add_edge("S-1-1", "S-1-2", "AdminTo")
        s.bh_add_edge("S-1-1", "S-1-3", "AdminTo")
        code, out, _ = self._run(
            ["bloodhound", "suggest", "--all-paths"], s)
        self.assertEqual(code, 0)
        self.assertIn("DC01", out)
        self.assertIn("FS01", out)


if __name__ == "__main__":
    unittest.main()
