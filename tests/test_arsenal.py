#!/usr/bin/env python3
"""Arsenal awareness — fieldkit knows what's staged and what each route needs.

Pinned:

  * parse_manifest reads the TSV; staged() scans the disk; find() resolves by name;
  * resolve() classifies each Need — builtin always ready, build ready iff its builder
    is installed, supplied never, staged only when the artifact (or category PoC) is on disk.

Run:  python3 -m unittest discover -s tests
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import arsenal  # noqa: E402
from fieldkit.arsenal import (  # noqa: E402
    BUILD, BUILTIN, STAGED, SUPPLIED, Need, find, parse_manifest, resolve, staged,
)


class ArsenalTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        os.makedirs(os.path.join(self.root, "win-potato"))
        os.makedirs(os.path.join(self.root, "lin-kernel"))
        open(os.path.join(self.root, "win-potato", "GodPotato"), "w").close()
        open(os.path.join(self.root, "lin-kernel", "pwnkit"), "w").close()
        with open(os.path.join(self.root, "manifest.tsv"), "w") as fh:
            fh.write("# comment\n")
            fh.write("win-potato\tGodPotato\tgit\thttps://x/GodPotato\t⚠ default\n")
            fh.write("tools\tnxc\tghrelease\thttps://x/NetExec\tengine\t*ubuntu*.zip\n")


class ManifestTest(ArsenalTestCase):
    def test_parse_skips_comments(self):
        arts = parse_manifest(os.path.join(self.root, "manifest.tsv"))
        self.assertEqual(len(arts), 2)
        self.assertEqual(arts[0].name, "GodPotato")
        self.assertEqual(arts[1].kind, "ghrelease")


class StagedFindTest(ArsenalTestCase):
    def test_staged_by_category(self):
        st = staged(self.root)
        self.assertEqual(st["win-potato"], ["GodPotato"])
        self.assertIn("pwnkit", st["lin-kernel"])

    def test_find_exact_and_prefix(self):
        self.assertTrue(find("GodPotato", self.root).endswith("win-potato/GodPotato"))
        self.assertTrue(find("godp", self.root).endswith("GodPotato"))  # ci prefix
        self.assertIsNone(find("PrintSpoofer", self.root))

    def test_find_recurses_into_a_precompiled_collection(self):
        # a binary nested inside a cloned collection (SharpCollection layout) still resolves.
        deep = os.path.join(self.root, "win-postex", "SharpCollection", "NetFramework_4.7_x64")
        os.makedirs(deep)
        open(os.path.join(deep, "SweetPotato.exe"), "w").close()
        self.assertTrue(find("SweetPotato.exe", self.root).endswith(
            "SharpCollection/NetFramework_4.7_x64/SweetPotato.exe"))
        self.assertTrue(find("SweetPotato", self.root).endswith("SweetPotato.exe"))  # ci prefix

    def test_find_prefers_shallowest_exact(self):
        # a category-level drop wins over the same name buried in a collection.
        open(os.path.join(self.root, "win-potato", "SweetPotato.exe"), "w").close()
        deep = os.path.join(self.root, "win-postex", "SharpCollection", "NetFramework_4.7_x64")
        os.makedirs(deep)
        open(os.path.join(deep, "SweetPotato.exe"), "w").close()
        self.assertTrue(find("SweetPotato.exe", self.root).endswith(
            "win-potato/SweetPotato.exe"))


class ResolveTest(ArsenalTestCase):
    def test_builtin_always_ready(self):
        self.assertTrue(resolve("x", Need(BUILTIN, "native"), self.root).ready)

    def test_build_ready_tracks_the_toolchain(self):
        # BUILD is ready iff its builder is installed — honest, not always-true (Phase 9).
        from fieldkit import poc
        need = Need(BUILD, "an exe", ("exe",))
        self.assertEqual(resolve("x", need, self.root).ready, poc.have("exe"))
        self.assertIn(poc.BUILDER["exe"], resolve("x", need, self.root).detail)

    def test_supplied_never_ready(self):
        self.assertFalse(resolve("x", Need(SUPPLIED, "byovd"), self.root).ready)

    def test_staged_present_vs_missing(self):
        ok = resolve("seimpersonate", Need(STAGED, "a Potato", ("GodPotato", "SweetPotato")),
                     self.root)
        self.assertTrue(ok.ready)
        self.assertTrue(ok.path.endswith("GodPotato"))
        miss = resolve("x", Need(STAGED, "nc", ("nc.exe",)), self.root)
        self.assertFalse(miss.ready)

    def test_staged_by_category(self):
        ok = resolve("kernel_cve", Need(STAGED, "a PoC", category="lin-kernel"), self.root)
        self.assertTrue(ok.ready)                       # lin-kernel/ has pwnkit
        empty = resolve("x", Need(STAGED, "a PoC", category="win-kernel"), self.root)
        self.assertFalse(empty.ready)                   # win-kernel/ absent

    def test_real_privesc_needs_cover_the_vectors(self):
        # every privesc report_type in the KB-mapped set has a Need
        for key in ("seimpersonate", "unquoted_service", "gtfobins_sudo", "ld_preload"):
            self.assertIn(key, arsenal.PRIVESC_NEEDS)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
