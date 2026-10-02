#!/usr/bin/env python3
"""Weaponization catalog — stdlib-only metadata about loader / bypass /
syscall / encoder / delivery techniques the operator can pick from."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import weaponization


class TestCatalogShape(unittest.TestCase):

    def test_catalog_is_non_empty(self):
        self.assertGreater(len(weaponization.all_techniques()), 20)

    def test_every_axis3_deliverable_has_at_least_one_entry(self):
        """Each category from the AXES-ROADMAP axis 3 must map to real
        catalog entries — otherwise a reader comes here looking for
        'syscall framework' and finds nothing."""
        cats = {t.category for t in weaponization.all_techniques()}
        for required in ("loader", "bypass", "syscall", "encoder", "delivery"):
            self.assertIn(required, cats, f"missing category: {required}")

    def test_keys_are_unique(self):
        keys = [t.key for t in weaponization.all_techniques()]
        self.assertEqual(len(keys), len(set(keys)))

    def test_every_entry_has_a_description(self):
        for t in weaponization.all_techniques():
            self.assertTrue(t.description.strip(),
                            f"{t.key} has empty description")

    def test_every_entry_has_an_opsec_label(self):
        allowed = {"quiet", "moderate", "loud"}
        for t in weaponization.all_techniques():
            self.assertIn(t.opsec, allowed, f"{t.key} has invalid opsec {t.opsec!r}")

    def test_every_entry_has_a_known_platform(self):
        allowed = {"windows", "linux", "cross"}
        for t in weaponization.all_techniques():
            self.assertIn(t.platform, allowed,
                          f"{t.key} has invalid platform {t.platform!r}")

    def test_every_entry_is_frozen(self):
        t = weaponization.all_techniques()[0]
        with self.assertRaises(Exception):
            t.name = "modified"


class TestKeyLookup(unittest.TestCase):

    def test_known_keys_resolve(self):
        for key in ("hells-gate", "amsi-patch-memory", "https-beacon",
                     "reflective-dotnet", "pe-signature-cloning"):
            self.assertIsNotNone(weaponization.by_key(key),
                                 f"{key} missing from catalog")

    def test_unknown_key_returns_None(self):
        self.assertIsNone(weaponization.by_key("totally-not-real"))


class TestCategoryLookup(unittest.TestCase):

    def test_loaders_include_the_core_set(self):
        keys = {t.key for t in weaponization.by_category("loader")}
        for required in ("reflective-dotnet", "reflective-dll",
                          "process-hollowing", "apc-injection",
                          "module-stomping", "wsl-pivot",
                          "chromium-extension"):
            self.assertIn(required, keys)

    def test_syscalls_include_hells_halos_tartarus_freshy(self):
        keys = {t.key for t in weaponization.by_category("syscall")}
        for required in ("hells-gate", "halos-gate", "tartarus-gate",
                          "freshy-calls"):
            self.assertIn(required, keys)

    def test_unknown_category_returns_empty(self):
        self.assertEqual(weaponization.by_category("fake"), [])


class TestPlatformFilter(unittest.TestCase):

    def test_windows_filter_includes_cross(self):
        """A cross-platform technique applies to a windows query (operator
        asking "what can I use ON WINDOWS?" expects both)."""
        wins = {t.key for t in weaponization.by_platform("windows")}
        self.assertIn("https-beacon", wins)  # cross
        self.assertIn("hells-gate", wins)    # windows-only

    def test_linux_filter_excludes_windows_only(self):
        lins = {t.key for t in weaponization.by_platform("linux")}
        self.assertNotIn("hells-gate", lins)
        # cross still shows
        self.assertIn("https-beacon", lins)


class TestCategoriesListing(unittest.TestCase):

    def test_categories_sorted_and_distinct(self):
        cats = weaponization.categories()
        self.assertEqual(cats, sorted(cats))
        self.assertEqual(len(cats), len(set(cats)))


class TestOPSECCoverage(unittest.TestCase):
    """Load-bearing: a 'quiet' entry in the catalog should actually be
    the operator's instinct quiet option. Pin a few known-quiet picks."""

    def test_known_quiet_picks(self):
        quiet_keys = {t.key for t in weaponization.all_techniques()
                      if t.opsec == "quiet"}
        for required in ("hells-gate", "freshy-calls", "etw-patch-memory",
                          "chromium-extension", "wsl-pivot"):
            self.assertIn(required, quiet_keys)

    def test_known_loud_picks(self):
        loud_keys = {t.key for t in weaponization.all_techniques()
                     if t.opsec == "loud"}
        for required in ("lolbas-rundll32", "amsi-provider-hijack",
                          "webdav-upload"):
            self.assertIn(required, loud_keys)


class TestTemplateLibrary(unittest.TestCase):
    """Slice 13: reference templates in fieldkit/loaders/ for catalog
    entries that carry a ``template`` field."""

    def test_entries_with_templates_resolve_to_real_files(self):
        for t in weaponization.all_techniques():
            if not t.template:
                continue
            with self.subTest(key=t.key):
                p = weaponization.template_path(t.key)
                self.assertIsNotNone(p,
                    f"{t.key} declares template {t.template!r} but file missing")
                self.assertTrue(os.path.exists(p))

    def test_template_body_returns_file_contents(self):
        """A keyed template is read + returned verbatim."""
        body = weaponization.template_body("amsi-patch-memory")
        self.assertIsNotNone(body)
        self.assertIn("amsi", body.lower())

    def test_entries_without_templates_return_None(self):
        """A catalog entry with no ``template`` field returns None, not
        an error, so the caller can downgrade cleanly."""
        for t in weaponization.all_techniques():
            if t.template:
                continue
            with self.subTest(key=t.key):
                self.assertIsNone(weaponization.template_body(t.key))

    def test_unknown_key_returns_None_from_template_helpers(self):
        self.assertIsNone(weaponization.template_path("totally-fake"))
        self.assertIsNone(weaponization.template_body("totally-fake"))

    def test_core_axis3_shapes_have_a_template(self):
        """The reference templates slice 13 landed must be reachable
        via their catalog keys."""
        for required in ("amsi-patch-memory", "etw-patch-memory",
                          "hells-gate", "freshy-calls",
                          "reflective-dotnet", "xor-roll",
                          "https-beacon"):
            with self.subTest(key=required):
                t = weaponization.by_key(required)
                self.assertTrue(t.template,
                    f"{required} should carry a template filename")
                self.assertIsNotNone(weaponization.template_body(required))


if __name__ == "__main__":
    unittest.main()
