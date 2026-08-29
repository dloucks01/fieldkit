#!/usr/bin/env python3
"""fieldkit.tui.theme — palette + glyph + severity helpers.

Pinned:

  * every palette color is a #-prefixed hex string (widgets read this, not literals)
  * accent and warn are the SAME value — attention IS the accent, per §2 of the brief
  * severity_dots produces the three-dot cluster shape at every tier
  * severity_color returns a palette member — never a raw hex not in `C`
  * the app-level TCSS references only palette constants (no stray literals)
"""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class ThemeTest(unittest.TestCase):
    def test_palette_constants_are_hex_strings(self):
        # Imported lazily so this doesn't trigger the vendor shim in isolation.
        from fieldkit.tui import theme
        hex_re = re.compile(r"^#[0-9A-Fa-f]{6}$")
        for name in ("BG", "SURFACE", "INK", "INK_DIM", "INK_DIM2", "RULE",
                     "ACCENT", "CRIT", "GOOD", "INFO", "WARN"):
            val = getattr(theme.C, name)
            self.assertTrue(hex_re.match(val), f"{name}={val!r} isn't #RRGGBB")

    def test_accent_and_warn_are_the_same(self):
        # Rule from the design brief §2: attention IS the accent — the same
        # value under two names so widget intent reads clearly.
        from fieldkit.tui import theme
        self.assertEqual(theme.C.ACCENT, theme.C.WARN)

    def test_glyphs_are_single_visible_characters(self):
        from fieldkit.tui import theme
        for name in ("ACTION", "SEV_ON", "SEV_OFF", "PROVEN", "OBSERVATION",
                     "CAUGHT", "ESCALATION", "ROUTE", "RUNNING", "PAUSED"):
            val = getattr(theme.G, name)
            self.assertIsInstance(val, str)
            self.assertEqual(len(val), 1, f"{name}={val!r} is not a single char")
            self.assertNotIn(val, (" ", "\t"), f"{name} is whitespace")

    def test_severity_dots_three_char_cluster(self):
        from fieldkit.tui import theme
        self.assertEqual(theme.severity_dots("critical"), "●●●")
        self.assertEqual(theme.severity_dots("high"),     "●●○")
        self.assertEqual(theme.severity_dots("medium"),   "●○○")
        self.assertEqual(theme.severity_dots("low"),      "○○○")
        self.assertEqual(theme.severity_dots("info"),     "○○○")
        self.assertEqual(theme.severity_dots(""),         "○○○")
        self.assertEqual(theme.severity_dots(None),       "○○○")

    def test_severity_color_maps_to_palette_members(self):
        from fieldkit.tui import theme
        palette = {v for k, v in vars(theme.C).items() if not k.startswith("_")}
        for sev in ("critical", "high", "medium", "low", "info", ""):
            self.assertIn(theme.severity_color(sev), palette,
                          f"severity_color({sev!r}) returned an off-palette color")

    def test_app_tcss_uses_only_palette_constants_for_colors(self):
        # Every hex color in the master CSS must be a value from `C`. No stray
        # literals — that's the "single source of truth" guarantee.
        from fieldkit.tui import theme
        palette = {v for k, v in vars(theme.C).items() if not k.startswith("_")}
        hexes = re.findall(r"#[0-9A-Fa-f]{6}", theme.APP_TCSS)
        for h in hexes:
            self.assertIn(h, palette, f"APP_TCSS uses off-palette color {h}")


class TUIImportTest(unittest.TestCase):
    """Importing fieldkit.tui triggers the vendor shim; importing app.py
    proves the shim works AND that Textual and Rich are reachable from
    fieldkit/vendor/. If either breaks, this test fails loudly rather than
    the user discovering it on first `fieldkit tui`."""

    def test_tui_package_import(self):
        import importlib
        importlib.import_module("fieldkit.tui")

    def test_vendor_shim_prepends_sys_path(self):
        # After import, vendor dir should be on sys.path
        import importlib
        importlib.import_module("fieldkit.tui")
        vendor_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "fieldkit", "vendor")
        # normalize both sides
        vendor_dir = os.path.abspath(vendor_dir)
        found = any(os.path.abspath(p) == vendor_dir for p in sys.path)
        self.assertTrue(found, f"vendor dir {vendor_dir} not on sys.path: {sys.path}")

    def test_textual_and_rich_import_from_vendor(self):
        import importlib
        importlib.import_module("fieldkit.tui")     # triggers vendor shim
        import textual
        import rich
        vendor_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "fieldkit", "vendor")
        vendor_dir = os.path.abspath(vendor_dir)
        self.assertTrue(os.path.abspath(textual.__file__).startswith(vendor_dir),
                        f"textual not from vendor: {textual.__file__}")
        self.assertTrue(os.path.abspath(rich.__file__).startswith(vendor_dir),
                        f"rich not from vendor: {rich.__file__}")

    def test_app_class_constructs(self):
        # Full import chain — vendor shim + textual + our theme + our app.
        # Not launching Textual's mainloop; just building the App class.
        from fieldkit.tui.app import FieldkitTUI
        app = FieldkitTUI(db_path=None)
        self.assertEqual(sorted(app.SCREENS.keys()),
                         ["analyze", "dashboard", "escalate", "help", "watch"])


if __name__ == "__main__":
    unittest.main()
