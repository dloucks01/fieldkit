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

    def test_app_tcss_uses_theme_variables_not_hex(self):
        # Every color in APP_TCSS must reference a Textual theme variable
        # ($foreground, $accent, $fk-ink-dim, ...) — never a hex literal.
        # Reason: Textual's theme switcher rebinds the variables, and hex
        # literals would make the switcher a no-op for those rules.
        from fieldkit.tui import theme
        hexes = re.findall(r"#[0-9A-Fa-f]{6}", theme.APP_TCSS)
        self.assertEqual(hexes, [],
                         f"APP_TCSS should use $variables, not hex: {hexes}")
        # And there IS at least one variable reference, so we're not just
        # trivially color-free.
        self.assertRegex(theme.APP_TCSS, r"\$(foreground|accent|background)")

    def test_fieldkit_dark_theme_maps_palette_to_textual_slots(self):
        # The Theme object is the second channel the palette flows through
        # (CSS variables); it must agree with `C` — one place changes color,
        # both channels update.
        from fieldkit.tui import theme
        t = theme.FIELDKIT_DARK
        self.assertEqual(t.name, "fieldkit-dark")
        self.assertTrue(t.dark)
        self.assertEqual(t.primary,    theme.C.ACCENT)
        self.assertEqual(t.accent,     theme.C.ACCENT)
        self.assertEqual(t.warning,    theme.C.WARN)
        self.assertEqual(t.error,      theme.C.CRIT)
        self.assertEqual(t.success,    theme.C.GOOD)
        self.assertEqual(t.foreground, theme.C.INK)
        self.assertEqual(t.background, theme.C.BG)
        self.assertEqual(t.surface,    theme.C.SURFACE)
        # We override the built-in Textual variables that matter to the brand.
        # No custom `$fk-*` vars — those would break the theme switcher.
        self.assertEqual(t.variables["border"],                 theme.C.RULE)
        self.assertEqual(t.variables["border-blurred"],         theme.C.RULE)
        self.assertEqual(t.variables["footer-key-foreground"],  theme.C.ACCENT)
        self.assertEqual(t.variables["footer-key-background"],  theme.C.BG)
        self.assertEqual(t.variables["block-cursor-background"], theme.C.ACCENT)

    def test_app_tcss_uses_only_canonical_textual_variables(self):
        # Every $variable in APP_TCSS must be a canonical Textual variable
        # (foreground, accent, error, border, etc.) — NOT a custom fk-* var.
        # Custom vars break the theme switcher: gruvbox/dracula/etc. don't
        # define them and CSS re-parse fails with UnresolvedVariableError.
        from fieldkit.tui import theme
        vars_used = set(re.findall(r"\$([a-z][a-z0-9-]+)", theme.APP_TCSS))
        self.assertNotIn("fk-ink-dim",  vars_used)
        self.assertNotIn("fk-ink-dim2", vars_used)
        self.assertNotIn("fk-rule",     vars_used)
        # The vars we DO use are all canonical Textual variables
        canonical = {
            "background", "foreground", "foreground-muted", "foreground-disabled",
            "accent", "error", "success", "secondary", "warning", "border",
            "surface", "panel", "primary", "boost",
        }
        for v in vars_used:
            self.assertIn(v, canonical, f"APP_TCSS uses non-canonical var $${v}")


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
        # Escalate is push-only (needs a highlighted move from Analyze),
        # not a named SCREENS entry — so the registered set is 4, not 5.
        # C9 slice 4 added `chain-plan`; C11 slice 2 added
        # `chain-launch` (profile-picker → chain-run). Escalate
        # remains push-only (needs a highlighted move from
        # Analyze), not a named SCREENS entry.
        self.assertEqual(sorted(app.SCREENS.keys()),
                         ["analyze", "chain-launch", "chain-plan",
                          "dashboard", "help", "watch"])


if __name__ == "__main__":
    unittest.main()
