#!/usr/bin/env python3
"""TUI TTPs browser — Textual counterpart to `ttps list/show`.

C14 slice 2. Two-pane screen: top scrolls the catalog, bottom
paints the selected TTP's detail inline (so the operator picks
+ inspects without hopping screens).

Pins:

  * on_mount loads the catalog, sorted by (technique, key);
  * cursor_down / cursor_up move selection with correct clamping;
  * on_input_changed live-filters the list case-insensitively;
  * empty filter resets to the full catalog;
  * selection clamps when filter shrinks the list past _selected;
  * header shows n/total with the current filter text;
  * detail pane picks fields from the selected TTP;
  * TUI CSS wired + screen registered in App.SCREENS;
  * app-level 't' binding routes to the ttps screen.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class _FakeStatic:
    def __init__(self):
        self.text = None
    def update(self, s):
        self.text = s


class _FakeInput:
    def __init__(self, value=""):
        self.value = value
    def focus(self):
        return None


def _make_screen():
    from fieldkit.tui.ttps_browser import TTPsBrowserScreen
    screen = TTPsBrowserScreen()
    statics = {"#ttps-header": _FakeStatic(),
                "#ttps-list":    _FakeStatic(),
                "#ttps-detail":  _FakeStatic(),
                "#ttps-filter-input": _FakeInput()}
    screen.query_one = lambda sel, _cls=None: statics[sel]
    screen._fake_statics = statics
    return screen


class LoadTest(unittest.TestCase):

    def test_on_mount_loads_catalog_sorted(self):
        s = _make_screen()
        s.on_mount()
        # Catalog has >= 100 TTPs
        self.assertGreater(len(s._all_ttps), 100)
        # Sorted by (technique, key)
        techs = [(t.technique, t.key) for t in s._all_ttps]
        self.assertEqual(techs, sorted(techs))
        # Filtered = full catalog initially
        self.assertEqual(len(s._filtered), len(s._all_ttps))


class CursorTest(unittest.TestCase):

    def test_cursor_down_advances_within_bounds(self):
        s = _make_screen()
        s.on_mount()
        initial = s._selected
        s.action_cursor_down()
        self.assertEqual(s._selected, initial + 1)

    def test_cursor_up_clamps_at_zero(self):
        s = _make_screen()
        s.on_mount()
        s.action_cursor_up()
        self.assertEqual(s._selected, 0)

    def test_cursor_down_clamps_at_last(self):
        s = _make_screen()
        s.on_mount()
        s._selected = len(s._filtered) - 1
        s.action_cursor_down()
        self.assertEqual(s._selected, len(s._filtered) - 1)


class FilterTest(unittest.TestCase):

    def _apply(self, s, text):
        class _Ev:
            value = text
        s.on_input_changed(_Ev())

    def test_filter_narrows_list_case_insensitively(self):
        s = _make_screen()
        s.on_mount()
        self._apply(s, "FORTIGATE")
        self.assertGreater(len(s._filtered), 0)
        self.assertLess(len(s._filtered), len(s._all_ttps))
        # Every remaining TTP has "fortigate" somewhere in key/name/tactic
        for t in s._filtered:
            hay = f"{t.key} {t.name}".lower()
            self.assertIn("fortigate", hay)

    def test_empty_filter_restores_full_catalog(self):
        s = _make_screen()
        s.on_mount()
        self._apply(s, "fortigate")
        self._apply(s, "")
        self.assertEqual(len(s._filtered), len(s._all_ttps))

    def test_filter_clamps_selection_when_list_shrinks(self):
        s = _make_screen()
        s.on_mount()
        s._selected = 100    # deep into catalog
        self._apply(s, "fortigate")
        # After narrowing, selection is at most len-1
        self.assertLess(s._selected, len(s._filtered))

    def test_no_match_filter_yields_empty_list(self):
        s = _make_screen()
        s.on_mount()
        self._apply(s, "xyz-really-no-such-ttp-xyz")
        self.assertEqual(len(s._filtered), 0)
        # Detail pane still renders (empty) without crash
        s._render()
        list_text = s._fake_statics["#ttps-list"].text
        self.assertIn("no TTPs match", list_text)


class RenderTest(unittest.TestCase):

    def test_header_shows_counts_and_filter(self):
        s = _make_screen()
        s.on_mount()
        class _Ev:
            value = "fortigate"
        s.on_input_changed(_Ev())
        s._render()
        h = s._fake_statics["#ttps-header"].text
        self.assertIn("TTPs", h)
        self.assertIn(f"/{len(s._all_ttps)}", h)
        self.assertIn("fortigate", h)

    def test_detail_shows_selected_ttp_fields(self):
        s = _make_screen()
        s.on_mount()
        # Filter to a known TTP so selection is deterministic
        class _Ev:
            value = "service_cve:2024-55591"
        s.on_input_changed(_Ev())
        s._render()
        d = s._fake_statics["#ttps-detail"].text
        self.assertIn("service_cve:2024-55591", d)
        self.assertIn("T1190", d)
        self.assertIn("exploit:", d)
        self.assertIn("description:", d)


class AppIntegrationTest(unittest.TestCase):

    def test_ttps_screen_registered(self):
        from fieldkit.tui.app import FieldkitTUI
        self.assertIn("ttps", FieldkitTUI.SCREENS)

    def test_ttps_css_in_app_css(self):
        from fieldkit.tui.app import FieldkitTUI
        self.assertIn("#ttps-body", FieldkitTUI.CSS)

    def test_app_level_t_binding_registered(self):
        from fieldkit.tui.app import FieldkitTUI
        keys = {b.key for b in FieldkitTUI.BINDINGS}
        self.assertIn("t", keys)


if __name__ == "__main__":
    unittest.main()
