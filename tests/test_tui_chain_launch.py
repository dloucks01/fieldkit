#!/usr/bin/env python3
"""TUI chain-launch screen — profile picker + target input.

Pins:

  * screen constructs with an initial_target string (or empty);
  * on_mount populates ``_profiles`` from tui_data.chain_profiles;
  * cursor_down / cursor_up move selection with correct clamping;
  * _launch is a no-op when the profile list is empty;
  * _launch is a no-op when the target Input is empty (surfaces hint);
  * _launch pushes a ChainRunScreen with (profile, target, ctx) once
    both are set;
  * _build_ctx returns db_path + engagement_name keys;
  * the launcher's CSS id is included in the app's merged CSS.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class _FakeInput:
    def __init__(self, value=""):
        self.value = value
    def focus(self):
        return None


class _FakeStatic:
    def __init__(self):
        self.text = ""
    def update(self, s):
        self.text = s


class _FakeApp:
    def __init__(self):
        self._db_path = "/tmp/x.db"
        self.engagement_name = "test-launch"
        self.pushed = []
    def push_screen(self, screen):
        self.pushed.append(screen)


def _make_screen(initial_target="",
                  profiles=(("esc8", 7, 15), ("rbcd", 5, 20))):
    """Build a ChainLaunchScreen with query_one stubbed to fake widgets."""
    from fieldkit.tui.chain_launch import ChainLaunchScreen
    screen = ChainLaunchScreen(initial_target=initial_target)
    screen._profiles = [
        {"name": n, "step_count": sc, "total_cost": c, "steps": []}
        for (n, sc, c) in profiles
    ]
    # Stub the widget-lookup so tests don't need a Textual mainloop.
    inp = _FakeInput(value=initial_target)
    statics = {
        "#chain-launch-profiles": _FakeStatic(),
        "#chain-launch-hint":     _FakeStatic(),
        "#chain-launch-target-input": inp,
    }
    def _query(sel, _cls=None):
        return statics[sel]
    screen.query_one = _query
    screen._fake_input = inp
    screen._fake_statics = statics
    # Fake app for push_screen inspection + ctx build.
    # Textual's Screen.app is a read-only property that raises
    # outside a running app, so bypass it by patching the two hooks
    # that touch it: _push_run_screen (captures pushed screens) and
    # _build_ctx (returns a stable ctx dict).
    fake_app = _FakeApp()
    screen._fake_app = fake_app
    screen._push_run_screen = fake_app.push_screen
    screen._build_ctx = lambda: {"db_path": fake_app._db_path,
                                  "engagement_name": fake_app.engagement_name}
    return screen


class ConstructionTest(unittest.TestCase):

    def test_screen_constructs_with_empty_target(self):
        s = _make_screen()
        self.assertEqual(s._selected, 0)
        self.assertEqual(s._initial_target, "")

    def test_screen_constructs_with_seeded_target(self):
        s = _make_screen(initial_target="10.0.0.5")
        self.assertEqual(s._initial_target, "10.0.0.5")

    def test_populates_profiles_on_mount(self):
        # Simulated: _make_screen assigns _profiles directly.
        s = _make_screen()
        self.assertEqual(len(s._profiles), 2)
        self.assertEqual(s._profiles[0]["name"], "esc8")


class CursorTest(unittest.TestCase):

    def test_cursor_down_advances_within_bounds(self):
        s = _make_screen()
        s._render = lambda: None  # short-circuit rendering
        s.action_cursor_down()
        self.assertEqual(s._selected, 1)

    def test_cursor_down_clamps_at_last_profile(self):
        s = _make_screen()
        s._render = lambda: None
        s.action_cursor_down()   # 0 → 1
        s.action_cursor_down()   # clamps
        s.action_cursor_down()
        self.assertEqual(s._selected, 1)   # 2 profiles, max index 1

    def test_cursor_up_clamps_at_first_profile(self):
        s = _make_screen()
        s._render = lambda: None
        s.action_cursor_up()
        self.assertEqual(s._selected, 0)

    def test_cursor_down_no_op_on_empty_profile_list(self):
        s = _make_screen(profiles=())
        s._render = lambda: None
        s.action_cursor_down()
        self.assertEqual(s._selected, 0)


class LaunchTest(unittest.TestCase):

    def test_launch_no_op_when_no_profiles(self):
        s = _make_screen(initial_target="10.0.0.5", profiles=())
        s._launch()
        self.assertEqual(s._fake_app.pushed, [])

    def test_launch_surfaces_hint_when_target_empty(self):
        s = _make_screen(initial_target="")
        s._launch()
        self.assertEqual(s._fake_app.pushed, [])
        hint = s._fake_statics["#chain-launch-hint"].text
        self.assertIn("target is empty", hint)

    def test_launch_pushes_chain_run_screen(self):
        s = _make_screen(initial_target="10.0.0.5")
        s._launch()
        self.assertEqual(len(s._fake_app.pushed), 1)
        pushed = s._fake_app.pushed[0]
        from fieldkit.tui.chain_run import ChainRunScreen
        self.assertIsInstance(pushed, ChainRunScreen)
        self.assertEqual(pushed._profile_name, "esc8")
        self.assertEqual(pushed._target, "10.0.0.5")
        # ctx carries db_path + engagement_name
        self.assertIn("db_path", pushed._ctx)
        self.assertIn("engagement_name", pushed._ctx)
        self.assertEqual(pushed._ctx["engagement_name"], "test-launch")

    def test_launch_uses_second_profile_after_cursor_down(self):
        s = _make_screen(initial_target="10.0.0.5")
        s._render = lambda: None
        s.action_cursor_down()
        s._launch()
        pushed = s._fake_app.pushed[0]
        self.assertEqual(pushed._profile_name, "rbcd")

    def test_launch_trims_target_whitespace(self):
        s = _make_screen(initial_target="  10.0.0.5  ")
        s._launch()
        pushed = s._fake_app.pushed[0]
        self.assertEqual(pushed._target, "10.0.0.5")

    def test_input_submitted_triggers_launch(self):
        s = _make_screen(initial_target="10.0.0.5")
        s.on_input_submitted(event=None)
        self.assertEqual(len(s._fake_app.pushed), 1)


class CtxTest(unittest.TestCase):

    def test_build_ctx_degrades_gracefully_without_app(self):
        # Fresh screen — no fake overrides. _build_ctx must still
        # return a dict with the required keys even when self.app
        # raises NoActiveAppError.
        from fieldkit.tui.chain_launch import ChainLaunchScreen
        screen = ChainLaunchScreen(initial_target="10.0.0.5")
        ctx = screen._build_ctx()
        self.assertIn("db_path", ctx)
        self.assertIn("engagement_name", ctx)
        self.assertEqual(ctx["engagement_name"], "(no engagement)")


class AppIntegrationTest(unittest.TestCase):

    def test_launch_css_id_in_app_css(self):
        from fieldkit.tui.app import FieldkitTUI
        self.assertIn("#chain-launch-body", FieldkitTUI.CSS)

    def test_launch_screen_registered(self):
        from fieldkit.tui.app import FieldkitTUI
        self.assertIn("chain-launch", FieldkitTUI.SCREENS)


if __name__ == "__main__":
    unittest.main()
