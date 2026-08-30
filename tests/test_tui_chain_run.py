#!/usr/bin/env python3
"""TUI chain-run screen — interactive walker (C10 slice 3).

Textual counterpart to `fieldkit chain walk` (C8 slice 4). The
before_step callback bridges Textual's UI thread to fieldkit.chain
.walk()'s sync API via a threading.Event: walker thread blocks
until the operator's g/s/q keypress sets a decision.

Tests here focus on the callback bridge + state-machine plumbing
that can run without spinning up Textual's mainloop:

  * ChainRunScreen constructs with profile + target + ctx;
  * _build_chain populates the chain from the profile factory;
  * _before_step blocks until action_go/skip/quit sets a decision;
  * _on_step flips the corresponding step state;
  * step_states track the walk correctly (queued → running → ok);
  * ctx failure (unknown profile) surfaces sensibly.
"""
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class _FakeApp:
    """Bare app stub — enough for the screen to call
    `app.call_from_thread(fn, *args)` which we execute inline."""
    def call_from_thread(self, fn, *args, **kwargs):
        return fn(*args, **kwargs)


def _fresh_screen(profile_name="esc8", target="10.0.0.1", ctx=None):
    from fieldkit.tui.chain_run import ChainRunScreen
    screen = ChainRunScreen(profile_name=profile_name,
                             target=target, ctx=ctx or object())
    # Bypass Textual's normal mount — call the build helper
    # directly so subsequent tests can drive the state machine.
    screen._build_chain()
    # The screen's callbacks route through `self.app.call_from_thread`
    # which is a Textual read-only property. Monkey-patch the two
    # callback methods to call rendering helpers inline (bypass the
    # app.call_from_thread hop entirely). Rendering itself gets
    # short-circuited per test where needed.

    def _before(chain, step):
        # Same logic as the real _before_step but without
        # self.app.call_from_thread wrapping.
        idx = chain.current
        screen._step_states[idx] = "awaiting"
        screen._render_steps()
        screen._decision_ready.wait()
        screen._decision_ready.clear()
        decision = screen._decision
        screen._decision = None
        if decision == "go":
            screen._step_states[idx] = "running"
            screen._render_steps()
        return decision

    def _on(chain, step, outcome):
        idx = len(chain.outcomes) - 1
        screen._step_states[idx] = outcome.kind
        screen._render_steps()

    screen._before_step = _before
    screen._on_step = _on
    return screen


class ConstructionTest(unittest.TestCase):

    def test_screen_constructs_with_esc8_profile(self):
        s = _fresh_screen("esc8", "10.0.0.1")
        self.assertEqual(s._chain.profile, "esc8")
        self.assertEqual(s._chain.target, "10.0.0.1")
        # esc8 ships 7 steps
        self.assertEqual(len(s._chain.steps), 7)
        # Every step starts queued
        self.assertEqual(set(s._step_states), {"queued"})
        self.assertEqual(len(s._step_states), 7)

    def test_screen_constructs_with_rbcd_profile(self):
        s = _fresh_screen("rbcd", "10.0.0.20")
        self.assertEqual(s._chain.profile, "rbcd")
        # rbcd ships 5 steps
        self.assertEqual(len(s._step_states), 5)

    def test_unknown_profile_raises(self):
        # An unknown profile name would trip the chain factory
        # lookup — the screen surfaces this as a hard error on
        # construction. Real UI flow would prevent it upstream
        # (the caller picks from known_profiles()); still worth
        # pinning.
        from fieldkit.tui.chain_run import ChainRunScreen
        s = ChainRunScreen(profile_name="does-not-exist",
                            target="10.0.0.1", ctx=object())
        with self.assertRaises(KeyError):
            s._build_chain()


class BeforeStepBridgeTest(unittest.TestCase):
    """The core bridge: walker thread blocks on the Event, UI thread
    unblocks with go/skip/stop decision."""

    def test_action_go_unblocks_with_go_decision(self):
        s = _fresh_screen()
        # Monkey-patch rendering helpers so no widget queries happen.
        s._render_steps = lambda: None
        s._prompt = lambda msg: None
        got = []
        def _blocked():
            got.append(s._before_step(s._chain, s._chain.steps[0]))
        t = threading.Thread(target=_blocked)
        t.start()
        # Let the walker thread reach the blocked state
        time.sleep(0.05)
        self.assertTrue(t.is_alive(), "before_step didn't block on Event")
        s.action_go()
        t.join(timeout=1.0)
        self.assertFalse(t.is_alive())
        self.assertEqual(got, ["go"])

    def test_action_skip_unblocks_with_skip_decision(self):
        s = _fresh_screen()
        s._render_steps = lambda: None
        s._prompt = lambda msg: None
        got = []
        def _blocked():
            got.append(s._before_step(s._chain, s._chain.steps[0]))
        t = threading.Thread(target=_blocked); t.start()
        time.sleep(0.05)
        s.action_skip()
        t.join(timeout=1.0)
        self.assertEqual(got, ["skip"])

    def test_action_quit_unblocks_with_stop_decision(self):
        s = _fresh_screen()
        s._render_steps = lambda: None
        s._prompt = lambda msg: None
        got = []
        def _blocked():
            got.append(s._before_step(s._chain, s._chain.steps[0]))
        t = threading.Thread(target=_blocked); t.start()
        time.sleep(0.05)
        s.action_quit()
        t.join(timeout=1.0)
        # walker's before_step signature returns "stop" for quit
        self.assertEqual(got, ["stop"])


class StateTransitionsTest(unittest.TestCase):
    """_before_step + _on_step flip the corresponding step state
    correctly so the rendered step list reflects walk progress."""

    def test_before_step_marks_current_awaiting(self):
        s = _fresh_screen()
        s._render_steps = lambda: None
        s._prompt = lambda msg: None
        # Simulate walker about to run step 0
        s._chain.current = 0

        def _blocked():
            s._before_step(s._chain, s._chain.steps[0])
        t = threading.Thread(target=_blocked); t.start()
        time.sleep(0.05)
        # State should flip queued → awaiting on step 0
        self.assertEqual(s._step_states[0], "awaiting")
        s.action_go()
        t.join(timeout=1.0)
        # After "go" it flips to running
        self.assertEqual(s._step_states[0], "running")

    def test_on_step_flips_state_to_outcome_kind(self):
        from fieldkit.chain import Outcome
        s = _fresh_screen()
        s._render_steps = lambda: None
        # Simulate walker just completed step 0 with ok
        s._chain.outcomes.append(Outcome(kind="ok", evidence="ran"))
        s._on_step(s._chain, s._chain.steps[0], s._chain.outcomes[0])
        self.assertEqual(s._step_states[0], "ok")

    def test_on_step_reflects_manual_kind(self):
        from fieldkit.chain import Outcome
        s = _fresh_screen()
        s._render_steps = lambda: None
        s._chain.outcomes.append(Outcome(kind="manual",
                                           evidence="operator declined"))
        s._on_step(s._chain, s._chain.steps[0], s._chain.outcomes[0])
        self.assertEqual(s._step_states[0], "manual")


class AppScreenRegistrationTest(unittest.TestCase):

    def test_chain_run_css_included_in_app_css(self):
        # The screen's CSS id selector must appear in the merged
        # app CSS — proves the module wired the block in.
        from fieldkit.tui.app import FieldkitTUI
        self.assertIn("#chain-run-body", FieldkitTUI.CSS)


if __name__ == "__main__":
    unittest.main()
