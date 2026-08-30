#!/usr/bin/env python3
"""TUI chain-detail screen — Textual counterpart to `chain show`.

C13 slice 4. Push-only screen constructed with a chain_id;
_load reads the store, _render paints header/trail/signals/hint.

Pins:

  * construction with chain_id + db_path;
  * _load populates self._data with row + trail + live_steps;
  * _load with unknown chain_id sets an error;
  * _load with no db at path sets an error;
  * _load with proven chain has live_steps_by_name populated
    (profile still registered);
  * action_resume is no-op on non-in_progress chains;
  * CSS wired into the app CSS aggregate.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class _FakeStatic:
    def __init__(self):
        self.text = None
    def update(self, s):
        self.text = s


def _make_store(test_case):
    tmp = tempfile.TemporaryDirectory()
    test_case.addCleanup(tmp.cleanup)
    from fieldkit.state import Store
    db_path = os.path.join(tmp.name, "e.db")
    s = Store.create(db_path)
    s.init_engagement("test-chain-detail")
    test_case.addCleanup(s.close)
    return s, db_path


def _persist_chain(store, target, outcome_kinds):
    """Reserve + finalize an esc8 chain with the given outcomes."""
    from fieldkit.chain import esc8_chain, Outcome
    ch = esc8_chain(target)
    for k in outcome_kinds:
        ch.outcomes.append(Outcome(kind=k, evidence=f"{k}-evidence"))
    ch.current = len(outcome_kinds)
    if any(o.kind == "fail" for o in ch.outcomes):
        ch.aborted_reason = "test-driven fail"
    cid = store.reserve_chain_id(ch)
    store.finalize_chain(cid, ch)
    return cid


def _fresh_screen(chain_id, db_path):
    from fieldkit.tui.chain_detail import ChainDetailScreen
    screen = ChainDetailScreen(chain_id=chain_id, db_path=db_path)
    # Stub the four Static widgets so _render can paint without
    # a live Textual mainloop.
    statics = {
        "#chain-detail-header":  _FakeStatic(),
        "#chain-detail-trail":   _FakeStatic(),
        "#chain-detail-signals": _FakeStatic(),
        "#chain-detail-hint":    _FakeStatic(),
    }
    screen.query_one = lambda sel, _cls=None: statics[sel]
    screen._fake_statics = statics
    return screen


class LoadTest(unittest.TestCase):

    def test_load_populates_data_for_existing_chain(self):
        s, db = _make_store(self)
        cid = _persist_chain(s, "10.0.0.5", ["ok"] * 3)
        screen = _fresh_screen(cid, db)
        screen._load()
        self.assertIn("row", screen._data)
        self.assertIn("trail", screen._data)
        self.assertIn("live_steps_by_name", screen._data)
        self.assertEqual(len(screen._data["trail"]), 3)

    def test_load_unknown_chain_sets_error(self):
        s, db = _make_store(self)
        screen = _fresh_screen(9999, db)
        screen._load()
        self.assertIn("error", screen._data)
        self.assertIn("no chain", screen._data["error"])

    def test_load_missing_db_sets_error(self):
        # Point at a non-existent DB path; Store.open should raise.
        screen = _fresh_screen(1, "/nonexistent/path/no.db")
        screen._load()
        self.assertIn("error", screen._data)

    def test_load_populates_live_steps_when_profile_registered(self):
        s, db = _make_store(self)
        cid = _persist_chain(s, "10.0.0.5", ["ok"] * 3)
        screen = _fresh_screen(cid, db)
        screen._load()
        # esc8 is a shipped profile → live_steps_by_name populated
        self.assertGreater(len(screen._data["live_steps_by_name"]), 0)
        self.assertIn("preflight:reachability",
                       screen._data["live_steps_by_name"])


class RenderTest(unittest.TestCase):

    def test_render_of_proven_chain_shows_expected_sections(self):
        s, db = _make_store(self)
        cid = _persist_chain(s, "10.0.0.5", ["ok"] * 7)
        screen = _fresh_screen(cid, db)
        screen._load()
        screen._render()
        h = screen._fake_statics["#chain-detail-header"].text
        t = screen._fake_statics["#chain-detail-trail"].text
        sig = screen._fake_statics["#chain-detail-signals"].text
        hint = screen._fake_statics["#chain-detail-hint"].text
        self.assertIn(f"chain #{cid}", h)
        self.assertIn("esc8", h)
        self.assertIn("proven", h)
        self.assertIn("trail:", t)
        self.assertIn("preflight:reachability", t)
        self.assertIn("detection signals:", sig)
        # esc8's coerce:petitpotam has rpc-call signals
        self.assertIn("rpc-call", sig)
        # Non-in_progress → no resume hint
        self.assertIn("no resume affordance", hint)

    def test_render_of_in_progress_chain_shows_resume_hint(self):
        s, db = _make_store(self)
        cid = _persist_chain(s, "10.0.0.5", ["ok"] * 3)
        # Row is in_progress by default with partial outcomes
        screen = _fresh_screen(cid, db)
        screen._load()
        screen._render()
        hint = screen._fake_statics["#chain-detail-hint"].text
        self.assertIn("press r to resume", hint)

    def test_render_of_aborted_chain_shows_aborted_reason(self):
        s, db = _make_store(self)
        cid = _persist_chain(s, "10.0.0.5", ["ok", "fail"])
        screen = _fresh_screen(cid, db)
        screen._load()
        screen._render()
        h = screen._fake_statics["#chain-detail-header"].text
        self.assertIn("aborted", h)
        self.assertIn("test-driven fail", h)

    def test_render_of_error_state_paints_header(self):
        screen = _fresh_screen(1, "/nonexistent/no.db")
        screen._load()
        screen._render()
        h = screen._fake_statics["#chain-detail-header"].text
        # error state → header shows the error
        self.assertTrue(any(term in h.lower()
                             for term in ("no engagement", "error")))


class ResumeActionTest(unittest.TestCase):

    def test_action_resume_no_op_on_proven_chain(self):
        s, db = _make_store(self)
        cid = _persist_chain(s, "10.0.0.5", ["ok"] * 7)
        screen = _fresh_screen(cid, db)
        screen._load()
        # Should not raise even without a live self.app
        try:
            screen.action_resume()
        except Exception as exc:                            # noqa: BLE001
            # NoActiveAppError is fine — we only care that the
            # method returned early WITHOUT touching self.app.
            self.fail(f"action_resume raised on proven chain: {exc}")

    def test_action_resume_no_op_when_data_missing(self):
        from fieldkit.tui.chain_detail import ChainDetailScreen
        screen = ChainDetailScreen(chain_id=1, db_path="/nonexistent")
        # _data is None; action_resume should degrade cleanly.
        screen.action_resume()


class AppIntegrationTest(unittest.TestCase):

    def test_chain_detail_css_included_in_app_css(self):
        from fieldkit.tui.app import FieldkitTUI
        self.assertIn("#chain-detail-body", FieldkitTUI.CSS)


if __name__ == "__main__":
    unittest.main()
