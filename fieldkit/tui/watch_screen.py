"""Watch screen — live JSONL event tail from the engagement.

Polls :mod:`fieldkit.watch` on the app's asyncio loop and streams new events
into a RichLog. Rows are styled per event kind (per §9 of the design brief):

  * ``▸ step`` in accent    — a captured command
  * ``● access``, ``● cred``, ``● loot`` in good — new state landing
  * ``★ finding`` in good   — a finding row appeared (proven or observation)
  * ``⚠ step CAUGHT``       — a step whose exit code / output looks like a
                              detection (marked in critical color for the
                              full row so the operator can spot it at a scan)

Auto-scrolls with new events; ``s`` pauses / resumes; ``c`` clears the view;
``esc`` returns to Dashboard. ``r`` forces an immediate poll cycle.

Reads state directly from the shared SQLite DB — a `fieldkit escalate` or
`fieldkit spray` running in another terminal writes rows the watcher sees on
its next poll (interval :data:`POLL_SECS`).
"""
from datetime import datetime

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Footer, RichLog, Static

from ..state import Store, default_db_path
from ..watch import EVENT_KINDS, _empty_cursors, poll_once
from . import theme

#: How often the poller ticks. Fast enough for a lively terminal, slow enough
#: that the sqlite reads don't spike CPU on an idle engagement.
POLL_SECS = 0.25


# --- formatting helpers ----------------------------------------------------

def _time_of(ts):
    """Extract a HH:MM:SS from an ISO timestamp; falls back to raw on parse fail."""
    if not ts:
        return "--:--:--"
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%H:%M:%S")
    except ValueError:
        return ts[-8:]


def _pad(s, w):
    """Trim or pad-right to exactly `w` visible chars — Rich markup doesn't
    count toward width, so we pad the plain string first, then wrap in style."""
    if len(s) > w:
        return s[: w - 1] + "…"
    return s.ljust(w)


def _host_label(store_row_cache, host_id):
    """Return the best available label for a host_id: hostname or ip.
    Uses a per-tick dict cache so repeated events on the same host don't
    each hit the DB."""
    if host_id is None:
        return "—"
    return store_row_cache.get(host_id, f"host#{host_id}")


def _fmt_step(event, hosts):
    """Render a captured command step. CAUGHT (non-zero exit or evasion catch)
    goes red across the row so the operator can pick it out of the stream."""
    tstamp = _time_of(event["ts"])
    kind_label = "step"
    where = f"{event.get('transport') or '?'}@{_host_label(hosts, event['host_id'])}"
    cmd = event["cmd"] or ""
    exit_code = event.get("exit_code")
    # CAUGHT: exit != 0 (and not None), OR transport contains 'caught' marker
    caught = exit_code not in (0, None)
    glyph = theme.G.CAUGHT if caught else theme.G.ACTION
    result = f"exit {exit_code}" if exit_code == 0 else (
        f"CAUGHT (exit {exit_code})" if caught else "—")

    # Layout: time · glyph+kind · where · cmd · result
    time_s = f"[{theme.C.INK_DIM}]{tstamp}[/]"
    glyph_s = (f"[{theme.C.CRIT}]{glyph} {_pad(kind_label, 7)}[/]" if caught
               else f"[{theme.C.ACCENT}]{glyph} {_pad(kind_label, 7)}[/]")
    where_s = f"[{theme.C.INK}]{_pad(where, 22)}[/]"
    cmd_s = (f"[{theme.C.CRIT}]{_pad(cmd, 40)}[/]" if caught
             else f"[{theme.C.INK}]{_pad(cmd, 40)}[/]")
    result_s = (f"[{theme.C.CRIT}]{result}[/]" if caught
                else f"[{theme.C.GOOD}]{result}[/]" if exit_code == 0
                else f"[{theme.C.INK_DIM2}]{result}[/]")
    return f"{time_s}  {glyph_s} {where_s} {cmd_s} {result_s}"


def _fmt_finding(event, hosts):
    tstamp = _time_of(event["ts"])
    where = _host_label(hosts, event["host_id"])
    title = event.get("title") or "(no title)"
    sev = (event.get("severity") or "info").lower()
    sev_color = theme.severity_color(sev)
    glyph = theme.G.PROVEN if event.get("proven") else theme.G.OBSERVATION
    tag = "proven" if event.get("proven") else "observed"
    return (
        f"[{theme.C.INK_DIM}]{tstamp}[/]  "
        f"[{theme.C.GOOD}]{glyph} {_pad('finding', 7)}[/] "
        f"[{theme.C.INK}]{_pad(where, 22)}[/] "
        f"[{sev_color}]{theme.severity_dots(sev)}[/] "
        f"[{theme.C.INK}]{_pad(title, 38)}[/] "
        f"[{theme.C.GOOD}]{tag}[/]")


def _fmt_credential(event, _hosts):
    tstamp = _time_of(event["ts"])
    principal = ((event.get("domain") or "") + "\\" if event.get("domain")
                 else "") + (event.get("username") or "?")
    stype = event.get("secret_type") or "?"
    src = event.get("source") or "?"
    return (
        f"[{theme.C.INK_DIM}]{tstamp}[/]  "
        f"[{theme.C.GOOD}]{theme.G.SEV_ON} {_pad('cred', 7)}[/] "
        f"[{theme.C.INK}]{_pad(principal, 22)}[/] "
        f"[{theme.C.INK_DIM}]{_pad(stype, 12)}[/] "
        f"[{theme.C.INK_DIM2}](from {src})[/]")


def _fmt_access(event, hosts):
    tstamp = _time_of(event["ts"])
    where = _host_label(hosts, event["host_id"])
    method = event.get("method") or "?"
    admin_tag = (f"  [{theme.C.ACCENT}]admin[/]"
                 if event.get("admin") else "")
    return (
        f"[{theme.C.INK_DIM}]{tstamp}[/]  "
        f"[{theme.C.GOOD}]{theme.G.SEV_ON} {_pad('access', 7)}[/] "
        f"[{theme.C.INK}]{_pad(where, 22)}[/] "
        f"[{theme.C.INK_DIM}]{method}[/]{admin_tag}")


def _fmt_loot(event, hosts):
    tstamp = _time_of(event["ts"])
    where = _host_label(hosts, event["host_id"])
    kind = event.get("kind") or "?"
    return (
        f"[{theme.C.INK_DIM}]{tstamp}[/]  "
        f"[{theme.C.GOOD}]{theme.G.SEV_ON} {_pad('loot', 7)}[/] "
        f"[{theme.C.INK}]{_pad(where, 22)}[/] "
        f"[{theme.C.INK_DIM}]{kind}[/]")


_FORMATTERS = {
    "step":       _fmt_step,
    "finding":    _fmt_finding,
    "credential": _fmt_credential,
    "access":     _fmt_access,
    "loot":       _fmt_loot,
}


# --- watch screen ----------------------------------------------------------

class WatchScreen(Screen):
    """Live event tail. Ship 3 of Phase A3d."""

    BINDINGS = [
        Binding("g", "app.switch_screen('dashboard')", "dashboard"),
        Binding("a", "app.switch_screen('analyze')",   "analyze"),
        Binding("e", "app.switch_screen('escalate')",  "escalate"),
        Binding("s", "toggle_pause",                    "pause"),
        Binding("c", "clear_log",                       "clear"),
        Binding("r", "poll_now",                        "refresh"),
        Binding("?", "app.push_screen('help')",         "help"),
        Binding("q", "app.quit",                        "quit"),
    ]

    def __init__(self):
        super().__init__()
        self._cursors = _empty_cursors()
        self._paused = False
        self._events_seen = 0
        self._primed = False   # whether we've done the "from-now" prime

    def compose(self) -> ComposeResult:
        with Vertical(id="frame"):
            yield WatchTitleBar(id="title-bar")
            yield RichLog(id="event-log", highlight=False, markup=True,
                          auto_scroll=True, wrap=False, max_lines=2000)
            yield WatchStatusBar(id="watch-status")
        yield Footer()

    def on_mount(self):
        self.query_one(WatchTitleBar).engagement = self.app.engagement_name
        # Prime cursors past existing rows so we only tail NEW events —
        # analogous to `fieldkit watch --json --from-now`. The Dashboard's
        # counts already summarize what's already there; this screen is for
        # the live stream. Header write follows so the operator sees context.
        self._prime_cursors()
        log = self.query_one(RichLog)
        log.write(
            f"[{theme.C.INK_DIM2}]"
            f"— tailing engagement events (from now). "
            f"press [{theme.C.ACCENT}]s[/{theme.C.ACCENT}] to pause, "
            f"[{theme.C.ACCENT}]c[/{theme.C.ACCENT}] to clear, "
            f"[{theme.C.ACCENT}]esc[/{theme.C.ACCENT}] to leave —"
            f"[/]")
        self.set_interval(POLL_SECS, self._tick)
        self._refresh_status()

    def _prime_cursors(self):
        """Skip existing rows so we only emit events newer than now."""
        db = self.app._db_path or default_db_path()
        try:
            store = Store.open(db)
        except Exception:  # noqa: BLE001
            return
        try:
            from ..watch import _query_after
            for kind in EVENT_KINDS:
                rows = _query_after(store, kind, 0)
                self._cursors[kind] = rows[-1]["id"] if rows else 0
            self._primed = True
        finally:
            store.close()

    def _tick(self):
        if self._paused:
            return
        db = self.app._db_path or default_db_path()
        try:
            store = Store.open(db)
        except Exception:  # noqa: BLE001 — a DB not there yet just means quiet tail
            return
        try:
            events, self._cursors = poll_once(store, self._cursors)
            if not events:
                return
            # Build a host_id → label cache for this batch so we don't do N
            # lookups per row.
            host_ids = {e.get("host_id") for e in events if e.get("host_id")}
            host_cache = {}
            for hid in host_ids:
                row = store.host_by_id(hid)
                if row is not None:
                    host_cache[hid] = row["hostname"] or row["ip"]
            log = self.query_one(RichLog)
            for e in events:
                fmt = _FORMATTERS.get(e["event"])
                if fmt is None:
                    continue
                try:
                    line = fmt(e, host_cache)
                except Exception:  # noqa: BLE001 — bad row shouldn't kill the tail
                    line = f"[{theme.C.CRIT}]unrenderable event: {e!r}[/]"
                log.write(line)
                self._events_seen += 1
        finally:
            store.close()
        self._refresh_status()

    def action_toggle_pause(self):
        self._paused = not self._paused
        self._refresh_status()

    def action_clear_log(self):
        self.query_one(RichLog).clear()
        self._events_seen = 0
        self._refresh_status()

    def action_poll_now(self):
        # Force a poll independent of the timer — useful for a "did that
        # step land yet?" nudge.
        self._tick()

    def _refresh_status(self):
        self.query_one(WatchStatusBar).paused = self._paused
        self.query_one(WatchStatusBar).count = self._events_seen


class WatchTitleBar(Static):
    """Same shape as the dashboard's title bar — kept as its own class so a
    later ship can add per-screen decoration (filter indicator, etc.)."""

    from textual.reactive import reactive as _reactive
    engagement = _reactive("")

    def on_mount(self):
        self.set_interval(1.0, self._tick)
        self._tick()

    def watch_engagement(self, _old, _new):
        self._tick()

    def _tick(self):
        now = datetime.utcnow().strftime("%Y-%m-%d · %H:%M UTC")
        eng = self.engagement or "(no engagement)"
        self.update(
            f"[bold]FIELDKIT[/bold] · [bold]{eng}[/bold] "
            f"[{theme.C.INK_DIM}]· Watch[/]"
            f"      [{theme.C.INK_DIM}]{now}[/]")


class WatchStatusBar(Static):
    """Bottom-of-screen status: [live | paused]  · N events since clear."""

    from textual.reactive import reactive as _reactive
    paused = _reactive(False)
    count = _reactive(0)

    def watch_paused(self, _o, _n): self._refresh()
    def watch_count(self, _o, _n): self._refresh()

    def on_mount(self):
        self._refresh()

    def _refresh(self):
        state = (f"[{theme.C.INK_DIM}][[/]"
                 f"[{theme.C.ACCENT}]{theme.G.PAUSED} paused[/]"
                 f"[{theme.C.INK_DIM}]][/]"
                 if self.paused else
                 f"[{theme.C.INK_DIM}][[/]"
                 f"[{theme.C.GOOD}]{theme.G.RUNNING} live[/]"
                 f"[{theme.C.INK_DIM}]][/]")
        self.update(
            f"      {state}"
            f"     [{theme.C.INK_DIM2}]{self.count} event(s) since clear[/]")


#: CSS additions for the Watch screen — merged into APP_TCSS by app.py.
WATCH_TCSS = """
#event-log {
    background: $background;
    color: $foreground;
    scrollbar-background: $background;
    scrollbar-color: $border;
    scrollbar-color-hover: $accent;
    scrollbar-color-active: $accent;
    padding: 1 2;
    height: 1fr;
}
#watch-status {
    height: 1;
    padding: 0 1;
    background: $background;
    color: $foreground-muted;
}
"""
