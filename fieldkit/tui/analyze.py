"""Analyze screen — ranked opportunities with a live detail pane.

Two-pane view per §7 of the design brief: the ranked list up top, the
focused-move detail below. ``j/k`` (and arrow keys) move the highlight; the
detail pane follows. ``⏎`` prints the escalate command as a notification (the
full launcher lands in Ship 5). ``/`` filters by axis-substring; ``esc``
returns to the Dashboard.

Data flows through :func:`fieldkit.tui.data.opportunities` — the screen
holds no engine logic, just rendering + selection state. Refreshes every
few seconds so a new spray/loot round shows up without a manual reload.
"""
from datetime import datetime, timezone

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.reactive import reactive
from textual.screen import Screen
from textual.widgets import Footer, Input, OptionList, Static
from textual.widgets.option_list import Option

from rich.text import Text

from . import data as tui_data
from . import theme

#: Poll the store this often — matches Dashboard's cadence.
REFRESH_SECS = 3.0


def _severity_dot_color(exploitability, safety):
    """The color for the severity-dot cluster on a move — critical when
    high-impact + config-change, warn when high, info when medium."""
    if exploitability == "high" and safety == "config-change":
        return theme.C.CRIT
    if exploitability == "high":
        return theme.C.WARN
    if exploitability == "medium":
        return theme.C.INFO
    return theme.C.INK_DIM


def _severity_dots_for(exploitability, safety):
    """The three-dot cluster to render for a move's ranking tier."""
    if exploitability == "high" and safety == "config-change":
        return theme.severity_dots("critical")
    if exploitability == "high":
        return theme.severity_dots("high")
    if exploitability == "medium":
        return theme.severity_dots("medium")
    return theme.severity_dots("low")


def _build_option_prompt(move, focused=False):
    """Render one move as a multi-line Rich Text. Two lines per move so the
    density matches the mockup and a scan reads dots-then-title."""
    dots = _severity_dots_for(move["exploitability"], move["safety"])
    dot_color = _severity_dot_color(move["exploitability"], move["safety"])
    axes = move["axes"] or (
        f"{move['exploitability']}/{move['safety']}/{move['detection']}")
    title = move["title"]
    host = move.get("host") or "—"
    score = move.get("score", 0)
    text = Text()
    # line 1: dots + axes  (dim rest of line)
    text.append(f"{dots}  ", style=f"bold {dot_color}")
    text.append(axes, style=theme.C.INK_DIM)
    text.append("\n")
    # line 2: score + title + host
    text.append(f"{score:>4}  ", style=theme.C.INK_DIM2)
    text.append(f"{title}", style="bold")
    text.append(f"   {host}", style=theme.C.INK_DIM)
    return text


class AnalyzeTitleBar(Static):
    """FIELDKIT · <engagement> · Analyze ················· <utc timestamp>."""

    engagement = reactive("")
    count = reactive(0)

    def on_mount(self):
        self.set_interval(1.0, self._tick)
        self._tick()

    def watch_engagement(self, _o, _n): self._tick()
    def watch_count(self, _o, _n): self._tick()

    def _tick(self):
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d · %H:%M UTC")
        eng = self.engagement or "(no engagement)"
        count = f"{self.count} move(s) ranked"
        self.update(
            f"[bold]FIELDKIT[/bold] · [bold]{eng}[/bold] "
            f"[{theme.C.INK_DIM}]· Analyze[/]"
            f"     [{theme.C.INK_DIM2}]{count}[/]"
            f"     [{theme.C.INK_DIM}]{now}[/]")


class DetailPane(Static):
    """The bottom pane showing details for the highlighted move."""

    def show(self, move):
        if move is None:
            self.update(
                f"\n  [{theme.C.INK_DIM2}]— no move selected — spray or "
                f"ingest a recce bridge to populate. —[/]")
            return
        lines = []
        lines.append("")
        # Section divider — matches Dashboard's rule style
        lines.append(f"  [{theme.C.RULE}]" + "─" * 66 + f"[/] "
                     f"[{theme.C.ACCENT}]{theme.G.ACTION} SELECTED[/]")
        lines.append("")
        lines.append(f"  [bold]{move['title']}[/]")
        if move.get("detail"):
            lines.append("")
            lines.append(f"  [{theme.C.INK_DIM}]{move['detail']}[/]")
        if move.get("evidence") and move["evidence"] != move.get("detail"):
            lines.append("")
            lines.append(f"  [{theme.C.INK_DIM}]evidence[/]   {move['evidence']}")
        if move.get("host"):
            lines.append(f"  [{theme.C.INK_DIM}]host[/]       "
                         f"[bold]{move['host']}[/]  "
                         f"[{theme.C.INK_DIM2}]· axes {move['axes']}"
                         f" · score {move['score']}[/]")
        if move.get("next_step"):
            lines.append("")
            lines.append(
                f"  [{theme.C.INK_DIM}]next[/]       "
                f"[{theme.C.ACCENT}]{theme.G.ROUTE}  {move['next_step']}[/]")
        if move.get("safe_proof"):
            lines.append("")
            lines.append(
                f"  [{theme.C.INK_DIM}]safe proof[/] "
                f"[{theme.C.INK_DIM2}]{move['safe_proof']}[/]")
        self.update("\n".join(lines))


class AnalyzeScreen(Screen):
    """Ship 4 of Phase A3d — ranked opportunities + detail pane."""

    BINDINGS = [
        Binding("g", "app.switch_screen('dashboard')", "dashboard"),
        Binding("e", "app.switch_screen('escalate')",  "escalate"),
        Binding("w", "app.switch_screen('watch')",     "watch"),
        Binding("j", "cursor_down",                     "down"),
        Binding("k", "cursor_up",                       "up"),
        Binding("slash", "start_filter",                "filter"),
        Binding("escape", "close_filter_or_back",       "back"),
        Binding("enter", "launch_selected",             "escalate this"),
        Binding("r", "refresh",                          "refresh"),
        Binding("?", "app.push_screen('help')",         "help"),
        Binding("q", "app.quit",                         "quit"),
    ]

    def __init__(self):
        super().__init__()
        self._moves = []          # all moves from data.opportunities()
        self._filter = ""          # current filter substring, "" = show all
        self._filter_active = False  # is the filter Input focused

    def compose(self) -> ComposeResult:
        with Vertical(id="frame"):
            yield AnalyzeTitleBar(id="title-bar")
            yield Input(placeholder="filter by title / axis / host …",
                        id="analyze-filter")
            yield OptionList(id="move-list")
            yield DetailPane(id="detail-pane")
        yield Footer()

    def on_mount(self):
        self.query_one(AnalyzeTitleBar).engagement = self.app.engagement_name
        self.query_one(Input).display = False   # filter hidden by default
        self.refresh_data()
        # Focus the OptionList so its native arrow-key nav works alongside our
        # j/k bindings, and so the highlighted cursor doesn't reset on movement.
        self.query_one(OptionList).focus()
        self.set_interval(REFRESH_SECS, self.refresh_data)

    def _visible_moves(self):
        if not self._filter:
            return list(self._moves)
        q = self._filter.lower()
        return [m for m in self._moves
                if q in (m.get("title") or "").lower()
                or q in (m.get("axes") or "").lower()
                or q in (m.get("host") or "").lower()
                or q in (m.get("exploitability") or "").lower()
                or q in (m.get("safety") or "").lower()
                or q in (m.get("detection") or "").lower()]

    def refresh_data(self):
        """Re-query opportunities; keep the current selection if the same
        move survives the refresh (identify by key)."""
        prev_key = None
        opt_list = self.query_one(OptionList)
        if opt_list.highlighted is not None and self._moves:
            visible = self._visible_moves()
            if 0 <= opt_list.highlighted < len(visible):
                prev_key = visible[opt_list.highlighted]["key"]

        self._moves = tui_data.opportunities(self.app._db_path)
        visible = self._visible_moves()

        opt_list.clear_options()
        if visible:
            opt_list.add_options([
                Option(_build_option_prompt(m), id=m["key"]) for m in visible
            ])
            # Restore selection if possible; else land on top row
            if prev_key:
                for i, m in enumerate(visible):
                    if m["key"] == prev_key:
                        opt_list.highlighted = i
                        break
                else:
                    opt_list.highlighted = 0
            else:
                opt_list.highlighted = 0

        self.query_one(AnalyzeTitleBar).count = len(visible)
        self._refresh_detail()

    def _refresh_detail(self):
        opt_list = self.query_one(OptionList)
        visible = self._visible_moves()
        if opt_list.highlighted is None or not visible:
            self.query_one(DetailPane).show(None)
            return
        idx = opt_list.highlighted
        if 0 <= idx < len(visible):
            self.query_one(DetailPane).show(visible[idx])
        else:
            self.query_one(DetailPane).show(None)

    # ---- messages / actions ----

    def on_option_list_option_highlighted(self, _msg):
        # Fires as the cursor moves — detail pane tracks live.
        self._refresh_detail()

    def on_option_list_option_selected(self, _msg):
        # OptionList captures ⏎ for its own select action (posts this message),
        # so the screen's `enter` binding never fires when OptionList has focus.
        # Route the message to the same launcher.
        self.action_launch_selected()

    def action_cursor_down(self):
        # Move highlighted directly — OptionList's own action_cursor_down
        # requires focus and resets highlighted to None when called without it.
        # Modifying the reactive fires watch_highlighted + OptionHighlighted
        # message so our detail pane still follows.
        opt_list = self.query_one(OptionList)
        n = opt_list.option_count
        if n == 0:
            return
        cur = opt_list.highlighted if opt_list.highlighted is not None else -1
        opt_list.highlighted = min(cur + 1, n - 1)

    def action_cursor_up(self):
        opt_list = self.query_one(OptionList)
        n = opt_list.option_count
        if n == 0:
            return
        cur = opt_list.highlighted if opt_list.highlighted is not None else n
        opt_list.highlighted = max(cur - 1, 0)

    def action_start_filter(self):
        inp = self.query_one(Input)
        inp.display = True
        inp.focus()
        self._filter_active = True

    def action_close_filter_or_back(self):
        # If the filter input is open, close it (keeping filter applied); else
        # go back to dashboard.
        if self._filter_active:
            inp = self.query_one(Input)
            inp.display = False
            self._filter_active = False
            self.query_one(OptionList).focus()
        else:
            self.app.switch_screen("dashboard")

    def on_input_changed(self, event):
        if event.input.id == "analyze-filter":
            self._filter = event.value or ""
            self.refresh_data()

    def on_input_submitted(self, event):
        if event.input.id == "analyze-filter":
            self.action_close_filter_or_back()

    def action_refresh(self):
        self.refresh_data()

    def action_launch_selected(self):
        """⏎ on a move — push the Escalate confirm screen (Ship 5)."""
        opt_list = self.query_one(OptionList)
        visible = self._visible_moves()
        if opt_list.highlighted is None or not visible:
            return
        move = visible[opt_list.highlighted]
        from .escalate import EscalateScreen
        self.app.push_screen(EscalateScreen(move))


#: CSS additions for the Analyze screen — merged into APP_TCSS by app.py.
ANALYZE_TCSS = """
#move-list {
    background: $background;
    color: $foreground;
    scrollbar-background: $background;
    scrollbar-color: $border;
    scrollbar-color-hover: $accent;
    scrollbar-color-active: $accent;
    padding: 1 2;
    height: 3fr;
    border: none;
}
#move-list:focus {
    border: none;
}
#move-list > .option-list--option {
    padding: 0 1;
}
#move-list > .option-list--option-highlighted {
    background: $accent 12%;
}
#detail-pane {
    background: $background;
    color: $foreground;
    padding: 0 2;
    height: 2fr;
    border: none;
}
#analyze-filter {
    background: $surface;
    color: $foreground;
    border: none;
    padding: 0 2;
    margin: 0 0 1 0;
    height: 3;
}
#analyze-filter:focus {
    border: none;
    background: $surface;
}
"""
