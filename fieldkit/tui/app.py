"""The fieldkit TUI app — Textual App with four screens + shared frame.

Ship 1 of Phase A3d: the shell. Screens exist and route via the global keymap,
but each is a placeholder pending its own ship (Dashboard = Ship 2, Watch =
Ship 3, Analyze = Ship 4, Escalate launcher = Ship 5). The frame, footer,
palette, and keymap are the design brief's ("The Operator View") load-bearing
elements — those are real from day one so we can react to them.

Every widget reads visual style from :mod:`fieldkit.tui.theme`. The stub
screens deliberately show the frame + a placeholder line + the shortcut hint
in-canvas, so the reader sees what shape the real screen will occupy.
"""
from datetime import datetime, timezone

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.reactive import reactive
from textual.screen import Screen
from textual.widgets import Footer, Static

from ..state import Store, default_db_path
from . import theme


# ---------------------------------------------------------------------------
# Shared frame — every screen wears the same top bar.
# ---------------------------------------------------------------------------

class TitleBar(Static):
    """Top bar: FIELDKIT · <engagement> ····· <utc timestamp>.

    Two updating fields: the engagement name (set once on mount) and the UTC
    clock (updated every second). Style comes from `#title-bar` in APP_TCSS.
    """

    engagement = reactive("")

    def on_mount(self):
        self.set_interval(1.0, self._tick)
        self._tick()

    def _tick(self):
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d · %H:%M UTC")
        eng = self.engagement or "(no engagement)"
        # Rich markup — [color] and [style] literals live only inside these
        # Static widgets, never on raw palette hex — theme.C is still the source.
        self.update(
            f"[bold]FIELDKIT[/bold] · [bold]{eng}[/bold]"
            f"      [dim {theme.C.INK_DIM}]{now}[/]")


# ---------------------------------------------------------------------------
# Screens — one per section of the design brief. Ship 1 = stubs; later ships
# fill in the widgets.
# ---------------------------------------------------------------------------

def _stub_body(name, ships_in):
    """Return a Static filled with an on-brand placeholder for a not-yet-built
    screen. Reads on-palette so the frame + shell already look right."""
    body = (
        f"\n"
        f"    [bold {theme.C.ACCENT}]{theme.G.ACTION} {name.upper()}[/]\n"
        f"\n"
        f"    [dim {theme.C.INK_DIM}]This screen ships in {ships_in}.[/]\n"
        f"    [dim {theme.C.INK_DIM2}]The frame, keymap, and palette are real;\n"
        f"    the content lands with its own commit so you can react\n"
        f"    to one screen at a time.[/]\n"
    )
    return Static(body, classes="stub")


class DashboardScreen(Screen):
    """The returning-operator view. Ship 2."""

    BINDINGS = [
        Binding("a", "app.switch_screen('analyze')", "analyze"),
        Binding("e", "app.switch_screen('escalate')", "escalate"),
        Binding("w", "app.switch_screen('watch')", "watch"),
        Binding("?", "app.push_screen('help')", "help"),
        Binding("q", "app.quit", "quit"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="frame"):
            yield TitleBar(id="title-bar")
            yield _stub_body("Dashboard", "Ship 2")
        yield Footer()

    def on_mount(self):
        self.query_one(TitleBar).engagement = self.app.engagement_name


class AnalyzeScreen(Screen):
    """Ranked opportunities + detail. Ship 4."""

    BINDINGS = [
        Binding("g", "app.switch_screen('dashboard')", "dashboard"),
        Binding("e", "app.switch_screen('escalate')", "escalate"),
        Binding("w", "app.switch_screen('watch')", "watch"),
        Binding("?", "app.push_screen('help')", "help"),
        Binding("q", "app.quit", "quit"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="frame"):
            yield TitleBar(id="title-bar")
            yield _stub_body("Analyze", "Ship 4")
        yield Footer()

    def on_mount(self):
        self.query_one(TitleBar).engagement = self.app.engagement_name


class EscalateScreen(Screen):
    """Confirm-before-fire launcher. Ship 5."""

    BINDINGS = [
        Binding("g", "app.switch_screen('dashboard')", "dashboard"),
        Binding("a", "app.switch_screen('analyze')", "analyze"),
        Binding("w", "app.switch_screen('watch')", "watch"),
        Binding("?", "app.push_screen('help')", "help"),
        Binding("q", "app.quit", "quit"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="frame"):
            yield TitleBar(id="title-bar")
            yield _stub_body("Escalate", "Ship 5")
        yield Footer()

    def on_mount(self):
        self.query_one(TitleBar).engagement = self.app.engagement_name


class WatchScreen(Screen):
    """Live event tail. Ship 3."""

    BINDINGS = [
        Binding("g", "app.switch_screen('dashboard')", "dashboard"),
        Binding("a", "app.switch_screen('analyze')", "analyze"),
        Binding("e", "app.switch_screen('escalate')", "escalate"),
        Binding("?", "app.push_screen('help')", "help"),
        Binding("q", "app.quit", "quit"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="frame"):
            yield TitleBar(id="title-bar")
            yield _stub_body("Watch", "Ship 3")
        yield Footer()

    def on_mount(self):
        self.query_one(TitleBar).engagement = self.app.engagement_name


class HelpScreen(Screen):
    """Translucent-feeling keymap overlay (pushed with ?, closed with esc)."""

    BINDINGS = [
        Binding("escape", "app.pop_screen", "close"),
        Binding("?", "app.pop_screen", "close"),
    ]

    def compose(self) -> ComposeResult:
        body = (
            f"\n"
            f"    [bold {theme.C.ACCENT}]{theme.G.ACTION} KEYMAP[/]\n"
            f"\n"
            f"    [bold]Global[/]\n"
            f"    [{theme.C.ACCENT}]g[/]    Dashboard\n"
            f"    [{theme.C.ACCENT}]a[/]    Analyze\n"
            f"    [{theme.C.ACCENT}]e[/]    Escalate\n"
            f"    [{theme.C.ACCENT}]w[/]    Watch\n"
            f"    [{theme.C.ACCENT}]?[/]    This keymap\n"
            f"    [{theme.C.ACCENT}]esc[/]  Back one screen · close overlay\n"
            f"    [{theme.C.ACCENT}]q[/]    Quit (confirm)\n"
            f"\n"
            f"    [dim {theme.C.INK_DIM2}]More per-screen shortcuts appear in "
            f"each screen's footer.[/]\n"
        )
        with Vertical(id="frame"):
            yield TitleBar(id="title-bar")
            yield Static(body, classes="stub")
        yield Footer()

    def on_mount(self):
        self.query_one(TitleBar).engagement = self.app.engagement_name


# ---------------------------------------------------------------------------
# App — the shell.
# ---------------------------------------------------------------------------

class FieldkitTUI(App):
    """The fieldkit workbench, in a terminal.

    Loads its CSS from :mod:`fieldkit.tui.theme`, registers the four primary
    screens by name, and installs the global keymap. Screens `.switch_screen`
    to each other via the keymap and `.push_screen`/`.pop_screen` for overlays
    (Help). No engine logic here — screens read state directly (Store) for
    display and dispatch subprocess `fieldkit` commands for actions.
    """

    CSS = theme.APP_TCSS
    TITLE = "fieldkit"

    SCREENS = {
        "dashboard": DashboardScreen,
        "analyze":   AnalyzeScreen,
        "escalate":  EscalateScreen,
        "watch":     WatchScreen,
        "help":      HelpScreen,
    }

    BINDINGS = [
        Binding("g", "switch_screen('dashboard')", "dashboard", show=False),
        Binding("a", "switch_screen('analyze')",   "analyze",   show=False),
        Binding("e", "switch_screen('escalate')",  "escalate",  show=False),
        Binding("w", "switch_screen('watch')",     "watch",     show=False),
        Binding("?", "push_screen('help')",        "help",      show=False),
        Binding("q", "quit",                       "quit",      show=False),
        Binding("ctrl+c", "quit",                  "quit",      show=False),
    ]

    def __init__(self, db_path=None):
        super().__init__()
        self._db_path = db_path
        self.engagement_name = "(no engagement)"
        # Register the fieldkit brand theme + set as default HERE (in __init__,
        # after super's built-in-theme registration) rather than in on_mount —
        # Textual parses App.CSS during app startup BEFORE on_mount runs, so a
        # theme registered later would leave `$fk-*` variables unresolved at
        # parse time. Textual's built-in themes remain registered, so Ctrl-P →
        # "Change theme" still works: brand is the default, not the only.
        self.register_theme(theme.FIELDKIT_DARK)
        self.theme = "fieldkit-dark"

    def on_mount(self):
        # Read the engagement name once at startup so the title bar has real
        # content the moment the shell paints. Store failures degrade quietly
        # to "(no engagement)" — the TUI must launch even if the DB is missing
        # or empty, so the operator can see the shell before setting things up.
        try:
            db = self._db_path or default_db_path()
            with Store.open(db) as store:
                row = store.engagement()
                if row:
                    self.engagement_name = row["name"]
        except Exception:  # noqa: BLE001 — startup must not crash on DB state
            pass
        self.push_screen("dashboard")


def run(db_path=None):
    """Entry point wired into the CLI's `fieldkit tui` handler."""
    FieldkitTUI(db_path=db_path).run()
