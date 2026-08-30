"""Chain-launch screen — pick a profile + target, push ChainRunScreen.

The counterpart to chain_plan (which is read-only) and chain_run
(which is push-only, requiring a pre-populated profile + target).
This screen collects those interactively:

  * Enumerates every registered chain profile (via
    :func:`fieldkit.tui.data.chain_profiles`) and lets the
    operator pick one with j/k + ⏎;
  * Collects a target string in an Input widget;
  * Assembles a minimal ctx (db_path + engagement_name) and
    pushes ChainRunScreen with the three arguments.

Ctx-collection stays minimal on purpose. The walker's steps that
need per-step values (listener_ip, ca_endpoint, cred, domain)
still surface those via `before_step`, so the operator can either
supply them out-of-band (env vars, config file) or answer "skip"
when the walker asks. A richer ctx-collection form (per-key
prompts) lands in a subsequent slice.
"""
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical
from textual.screen import Screen
from textual.widgets import Footer, Input, Static

from . import data as tui_data
from . import theme
from ..state import default_db_path


class ChainLaunchScreen(Screen):
    """Pick a chain profile + target and hand off to ChainRunScreen.

    Keyboard model:

      * ``j`` / ``k`` (or ↓ / ↑) — move the selection cursor;
      * ``tab``                  — focus the target Input;
      * ``⏎`` (Enter) on Input   — launch;
      * ``l``                    — launch from anywhere on the screen;
      * ``q`` / ``esc``          — back out.
    """

    BINDINGS = [
        Binding("j",      "cursor_down", "next profile", show=True),
        Binding("down",   "cursor_down", "next profile", show=False),
        Binding("k",      "cursor_up",   "prev profile", show=True),
        Binding("up",     "cursor_up",   "prev profile", show=False),
        Binding("l",      "launch",       "launch",       show=True),
        Binding("tab",    "focus_input", "target",       show=True),
        Binding("d",      "app.switch_screen('dashboard')", "dashboard", show=False),
        Binding("c",      "app.switch_screen('chain-plan')", "chain-plan", show=False),
        Binding("q",      "app.pop_screen", "back",       show=True),
        Binding("escape", "app.pop_screen", "back",       show=False),
        Binding("?",      "app.push_screen('help')", "help", show=False),
    ]

    def __init__(self, initial_target=""):
        super().__init__()
        self._selected = 0
        self._initial_target = initial_target
        self._profiles = []

    def compose(self) -> ComposeResult:
        with Vertical(id="frame"):
            with Container(id="chain-launch-body"):
                yield Static(self._header(), id="chain-launch-header")
                yield Static("", id="chain-launch-profiles")
                yield Static(f"\n  [{theme.C.INK_DIM}]target:[/]",
                              id="chain-launch-target-label")
                yield Input(value=self._initial_target,
                             placeholder="e.g. 10.0.0.5",
                             id="chain-launch-target-input")
                yield Static("", id="chain-launch-hint")
            yield Footer()

    def _header(self):
        return (f"\n  [{theme.C.ACCENT} bold]{theme.G.ACTION} chain launch[/]  "
                f"[{theme.C.INK_DIM}]— pick a profile, "
                f"supply a target, launch[/]\n")

    def on_mount(self):
        self._profiles = tui_data.chain_profiles()
        # Clamp selection in case the profile list is short — refresh_data
        # can be called again if profiles are registered mid-session.
        if self._selected >= len(self._profiles):
            self._selected = max(0, len(self._profiles) - 1)
        self._render()

    # ---------- rendering --------------------------------------------

    def _render(self):
        self.query_one("#chain-launch-profiles", Static).update(
            self._render_profiles())
        self.query_one("#chain-launch-hint", Static).update(
            self._render_hint())

    def _render_profiles(self):
        if not self._profiles:
            return f"\n  [{theme.C.INK_DIM}](no chain profiles registered)[/]"
        lines = [""]
        for i, p in enumerate(self._profiles):
            marker = f"[{theme.C.ACCENT}]▸[/]" if i == self._selected \
                else " "
            lines.append(
                f"    {marker} [{theme.C.INK}]{p['name']:<20}[/]  "
                f"[{theme.C.INK_DIM}]{p['step_count']} steps, "
                f"cost={p['total_cost']:>2}[/]")
        return "\n".join(lines)

    def _render_hint(self):
        if not self._profiles:
            return (f"\n  [{theme.C.WARN}]no profiles to launch — "
                    f"register one via fieldkit.chain.register[/]")
        picked = self._profiles[self._selected]["name"] \
            if self._profiles else "(none)"
        return (f"\n  [{theme.C.INK_DIM}]"
                f"j/k select · tab target · l launch · q back[/]\n"
                f"  [{theme.C.INK_DIM}]will launch:[/] "
                f"[{theme.C.ACCENT}]{picked}[/]")

    # ---------- actions -----------------------------------------------

    def action_cursor_down(self):
        if self._profiles and self._selected < len(self._profiles) - 1:
            self._selected += 1
            self._render()

    def action_cursor_up(self):
        if self._selected > 0:
            self._selected -= 1
            self._render()

    def action_focus_input(self):
        self.query_one("#chain-launch-target-input", Input).focus()

    def on_input_submitted(self, event):
        """Enter in the target Input → launch."""
        self._launch()

    def action_launch(self):
        self._launch()

    def _launch(self):
        """Push a ChainRunScreen with the current selection + target."""
        if not self._profiles:
            return
        target = self.query_one("#chain-launch-target-input", Input).value.strip()
        if not target:
            self.query_one("#chain-launch-hint", Static).update(
                f"\n  [{theme.C.WARN}]target is empty — "
                f"type a host and press ⏎ or l[/]")
            return
        profile_name = self._profiles[self._selected]["name"]
        ctx = self._build_ctx()
        from .chain_run import ChainRunScreen
        self._push_run_screen(ChainRunScreen(profile_name=profile_name,
                                              target=target, ctx=ctx))

    # Extracted so tests can monkey-patch the app hop without setting
    # `self.app` (which is a Textual read-only property).
    def _push_run_screen(self, screen):
        self.app.push_screen(screen)

    def _build_ctx(self):
        """Minimal ctx for the walker: db_path + engagement_name.

        Steps that need more (listener_ip, ca_endpoint, cred, domain)
        surface their need via before_step — the operator supplies it
        out-of-band or answers 'skip'.
        """
        # Same reason for the getattr hop: `self.app` is a property
        # that raises NoActiveAppError outside a running app.
        try:
            app = self.app
        except Exception:                                       # noqa: BLE001
            app = None
        db_path = getattr(app, "_db_path", None) or default_db_path()
        eng = getattr(app, "engagement_name", "(no engagement)")
        return {"db_path": db_path, "engagement_name": eng}


#: CSS additions for the chain-launch screen.
CHAIN_LAUNCH_TCSS = """
#chain-launch-body {
    padding: 1 0 0 0;
}
#chain-launch-body > Static {
    height: auto;
    padding: 0 2;
}
#chain-launch-target-input {
    margin: 0 2;
    width: 60;
}
"""
