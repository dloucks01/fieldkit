"""Chain-launch screen — pick a profile + target + ctx, push ChainRunScreen.

The counterpart to chain_plan (which is read-only) and chain_run
(which is push-only, requiring a pre-populated profile + target
+ ctx). This screen collects those interactively.

Beyond target, the launcher collects the most commonly-needed
ctx keys (listener_ip, ca, domain, cred_id) as optional Inputs.
Empty fields are absent from ctx — a step that needs a missing
key still surfaces its need via before_step; the operator can
either supply it out-of-band or answer "skip". So the form is
additive: filling it out means fewer mid-walk stalls, but
leaving it blank is fine too.

The set of collected keys is the intersection of "commonly
needed" and "single-line-input-friendly" — probe ports, relay
ports, capture timeouts all have sensible defaults; relay_mode
+ impersonate + template are picker-worthy but ship as CLI
flags for now.
"""
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical
from textual.screen import Screen
from textual.widgets import Footer, Input, Static

from . import data as tui_data
from . import theme
from ..state import default_db_path


#: The ctx fields the launcher form collects. Order = render
#: order + tab order. Each entry: (ctx_key, label, placeholder,
#: kind — "str" or "int"). Kind "int" empty is None; "int"
#: unparseable stays as the raw string and the step will
#: surface the mismatch.
_CTX_FIELDS = (
    ("listener_ip", "listener-ip", "e.g. 10.0.0.100 (fieldkit reachable IP)", "str"),
    ("ca_endpoint", "ca",          "e.g. ca01.corp.local (esc8)",             "str"),
    ("domain",      "domain",       "e.g. CORP.LOCAL (post-relay steps)",     "str"),
    ("cred_id",     "cred-id",     "credential id from `fieldkit list creds`", "int"),
)


class ChainLaunchScreen(Screen):
    """Pick a chain profile + target + optional ctx and hand off
    to ChainRunScreen.

    Keyboard model:

      * ``j`` / ``k`` (or ↓ / ↑) — move the profile-selection cursor;
      * ``tab``                  — focus the next Input field;
      * ``⏎`` (Enter) on the last Input — launch;
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

    def __init__(self, initial_target="", initial_ctx=None):
        super().__init__()
        self._selected = 0
        self._initial_target = initial_target
        self._initial_ctx = dict(initial_ctx or {})
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
                # Optional ctx fields — the walker uses whatever is
                # populated; empty rows are omitted from ctx.
                yield Static(f"\n  [{theme.C.INK_DIM}]"
                              "optional context (steps that need a "
                              "missing key still prompt via before_step)"
                              ":[/]",
                              id="chain-launch-ctx-label")
                for key, label, placeholder, _kind in _CTX_FIELDS:
                    yield Static(
                        f"  [{theme.C.INK_DIM}]{label}:[/]",
                        id=f"chain-launch-{key}-label")
                    yield Input(
                        value=str(self._initial_ctx.get(key, "") or ""),
                        placeholder=placeholder,
                        id=f"chain-launch-{key}-input")
                yield Static("", id="chain-launch-hint")
            yield Footer()

    def _header(self):
        return (f"\n  [{theme.C.ACCENT} bold]{theme.G.ACTION} chain launch[/]  "
                f"[{theme.C.INK_DIM}]— pick a profile, "
                f"supply target + ctx, launch[/]\n")

    def on_mount(self):
        self._profiles = tui_data.chain_profiles()
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
        """Enter in any Input → launch."""
        self._launch()

    def action_launch(self):
        self._launch()

    def _launch(self):
        """Push a ChainRunScreen with (profile, target, ctx)."""
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

    def _push_run_screen(self, screen):
        self.app.push_screen(screen)

    def _build_ctx(self):
        """Build the walker ctx: base (db_path + engagement_name) plus
        any of the optional form fields the operator filled in.

        Empty inputs are omitted rather than passed as empty strings —
        a walker step that checks ``if ctx.listener_ip:`` will see the
        difference between "empty" and "not provided". Int fields
        parse to int when possible; unparseable ints stay as the raw
        string and the step will surface its complaint.
        """
        try:
            app = self.app
        except Exception:                                       # noqa: BLE001
            app = None
        db_path = getattr(app, "_db_path", None) or default_db_path()
        eng = getattr(app, "engagement_name", "(no engagement)")
        ctx = {"db_path": db_path, "engagement_name": eng}
        for key, _label, _placeholder, kind in _CTX_FIELDS:
            val = self._read_field(key)
            if not val:
                continue
            if kind == "int":
                try:
                    ctx[key] = int(val)
                except ValueError:
                    ctx[key] = val    # step will complain honestly
            else:
                ctx[key] = val
        return ctx

    def _read_field(self, key):
        """Read one ctx-input field's current value (trimmed). Extracted
        so tests can monkey-patch without stubbing query_one for every
        field individually."""
        try:
            widget = self.query_one(f"#chain-launch-{key}-input", Input)
        except Exception:                                       # noqa: BLE001
            return ""
        return (widget.value or "").strip()


#: CSS additions for the chain-launch screen.
CHAIN_LAUNCH_TCSS = """
#chain-launch-body {
    padding: 1 0 0 0;
}
#chain-launch-body > Static {
    height: auto;
    padding: 0 2;
}
#chain-launch-body > Input {
    margin: 0 2;
    width: 60;
}
"""
