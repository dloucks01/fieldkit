"""Chain-plan screen — Textual view over `fieldkit chain plan`.

Answers one question in one glance: for each registered chain
profile, what steps will it walk against a target, and how much
detection debt does the whole plan cost. Same output the CLI
`chain plan <profile> <target>` produces, just interactive so an
operator can flip between profiles without re-running the command.

The screen reads from :func:`fieldkit.tui.data.chain_profiles`
(no engine logic in this file) and re-renders on refresh — chain
profiles are module-scoped constants, so refresh is close to
free.

D5 shipped 4 chain profiles (esc8 / rbcd / smb-relay-exec / esc1)
in the fieldkit.chain module; when new profiles land via
:func:`fieldkit.chain.register`, this screen picks them up on
the next re-render without code change.
"""
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical
from textual.screen import Screen
from textual.widgets import Footer, Static

from . import data as tui_data
from . import theme


#: Poll interval for auto-refresh — chain profiles rarely change
#: between refreshes, so we pick a longer interval than the
#: dashboard's REFRESH_SECS. The operator can hit `r` for an
#: immediate refresh anyway.
REFRESH_SECS = 5.0


class ChainPlanScreen(Screen):
    """Renders every registered chain profile + its step plan.

    Layout: one Static per profile, stacked vertically. Each profile
    block shows the profile name + target header, then the ordered
    step list with per-step cost + running-total, then a footer with
    the aggregate detection debt.
    """

    BINDINGS = [
        Binding("d", "app.switch_screen('dashboard')", "dashboard"),
        Binding("a", "app.switch_screen('analyze')",   "analyze"),
        Binding("e", "app.switch_screen('escalate')",  "escalate"),
        Binding("r", "refresh",                         "refresh"),
        Binding("?", "app.push_screen('help')",        "help"),
        Binding("q", "app.quit",                       "quit"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="frame"):
            with Container(id="chain-plan-body"):
                yield Static(self._header(), id="chain-plan-header")
                yield Static("", id="chain-plan-list")
            yield Footer()

    def on_mount(self):
        self.refresh_data()
        self.set_interval(REFRESH_SECS, self.refresh_data)

    def action_refresh(self):
        self.refresh_data()

    def _header(self):
        return (f"  [{theme.C.ACCENT} bold]Chain profiles[/]  "
                f"— registered in `fieldkit.chain`; plan-only view "
                f"(no target ran)\n")

    def refresh_data(self):
        profiles = tui_data.chain_profiles()
        self.query_one("#chain-plan-list", Static).update(
            _render_profiles(profiles))


def _render_profiles(profiles):
    """Text-blob rendering of every profile + its step plan. Kept
    as one big Rich-markup string so the layout stays trivial —
    the Static widget handles wrapping and scrolling."""
    if not profiles:
        return f"  [{theme.C.INK_DIM}](no chain profiles registered)[/]"
    out = []
    for p in profiles:
        out.append(
            f"\n  [{theme.C.ACCENT}]▸ {p['name']}[/]   "
            f"[{theme.C.INK_DIM}]{p['step_count']} steps, "
            f"aggregate detection debt = "
            f"[bold]{p['total_cost']}[/][/]")
        running = 0
        for i, s in enumerate(p["steps"]):
            running += s["cost"]
            marker = "*" if i == 0 else " "
            kind = s["kind"]
            out.append(
                f"     {marker} {i}. "
                f"[{theme.C.INK}]{s['name']:<30}[/]  "
                f"[{theme.C.INK_DIM}][{kind:14s}][/]  "
                f"cost={s['cost']:>2}  running={running:>3}")
    return "\n".join(out)


#: CSS additions for the chain-plan screen — merged into APP_TCSS
#: at import so theme.py stays the single source for the shell.
CHAIN_PLAN_TCSS = """
#chain-plan-body {
    padding: 1 0 0 0;
}
#chain-plan-body > Static {
    height: auto;
}
#chain-plan-list {
    padding: 0 2 1 2;
}
"""
