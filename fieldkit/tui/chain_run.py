"""Chain-run screen — interactive Textual walker for a coerce chain.

Textual counterpart to the CLI `fieldkit chain walk` (C8 slice 4).
Same underlying `fieldkit.chain.walk()` with a `before_step`
callback; the callback here bridges to Textual reactivity — the
screen pauses before each step, renders a big "run this?" prompt,
and consumes the operator's g/s/q keypress before advancing.

Design shape kept deliberately narrow:

  * Renders a single chain plan (profile + target chosen when
    the screen is pushed) with per-step status lines
    (queued / running / ok / manual / skip / fail).
  * The `before_step` callback flips the current step from
    "queued" to "awaiting" and posts a message the screen
    handles by pausing the walker until the operator hits
    g / s / q. Uses a threading.Event to bridge async / sync.
  * The `on_step` callback flips step status to the completed
    kind + rerenders.
  * Walk runs in a Textual worker thread; no async chain module
    needed.

The screen is push-only — the operator navigates to it via a
future dashboard "start walk" affordance, or (for now) via the
programmatic `app.push_screen(ChainRunScreen(...))` in tests +
integration harnesses. Adding a keyboard shortcut for "pick a
profile + target interactively" lands in a subsequent slice
alongside a target-picker widget.
"""
import threading

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical
from textual.screen import Screen
from textual.widgets import Footer, Static

from . import theme


class ChainRunScreen(Screen):
    """Interactive walker for one chain-profile + target.

    Construction:

        screen = ChainRunScreen(profile_name="esc8", target="10.0.0.5",
                                ctx=my_ctx)
        app.push_screen(screen)

    ``ctx`` should be pre-populated with everything the walker's
    steps need (listener_ip, ca_endpoint, cred, domain, etc.).
    The screen doesn't collect those interactively — that's the
    next slice.
    """

    BINDINGS = [
        Binding("g", "go",     "go — run the current step",     show=True),
        Binding("s", "skip",   "skip — advance without running", show=True),
        Binding("q", "quit",   "quit — stop the walk here",     show=True),
        Binding("d", "app.switch_screen('dashboard')",
                "dashboard", show=False),
        Binding("c", "app.switch_screen('chain-plan')",
                "chain-plan", show=False),
        Binding("?", "app.push_screen('help')", "help", show=False),
    ]

    def __init__(self, profile_name, target, ctx):
        super().__init__()
        self._profile_name = profile_name
        self._target = target
        self._ctx = ctx
        # Bridging state — walker thread waits on this event; UI
        # thread sets a decision + signals to unblock.
        self._decision = None
        self._decision_ready = threading.Event()
        self._chain = None      # populated in start_walk
        self._step_states = []  # per-step status strings for rendering

    def compose(self) -> ComposeResult:
        with Vertical(id="frame"):
            with Container(id="chain-run-body"):
                yield Static(self._header(), id="chain-run-header")
                yield Static("", id="chain-run-steps")
                yield Static("", id="chain-run-prompt")
            yield Footer()

    def _header(self):
        return (f"  [{theme.C.ACCENT} bold]chain walk[/] — "
                f"{self._profile_name} against [{theme.C.INK}]"
                f"{self._target}[/]")

    def on_mount(self):
        self._build_chain()
        self._render_steps()
        self._prompt("press [g]o to fire the first step")
        # Kick the walker off in a worker thread so the UI stays
        # responsive during subprocess-heavy steps.
        self.run_worker(self._walk_thread, exclusive=True, thread=True)

    def _build_chain(self):
        from .. import chain as chain_mod
        factory = chain_mod.profile(self._profile_name)
        self._chain = factory(self._target)
        self._step_states = ["queued" for _ in self._chain.steps]

    def _render_steps(self):
        """Render the current step list with per-step status markers."""
        lines = [""]
        markers = {
            "queued":   ("[{}]·[/]", theme.C.INK_DIM),
            "awaiting": ("[{}]?[/]", theme.C.WARN),
            "running":  ("[{}]▶[/]", theme.C.ACCENT),
            "ok":       ("[{}]+[/]", theme.C.GOOD),
            "manual":   ("[{}]?[/]", theme.C.WARN),
            "skip":     ("[{}]-[/]", theme.C.INK_DIM),
            "fail":     ("[{}]X[/]", theme.C.CRIT),
        }
        for i, s in enumerate(self._chain.steps):
            state = self._step_states[i]
            fmt, colour = markers[state]
            marker = fmt.format(colour)
            cost = s.signal_cost if s.signals else s.detection_cost
            lines.append(
                f"    {marker} {s.name:<30}  "
                f"[{theme.C.INK_DIM}][{s.kind:14s}][/]  "
                f"cost={cost:>2}")
        # Trail evidence for completed steps
        self.query_one("#chain-run-steps", Static).update("\n".join(lines))

    def _prompt(self, msg):
        self.query_one("#chain-run-prompt", Static).update(
            f"\n    {msg}")

    # ---------- callback bridge --------------------------------------

    def _before_step(self, chain, step):
        # Find the step index by name (the callback signature doesn't
        # give us the index directly).
        idx = self._chain.current   # walk() uses this to pick the step
        self._step_states[idx] = "awaiting"
        self.app.call_from_thread(self._render_steps)
        self.app.call_from_thread(
            self._prompt,
            f"about to fire step {idx}: [{theme.C.INK}]{step.name}[/]  "
            f"— [g]o / [s]kip / [q]uit")
        # Block until UI thread posts a decision.
        self._decision_ready.wait()
        self._decision_ready.clear()
        decision = self._decision
        self._decision = None
        if decision == "go":
            self._step_states[idx] = "running"
            self.app.call_from_thread(self._render_steps)
        return decision

    def _on_step(self, chain, step, outcome):
        idx = len(chain.outcomes) - 1
        self._step_states[idx] = outcome.kind
        self.app.call_from_thread(self._render_steps)

    def _walk_thread(self):
        from .. import chain as chain_mod
        chain_mod.walk(self._chain, self._ctx,
                        on_step=self._on_step,
                        before_step=self._before_step)
        # Terminal prompt when the walk finishes.
        status = self._chain.status
        debt = self._chain.total_detection_cost
        self.app.call_from_thread(
            self._prompt,
            f"walk complete — status={status}, detection debt={debt}")

    # ---------- action handlers --------------------------------------

    def action_go(self):
        self._decision = "go"
        self._decision_ready.set()

    def action_skip(self):
        self._decision = "skip"
        self._decision_ready.set()

    def action_quit(self):
        self._decision = "stop"
        self._decision_ready.set()


#: CSS additions for the chain-run screen.
CHAIN_RUN_TCSS = """
#chain-run-body {
    padding: 1 0 0 0;
}
#chain-run-body > Static {
    height: auto;
    padding: 0 2;
}
"""
