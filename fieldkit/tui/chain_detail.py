"""Chain-detail screen — Textual counterpart to `fieldkit chain show`.

Renders one recorded chain: header, per-step trail with outcome
markers + costs, per-step signal breakdown (sourced from the
live profile registry so an evolved catalog reflects), + a
"resume" affordance when the chain is in_progress.

Push-only — construction takes ``chain_id``, so this screen
isn't in App.SCREENS. Callers push it via
``app.push_screen(ChainDetailScreen(chain_id))``. A follow-up
slice can wire this into the dashboard's ChainsBlock via a
per-row keypress.
"""
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical
from textual.screen import Screen
from textual.widgets import Footer, Static

from . import theme
from ..state import Store, default_db_path


class ChainDetailScreen(Screen):
    """Per-chain trail + signal breakdown + resume affordance.

    Construction:

        screen = ChainDetailScreen(chain_id=42, db_path=None)
        app.push_screen(screen)

    ``db_path`` defaults to :func:`default_db_path` — leave it None
    unless a test injects a fixture store path.
    """

    BINDINGS = [
        Binding("r",      "resume",         "resume",       show=True),
        Binding("q",      "app.pop_screen", "back",         show=True),
        Binding("escape", "app.pop_screen", "back",         show=False),
        Binding("d",      "app.switch_screen('dashboard')", "dashboard", show=False),
        Binding("?",      "app.push_screen('help')", "help", show=False),
    ]

    def __init__(self, chain_id, db_path=None):
        super().__init__()
        self._chain_id = chain_id
        self._db_path = db_path
        self._data = None      # populated on mount by _load()

    def compose(self) -> ComposeResult:
        with Vertical(id="frame"):
            with Container(id="chain-detail-body"):
                yield Static("", id="chain-detail-header")
                yield Static("", id="chain-detail-trail")
                yield Static("", id="chain-detail-signals")
                yield Static("", id="chain-detail-hint")
            yield Footer()

    def on_mount(self):
        self._load()
        self._render()

    def _load(self):
        """Read the chain row + trail from the store. Also pull the
        live-profile step catalog when the profile is still
        registered so the signals rendering reflects any evolved
        catalog. Populates ``self._data`` — a dict-of-dicts,
        deliberate rather than an object graph so tests can
        construct it directly."""
        db = self._db_path or default_db_path()
        try:
            store = Store.open(db)
        except Exception:                                       # noqa: BLE001
            self._data = {"error": f"no engagement at {db}"}
            return
        try:
            row = store.chain_by_id(self._chain_id)
            if row is None:
                self._data = {"error": f"no chain #{self._chain_id}"}
                return
            trail = store.chain_step_trail(self._chain_id)
            live_steps_by_name = {}
            try:
                from .. import chain as chain_mod
                factory = chain_mod.profile(row["profile"])
                live = factory(row["target"])
                live_steps_by_name = {s.name: s for s in live.steps}
            except Exception:                                    # noqa: BLE001
                # Profile dropped from registry — trail still
                # renders; signals block just says "no live catalog".
                pass
            self._data = {"row": dict(row), "trail": trail,
                            "live_steps_by_name": live_steps_by_name}
        finally:
            store.close()

    def _render(self):
        if not self._data or "error" in (self._data or {}):
            msg = (self._data or {}).get("error",
                                          "chain data not loaded")
            self.query_one("#chain-detail-header", Static).update(
                f"\n  [{theme.C.CRIT}]{msg}[/]")
            return
        row = self._data["row"]
        trail = self._data["trail"]
        live = self._data["live_steps_by_name"]

        # Header
        status_colour = {
            "proven":       theme.C.GOOD,
            "in_progress":  theme.C.WARN,
            "aborted":      theme.C.CRIT,
        }.get(row["status"], theme.C.INK_DIM)
        header = (
            f"\n  [{theme.C.ACCENT} bold]{theme.G.ACTION} "
            f"chain #{row['id']}[/]  "
            f"[{theme.C.INK}]{row['profile']}[/] → "
            f"[{theme.C.INK}]{row['target']}[/]\n"
            f"  [{theme.C.INK_DIM}]status = [{status_colour}]"
            f"{row['status']}[/][/]   "
            f"[{theme.C.INK_DIM}]detection debt = "
            f"[bold]{row['total_detection_cost']}[/][/]\n"
        )
        if row.get("aborted_reason"):
            header += (f"  [{theme.C.CRIT}]aborted:[/] "
                       f"{row['aborted_reason']}\n")
        self.query_one("#chain-detail-header", Static).update(header)

        # Trail
        marker = {
            "ok":       ("[{}]+[/]", theme.C.GOOD),
            "manual":   ("[{}]?[/]", theme.C.WARN),
            "skip":     ("[{}]-[/]", theme.C.INK_DIM),
            "fail":     ("[{}]X[/]", theme.C.CRIT),
        }
        trail_lines = ["  trail:"]
        for t in trail:
            fmt, col = marker.get(t["outcome_kind"],
                                    ("[{}]?[/]", theme.C.INK_DIM))
            marker_txt = fmt.format(col)
            ev = (t.get("evidence") or "")[:70]
            trail_lines.append(
                f"    {marker_txt} {t['idx']:>2}. "
                f"{t['step_name']:<30}  "
                f"[{theme.C.INK_DIM}][{t['step_kind']:14s}][/]  "
                f"cost={t['detection_cost']:>2}   "
                f"[{theme.C.INK_DIM2}]{ev}[/]")
        self.query_one("#chain-detail-trail", Static).update(
            "\n".join(trail_lines))

        # Signals — pulled from live profile so an evolved
        # catalog reflects. When the profile is dropped, the
        # block just says so.
        sig_lines = ["\n  detection signals:"]
        if not live:
            sig_lines.append(f"    [{theme.C.INK_DIM}]"
                              "(profile no longer registered — no "
                              "live catalog)[/]")
        else:
            any_signal = False
            for t in trail:
                step = live.get(t["step_name"])
                if step is None or not step.signals:
                    continue
                any_signal = True
                sig_lines.append(
                    f"    [{theme.C.ACCENT}]{t['step_name']}[/]:")
                for sig in step.signals:
                    note = f"  # {sig.note}" if sig.note else ""
                    count = f" ×{sig.count}" if sig.count != 1 else ""
                    sig_lines.append(
                        f"      [{theme.C.INK_DIM}]{sig.kind:14s}[/] "
                        f"{sig.identifier}{count}{note}")
            if not any_signal:
                sig_lines.append(f"    [{theme.C.INK_DIM}]"
                                  "(no per-step signals recorded)[/]")
        self.query_one("#chain-detail-signals", Static).update(
            "\n".join(sig_lines))

        # Hint — the resume affordance is only meaningful when
        # in_progress. Different message per status.
        if row["status"] == "in_progress":
            hint = (f"\n  [{theme.C.WARN}]▶ press r to resume this chain[/]  "
                    f"[{theme.C.INK_DIM}](same walker as "
                    f"`fieldkit chain resume`)[/]")
        else:
            hint = (f"\n  [{theme.C.INK_DIM}]"
                    f"chain is {row['status']} — no resume affordance.[/]")
        self.query_one("#chain-detail-hint", Static).update(hint)

    def action_resume(self):
        """Push a ChainRunScreen seeded from the resumed chain when
        the chain is in_progress. No-op otherwise."""
        if not self._data or "row" not in self._data:
            return
        row = self._data["row"]
        if row["status"] != "in_progress":
            return
        # Reconstruct via chain.resume so the outcomes are seeded
        # from the persisted trail before ChainRunScreen picks up.
        # Same walker semantics as CLI's `chain resume`.
        db = self._db_path or default_db_path()
        try:
            store = Store.open(db)
        except Exception:                                       # noqa: BLE001
            return
        try:
            from .. import chain as chain_mod
            resumed = chain_mod.resume(store, self._chain_id)
        except Exception:                                       # noqa: BLE001
            return
        finally:
            store.close()
        # Hand off to a ChainRunScreen already stamped with the
        # persisted-id + pre-walked outcomes. ChainRunScreen's
        # _build_chain rebuilds from profile+target; we override
        # the built chain with the resumed one via a post-mount
        # hook.
        from .chain_run import ChainRunScreen
        ctx = {"db_path": db,
                "engagement_name": getattr(self.app,
                                             "engagement_name",
                                             "")}
        run_screen = ChainRunScreen(profile_name=resumed.profile,
                                     target=resumed.target, ctx=ctx)
        # Seed the walker's chain state so _build_chain sees the
        # resumed outcomes; ChainRunScreen's on_mount rebuilds a
        # fresh chain, so we monkey-patch _build_chain to install
        # the resumed one.
        def _install_resumed(self=run_screen, resumed=resumed):
            self._chain = resumed
            self._step_states = []
            for i in range(len(resumed.steps)):
                if i < len(resumed.outcomes):
                    self._step_states.append(resumed.outcomes[i].kind)
                else:
                    self._step_states.append("queued")
        run_screen._build_chain = _install_resumed
        self.app.push_screen(run_screen)


#: CSS additions for the chain-detail screen.
CHAIN_DETAIL_TCSS = """
#chain-detail-body {
    padding: 1 0 0 0;
}
#chain-detail-body > Static {
    height: auto;
    padding: 0 2;
}
"""
