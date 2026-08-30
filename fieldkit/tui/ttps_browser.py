"""TTPs browser — Textual counterpart to ``fieldkit ttps list/show``.

Two-pane screen: top scrolls the TTP catalog (technique + key +
name + platform + ranking); bottom shows the detail for the
currently-selected TTP (every populated field — same layout as
the CLI show). Filter with ``/`` (opens an Input; typing filters
the list case-insensitively over key/name/technique/tactic).

Push-registered under ``ttps`` so the app-level ``t`` shortcut
switches to it.
"""
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical
from textual.screen import Screen
from textual.widgets import Footer, Input, Static

from . import theme


class TTPsBrowserScreen(Screen):
    """Browse the shipped TTP catalog. Cursor picks a row; the
    detail pane paints the corresponding TTP inline so an operator
    doesn't need to hop screens for each entry."""

    BINDINGS = [
        Binding("j",       "cursor_down", "next",   show=True),
        Binding("down",    "cursor_down", "next",   show=False),
        Binding("k",       "cursor_up",   "prev",   show=True),
        Binding("up",      "cursor_up",   "prev",   show=False),
        Binding("slash",   "focus_filter","filter", show=True),
        Binding("g",       "app.switch_screen('dashboard')", "dashboard", show=False),
        Binding("q",       "app.pop_screen", "back", show=True),
        Binding("escape",  "app.pop_screen", "back", show=False),
        Binding("?",       "app.push_screen('help')", "help", show=False),
    ]

    def __init__(self):
        super().__init__()
        self._all_ttps = []
        self._filtered = []
        self._selected = 0
        self._filter_text = ""

    def compose(self) -> ComposeResult:
        with Vertical(id="frame"):
            with Container(id="ttps-body"):
                yield Static("", id="ttps-header")
                yield Input(value="", placeholder="filter (over key/name/technique/tactic)",
                             id="ttps-filter-input")
                yield Static("", id="ttps-list")
                yield Static("", id="ttps-detail")
            yield Footer()

    def on_mount(self):
        from ..ttps import load_all
        try:
            self._all_ttps = list(load_all())
        except Exception:                                    # noqa: BLE001
            self._all_ttps = []
        self._all_ttps.sort(key=lambda t: (t.technique, t.key))
        self._filtered = list(self._all_ttps)
        self._render()

    # ---------- rendering ---------------------------------------------

    def _render(self):
        self.query_one("#ttps-header", Static).update(self._header())
        self.query_one("#ttps-list", Static).update(self._render_list())
        self.query_one("#ttps-detail", Static).update(self._render_detail())

    def _header(self):
        n = len(self._filtered)
        total = len(self._all_ttps)
        filt = f' filter="{self._filter_text}"' if self._filter_text else ""
        return (f"\n  [{theme.C.ACCENT} bold]{theme.G.ACTION} TTPs[/]  "
                f"[{theme.C.INK_DIM}]{n}/{total} shown{filt}[/]\n"
                f"  [{theme.C.INK_DIM2}]"
                f"j/k select · / filter · q back[/]\n")

    def _render_list(self):
        if not self._filtered:
            return (f"\n  [{theme.C.INK_DIM}]no TTPs match "
                    f"the filter — press / to clear[/]")
        lines = [""]
        # Only render a window around the selection so the list
        # doesn't become 145 rows of noise.
        window = 20
        start = max(0, self._selected - window // 2)
        end = min(len(self._filtered), start + window)
        start = max(0, end - window)                          # shift left when at end
        if start > 0:
            lines.append(f"    [{theme.C.INK_DIM2}]"
                          f"… {start} above …[/]")
        for i in range(start, end):
            t = self._filtered[i]
            marker = (f"[{theme.C.ACCENT}]▸[/]"
                       if i == self._selected else " ")
            lines.append(
                f"    {marker} "
                f"[{theme.C.INK_DIM}]{t.technique:<10}[/]  "
                f"[{theme.C.INK}]{t.key:<42}[/] "
                f"[{theme.C.INK_DIM2}]{t.name[:40]}[/]")
        if end < len(self._filtered):
            lines.append(f"    [{theme.C.INK_DIM2}]"
                          f"… {len(self._filtered) - end} below …[/]")
        return "\n".join(lines)

    def _render_detail(self):
        if not self._filtered:
            return ""
        t = self._filtered[self._selected]
        lines = [f"\n  [{theme.C.RULE}]" + "─" * 66 + "[/]"]
        lines.append(f"  [{theme.C.ACCENT} bold]{t.key}[/]  "
                      f"[{theme.C.INK_DIM}]{t.technique}[/]")
        lines.append(f"  {t.name}")
        r = t.ranking
        lines.append(
            f"  [{theme.C.INK_DIM}]platform:[/] "
            f"{', '.join(t.platform)}   "
            f"[{theme.C.INK_DIM}]tactic:[/] "
            f"{', '.join(t.tactic)}   ")
        lines.append(
            f"  [{theme.C.INK_DIM}]exploit:[/] {r.exploitability}   "
            f"[{theme.C.INK_DIM}]safety:[/] {r.safety}   "
            f"[{theme.C.INK_DIM}]detection:[/] {r.detection}")
        if t.detect and t.detect.value:
            lines.append(f"  [{theme.C.INK_DIM}]detect ({t.detect.kind}):[/]")
            val = t.detect.value
            if isinstance(val, dict):
                for k, v in val.items():
                    lines.append(f"    {k}: {v}")
            else:
                # Some detect kinds carry a scalar (e.g. a command
                # to run) rather than a version-range map.
                lines.append(f"    {val}")
        if t.report and t.report.description:
            desc = t.report.description.strip()
            desc = desc[:280] + ("…" if len(desc) > 280 else "")
            lines.append(f"  [{theme.C.INK_DIM}]description:[/]")
            lines.append(f"    {desc}")
        if t.playbook and t.playbook.steps:
            lines.append(f"  [{theme.C.INK_DIM}]playbook ({len(t.playbook.steps)} steps):[/]")
            for i, s in enumerate(t.playbook.steps[:3], 1):
                snippet = s[:80] + ("…" if len(s) > 80 else "")
                lines.append(f"    {i}. {snippet}")
            if len(t.playbook.steps) > 3:
                lines.append(f"    … + {len(t.playbook.steps) - 3} more "
                              f"(see `fieldkit ttps show {t.key}`)")
        return "\n".join(lines)

    # ---------- actions -----------------------------------------------

    def action_cursor_down(self):
        if self._selected < len(self._filtered) - 1:
            self._selected += 1
            self._render()

    def action_cursor_up(self):
        if self._selected > 0:
            self._selected -= 1
            self._render()

    def action_focus_filter(self):
        self.query_one("#ttps-filter-input", Input).focus()

    def on_input_changed(self, event):
        """Live filter — every keypress in the Input re-filters."""
        self._filter_text = (event.value or "").strip()
        self._apply_filter()
        self._render()

    def _apply_filter(self):
        needle = self._filter_text.lower()
        if not needle:
            self._filtered = list(self._all_ttps)
        else:
            def _match(t):
                hay = (f"{t.key} {t.name} {t.technique} "
                        f"{' '.join(t.tactic)} "
                        f"{t.report.vector_type if t.report else ''}").lower()
                return needle in hay
            self._filtered = [t for t in self._all_ttps if _match(t)]
        # Clamp selection to the new list.
        if self._selected >= len(self._filtered):
            self._selected = max(0, len(self._filtered) - 1)


#: CSS additions for the TTPs browser.
TTPS_BROWSER_TCSS = """
#ttps-body {
    padding: 1 0 0 0;
}
#ttps-body > Static {
    height: auto;
    padding: 0 2;
}
#ttps-filter-input {
    margin: 0 2;
    width: 60;
}
"""
