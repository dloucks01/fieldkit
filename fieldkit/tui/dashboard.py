"""Dashboard screen — the returning-operator view.

Answers three questions in one glance (per §6 of the design brief):

  * where is the engagement — phase name + hot hosts;
  * what's the next move — top 3 ranked, with severity + axes + next-step;
  * what am I burning through — detection budget (Phase D placeholder here).

The screen is a thin renderer over :class:`~fieldkit.tui.data.DashboardData`.
An auto-refresh timer (:data:`REFRESH_SECS`) re-queries every few seconds so
new state from another terminal (a `fieldkit escalate` in-flight, a spray
that just promoted a cred) surfaces without a manual reload. All state
reads flow through :func:`~fieldkit.tui.data.dashboard`; no engine logic
lives in this file.
"""
from datetime import datetime, timezone

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical
from textual.reactive import reactive
from textual.screen import Screen
from textual.widgets import Footer, Static

from . import data as tui_data
from . import theme

#: Poll interval for the dashboard's auto-refresh. Cheap on a single-op DB.
REFRESH_SECS = 2.0


# --- helpers ---------------------------------------------------------------

def _fmt_int(n):
    """A single integer for the counts row — tabular alignment happens in CSS."""
    return f"{n:>3}"


def _accent(text):
    """Rich-markup a string in the accent color, bold. Every widget that wants
    on-brand emphasis routes through this so we can retune globally later."""
    return f"[bold {theme.C.ACCENT}]{text}[/]"


def _dim(text):
    return f"[{theme.C.INK_DIM}]{text}[/]"


def _dim2(text):
    return f"[{theme.C.INK_DIM2}]{text}[/]"


def _severity_line(exploitability, safety, detection):
    """The 'axes' line: severity dots + text. Uses the palette so the density
    reads before the words."""
    color = theme.severity_color(exploitability)
    dots = theme.severity_dots(
        "critical" if exploitability == "high" and safety == "config-change"
        else "high" if exploitability == "high"
        else "medium" if exploitability == "medium"
        else "low")
    return (f"[bold {color}]{dots}[/]  "
            f"[{color}]{exploitability}[/] · {safety} · {detection}")


# --- title bar (same shape as app.TitleBar but bound to our data) ----------

class DashboardTitleBar(Static):
    """FIELDKIT · <engagement> ················· <utc timestamp>."""

    engagement = reactive("")

    def on_mount(self):
        self.set_interval(1.0, self._tick)
        self._tick()

    def watch_engagement(self, _old, _new):
        # Reactive-updated the moment refresh_data assigns the engagement name,
        # so the first paint doesn't briefly show "(no engagement)".
        self._tick()

    def _tick(self):
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d · %H:%M UTC")
        eng = self.engagement or "(no engagement)"
        self.update(
            f"[bold]FIELDKIT[/bold] · [bold]{eng}[/bold]"
            f"      [{theme.C.INK_DIM}]{now}[/]")


# --- content blocks --------------------------------------------------------

class MetaBlock(Static):
    """engagement / database / config summary lines."""

    def render_from(self, d):
        engagement = d.engagement_name or "(no engagement)"
        db = d.db_path or "(no db)"
        phase = d.phase_name or "setup"
        lines = [
            f"  [{theme.C.INK_DIM}]engagement[/]    [bold]{engagement}[/]"
            f"          [{theme.C.INK_DIM}]phase[/]   {_accent(phase)}",
            f"  [{theme.C.INK_DIM}]database[/]      [bold]{db}[/]",
            f"  [{theme.C.INK_DIM}]hint[/]          [{theme.C.INK_DIM2}]{d.phase_hint}[/]",
        ]
        self.update("\n".join(lines))


class CountsBlock(Static):
    """The one-line count row — HOSTS SERVICES CREDS ADMIN PWND.

    Each column is a fixed :data:`_COL_W` characters wide with label + value
    centered inside. Manual space-padding (the previous approach) broke as
    soon as a count went above single digits — 103 hosts and 0/0 admin were
    both off-center. Centering in a known width is guaranteed correct.
    """

    _COL_W = 12    # cells per column; five columns → 60 char inner width

    def render_from(self, d):
        c = d.counts
        pwnd = len(d.pwned_hosts)
        labels = ["HOSTS", "SERVICES", "CREDS", "ADMIN", "PWND"]
        values = [
            str(c["hosts"]),
            str(c["services"]),
            str(c["credentials"]),
            f"{c.get('admin_access', 0)}/{c.get('access', 0)}",
            str(pwnd),
        ]
        # centered-in-column, then wrap the individual cells in style spans
        top = "  " + "".join(
            f"[{theme.C.INK_DIM}]{lbl.center(self._COL_W)}[/]"
            for lbl in labels)
        # PWND value takes the accent when non-zero — the eye tracks proven wins
        def _style(i, v):
            if i == len(values) - 1 and pwnd:
                return f"[bold {theme.C.ACCENT}]{v.center(self._COL_W)}[/]"
            return f"[bold]{v.center(self._COL_W)}[/]"
        bot = "  " + "".join(_style(i, v) for i, v in enumerate(values))
        self.update(f"\n{top}\n{bot}\n")


class TopMovesBlock(Static):
    """Section header + up to three ranked moves. Each move renders as four
    lines at a uniform indent (6 chars) so a vertical scan reads the same
    left-edge across every move — the header is unindented within its section
    padding, everything below aligns to its indent."""

    _INDENT = "      "     # 6 chars: matches the visual bay under "▸ TOP MOVES"

    def render_from(self, d):
        header = f"  {_accent(theme.G.ACTION + ' TOP MOVES')}"
        if not d.top_moves:
            self.update(
                f"\n{header}\n\n{self._INDENT}"
                f"[{theme.C.INK_DIM2}]no opportunities yet — spray or ingest a "
                f"recce bridge to populate.[/]\n")
            return
        parts = [f"\n{header}\n"]
        for m in d.top_moves:
            title = m["title"]
            host = m.get("host") or "—"
            axes_line = _severity_line(
                m.get("exploitability", "medium"),
                m.get("safety", "read-only"),
                m.get("detection", "quiet"))
            score = m.get("score", 0)
            next_step = m.get("next_step", "")
            parts.append(f"{self._INDENT}{axes_line}")
            parts.append(f"{self._INDENT}[bold]{title}[/]")
            parts.append(f"{self._INDENT}[{theme.C.INK_DIM}]{host}[/]  "
                         f"[{theme.C.INK_DIM2}]· score {score}[/]")
            if next_step:
                parts.append(f"{self._INDENT}"
                             f"{_accent(theme.G.ROUTE + '  ' + next_step)}")
            parts.append("")
        self.update("\n".join(parts))


class PwnedBlock(Static):
    """List of admin hosts, one per line, DC-marked. Consistent 6-char indent
    matches every other section's content bay."""

    _INDENT = "      "

    def render_from(self, d):
        header = f"  {_accent(theme.G.ACTION + ' PWNED')}"
        if not d.pwned_hosts:
            self.update(f"\n{header}\n{self._INDENT}"
                        f"[{theme.C.INK_DIM2}]no hosts pwned yet.[/]")
            return
        lines = [f"\n{header}"]
        for h in d.pwned_hosts:
            label = h["hostname"] or ""
            ip = h["ip"]
            dc_tag = f"  [{theme.C.GOOD}]{theme.G.PROVEN} DC[/]" if h["is_dc"] else ""
            lines.append(
                f"{self._INDENT}[bold]{label:<10}[/]"
                f"[{theme.C.INK_DIM}]{ip}[/]{dc_tag}")
        self.update("\n".join(lines))


class DetectionBlock(Static):
    """Placeholder for the detection-ledger sparkline (Phase D)."""

    def render_from(self, d):
        # Detection ledger lands in Phase D; render honest placeholder until then.
        # Header on its own line, content indented — matches every other section.
        self.update(
            f"\n  {_accent(theme.G.ACTION + ' DETECTION')}\n"
            f"      [{theme.C.INK_DIM2}]ledger — Phase D. "
            f"Every action captured to the step table.[/]")


class PreflightBlock(Static):
    """Shows required tools missing (nxc, impacket-secretsdump, etc.)."""

    def render_from(self, d):
        if not d.preflight_missing:
            self.update("")
            return
        names = ", ".join(m["tool"] for m in d.preflight_missing)
        self.update(
            f"\n  [{theme.C.CRIT}]{theme.G.CAUGHT} required tools missing:[/]"
            f" [{theme.C.INK}]{names}[/]"
            f"    [{theme.C.INK_DIM2}]— run `fieldkit preflight`.[/]"
        )


# --- the screen ------------------------------------------------------------

class DashboardScreen(Screen):
    """The returning-operator view. Ship 2 of Phase A3d."""

    BINDINGS = [
        Binding("a", "app.switch_screen('analyze')",  "analyze"),
        Binding("e", "app.switch_screen('escalate')", "escalate"),
        Binding("w", "app.switch_screen('watch')",    "watch"),
        Binding("r", "refresh",                        "refresh"),
        Binding("?", "app.push_screen('help')",       "help"),
        Binding("q", "app.quit",                      "quit"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="frame"):
            yield DashboardTitleBar(id="title-bar")
            with Container(id="dashboard-body"):
                yield MetaBlock(id="meta")
                yield Static(f"  [{theme.C.RULE}]" + "─" * 68 + "[/]", classes="rule-line")
                yield CountsBlock(id="counts")
                yield Static(f"  [{theme.C.RULE}]" + "─" * 68 + "[/]", classes="rule-line")
                yield TopMovesBlock(id="top-moves")
                yield Static(f"  [{theme.C.RULE}]" + "─" * 68 + "[/]", classes="rule-line")
                yield PwnedBlock(id="pwned")
                yield DetectionBlock(id="detection")
                yield PreflightBlock(id="preflight")
        yield Footer()

    def on_mount(self):
        self.refresh_data()
        self.set_interval(REFRESH_SECS, self.refresh_data)

    def action_refresh(self):
        self.refresh_data()

    def refresh_data(self):
        """Re-query the store and push data into every block. Cheap because
        DashboardData is a plain dataclass and Static.update is O(1)."""
        d = tui_data.dashboard(self.app._db_path)
        self.query_one(DashboardTitleBar).engagement = d.engagement_name
        self.query_one(MetaBlock).render_from(d)
        self.query_one(CountsBlock).render_from(d)
        self.query_one(TopMovesBlock).render_from(d)
        self.query_one(PwnedBlock).render_from(d)
        self.query_one(DetectionBlock).render_from(d)
        self.query_one(PreflightBlock).render_from(d)


#: CSS additions for the Dashboard — merged into APP_TCSS at import so the
#: theme.py file stays the single source for the shell.
DASHBOARD_TCSS = """
#dashboard-body {
    padding: 1 0 0 0;
}
#dashboard-body > Static {
    height: auto;
}
.rule-line {
    height: 1;
    margin: 1 0;
}
"""
