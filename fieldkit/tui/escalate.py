"""Escalate confirm screen — the moment the operator commits.

Pushed from Analyze on ⏎ with a highlighted move. Shows target / vector /
transport / safety / detection-forecast / exact CLI command, per §8 of the
design brief. ``y`` spawns the fieldkit escalate subprocess in the background
and switches to Watch so the operator sees each step land in real time.
``n``/``esc`` cancels back to Analyze without firing.

The subprocess pattern (not an in-process call): the escalate loop can run
for minutes; blocking the TUI's asyncio loop would freeze every screen. A
subprocess lets the TUI stay responsive, and the events land in the shared
SQLite DB where Watch picks them up on its next poll.
"""
import os
import shlex
import subprocess
import sys

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Footer, Static

from ..state import Store, default_db_path
from . import theme


def _accent(s): return f"[{theme.C.ACCENT}]{s}[/]"
def _dim(s):    return f"[{theme.C.INK_DIM}]{s}[/]"


def _build_command(move, db_path):
    """Compose the argv fieldkit will run for this move. Returns
    (argv, description) — description names why this argv was chosen so the
    operator sees exactly what will run before pressing y.

    Currently supports host-scoped moves via `fieldkit escalate <host>
    --allow <safety>`. Non-host moves (password-reuse, roast-loot, etc.)
    return ``(None, reason)`` and firing is refused with an operator note.
    """
    host = move.get("host")
    if not host:
        return None, "no host on this move — run it from the CLI directly"
    safety = move.get("safety", "read-only")
    argv = [sys.executable, "-m", "fieldkit"]
    if db_path:
        argv.extend(["--db", db_path])
    argv.extend(["escalate", host, "--yes"])
    if safety in ("config-change", "crash-risk"):
        argv.extend(["--allow", safety])
    return argv, f"escalate {host} at safety={safety}"


def _host_context(db_path, ip):
    """Look up hostname / os / already-proven access for the target host.
    Best-effort — a missing DB or missing host returns partial info."""
    if not ip:
        return {}
    try:
        with Store.open(db_path or default_db_path()) as store:
            row = store.host_by_ip(ip)
            if row is None:
                return {"ip": ip}
            info = {
                "ip": ip,
                "hostname": row["hostname"] or "",
                "os": row["os"] or "unknown",
                "is_dc": bool(row["is_dc"]),
                "access": [],
            }
            for a in store.access_on(row["id"]):
                info["access"].append({
                    "method": a["method"],
                    "admin": bool(a["admin"]),
                })
            return info
    except Exception:  # noqa: BLE001 — degrade to bare ip on any error
        return {"ip": ip}


class EscalateScreen(Screen):
    """The pre-fire confirm. Constructed with a move dict from Analyze."""

    BINDINGS = [
        Binding("y", "fire",   "fire & watch"),
        Binding("n", "cancel", "cancel"),
        Binding("escape", "cancel", "cancel"),
        Binding("?", "app.push_screen('help')", "help"),
    ]

    def __init__(self, move):
        super().__init__()
        self._move = move

    def compose(self) -> ComposeResult:
        with Vertical(id="frame"):
            yield Static(id="escalate-title-bar")
            yield Static(id="escalate-body")
            yield Static(id="escalate-command")
        yield Footer()

    def on_mount(self):
        eng = self.app.engagement_name
        self.query_one("#escalate-title-bar", Static).update(
            f"[bold]FIELDKIT[/bold] · [bold]{eng}[/bold] "
            f"[{theme.C.INK_DIM}]· Escalate[/]"
            f"      [{theme.C.INK_DIM2}]confirm before fire[/]")
        self._render_body()

    def _render_body(self):
        m = self._move
        host_info = _host_context(self.app._db_path, m.get("host"))
        argv, why = _build_command(m, self.app._db_path)

        lines = []

        # TARGET block
        lines.append(f"\n  {_accent(theme.G.ACTION + ' TARGET')}")
        if host_info.get("hostname") or host_info.get("ip"):
            label = host_info.get("hostname") or ""
            ip = host_info.get("ip") or "?"
            osn = host_info.get("os") or "unknown"
            dc = f"  [{theme.C.GOOD}]{theme.G.PROVEN} DC[/]" if host_info.get("is_dc") else ""
            lines.append(f"    [bold]{label}[/]  {_dim(ip)}  ·  {_dim(osn)}{dc}")
            access = host_info.get("access", [])
            if access:
                methods = ", ".join(
                    f"{a['method']}{' [admin]' if a['admin'] else ''}"
                    for a in access)
                lines.append(f"    {_dim('proven access:')}  {methods}")
            else:
                lines.append(f"    {_dim('proven access:')}  "
                             f"[{theme.C.INK_DIM2}]none yet on this host[/]")
        else:
            lines.append(f"    [{theme.C.CRIT}]{theme.G.CAUGHT} no host — "
                         f"this move is not fire-from-TUI eligible[/]")

        # VECTOR block
        lines.append(f"\n  {_accent(theme.G.ACTION + ' VECTOR')}")
        lines.append(f"    [bold]{m['title']}[/]")
        lines.append(f"    {_dim(m.get('axes') or '?')}"
                     f"  {_dim('· score')} {m.get('score', 0)}")

        # SAFETY block
        safety = m.get("safety", "read-only")
        sev_color = (theme.C.CRIT if safety == "crash-risk"
                     else theme.C.WARN if safety == "config-change"
                     else theme.C.GOOD)
        sev_note = ("modifies target state; cleanup manifest updated"
                    if safety == "config-change"
                    else "may crash the target — explicit opt-in required"
                    if safety == "crash-risk"
                    else "read-only — no target-state changes")
        lines.append(f"\n  {_accent(theme.G.ACTION + ' SAFETY GATE')}")
        lines.append(f"    [{sev_color}]{safety}[/] "
                     f"[{theme.C.INK_DIM}]— {sev_note}[/]")

        # DETECTION forecast block
        det = m.get("detection", "unknown")
        det_color = (theme.C.CRIT if det == "loud"
                     else theme.C.WARN if det == "moderate"
                     else theme.C.GOOD if det == "quiet"
                     else theme.C.INK_DIM)
        lines.append(f"\n  {_accent(theme.G.ACTION + ' DETECTION FORECAST')}")
        lines.append(
            f"    [{det_color}]{det}[/] "
            f"[{theme.C.INK_DIM2}](evasion posture ledger — Phase D; "
            f"forecast uses vector's declared detection axis for now)[/]")

        # DETAIL
        if m.get("detail"):
            lines.append(f"\n  {_accent(theme.G.ACTION + ' DETAIL')}")
            lines.append(f"    {_dim(m['detail'])}")

        # SAFE PROOF — the honest read-only demonstration of the primitive.
        # Shown here (not just on Analyze) because this is the moment the
        # operator decides whether to escalate or run the proof and stop.
        if m.get("safe_proof"):
            lines.append(f"\n  {_accent(theme.G.ACTION + ' SAFE PROOF')}")
            lines.append(f"    {_dim(m['safe_proof'])}")

        self.query_one("#escalate-body", Static).update("\n".join(lines))

        # COMMAND (or the reason firing is blocked)
        cmd_lines = [f"\n  [{theme.C.RULE}]" + "─" * 66 + "[/]\n"]
        cmd_lines.append(f"  {_accent(theme.G.ACTION + ' COMMAND')}")
        if argv is None:
            cmd_lines.append(
                f"    [{theme.C.CRIT}]{theme.G.CAUGHT} cannot fire from TUI:"
                f"[/] [{theme.C.INK}]{why}[/]")
            if m.get("next_step"):
                cmd_lines.append(f"    [{theme.C.INK_DIM}]suggested next step:[/]")
                cmd_lines.append(f"    [bold]{m['next_step']}[/]")
            cmd_lines.append(f"\n    [{theme.C.INK_DIM2}]press esc to go back.[/]")
        else:
            rendered = " ".join(shlex.quote(a) for a in argv)
            cmd_lines.append(f"    [bold]{rendered}[/]")
            cmd_lines.append(
                f"\n    [{theme.C.INK_DIM}]press[/] "
                f"[{theme.C.ACCENT}]y[/] "
                f"[{theme.C.INK_DIM}]to fire and jump to Watch, "
                f"or[/] [{theme.C.ACCENT}]n[/] [{theme.C.INK_DIM}]to cancel.[/]")
        self.query_one("#escalate-command", Static).update("\n".join(cmd_lines))

    def action_fire(self):
        argv, _why = _build_command(self._move, self.app._db_path)
        if argv is None:
            # Non-host moves can't be fired from here; just close silently.
            self.app.pop_screen()
            return
        # Spawn detached so the TUI's asyncio loop stays responsive. We don't
        # need the exit code — Watch tails the DB and shows every step as it
        # lands, which is the honest ground-truth signal anyway.
        try:
            subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                cwd=os.getcwd(),
            )
        except OSError as exc:
            self.app.notify(str(exc), title="failed to spawn escalate",
                             severity="error", timeout=8)
            return
        host = self._move.get("host") or "?"
        self.app.notify(
            f"escalate {host} fired — switching to Watch",
            title="fire", severity="information", timeout=4)
        self.app.pop_screen()          # off the confirm
        self.app.switch_screen("watch")

    def action_cancel(self):
        self.app.pop_screen()


#: CSS additions for the Escalate screen — merged into APP_TCSS by app.py.
ESCALATE_TCSS = """
#escalate-title-bar {
    color: $foreground;
    text-style: bold;
    height: 1;
    padding: 0 1;
}
#escalate-body {
    color: $foreground;
    padding: 0 2;
    height: auto;
}
#escalate-command {
    color: $foreground;
    padding: 0 2;
    height: auto;
}
"""
