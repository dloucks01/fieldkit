"""Engagement timeline — a chronological projection of what fieldkit did
during the run.

Every event in the store has a timestamp (step rows, finding rows, evasion
verdicts, credential promotions). Reading the raw tables jumbles kinds —
the operator wants "here's what happened, in order, with each row's kind
and summary". ``build_timeline`` does that merge once; ``render`` prints
it as a plain-text ribbon suitable for a report preface or an incident
narrative.

Pure projection — never writes to state."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Event:
    """One timeline event — ``ts`` is the ISO-8601 string from the store
    (always present on step/finding/evasion rows), ``kind`` is a short
    tag (``step`` / ``finding`` / ``credential`` / ``evasion``), ``summary``
    is a one-line human description."""
    ts: str
    kind: str
    summary: str
    detail: str = ""


def _row_get(row, key, default=None):
    """Row-shape adapter — accept sqlite3.Row, dict, or dataclass-like."""
    if hasattr(row, "keys"):           # sqlite3.Row / dict
        try:
            return row[key]
        except (KeyError, IndexError):
            return default
    return getattr(row, key, default)


def _step_summary(row):
    """Compress a step into one line: ``[host] cmd (exit=N, Nchars)``."""
    cmd = _row_get(row, "cmd") or ""
    exit_code = _row_get(row, "exit_code")
    output = _row_get(row, "output") or ""
    host_id = _row_get(row, "host_id")
    # Keep cmd short — many fieldkit cmds are long nxc / python one-liners.
    head = cmd.strip().splitlines()[0] if cmd else ""
    if len(head) > 100:
        head = head[:100] + "…"
    tail = f"exit={exit_code}" if exit_code is not None else "no-exit"
    if output:
        tail += f", {len(output)}c"
    host_bit = f"[host#{host_id}] " if host_id else ""
    return f"{host_bit}{head}  ({tail})"


def _finding_summary(row):
    key = _row_get(row, "key") or _row_get(row, "vector_type") or "finding"
    host = _row_get(row, "host") or _row_get(row, "host_id") or "?"
    proven = _row_get(row, "proven")
    marker = "✓" if proven else "·"
    return f"{marker} {key} on {host}"


def _cred_summary(row):
    user = _row_get(row, "username") or ""
    domain = _row_get(row, "domain") or ""
    source = _row_get(row, "source") or ""
    stype = _row_get(row, "secret_type") or "secret"
    dom = f"{domain}\\" if domain else ""
    return f"{dom}{user} ({stype}) from {source}"


def _evasion_summary(row):
    tech = _row_get(row, "technique") or ""
    verdict = _row_get(row, "verdict") or ""
    return f"{tech}: {verdict}"


def build_timeline(store):
    """Walk every timestamped table and return a chronological list of
    :class:`Event` records. Order: ascending ``ts`` (sqlite's ISO-8601
    strings sort lexically).

    Rows that lack a timestamp are placed at the END with ``ts=""`` so a
    future store write that forgets to stamp doesn't silently sink into
    the middle of the ribbon."""
    events = []
    for row in store.steps():
        events.append(Event(
            ts=_row_get(row, "ts") or "",
            kind="step",
            summary=_step_summary(row)))
    for row in store.findings():
        events.append(Event(
            ts=_row_get(row, "ts") or "",
            kind="finding",
            summary=_finding_summary(row)))
    try:
        creds = store.credentials()
    except AttributeError:
        creds = []
    for row in creds:
        events.append(Event(
            ts=_row_get(row, "ts") or "",
            kind="credential",
            summary=_cred_summary(row)))
    try:
        evasions = store.evasion_results()
    except AttributeError:
        evasions = []
    for row in evasions:
        events.append(Event(
            ts=_row_get(row, "ts") or _row_get(row, "run_at") or "",
            kind="evasion",
            summary=_evasion_summary(row)))
    # Lexical sort on ISO-8601 strings; empties pile at the top otherwise,
    # so push them to the back.
    events.sort(key=lambda e: (e.ts == "", e.ts))
    return events


def render(events, kinds=None):
    """Render a list of events as a plain-text timeline. ``kinds`` filters
    to a specific set of event kinds (``{"step","finding"}``); None shows
    all. Returns a single string suitable for ``print`` or a report
    section."""
    if kinds:
        events = [e for e in events if e.kind in kinds]
    if not events:
        return "(no timeline events)"
    lines = []
    last_ts = None
    for e in events:
        ts = e.ts or "(no timestamp)"
        # Collapse repeated ts stamps to a left-margin blank for easier scan
        prefix = ts if ts != last_ts else " " * len(ts)
        lines.append(f"{prefix}  {e.kind:10s}  {e.summary}")
        last_ts = ts
    return "\n".join(lines)


def render_narrative(events):
    """Prose narrative of the engagement for a report preface. One
    sentence per kind-cluster, counting events.

    Example output:
      "During the engagement fieldkit captured 42 step rows across 3
      hosts, promoted 5 proven findings, discovered 4 credentials, and
      recorded 3 evasion verdicts (2 clean, 1 caught)."
    """
    if not events:
        return "No activity recorded during this engagement."
    counts = {}
    for e in events:
        counts[e.kind] = counts.get(e.kind, 0) + 1
    parts = ["During the engagement fieldkit"]
    bits = []
    if "step" in counts:
        bits.append(f"captured {counts['step']} step rows")
    if "finding" in counts:
        bits.append(f"promoted {counts['finding']} findings")
    if "credential" in counts:
        bits.append(f"discovered {counts['credential']} credentials")
    if "evasion" in counts:
        # Count sub-verdicts
        verdicts = {}
        for e in events:
            if e.kind == "evasion":
                v = e.summary.split(":")[-1].strip()
                verdicts[v] = verdicts.get(v, 0) + 1
        verdict_bits = ", ".join(f"{n} {v}" for v, n in sorted(verdicts.items()))
        bits.append(f"recorded {counts['evasion']} evasion verdicts ({verdict_bits})")
    if not bits:
        return "No activity recorded during this engagement."
    if len(bits) == 1:
        parts.append(bits[0] + ".")
    else:
        parts.append(", ".join(bits[:-1]) + ", and " + bits[-1] + ".")
    return " ".join(parts)
