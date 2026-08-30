"""Data layer for the TUI — reads engagement state, returns display-ready dicts.

The TUI runs in-process, so it can read the store directly (no subprocess, no
JSON round-trip). This module isolates those queries so:

  * screens hold no data-layer logic — they consume :class:`DashboardData` or
    :class:`WatchTail` etc. and render;
  * refresh strategies (poll every N seconds, or subscribe to :mod:`watch`
    events) are one seam away;
  * tests can stub the data layer with a canned :class:`DashboardData` instead
    of standing up a store.

Every function here is safe to call on an empty engagement, a missing DB, or a
partially-populated state — the screens will render an honest "no engagement"
or "nothing yet" placeholder rather than crash.
"""
from dataclasses import dataclass, field

from .. import config as config_mod
from ..state import Store, default_db_path


@dataclass
class DashboardData:
    """What the Dashboard screen needs to render, all in one shot."""

    engagement_name: str = "(no engagement)"
    engagement_created: str = ""
    db_path: str = ""

    phase_name: str = "setup"
    phase_hint: str = "no engagement yet"

    counts: dict = field(default_factory=lambda: {
        "hosts": 0, "services": 0, "credentials": 0,
        "access": 0, "admin_access": 0, "admin_hosts": 0,
        "findings": 0, "proven_findings": 0, "loot": 0,
    })

    os_breakdown: dict = field(default_factory=dict)
    cred_types: dict = field(default_factory=dict)
    #: Each entry: {"ip": ..., "hostname": ..., "is_dc": bool}
    pwned_hosts: list = field(default_factory=list)
    #: Each entry: {"key", "title", "host", "axes", "score", "exploitability",
    #: "safety", "detection", "next_step", "detail"}
    top_moves: list = field(default_factory=list)
    preflight_missing: list = field(default_factory=list)
    #: Recent coerce-chain runs — {id, profile, target, status,
    #: detection_debt}. Populated by dashboard() from store.chains();
    #: empty when no chains have been recorded in the engagement.
    chains_recent: list = field(default_factory=list)
    #: Rollup: {"total", "proven", "in_progress", "aborted"}.
    #: Feeds the dashboard's chain-history block header.
    chains_summary: dict = field(default_factory=lambda: {
        "total": 0, "proven": 0, "in_progress": 0, "aborted": 0,
    })
    #: Per-hour count of steps captured across the last 24 hours,
    #: oldest → newest. Feeds the detection-ledger sparkline; each
    #: bucket is one hour's worth of executor-captured steps
    #: (steps table + chain_step table combined). Empty list on
    #: engagements with no captured activity.
    detection_ledger: list = field(default_factory=list)


def _phase_from_counts(counts):
    """Compact phase-name+hint from live counts. Mirrors cli._current_phase but
    is duplicated here to keep the tui module self-contained (no import of cli
    into the UI layer)."""
    if not counts["hosts"] and not counts["credentials"]:
        return "setup", "add hosts + a credential"
    if not counts["hosts"]:
        return "setup", "add hosts"
    if not counts["credentials"]:
        return "setup", "add a credential (or spray --wordlist)"
    if not counts["access"]:
        return "spraying", "spray to validate stored credentials"
    if not counts["findings"]:
        return "enumeration", "enum a Pwn3d host, then analyze"
    if not counts["proven_findings"]:
        return "exploitation", "escalate <host> --allow config-change"
    return "reporting", "report + export-recce"


def _top_moves(store, cfg, limit=3):
    """Run analyze + privesc predicates and return the top ``limit`` moves.

    We import lazily so `data.py` stays cheap when a screen doesn't need moves
    (Watch, for example, doesn't need to rank opportunities on every refresh).
    """
    from .. import kb, privesc

    def _stage_dirs():
        return {"stage_win": cfg.get("stage_win"), "stage_lin": cfg.get("stage_lin")}

    items = list(kb.analyze(store))
    try:
        items += privesc.vectors_from_state(store, **_stage_dirs())
    except Exception as exc:  # noqa: BLE001 — partial state can raise
        # Silently dropping the failure hides regressions in
        # privesc during dashboard render. Print to stderr so
        # a curious operator sees "why is top-moves empty?" —
        # can't raise, that would blank the whole dashboard.
        import sys as _sys
        print(f"tui: vectors_from_state failed: "
              f"{type(exc).__name__}: {exc}",
              file=_sys.stderr)
    items.sort(key=lambda x: -getattr(x, "score", 0))
    return items[:limit]


def opportunities(db_path=None, limit=50):
    """Return every ranked opportunity for the engagement, best-first.

    Same predicates as :func:`_top_moves` but with a larger cap and each move
    projected into a display-ready dict (so the screen never touches an
    Opportunity object). A missing DB returns ``[]``.
    """
    db = db_path or default_db_path()
    try:
        store = Store.open(db)
    except Exception:  # noqa: BLE001
        return []
    try:
        if store.engagement() is None:
            return []
        cfg = config_mod.load(store)
        moves = _top_moves(store, cfg, limit=limit)
        return [{
            "key": getattr(m, "key", ""),
            "title": getattr(m, "title", ""),
            "host": getattr(m, "host", None),
            "axes": getattr(m, "axes", ""),
            "score": getattr(m, "score", 0),
            "exploitability": getattr(m, "exploitability", "medium"),
            "safety": getattr(m, "safety", "read-only"),
            "detection": getattr(m, "detection", "quiet"),
            "next_step": getattr(m, "next_step", ""),
            "detail": getattr(m, "detail", ""),
            "evidence": getattr(m, "evidence", ""),
            "safe_proof": getattr(m, "safe_proof", ""),
            "manual": bool(getattr(m, "manual", False)),
        } for m in moves]
    finally:
        store.close()


def dashboard(db_path=None):
    """Read the store and return a fully-populated :class:`DashboardData`.

    A missing / empty / broken DB returns the default-empty dashboard so the
    screen paints an honest zero rather than crashing.
    """
    data = DashboardData()
    db = db_path or default_db_path()
    try:
        store = Store.open(db)
    except Exception:  # noqa: BLE001 — no DB → empty dashboard, no crash
        return data
    try:
        row = store.engagement()
        if row is None:
            data.db_path = store.path
            return data
        cfg = config_mod.load(store)
        counts = store.counts()
        # Always run analyze — recce-confirmed findings surface as opportunities
        # even before we have proven access. Gating on access here would leave
        # the dashboard blank right after `ingest recce`, which is exactly the
        # moment the operator most wants to see ranked next moves.
        moves = _top_moves(store, cfg)

        data.engagement_name = row["name"]
        data.engagement_created = row["created"]
        data.db_path = store.path
        data.phase_name, data.phase_hint = _phase_from_counts(counts)
        data.counts = counts
        data.os_breakdown = {(r["os"] or "unknown"): r["n"]
                             for r in store.host_os_breakdown()}
        data.cred_types = {r["secret_type"]: r["n"]
                           for r in store.credential_type_breakdown()}
        data.pwned_hosts = [
            {"ip": h["ip"], "hostname": h["hostname"], "is_dc": bool(h["is_dc"])}
            for h in store.admin_hosts()[:8]
        ]
        data.top_moves = [{
            "key": getattr(m, "key", ""),
            "title": getattr(m, "title", ""),
            "host": getattr(m, "host", None),
            "axes": getattr(m, "axes", ""),
            "score": getattr(m, "score", 0),
            "exploitability": getattr(m, "exploitability", ""),
            "safety": getattr(m, "safety", ""),
            "detection": getattr(m, "detection", ""),
            "next_step": getattr(m, "next_step", ""),
            "detail": getattr(m, "detail", ""),
        } for m in moves]

        from .. import preflight
        data.preflight_missing = [
            {"tool": r[0], "reason": r[1]}
            for r in preflight.missing_required(preflight.check())
        ]

        # Chain history — read the coerce_chain table, aggregate
        # counts by status + surface the most-recent few. Graceful
        # degradation when the schema doesn't have coerce_chain
        # (pre-D1 databases) so the dashboard renders anyway.
        try:
            chain_rows = store.chains()
        except Exception:                                     # noqa: BLE001
            chain_rows = []
        summary = {"total": len(chain_rows), "proven": 0,
                    "in_progress": 0, "aborted": 0}
        for r in chain_rows:
            status = r.get("status") or ""
            if status in summary:
                summary[status] += 1
        data.chains_summary = summary
        data.chains_recent = [{
            "id": r["id"],
            "profile": r["profile"],
            "target": r["target"],
            "status": r.get("status") or "",
            "detection_debt": r.get("total_detection_cost") or 0,
        } for r in chain_rows[:5]]      # newest-first from store.chains()

        # Detection ledger: per-hour bucket counts of captured
        # steps over the last 24 hours. Sources both the classic
        # `step` table (executor captures) and `chain_step`
        # (coerce-chain step outcomes) so a chain-heavy engagement
        # doesn't render an empty ledger.
        data.detection_ledger = _detection_ledger(store)
    finally:
        store.close()
    return data


#: Number of buckets in the detection-ledger sparkline. 24 hourly
#: buckets covers a work-day-plus-overnight and fits comfortably in
#: a terminal row.
LEDGER_BUCKETS = 24


def _detection_ledger(store, buckets=LEDGER_BUCKETS):
    """Return per-hour counts of captured activity across the last
    ``buckets`` hours, oldest → newest.

    Sources:
      * ``step.ts``       — executor-captured commands (every ``escalate``,
                            ``enum``, ``run`` step lands here);
      * ``chain_step.ran_at`` — coerce-chain per-step outcomes.

    Both tables carry ISO-8601 UTC timestamps (utcnow() format). Zero-
    activity engagements return a list of zeros — the dashboard shows
    a flat sparkline in that case, honest rather than blank.
    """
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    # Bucket boundaries: [now - N h, now - (N-1) h, ..., now]
    edges = [now - timedelta(hours=(buckets - i)) for i in range(buckets + 1)]

    def _to_dt(iso):
        if not iso:
            return None
        try:
            # Handles both "…+00:00" and legacy "…Z" forms.
            return datetime.fromisoformat(iso.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None

    stamps = []
    for table, column in (("step", "ts"), ("chain_step", "ran_at")):
        try:
            rows = store.conn.execute(
                f"SELECT {column} FROM {table} "
                f"WHERE {column} >= ?",
                (edges[0].isoformat(),)).fetchall()
        except Exception:                                       # noqa: BLE001
            # chain_step doesn't exist on pre-D1 databases;
            # step is v1 so its absence would be a broken store.
            continue
        for r in rows:
            dt = _to_dt(r[0])
            if dt is not None:
                stamps.append(dt)

    counts = [0] * buckets
    for dt in stamps:
        for i in range(buckets):
            if edges[i] <= dt < edges[i + 1]:
                counts[i] += 1
                break
    return counts


def chain_profiles():
    """Return every registered chain profile as a display-ready dict:
    {name, step_count, total_cost, steps: [{name, kind, cost}]}.
    Uses a placeholder target ("<target>") when constructing the
    Chain object; step cost + count don't depend on target IP.

    Zero-cost when the chain module isn't importable (empty list).
    """
    try:
        from .. import chain as chain_mod
    except Exception:                                             # noqa: BLE001
        return []
    out = []
    for name in chain_mod.known_profiles():
        try:
            factory = chain_mod.profile(name)
            ch = factory("<target>")
        except Exception:                                         # noqa: BLE001
            continue
        steps = []
        total = 0
        for s in ch.steps:
            # signal_cost preferred over legacy detection_cost when
            # the step has a catalog — same shape as
            # Chain.total_detection_cost.
            cost = s.signal_cost if s.signals else s.detection_cost
            total += cost
            steps.append({"name": s.name, "kind": s.kind, "cost": cost})
        out.append({"name": name, "step_count": len(ch.steps),
                     "total_cost": total, "steps": steps})
    # Sort quietest-first (operator preference: pick lowest-debt
    # profile when multiple apply).
    out.sort(key=lambda p: p["total_cost"])
    return out
