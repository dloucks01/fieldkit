"""JSONL event stream for the engagement — poll state, emit deltas.

Ships as ``fieldkit watch --json`` and is what the TUI (Phase A3d) subscribes to
so its dashboard updates in near-real-time without in-process hooks — the TUI
runs fieldkit as a subprocess, so we need a stream, not a callback.

Watching is polling: every :data:`INTERVAL` seconds, look at the ``id`` column of
each interesting table, emit new rows as events, advance the cursor. Cheap on the
scale of a single engagement (thousands of rows, not millions) and no writer-side
changes required — a running ``fieldkit escalate`` in another terminal writes
rows the watcher sees on its next poll.

Event shape:

  {"event": "<kind>", "ts": "<iso>", ...kind-specific fields}

Kinds: ``step``, ``finding``, ``credential``, ``access``, ``loot``. The kind list
is closed — an unknown kind means the schema changed, and the consumer should
refuse rather than skip silently.
"""
import json
import time

#: Polling interval in seconds. Fast enough that a live TUI feels responsive,
#: slow enough that we're not hammering SQLite when idle.
INTERVAL = 0.25

#: Bump on any breaking change to the event shape (rename, remove, or type change
#: of a field). Consumers may refuse unsupported versions.
WATCH_VERSION = 1

EVENT_KINDS = ("step", "finding", "credential", "access", "loot")


def _empty_cursors():
    """Fresh cursor state — one last-seen ``id`` per table we tail."""
    return {k: 0 for k in EVENT_KINDS}


def _row_step(row):
    return {
        "event": "step",
        "id": row["id"],
        "ts": row["ts"],
        "host_id": row["host_id"],
        "finding_id": row["finding_id"],
        "cmd": row["cmd"],
        "exit_code": row["exit_code"],
        "transport": row["transport"],
        "label": row["label"],
        # output can be very large — the watch stream summarizes; consumers that
        # need the full text can query the store directly by step id.
        "output_len": len(row["output"] or ""),
    }


def _row_finding(row):
    return {
        "event": "finding",
        "id": row["id"],
        "ts": row["created"],
        "host_id": row["host_id"],
        "vector_type": row["vector_type"],
        "title": row["title"],
        "severity": row["severity"],
        "proven": bool(row["proven"]),
    }


def _row_credential(row):
    return {
        "event": "credential",
        "id": row["id"],
        "ts": row["added"],
        "domain": row["domain"],
        "username": row["username"],
        "secret_type": row["secret_type"],
        "source": row["source"],
    }


def _row_access(row):
    return {
        "event": "access",
        "id": row["id"],
        "ts": row["proven_at"],
        "host_id": row["host_id"],
        "cred_id": row["cred_id"],
        "method": row["method"],
        "admin": bool(row["admin"]),
    }


def _row_loot(row):
    return {
        "event": "loot",
        "id": row["id"],
        "ts": row["added"],
        "kind": row["kind"],
        "host_id": row["host_id"],
    }


_PROJECTORS = {
    "step": _row_step,
    "finding": _row_finding,
    "credential": _row_credential,
    "access": _row_access,
    "loot": _row_loot,
}


def _query_after(store, kind, cursor):
    """Return rows in ``kind`` with id > cursor, oldest first."""
    if kind == "step":
        return store.conn.execute(
            "SELECT * FROM step WHERE id > ? ORDER BY id", (cursor,)).fetchall()
    if kind == "finding":
        return store.conn.execute(
            "SELECT * FROM finding WHERE id > ? ORDER BY id", (cursor,)).fetchall()
    if kind == "credential":
        return store.conn.execute(
            "SELECT * FROM credential WHERE id > ? ORDER BY id", (cursor,)).fetchall()
    if kind == "access":
        return store.conn.execute(
            "SELECT * FROM access WHERE id > ? ORDER BY id", (cursor,)).fetchall()
    if kind == "loot":
        return store.conn.execute(
            "SELECT * FROM loot WHERE id > ? ORDER BY id", (cursor,)).fetchall()
    return []


def poll_once(store, cursors=None, kinds=None):
    """One polling pass. Returns ``(events, cursors)`` — events oldest-first,
    across all requested kinds; cursors is a new dict (never the same object) so
    tests can compare pre/post safely.
    """
    cursors = dict(cursors or _empty_cursors())
    kinds = kinds or EVENT_KINDS
    events = []
    for kind in kinds:
        rows = _query_after(store, kind, cursors.get(kind, 0))
        proj = _PROJECTORS[kind]
        for row in rows:
            events.append(proj(row))
            cursors[kind] = row["id"]
    # sort a mixed batch by ts so a consumer sees engagement-order truth,
    # not table-order; ts values are ISO strings so string sort is chronological.
    events.sort(key=lambda e: e.get("ts") or "")
    return events, cursors


def watch(store, *, cursors=None, kinds=None, sleep=None, run=None):
    """Yield JSONL-serializable event dicts forever, advancing cursors as we go.

    ``sleep`` and ``run`` are injectable for tests — ``sleep`` is called between
    polls (default: ``time.sleep(INTERVAL)``); ``run`` is a callable that returns
    True as long as watching should continue (default: infinite). The CLI wraps
    this and handles SIGINT.
    """
    sleep = sleep or (lambda: time.sleep(INTERVAL))
    run = run or (lambda: True)
    cursors = cursors or _empty_cursors()
    while run():
        events, cursors = poll_once(store, cursors)
        for event in events:
            yield event
        if run():
            sleep()


def dumps(event):
    """Serialize one event to a single JSON line — the wire format."""
    return json.dumps(event, sort_keys=True)
