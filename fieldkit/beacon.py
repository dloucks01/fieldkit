"""Beacon orchestration — fieldkit-side pieces of axis 4.

What this is: the engagement-store side of a beacon framework. It
tracks named beacon configurations, generates per-build mutation seeds
for reproducible-but-unique binaries, and manages the task queue
(what the operator asks a beacon to do + what the beacon reports back).

What this is NOT: a live C2 server. fieldkit does not open listening
sockets, does not accept check-ins over the wire, does not execute
beacon code. Operators run their own C2 (Havoc, Mythic, Sliver,
operator-authored) and use this module to KEEP TRACK of their
engagement's beacon state alongside the rest of fieldkit's engagement
data — so beacon check-ins land in the same ``step`` table as every
other captured proof, and the report machinery sees them.

The reference templates for actual beacon payloads live under
``fieldkit/loaders/`` (slice 13). This module manages the metadata +
task queue around those payloads.

Pure stdlib. All state lives in the engagement SQLite DB."""
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, UTC


# Transports the catalog recognizes. Each maps to a reference template
# under fieldkit/loaders/ (slice 13) that the operator adapts in their
# own arsenal.
TRANSPORTS = {
    "https": {
        "template": "https_beacon.py.j2",
        "description": "HTTPS POST to an operator-controlled endpoint. "
                        "Cross-platform, flexible, high bandwidth. "
                        "Signature: standard TLS to the C2 domain."},
    "smb-pipe": {
        "template": None,  # operator-supplied; no reference ship
        "description": "SMB named pipe, pivot-to-isolated-host C2. "
                        "Windows-only. Egress-free. Peer-to-peer between "
                        "pivot beacon + isolated beacon."},
    "doh": {
        "template": None,
        "description": "DNS-over-HTTPS tunnel via a public resolver. "
                        "Reaches targets with no direct HTTPS egress. "
                        "Low bandwidth; higher latency."},
    "webdav": {
        "template": None,
        "description": "WebDAV staging — Windows SMB redirector pulls "
                        "the payload over HTTP + runs it. Loud signature."},
}


# Supported task command verbs. Each maps to a well-defined operator
# intent; the beacon's actual implementation decides semantics.
TASK_COMMANDS = ("shell", "upload", "download", "sleep", "kill")


@dataclass(frozen=True)
class BeaconConfig:
    """Operator-authored config for one beacon build.

    ``name`` is a short identifier (``corp-ws02-primary``).
    ``platform`` is ``windows`` / ``linux`` / ``cross``.
    ``transport`` is a key from :data:`TRANSPORTS`.
    ``callback_url`` is the operator-controlled C2 endpoint.
    ``interval_s`` + ``jitter_pct`` set the beacon's poll shape.
    ``build_seed`` is the 16-byte hex that drives per-build mutation
    (variable names, string ordering, dead-code insertion) so two
    builds of the same beacon config produce distinct byte patterns —
    operator's choice to supply or let :func:`new_build_seed` generate.
    """
    name: str
    platform: str
    transport: str
    callback_url: str
    interval_s: int = 60
    jitter_pct: int = 30
    build_seed: str = ""


def new_build_seed():
    """Return a fresh 32-char hex string suitable for ``build_seed``.
    Uses ``secrets`` so operator cannot accidentally reuse one across
    builds."""
    return secrets.token_hex(16)


def _now():
    return datetime.now(UTC).isoformat(timespec="seconds")


# ---------------------------------------------------------------- store wrappers


def register_beacon(store, config):
    """Insert a beacon row + return its id. Fails cleanly on duplicate
    name."""
    if config.transport not in TRANSPORTS:
        raise ValueError(f"unknown transport {config.transport!r}; "
                         f"supported: {sorted(TRANSPORTS)}")
    seed = config.build_seed or new_build_seed()
    config_json = json.dumps({
        "name": config.name, "platform": config.platform,
        "transport": config.transport, "callback_url": config.callback_url,
        "interval_s": config.interval_s, "jitter_pct": config.jitter_pct,
    })
    cur = store.conn.execute(
        "INSERT INTO beacon (name, platform, transport, build_seed, "
        "config_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (config.name, config.platform, config.transport, seed,
         config_json, _now()))
    store.conn.commit()
    return cur.lastrowid


def list_beacons(store):
    """Return every registered beacon, newest first."""
    rows = store.conn.execute(
        "SELECT id, name, platform, transport, build_seed, created_at, "
        "last_seen FROM beacon ORDER BY id DESC").fetchall()
    return [dict(r) if hasattr(r, "keys") else r for r in rows]


def issue_task(store, beacon_id, cmd, args):
    """Queue a task for the named beacon. ``args`` is a list; it's
    JSON-encoded so operator-supplied shell command tokens survive
    SQLite's string type cleanly."""
    if cmd not in TASK_COMMANDS:
        raise ValueError(f"unknown cmd {cmd!r}; supported: {TASK_COMMANDS}")
    if not isinstance(args, (list, tuple)):
        raise TypeError(f"args must be a list, got {type(args).__name__}")
    cur = store.conn.execute(
        "INSERT INTO beacon_task (beacon_id, cmd, args_json, issued_at) "
        "VALUES (?, ?, ?, ?)",
        (beacon_id, cmd, json.dumps(list(args)), _now()))
    store.conn.commit()
    return cur.lastrowid


def pending_tasks(store, beacon_id):
    """Tasks the named beacon has NOT yet reported a result for."""
    rows = store.conn.execute(
        "SELECT id, cmd, args_json, issued_at FROM beacon_task "
        "WHERE beacon_id = ? AND completed_at IS NULL ORDER BY id",
        (beacon_id,)).fetchall()
    out = []
    for r in rows:
        d = dict(r) if hasattr(r, "keys") else r
        d["args"] = json.loads(d.pop("args_json"))
        out.append(d)
    return out


def record_result(store, task_id, result):
    """Record a task's captured output. Updates the beacon's
    ``last_seen`` too — one write path for every check-in."""
    row = store.conn.execute(
        "SELECT beacon_id FROM beacon_task WHERE id = ?",
        (task_id,)).fetchone()
    if not row:
        raise LookupError(f"no beacon_task #{task_id}")
    beacon_id = row[0] if not hasattr(row, "keys") else row["beacon_id"]
    now = _now()
    store.conn.execute(
        "UPDATE beacon_task SET result = ?, completed_at = ? WHERE id = ?",
        (result, now, task_id))
    store.conn.execute(
        "UPDATE beacon SET last_seen = ? WHERE id = ?",
        (now, beacon_id))
    store.conn.commit()


def task_history(store, beacon_id, limit=50):
    """Return every task for a beacon, newest first — pending + completed
    interleaved, so an operator sees the full timeline. ``result`` is
    present only when the beacon has reported back."""
    rows = store.conn.execute(
        "SELECT id, cmd, args_json, issued_at, result, completed_at "
        "FROM beacon_task WHERE beacon_id = ? ORDER BY id DESC LIMIT ?",
        (beacon_id, limit)).fetchall()
    out = []
    for r in rows:
        d = dict(r) if hasattr(r, "keys") else r
        d["args"] = json.loads(d.pop("args_json"))
        out.append(d)
    return out


def by_name(store, name):
    """Return a beacon row keyed by name, or None."""
    row = store.conn.execute(
        "SELECT id, name, platform, transport, build_seed, created_at, "
        "last_seen FROM beacon WHERE name = ?", (name,)).fetchone()
    if row is None:
        return None
    return dict(row) if hasattr(row, "keys") else row


# ---------------------------------------------------------------- build config


def render_build_config(config):
    """Return a dict the operator feeds to their build toolchain —
    substitution variables for the reference template under
    ``fieldkit/loaders/``. Deterministic given the same (config,
    build_seed) pair — reproducible builds.

    The dict is JSON-serializable so a CI pipeline can read it from a
    file.
    """
    return {
        "beacon_id": config.name,
        "c2_url": config.callback_url,
        "interval_s": config.interval_s,
        "jitter_pct": config.jitter_pct,
        "user_agent": _ua_for_seed(config.build_seed or ""),
        "build_seed": config.build_seed or "",
    }


_UA_POOL = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
)


def _ua_for_seed(seed):
    """Deterministically map a build seed to one of the User-Agent
    strings in the pool. Operators who want seed-driven mutation of the
    beacon's HTTP shape get one knob: the UA. Everything else they
    choose."""
    if not seed:
        return _UA_POOL[0]
    idx = int(seed[:4], 16) % len(_UA_POOL)
    return _UA_POOL[idx]
