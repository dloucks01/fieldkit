"""SQLite state store — the engine's memory.

One engagement per database file (default ``./engagement.db``). Stdlib ``sqlite3``
only: standalone, zero-install, and queryable at 400-host scale.

The schema is the superset of the v1 ``findings.json`` template, so the report gate,
the renderer and the recce bridge can all be served from it:

  engagement  one row: name + engagement config (replaces configure.sh)
  host        the scope; ``ip`` unique, IPv6-safe
  service     port/proto with product+version (the CVE-match input)
  credential  the canonical credential model (see creds.py)
  access      "who is admin where" — the (Pwn3d!) result set
  finding     privesc/foothold findings; report + bridge read from here
  step        executor-captured verbatim evidence (satisfies --check by construction)
  artifact    the cleanup manifest
  loot        hashes/tickets/files not yet promoted to credentials

Schema changes go through MIGRATIONS + ``PRAGMA user_version``; an older database is
upgraded in place on open, never silently reinterpreted.
"""
import json
import os
import sqlite3
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone

from .errors import FieldkitError
from .scope import subnet_of

DEFAULT_DB_NAME = "engagement.db"
DB_ENV_VAR = "FIELDKIT_DB"


class StateError(FieldkitError):
    """Raised for store-level problems the operator can act on."""


def utcnow():
    """Timestamps are ISO-8601 UTC strings — comparable, sortable, adapter-free."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _subnet_label(ip):
    """The host's segment, or None if the caller keyed it on something odd."""
    try:
        return subnet_of(ip)
    except ValueError:
        return None


# --------------------------------------------------------------------------- schema

_V1 = [
    """
    CREATE TABLE engagement (
        id          INTEGER PRIMARY KEY CHECK (id = 1),
        name        TEXT NOT NULL,
        created     TEXT NOT NULL,
        config_json TEXT NOT NULL DEFAULT '{}'
    )
    """,
    """
    CREATE TABLE host (
        id         INTEGER PRIMARY KEY,
        ip         TEXT NOT NULL UNIQUE,
        hostname   TEXT,
        os         TEXT,
        os_version TEXT,
        arch       TEXT,
        is_dc      INTEGER NOT NULL DEFAULT 0,
        subnet     TEXT,
        notes      TEXT,
        added      TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE service (
        id      INTEGER PRIMARY KEY,
        host_id INTEGER NOT NULL REFERENCES host(id) ON DELETE CASCADE,
        port    INTEGER NOT NULL,
        proto   TEXT NOT NULL DEFAULT 'tcp',
        product TEXT,
        version TEXT,
        banner  TEXT,
        UNIQUE (host_id, port, proto)
    )
    """,
    # domain/username compare case-insensitively (AD is), secrets do not.
    # No-domain is stored as '' rather than NULL so the uniqueness key is total.
    """
    CREATE TABLE credential (
        id            INTEGER PRIMARY KEY,
        domain        TEXT NOT NULL DEFAULT '' COLLATE NOCASE,
        username      TEXT NOT NULL COLLATE NOCASE,
        secret        TEXT NOT NULL,
        secret_type   TEXT NOT NULL,
        source        TEXT NOT NULL DEFAULT 'manual',
        local_auth    INTEGER NOT NULL DEFAULT 0,
        valid_on_json TEXT NOT NULL DEFAULT '[]',
        notes         TEXT,
        added         TEXT NOT NULL,
        UNIQUE (domain, username, secret, secret_type, local_auth)
    )
    """,
    """
    CREATE TABLE access (
        id        INTEGER PRIMARY KEY,
        host_id   INTEGER NOT NULL REFERENCES host(id) ON DELETE CASCADE,
        cred_id   INTEGER REFERENCES credential(id) ON DELETE CASCADE,
        method    TEXT NOT NULL,
        admin     INTEGER NOT NULL DEFAULT 0,
        integrity TEXT,
        proven_at TEXT NOT NULL,
        UNIQUE (host_id, cred_id, method)
    )
    """,
    """
    CREATE TABLE finding (
        id          INTEGER PRIMARY KEY,
        host_id     INTEGER REFERENCES host(id) ON DELETE CASCADE,
        vector_type TEXT NOT NULL,
        title       TEXT NOT NULL,
        evidence    TEXT,
        severity    TEXT,
        risk        TEXT,
        proven      INTEGER NOT NULL DEFAULT 0,
        created     TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE step (
        id         INTEGER PRIMARY KEY,
        finding_id INTEGER NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
        seq        INTEGER NOT NULL,
        cmd        TEXT NOT NULL,
        output     TEXT,
        exit_code  INTEGER,
        ts         TEXT NOT NULL,
        UNIQUE (finding_id, seq)
    )
    """,
    """
    CREATE TABLE artifact (
        id          INTEGER PRIMARY KEY,
        finding_id  INTEGER REFERENCES finding(id) ON DELETE CASCADE,
        host_id     INTEGER REFERENCES host(id) ON DELETE CASCADE,
        description TEXT NOT NULL,
        cleanup_cmd TEXT,
        removed     INTEGER NOT NULL DEFAULT 0,
        created     TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE loot (
        id      INTEGER PRIMARY KEY,
        host_id INTEGER REFERENCES host(id) ON DELETE CASCADE,
        kind    TEXT NOT NULL,
        value   TEXT,
        path    TEXT,
        added   TEXT NOT NULL
    )
    """,
    # Indexed for the queries that matter at 400-host scale.
    "CREATE INDEX ix_host_subnet     ON host(subnet)",
    "CREATE INDEX ix_service_port    ON service(port)",
    "CREATE INDEX ix_cred_username   ON credential(username)",
    "CREATE INDEX ix_access_cred     ON access(cred_id, admin)",
    "CREATE INDEX ix_access_host     ON access(host_id, admin)",
    "CREATE INDEX ix_finding_host    ON finding(host_id, proven)",
    "CREATE INDEX ix_finding_vector  ON finding(vector_type)",
    "CREATE INDEX ix_loot_host       ON loot(host_id, kind)",
]

#: (version, [statements]) applied in order; a database records the last applied
#: version in PRAGMA user_version. Append to migrate; never edit a shipped entry.
MIGRATIONS = [(1, _V1)]

SCHEMA_VERSION = MIGRATIONS[-1][0]


# ----------------------------------------------------------------------- db location

def default_db_path(cwd=None):
    """Where the store lives when the operator did not say: $FIELDKIT_DB, else ./engagement.db."""
    env = os.environ.get(DB_ENV_VAR)
    if env:
        return os.path.abspath(os.path.expanduser(env))
    return os.path.join(os.path.abspath(cwd or os.getcwd()), DEFAULT_DB_NAME)


# ---------------------------------------------------------------------------- store

class Store:
    """A thin, explicit wrapper around one engagement database.

    Not a generic ORM: every method here is a query the engine actually runs. Rows
    come back as ``sqlite3.Row`` (index- and name-addressable).
    """

    def __init__(self, conn, path=None):
        self.conn = conn
        self.path = path
        self._in_transaction = False

    # -- lifecycle ----------------------------------------------------------

    @classmethod
    def open(cls, path, create=False):
        """Open an existing store (or create one when ``create=True``)."""
        path = os.path.abspath(os.path.expanduser(path))
        exists = os.path.exists(path)
        if not exists and not create:
            raise StateError(
                f"no engagement database at {path} — run `fieldkit init` first")
        if exists and create:
            raise StateError(f"{path} already exists — refusing to overwrite it")
        try:
            conn = sqlite3.connect(path)
        except sqlite3.OperationalError as exc:
            raise StateError(f"cannot open {path}: {exc}") from None
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        store = cls(conn, path)
        store.migrate()
        return store

    @classmethod
    def create(cls, path):
        return cls.open(path, create=True)

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def migrate(self):
        """Apply any migrations this database has not seen. Idempotent."""
        cur = self.conn.execute("PRAGMA user_version")
        have = cur.fetchone()[0]
        if have > SCHEMA_VERSION:
            raise StateError(
                f"database schema v{have} is newer than this fieldkit (v{SCHEMA_VERSION}) "
                "— upgrade fieldkit rather than downgrading the database")
        for version, statements in MIGRATIONS:
            if version <= have:
                continue
            with self.conn:
                for sql in statements:
                    self.conn.execute(sql)
                # PRAGMA does not accept a bound parameter.
                self.conn.execute(f"PRAGMA user_version = {int(version)}")
        return self.schema_version()

    def schema_version(self):
        return self.conn.execute("PRAGMA user_version").fetchone()[0]

    @contextmanager
    def transaction(self):
        """Batch many writes into one commit.

        Ingest is bulk by nature — a /22 of scope, an nxc sweep, a secretsdump — and
        a commit per row costs milliseconds each. Inside this block the per-method
        commits are suppressed and the whole batch lands (or rolls back) at once.
        """
        if self._in_transaction:
            yield  # already batching; the outermost block owns the commit
            return
        self._in_transaction = True
        try:
            with self.conn:
                yield
        finally:
            self._in_transaction = False

    def _write(self):
        return nullcontext() if self._in_transaction else self.conn

    # -- engagement ---------------------------------------------------------

    def init_engagement(self, name, config=None):
        """Create the single engagement row. Fails if one already exists."""
        if self.engagement() is not None:
            raise StateError("this database already has an engagement")
        with self.conn:
            self.conn.execute(
                "INSERT INTO engagement (id, name, created, config_json) VALUES (1, ?, ?, ?)",
                (name, utcnow(), json.dumps(config or {}, sort_keys=True)))
        return self.engagement()

    def engagement(self):
        return self.conn.execute("SELECT * FROM engagement WHERE id = 1").fetchone()

    def require_engagement(self):
        row = self.engagement()
        if row is None:
            raise StateError("this database has no engagement — run `fieldkit init`")
        return row

    def get_config(self):
        return json.loads(self.require_engagement()["config_json"])

    def set_config(self, config):
        """Replace the whole config blob (config.py owns the merge + validation)."""
        self.require_engagement()
        with self.conn:
            self.conn.execute(
                "UPDATE engagement SET config_json = ? WHERE id = 1",
                (json.dumps(config, sort_keys=True),))

    # -- hosts --------------------------------------------------------------

    def add_host(self, ip, hostname=None, os_name=None, os_version=None, arch=None,
                 is_dc=None, subnet=None, notes=None):
        """Insert or enrich a host, keyed on ``ip``.

        Returns ``(host_id, created)``. Enrichment never overwrites a known field
        with ``None`` — later ingest fills gaps, it does not erase what we learned.
        The subnet label is derived from the IP unless the caller overrides it, so
        every ingest path (scope file, nxc sweep, recce bridge) groups the same way
        and per-subnet lhost overrides keep working.
        """
        fields = {"hostname": hostname, "os": os_name, "os_version": os_version,
                  "arch": arch, "is_dc": None if is_dc is None else int(bool(is_dc)),
                  "subnet": subnet or _subnet_label(ip), "notes": notes}
        present = [(k, v) for k, v in fields.items() if v is not None]
        with self._write():
            row = self.conn.execute("SELECT * FROM host WHERE ip = ?", (ip,)).fetchone()
            if row is None:
                cols = ["ip", "added"] + [k for k, _ in present]
                vals = [ip, utcnow()] + [v for _, v in present]
                cur = self.conn.execute(
                    f"INSERT INTO host ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
                    vals)
                return cur.lastrowid, True
            updates = {k: v for k, v in fields.items() if v is not None and row[k] != v}
            if updates:
                self.conn.execute(
                    "UPDATE host SET " + ", ".join(f"{k} = ?" for k in updates) + " WHERE id = ?",
                    list(updates.values()) + [row["id"]])
            return row["id"], False

    def hosts(self, subnet=None):
        if subnet:
            return self.conn.execute(
                "SELECT * FROM host WHERE subnet = ? ORDER BY id", (subnet,)).fetchall()
        return self.conn.execute("SELECT * FROM host ORDER BY id").fetchall()

    def host_by_ip(self, ip):
        return self.conn.execute("SELECT * FROM host WHERE ip = ?", (ip,)).fetchone()

    # -- credentials --------------------------------------------------------

    def add_credential(self, cred, source="manual", notes=None):
        """Store a :class:`fieldkit.creds.Credential`. Returns ``(cred_id, created)``.

        Identity is (domain, username, secret, secret_type, local_auth) — re-adding
        the same credential from a second source is a no-op, not a duplicate row.
        """
        key = (cred.domain or "", cred.username, cred.secret, cred.secret_type,
               int(bool(cred.local_auth)))
        with self._write():
            row = self.conn.execute(
                "SELECT id FROM credential WHERE domain = ? AND username = ? AND secret = ? "
                "AND secret_type = ? AND local_auth = ?", key).fetchone()
            if row is not None:
                return row["id"], False
            cur = self.conn.execute(
                "INSERT INTO credential (domain, username, secret, secret_type, local_auth, "
                "source, notes, added) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                key + (source, notes, utcnow()))
            return cur.lastrowid, True

    def credentials(self):
        return self.conn.execute(
            "SELECT * FROM credential ORDER BY domain, username, id").fetchall()

    # -- board --------------------------------------------------------------

    def counts(self):
        """The headline numbers `status` shows."""
        def one(sql):
            return self.conn.execute(sql).fetchone()[0]

        return {
            "hosts": one("SELECT COUNT(*) FROM host"),
            "services": one("SELECT COUNT(*) FROM service"),
            "credentials": one("SELECT COUNT(*) FROM credential"),
            "access": one("SELECT COUNT(*) FROM access"),
            "admin_access": one("SELECT COUNT(*) FROM access WHERE admin = 1"),
            "admin_hosts": one("SELECT COUNT(DISTINCT host_id) FROM access WHERE admin = 1"),
            "findings": one("SELECT COUNT(*) FROM finding"),
            "proven_findings": one("SELECT COUNT(*) FROM finding WHERE proven = 1"),
            "loot": one("SELECT COUNT(*) FROM loot"),
        }

    def host_os_breakdown(self):
        """``os`` is NULL for hosts nothing has fingerprinted yet — the caller labels it."""
        return self.conn.execute(
            "SELECT os, COUNT(*) AS n FROM host GROUP BY os ORDER BY n DESC, os").fetchall()

    def credential_type_breakdown(self):
        return self.conn.execute(
            "SELECT secret_type, COUNT(*) AS n FROM credential "
            "GROUP BY secret_type ORDER BY n DESC, secret_type").fetchall()
