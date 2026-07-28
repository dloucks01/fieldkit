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

# v2: the executor captures every command it runs, including enumeration that belongs
# to no finding yet. Rebuild `step` so finding_id is optional and a step records the
# host, its purpose (label) and the transport that carried it. SQLite cannot drop a
# NOT NULL in place, so the table is rebuilt and its rows copied.
_V2 = [
    """
    CREATE TABLE step_new (
        id         INTEGER PRIMARY KEY,
        finding_id INTEGER REFERENCES finding(id) ON DELETE CASCADE,
        host_id    INTEGER REFERENCES host(id) ON DELETE CASCADE,
        seq        INTEGER NOT NULL,
        label      TEXT,
        transport  TEXT,
        cmd        TEXT NOT NULL,
        output     TEXT,
        exit_code  INTEGER,
        ts         TEXT NOT NULL
    )
    """,
    "INSERT INTO step_new (id, finding_id, seq, cmd, output, exit_code, ts) "
    "SELECT id, finding_id, seq, cmd, output, exit_code, ts FROM step",
    "DROP TABLE step",
    "ALTER TABLE step_new RENAME TO step",
    "CREATE INDEX ix_step_finding ON step(finding_id)",
    "CREATE INDEX ix_step_host    ON step(host_id)",
]

# v3: evasion lab results — the green/red matrix. One latest verdict per technique,
# stamped with the Defender signature version it was taken under (so `posture` can
# age it out). Upserted by technique.
_V3 = [
    """
    CREATE TABLE evasion (
        id         INTEGER PRIMARY KEY,
        technique  TEXT NOT NULL UNIQUE,
        verdict    TEXT NOT NULL,          -- clean | caught | error
        signature  TEXT,                    -- Defender AV signature version at test time
        detail     TEXT,
        tested_at  TEXT NOT NULL
    )
    """,
]

#: (version, [statements]) applied in order; a database records the last applied
#: version in PRAGMA user_version. Append to migrate; never edit a shipped entry.
MIGRATIONS = [(1, _V1), (2, _V2), (3, _V3)]

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

    def credential_by_id(self, cred_id):
        return self.conn.execute(
            "SELECT * FROM credential WHERE id = ?", (cred_id,)).fetchone()

    def find_credential(self, cred):
        """The stored row matching this :class:`~fieldkit.creds.Credential`, or None.

        Same identity key as :meth:`add_credential`, so ``ingest``/``spray`` can link
        a parsed result to a credential without risking a duplicate insert.
        """
        row = self.conn.execute(
            "SELECT * FROM credential WHERE domain = ? AND username = ? AND secret = ? "
            "AND secret_type = ? AND local_auth = ?",
            (cred.domain or "", cred.username, cred.secret, cred.secret_type,
             int(bool(cred.local_auth)))).fetchone()
        return row

    # -- access -------------------------------------------------------------

    def add_access(self, host_id, cred_id, method, admin=False, integrity=None):
        """Record that a credential authenticates on a host — the ``(Pwn3d!)`` set.

        Keyed on ``(host_id, cred_id, method)``: re-proving the same access is a
        no-op. An upgrade from non-admin to admin *is* applied (a later WinRM Pwn3d
        after an SMB foothold), because the loop only ever learns more access, never
        less. Returns ``(access_id, created)``.
        """
        admin = int(bool(admin))
        with self._write():
            row = self.conn.execute(
                "SELECT id, admin, integrity FROM access "
                "WHERE host_id = ? AND cred_id IS ? AND method = ?",
                (host_id, cred_id, method)).fetchone()
            if row is None:
                cur = self.conn.execute(
                    "INSERT INTO access (host_id, cred_id, method, admin, integrity, "
                    "proven_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (host_id, cred_id, method, admin, integrity, utcnow()))
                return cur.lastrowid, True
            updates = {}
            if admin and not row["admin"]:
                updates["admin"] = admin
            if integrity is not None and row["integrity"] != integrity:
                updates["integrity"] = integrity
            if updates:
                updates["proven_at"] = utcnow()
                self.conn.execute(
                    "UPDATE access SET " + ", ".join(f"{k} = ?" for k in updates)
                    + " WHERE id = ?", list(updates.values()) + [row["id"]])
            return row["id"], False

    def admin_hosts(self):
        """Hosts we hold admin on — where the loop dumps next. Distinct host rows."""
        return self.conn.execute(
            "SELECT DISTINCT h.* FROM host h JOIN access a ON a.host_id = h.id "
            "WHERE a.admin = 1 ORDER BY h.id").fetchall()

    def access_on(self, host_id):
        return self.conn.execute(
            "SELECT * FROM access WHERE host_id = ? ORDER BY admin DESC, id",
            (host_id,)).fetchall()

    def credential_with_access_on(self, host_id):
        """A credential that authenticates on this host — the acting foothold for enum
        and privesc. Prefers admin, then a password (least surprising to render)."""
        return self.conn.execute(
            "SELECT c.* FROM credential c JOIN access a ON a.cred_id = c.id "
            "WHERE a.host_id = ? "
            "ORDER BY a.admin DESC, (c.secret_type = 'password') DESC, a.id LIMIT 1",
            (host_id,)).fetchone()

    def admin_credential_for(self, host_id):
        """A credential that holds admin on this host — the key the loot step uses.

        Prefers a full-secret credential (password/hash both dump fine, but a plain
        password is the least surprising to see in the captured command)."""
        return self.conn.execute(
            "SELECT c.* FROM credential c JOIN access a ON a.cred_id = c.id "
            "WHERE a.host_id = ? AND a.admin = 1 "
            "ORDER BY (c.secret_type = 'password') DESC, a.id LIMIT 1",
            (host_id,)).fetchone()

    # -- loot ---------------------------------------------------------------

    def add_loot(self, host_id, kind, value=None, path=None):
        """Store a hash/ticket/file recovered from a host, before it becomes a cred.

        Deduplicated on ``(host_id, kind, value)`` so re-dumping the same SAM does not
        pile up rows. Returns ``(loot_id, created)``.
        """
        with self._write():
            if value is not None:
                row = self.conn.execute(
                    "SELECT id FROM loot WHERE host_id IS ? AND kind = ? AND value = ?",
                    (host_id, kind, value)).fetchone()
                if row is not None:
                    return row["id"], False
            cur = self.conn.execute(
                "INSERT INTO loot (host_id, kind, value, path, added) VALUES (?, ?, ?, ?, ?)",
                (host_id, kind, value, path, utcnow()))
            return cur.lastrowid, True

    def loot(self, kind=None):
        if kind:
            return self.conn.execute(
                "SELECT * FROM loot WHERE kind = ? ORDER BY id", (kind,)).fetchall()
        return self.conn.execute("SELECT * FROM loot ORDER BY id").fetchall()

    # -- findings / evidence / cleanup --------------------------------------

    def add_finding(self, vector_type, title, host_id=None, evidence=None,
                    severity=None, risk=None, proven=None):
        """Insert or update a finding, keyed on ``(host_id, vector_type, title)``.

        Idempotent so re-running a vector does not fan out duplicate findings; a later
        proof upgrades ``proven`` to 1 in place. Returns ``(finding_id, created)``.
        """
        with self._write():
            row = self.conn.execute(
                "SELECT id, proven FROM finding WHERE host_id IS ? AND vector_type = ? "
                "AND title = ?", (host_id, vector_type, title)).fetchone()
            if row is None:
                cur = self.conn.execute(
                    "INSERT INTO finding (host_id, vector_type, title, evidence, severity, "
                    "risk, proven, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (host_id, vector_type, title, evidence, severity, risk,
                     int(bool(proven)), utcnow()))
                return cur.lastrowid, True
            updates = {}
            if evidence is not None:
                updates["evidence"] = evidence
            if proven and not row["proven"]:
                updates["proven"] = 1
            if updates:
                self.conn.execute(
                    "UPDATE finding SET " + ", ".join(f"{k} = ?" for k in updates)
                    + " WHERE id = ?", list(updates.values()) + [row["id"]])
            return row["id"], False

    def add_step(self, cmd, output=None, exit_code=None, host_id=None,
                 finding_id=None, label=None, transport=None):
        """Append one captured command — verbatim evidence, the anti-fabrication spine.

        ``seq`` is assigned per finding (or per host for finding-less enum steps), so a
        finding's evidence renders in run order. Returns the new step id.
        """
        with self._write():
            scope = ("finding_id", finding_id) if finding_id is not None else ("host_id", host_id)
            prev = self.conn.execute(
                f"SELECT COALESCE(MAX(seq), 0) FROM step WHERE {scope[0]} IS ?",
                (scope[1],)).fetchone()[0]
            cur = self.conn.execute(
                "INSERT INTO step (finding_id, host_id, seq, label, transport, cmd, "
                "output, exit_code, ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (finding_id, host_id, prev + 1, label, transport, cmd, output,
                 exit_code, utcnow()))
            return cur.lastrowid

    def steps(self, finding_id=None, host_id=None):
        if finding_id is not None:
            return self.conn.execute(
                "SELECT * FROM step WHERE finding_id = ? ORDER BY seq", (finding_id,)).fetchall()
        if host_id is not None:
            return self.conn.execute(
                "SELECT * FROM step WHERE host_id = ? ORDER BY id", (host_id,)).fetchall()
        return self.conn.execute("SELECT * FROM step ORDER BY id").fetchall()

    def add_artifact(self, description, cleanup_cmd=None, host_id=None, finding_id=None):
        """Record a change made on a target so cleanup is a manifest, not memory."""
        with self._write():
            cur = self.conn.execute(
                "INSERT INTO artifact (finding_id, host_id, description, cleanup_cmd, "
                "created) VALUES (?, ?, ?, ?, ?)",
                (finding_id, host_id, description, cleanup_cmd, utcnow()))
            return cur.lastrowid

    def artifacts(self, pending_only=False):
        sql = "SELECT * FROM artifact"
        if pending_only:
            sql += " WHERE removed = 0"
        return self.conn.execute(sql + " ORDER BY id").fetchall()

    def findings(self, proven_only=False):
        sql = "SELECT * FROM finding"
        if proven_only:
            sql += " WHERE proven = 1"
        return self.conn.execute(sql + " ORDER BY id").fetchall()

    # -- evasion lab --------------------------------------------------------

    def record_evasion(self, technique, verdict, signature=None, detail=None):
        """Upsert the latest lab verdict for a technique. Returns the row id."""
        with self._write():
            self.conn.execute(
                "INSERT INTO evasion (technique, verdict, signature, detail, tested_at) "
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT(technique) DO UPDATE SET "
                "verdict=excluded.verdict, signature=excluded.signature, "
                "detail=excluded.detail, tested_at=excluded.tested_at",
                (technique, verdict, signature, detail, utcnow()))
            return self.conn.execute(
                "SELECT id FROM evasion WHERE technique = ?", (technique,)).fetchone()[0]

    def evasion_result(self, technique):
        return self.conn.execute(
            "SELECT * FROM evasion WHERE technique = ?", (technique,)).fetchone()

    def evasion_results(self):
        return self.conn.execute("SELECT * FROM evasion ORDER BY technique").fetchall()

    # -- analysis (what `analyze` ranks) ------------------------------------

    def admin_on_dcs(self):
        """(host, credential) pairs where we hold admin on a domain controller —
        the shortest path to the whole domain (DCSync / NTDS)."""
        return self.conn.execute(
            "SELECT h.ip, h.hostname, c.id AS cred_id, c.domain, c.username, c.secret_type "
            "FROM access a JOIN host h ON h.id = a.host_id "
            "JOIN credential c ON c.id = a.cred_id "
            "WHERE a.admin = 1 AND h.is_dc = 1 ORDER BY h.id").fetchall()

    def creds_valid_on_multiple(self, min_hosts=2):
        """Credentials proven valid on ``min_hosts`` or more — proven password reuse,
        the lateral-movement finding. Admin count comes along for the ranking."""
        return self.conn.execute(
            "SELECT c.id AS cred_id, c.domain, c.username, c.secret_type, c.local_auth, "
            "COUNT(DISTINCT a.host_id) AS hosts, "
            "SUM(CASE WHEN a.admin = 1 THEN 1 ELSE 0 END) AS admin_hits "
            "FROM credential c JOIN access a ON a.cred_id = c.id "
            "GROUP BY c.id HAVING hosts >= ? ORDER BY hosts DESC, admin_hits DESC",
            (min_hosts,)).fetchall()

    def local_hash_credentials(self):
        """Local-account NT hashes — the pass-the-hash sweep input (LAPS-less fleets
        share a local admin hash)."""
        return self.conn.execute(
            "SELECT * FROM credential WHERE local_auth = 1 "
            "AND secret_type IN ('nt', 'lm:nt') ORDER BY id").fetchall()

    def admin_hosts_without_loot(self):
        """Hosts we own but have not dumped — free credentials waiting to be read."""
        return self.conn.execute(
            "SELECT DISTINCT h.* FROM host h JOIN access a ON a.host_id = h.id "
            "WHERE a.admin = 1 AND NOT EXISTS "
            "(SELECT 1 FROM loot l WHERE l.host_id = h.id) ORDER BY h.id").fetchall()

    def footholds_without_admin(self):
        """Hosts where a credential is valid but not admin — a foothold needing local
        privilege escalation (shell + enum)."""
        return self.conn.execute(
            "SELECT h.ip, h.hostname, h.os, c.domain, c.username "
            "FROM access a JOIN host h ON h.id = a.host_id "
            "JOIN credential c ON c.id = a.cred_id "
            "WHERE a.admin = 0 AND NOT EXISTS "
            "(SELECT 1 FROM access a2 WHERE a2.host_id = h.id AND a2.admin = 1) "
            "ORDER BY h.id").fetchall()

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
