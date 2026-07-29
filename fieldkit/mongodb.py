"""MongoDB privilege enumeration + credential extraction.

MongoDB (4.0+) removed ``db.eval()``, so there is no clean OS-exec analog on modern
clusters. The realistic wins for an authorized pentest are:

1. **Unauth access** — the server has no authentication enabled (an *extremely* common
   custom-app finding). Any client reads every database and dumps
   ``admin.system.users``. Recorded as Critical.
2. **Privileged role** — the current login holds ``root``, ``__system``,
   ``userAdminAnyDatabase``, or ``dbOwner`` on a data database. Full user + data
   surface. Recorded as High.
3. **Application data → credentials** — application user documents commonly contain
   password material (bcrypt/argon2 hashes to crack offline, or plaintext for the
   sadder custom apps). A configurable field filter surfaces the candidates as loot
   (fields are *named* here, values only counted — the driver never captures a raw
   plaintext password into a step, so the deletion obligation for the extracted data
   is what the operator reviews on disk).

Auth surface only — no writes, no ``db.eval()``. The ``mongosh`` invocation goes
through the injected runner.
"""
import json
import re
from dataclasses import dataclass, field

from .creds import Credential, render_mongosh


# Every result carries an ``FK:`` sentinel; mongosh with ``--quiet`` still emits a
# connection banner on some builds, so parsing the raw output is fragile without it.
_WHOAMI = (
    "var s=db.runCommand({connectionStatus:1}).authInfo;"
    "print('FK:'+(s.authenticatedUsers.map(u=>u.user+'@'+u.db).join(',')||'anon'));"
    "s.authenticatedUserRoles.forEach(r=>print('FKR:'+r.role+'@'+r.db));"
)
_LIST_DB = ("db.adminCommand({listDatabases:1}).databases"
            ".forEach(d=>print('FK:'+d.name));")
_LIST_USERS = ("db.getSiblingDB('admin').system.users.find({},"
               "{user:1,db:1,roles:1,_id:0}).forEach("
               "u=>print('FK:'+JSON.stringify(u)));")

#: Roles that grant enough to dump the credential collection or all user data.
PRIVILEGED_ROLES = frozenset({
    "root", "__system",
    "userAdmin", "userAdminAnyDatabase",
    "readAnyDatabase", "readWriteAnyDatabase",
    "dbAdmin", "dbAdminAnyDatabase", "dbOwner",
    "clusterAdmin", "hostManager",
})

#: Field names that commonly hold password material in custom-app user collections.
#: Recorded as *loot candidates* only — the driver counts documents matching each
#: field, it does not capture the values (that goes on disk, under the deletion
#: obligation the ``mongodump`` step records).
CRED_FIELDS = ("password", "passwd", "pwd", "passwordHash", "password_hash",
               "hashedPassword", "bcrypt", "hash", "secret", "apiKey", "api_key",
               "token", "authToken")


def _fk(output, prefix="FK:"):
    """Every ``FK:<value>`` (or ``FKR:<role>@<db>``) the driven eval relayed."""
    return [m.strip() for m in re.findall(rf"{re.escape(prefix)}(.*)", output or "")]


def _query_argv(cred, ip, script, *, port=None, database=None, auth_source="admin",
                unauth=False):
    """Build ``mongosh --eval JS``. When ``unauth`` we drop the credential entirely —
    an unauth connection attempt is the finding itself."""
    if unauth:
        stub = Credential(username="_", secret="_", secret_type="password")
        rendered = render_mongosh(stub, ip, port=port, database=database,
                                  auth_source=None, script=script)
        # strip -u/-p/--authenticationDatabase — the whole point is anonymous
        argv = [a for a in rendered.argv if a not in ("-u", "-p", "_",
                                                     "--authenticationDatabase")]
        return type(rendered)(argv=argv, env=rendered.env, notes=rendered.notes)
    return render_mongosh(cred, ip, port=port, database=database,
                          auth_source=auth_source, script=script)


@dataclass
class MongoReport:
    host: str
    port: int = 27017
    status: str = "none"       # unauth | admin | user | gated | none | failed | aborted
    is_unauth: bool = False
    identity: str = None       # user@db, or "anon"
    roles: list = field(default_factory=list)         # [(role, db)]
    privileged_roles: list = field(default_factory=list)   # subset in PRIVILEGED_ROLES
    databases: list = field(default_factory=list)
    users_dumped: int = 0
    cred_candidates: list = field(default_factory=list)    # [(db, coll, field, count)]
    aborted: str = None
    via: str = None
    error: str = None


def enumerate_privs(store, host, cred, *, run=None, allow_config_change=False,
                    port=27017, database="admin", scan_data=False, on_event=None):
    """Enumerate MongoDB privileges + auth surface.

    Read-only always. ``allow_config_change`` gates the credential-collection dump and
    (with ``scan_data=True``) the application-collection field scan — both writes to
    the target's audit log, not to its state, but auditors treat them as changes.
    """
    from . import runner as runner_mod
    run = run or (lambda argv, env=None: runner_mod.run(argv, env_add=env))
    cred = cred if isinstance(cred, Credential) else Credential.from_row(cred)
    ip = host["ip"]
    rep = MongoReport(host=ip, port=port)

    def emit(m):
        if on_event:
            on_event(m)

    def query(script, *, unauth=False, db="admin"):
        rendered = _query_argv(cred, ip, script, port=port, database=db,
                               unauth=unauth)
        return run(rendered.argv, rendered.env)

    # 1) unauth probe — one connection with no credentials. Success is Critical.
    probe = query(_WHOAMI, unauth=True)
    if probe.error:
        rep.aborted = probe.error
        return rep
    if _fk(probe.output):
        rep.is_unauth = True
        rep.identity = "anon"
        emit(f"  connected anonymously to {ip}:{port} — no authentication required")
        _record_unauth(store, host, ip, port, probe.output)
        rep.status = "unauth"
        # fall through: enumerate the surface anonymously anyway
    else:
        who = query(_WHOAMI)
        if who.error:
            rep.aborted = who.error
            return rep
        ids = _fk(who.output)
        rep.identity = ids[0] if ids else cred.username

    # roles held (authenticated or not)
    out_who = probe if rep.is_unauth else query(_WHOAMI)
    for entry in _fk(out_who.output, prefix="FKR:"):
        role, _, dbname = entry.partition("@")
        rep.roles.append((role, dbname))
        if role in PRIVILEGED_ROLES:
            rep.privileged_roles.append(role)

    rep.databases = _fk(query(_LIST_DB, unauth=rep.is_unauth).output)
    emit(f"  identity={rep.identity}, roles={rep.roles or 'none'}, "
         f"databases={rep.databases or 'none'}")

    # A privileged role is the "admin" status.
    if rep.privileged_roles and not rep.is_unauth:
        rep.status = "admin"
        _record_admin(store, host, cred, rep)
    elif rep.identity and not rep.is_unauth:
        rep.status = "user"

    # 2) dump admin.system.users (unauth or admin roles get to)
    if allow_config_change and (rep.is_unauth or rep.privileged_roles):
        emit("  dumping admin.system.users…")
        users = query(_LIST_USERS, unauth=rep.is_unauth).output or ""
        rep.users_dumped = len(_fk(users))
        for u in _fk(users):
            try:
                doc = json.loads(u)
            except (ValueError, TypeError):
                continue
            store.add_loot(host["id"], "mongodb:user",
                           value=f"{doc.get('user')}@{doc.get('db')}",
                           path=None)

    # 3) scan application data for likely credential fields (counts only)
    if allow_config_change and scan_data:
        for dbname in rep.databases:
            if dbname in ("admin", "config", "local"):
                continue
            js = _scan_script(dbname)
            r = query(js, db=dbname, unauth=rep.is_unauth)
            for hit in _fk(r.output):
                try:
                    coll, field, count = hit.split("|", 2)
                    rep.cred_candidates.append((dbname, coll, field, int(count)))
                    store.add_loot(host["id"], "mongodb:cred-field",
                                   value=f"{dbname}.{coll}.{field}={count} docs")
                except ValueError:
                    continue

    return rep


def _scan_script(dbname):
    """A JS one-liner: for each user-visible collection, print each cred-field's
    document count as ``FK:<coll>|<field>|<count>``."""
    fields = ",".join(f"'{f}'" for f in CRED_FIELDS)
    return (
        f"db.getSiblingDB('{dbname}').getCollectionNames().forEach(function(c){{"
        f"  var fields=[{fields}];"
        "  fields.forEach(function(f){"
        "    var q={}; q[f]={$exists:true};"
        f"   var n=db.getSiblingDB('{dbname}')[c].countDocuments(q);"
        "    if(n>0) print('FK:'+c+'|'+f+'|'+n);"
        "  });"
        "});"
    )


def _record_unauth(store, host, ip, port, proof):
    from .mssql import _cred_id       # for parity — not used unauth (no cred)
    _ = _cred_id
    with store.transaction():
        fid, _ = store.add_finding(
            "mongodb_unauth",
            f"MongoDB on {ip}:{port} accepts unauthenticated connections",
            host_id=host["id"], proven=True,
            evidence=(f"An anonymous mongosh connection to {ip}:{port} succeeded — "
                      "the server accepts clients without credentials."))
        store.add_step(cmd=f"mongosh --host {ip} --port {port} --quiet "
                           f"--eval \"{_WHOAMI[:80]}…\"",
                       output=(proof or "").strip()[:500],
                       host_id=host["id"], finding_id=fid, transport="mongosh")


def _record_admin(store, host, cred, rep):
    from .mssql import _cred_id
    which = ", ".join(sorted(set(rep.privileged_roles)))
    with store.transaction():
        fid, _ = store.add_finding(
            "mongodb_admin",
            f"MongoDB privileged role ({which}) on {rep.host}:{rep.port}",
            host_id=host["id"], proven=True,
            evidence=(f"{rep.identity} holds {which} on {rep.host}:{rep.port} — full "
                      "user and data administration."))
        store.add_access(host["id"], _cred_id(store, cred), "mongodb", admin=True)
        store.add_step(cmd=f"mongosh --host {rep.host} --port {rep.port} --quiet "
                           f"-u {cred.username} … --eval \"{_WHOAMI[:60]}…\"",
                       output=f"identity={rep.identity}; roles={rep.roles}",
                       host_id=host["id"], finding_id=fid, transport="mongosh")
