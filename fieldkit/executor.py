"""The executor — run one command on a target, through the safety gate, captured.

Everything fieldkit does *to* a host goes through here, so three of the design's
rules hold by construction:

  * **everything that runs is captured** — the verbatim command, output and exit code
    land in the ``step`` table as evidence, so the report's anti-fabrication check
    passes without anyone remembering to log;
  * **the safety gate** — an action declares its blast radius (``read-only`` /
    ``config-change`` / ``crash-risk``); the executor refuses anything the operator
    has not authorized, so a kernel-exploit vector cannot fire from an idle
    ``analyze`` the way a read-only enum can;
  * **cleanup is a manifest, not memory** — an action lists what it changes, and the
    executor records each as a cleanup artifact the moment it runs.

The transport is chosen from what we have *proven* works for the acting credential on
the host (see :mod:`fieldkit.transport`), so the executor never assumes a path it has
not already walked. The subprocess runner is injected for testing, exactly as in the
spray loop.
"""
from dataclasses import dataclass

from . import runner as runner_mod
from . import transport as transport_mod
from .creds import Credential

#: Blast-radius ladder, least to most dangerous. The gate admits a prefix of this.
SAFETY_LEVELS = ("read-only", "config-change", "crash-risk")


@dataclass
class Action:
    """One thing to run on a host: the command, why, and how dangerous it is."""

    host: object            # host row
    cred: object            # credential row (must have proven access on the host)
    command: str
    label: str              # "enum:sudo_l", "vector:pwnkit" — groups the evidence
    safety: str = "read-only"
    shell: str = None       # constrain the transport to cmd/powershell/sh when a vector needs it
    transport: str = None   # force a transport by name, else auto-select the quietest proven path
    finding_id: int = None
    #: cleanup manifest entries this action will create: (description, cleanup_cmd).
    creates: tuple = ()
    #: (local, remote) to push instead of running a command — a stage step. Uses a
    #: file-transfer transport (smb/ssh); config-change by nature (it writes to disk).
    upload: tuple = None


@dataclass
class ExecResult:
    """What happened. ``blocked`` is set (and nothing ran) when the gate refused."""

    ok: bool = False
    blocked: str = None
    transport: str = None
    run: object = None       # runner.RunResult, or None when blocked before exec
    step_id: int = None

    @property
    def output(self):
        return self.run.output if self.run else ""


def _default_runner(timeout):
    return lambda argv, env=None: runner_mod.run(argv, env_add=env, timeout=timeout)


def gate(safety, allow):
    """True when an action of this ``safety`` is permitted by ``allow`` (a level name
    or an iterable of them). ``read-only`` is always in-bounds; the rest are opt-in."""
    if isinstance(allow, str):
        allow = SAFETY_LEVELS[: SAFETY_LEVELS.index(allow) + 1]
    return safety in set(allow)


def _proven_path(store, host_id, cred_id):
    """The (methods, is_admin) this credential has actually proven on the host."""
    rows = [r for r in store.access_on(host_id) if r["cred_id"] == cred_id]
    return {r["method"] for r in rows}, any(r["admin"] for r in rows)


def execute(store, action, *, run=None, allow="read-only", timeout=600, on_event=None):
    """Run one :class:`Action`. Returns an :class:`ExecResult`; never raises for an
    operator-caused failure (a missing transport, a blocked action, a dead tool)."""
    run = run or _default_runner(timeout)
    host, cred_row = action.host, action.cred

    if action.transport:
        transport = transport_mod.by_name(action.transport)
        if transport is None:
            return ExecResult(blocked=f"unknown transport {action.transport!r}")
    elif action.upload:
        methods, is_admin = _proven_path(store, host["id"], cred_row["id"])
        transport = transport_mod.select_put(host["os"], methods, is_admin)
        if transport is None:
            return ExecResult(
                blocked=f"no proven file-transfer path to {host['ip']} — staging needs "
                        "smb (as admin) or ssh proven on the host first")
    else:
        methods, is_admin = _proven_path(store, host["id"], cred_row["id"])
        transport = transport_mod.select(host["os"], methods, is_admin, shell=action.shell)
        if transport is None:
            return ExecResult(
                blocked=f"no proven way to run a {action.shell or 'command'} on "
                        f"{host['ip']} as this credential — spray/validate a usable "
                        "protocol (winrm/ssh, or smb as admin) first")

    if not gate(action.safety, allow):
        return ExecResult(
            blocked=f"{action.safety} action blocked by the safety gate — re-run with "
                    "--allow " + " or --allow ".join(
                        SAFETY_LEVELS[1: SAFETY_LEVELS.index(action.safety) + 1]),
            transport=transport.name)

    cred = Credential.from_row(cred_row)
    if action.upload:
        local, remote = action.upload
        rendered = transport_mod.render_put(transport, cred, host["ip"], local, remote)
        recorded_cmd = f"put-file {local} -> {remote}"
    else:
        rendered = transport_mod.render_exec(transport, cred, host["ip"], action.command)
        recorded_cmd = action.command
    if on_event:
        on_event(f"  [{transport.name}] {host['ip']}: {recorded_cmd}")
    result = run(rendered.argv, rendered.env)

    with store.transaction():
        step_id = store.add_step(
            cmd=recorded_cmd, output=result.output,
            exit_code=result.exit_code, host_id=host["id"],
            finding_id=action.finding_id, label=action.label, transport=transport.name)
        for entry in action.creates:
            desc, cleanup = entry if isinstance(entry, (tuple, list)) else (entry, None)
            store.add_artifact(desc, cleanup_cmd=cleanup, host_id=host["id"],
                               finding_id=action.finding_id)
    return ExecResult(ok=result.ok, transport=transport.name, run=result, step_id=step_id)
