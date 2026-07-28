"""Transports — run a command *on a host* with a credential, and capture it.

Phase 1 authenticated; Phase 2 needs to *do* things on the box: enumerate it, then
fire an escalation vector. A transport is the answer to "given this host, this
credential and what we have proven works, how do I run a command and read its
output?" It wraps the credential renderers (fieldkit still shells out to nxc/impacket,
it does not speak the protocols) and adds the one-shot command + shell.

    Transport + Credential + host + command  ->  render_exec()  ->  argv (never a shell string)

Applicability is honest about preconditions: an SMB command-exec needs admin
(wmiexec runs as the machine), WinRM needs the account in Remote Management Users,
SSH needs a valid login. :func:`select` picks the least-privileged transport we have
actually proven works on the host, so a non-admin foothold uses WinRM/SSH rather than
pretending SMB-exec will run.
"""
from dataclasses import dataclass

from .creds import render_nxc

WINDOWS, LINUX = "windows", "linux"


@dataclass(frozen=True)
class Transport:
    """One way to run a command on a host. ``flag`` is nxc's exec switch."""

    name: str
    proto: str          # the proven access method this rides on (nxc proto)
    os: str
    shell: str          # cmd | powershell | sh — how to phrase the command
    needs_admin: bool   # SMB exec runs as the machine account: admin-only
    flag: str           # nxc: -x (cmd/sh) or -X (powershell)
    #: lower = preferred. Quiet, low-privilege transports float up; SMB-exec (loud,
    #: admin-only, drops a service) sinks.
    rank: int


#: The transports fieldkit can drive. WinRM before SMB on Windows: it needs no admin
#: and no on-disk service. cmd/sh before powershell: simpler output to parse for enum.
TRANSPORTS = (
    Transport("winrm", "winrm", WINDOWS, "cmd", False, "-x", rank=10),
    Transport("winrm-ps", "winrm", WINDOWS, "powershell", False, "-X", rank=11),
    Transport("ssh", "ssh", LINUX, "sh", False, "-x", rank=10),
    Transport("smb", "smb", WINDOWS, "cmd", True, "-x", rank=30),
    Transport("smb-ps", "smb", WINDOWS, "powershell", True, "-X", rank=31),
)

_BY_NAME = {t.name: t for t in TRANSPORTS}


def by_name(name):
    return _BY_NAME.get(name)


def render_exec(transport, cred, host, command):
    """Render the argv that runs ``command`` on ``host`` as ``cred`` via ``transport``.

    The command is a single argv element (nxc receives it after ``-x``/``-X`` and runs
    it target-side), so quotes, ``&&`` and pipes in the command survive verbatim.
    """
    return render_nxc(cred, transport.proto, target=host,
                      extra=[transport.flag, command])


def applicable(transport, os_name, methods, is_admin):
    """Can this transport run on a host with the given proven access?

    ``methods`` is the set of nxc protocols we have an access row for on the host;
    ``is_admin`` whether any of them is admin. The OS is only enforced when known —
    an unfingerprinted host is not excluded, just deprioritized by the caller.
    """
    if os_name and transport.os != os_name:
        return False
    if transport.proto not in methods:
        return False
    if transport.needs_admin and not is_admin:
        return False
    return True


def select(os_name, methods, is_admin, *, shell=None, prefer=None):
    """The best transport for a host, or ``None`` if we have proven no way onto it.

    ``shell`` (``cmd``/``powershell``/``sh``) constrains the choice when a vector needs
    a particular shell; ``prefer`` names a transport to try first. Ties break by
    ``rank`` — the quiet, low-privilege path wins.
    """
    methods = set(methods)
    candidates = [t for t in TRANSPORTS if applicable(t, os_name, methods, is_admin)]
    if shell:
        candidates = [t for t in candidates if t.shell == shell]
    if not candidates:
        return None
    candidates.sort(key=lambda t: (t.name != prefer, t.rank, t.name))
    return candidates[0]
