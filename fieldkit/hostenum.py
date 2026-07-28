"""Host enumeration — read the box, structure what it says.

Escalation is only as good as the enumeration under it. This module runs the same
checks the v1 ``enum.sh`` / ``enum.bat`` printed, but now it *executes* them through
the read-only executor (so every check is captured evidence) and *parses* the output
into a :class:`HostFacts` the privesc predicates match against — the ``whoami /priv``
→ route mapping the v1 batch file did by eye, done in code.

Two halves:

  * :data:`ENUM_PLAN` + :func:`run_enum` — the per-OS command set, executed and
    captured (all ``read-only``: nothing here changes the target);
  * :func:`facts_for` — reparse a host's captured enum steps into structured facts,
    so detection reads a :class:`HostFacts`, never raw text.

Facts are derived from the ``step`` evidence, not stored separately: the captured
output is the single source of truth, and re-enumerating simply overwrites it.
"""
import re
from dataclasses import dataclass, field

from .executor import Action, execute

WINDOWS, LINUX = "windows", "linux"


@dataclass(frozen=True)
class EnumCheck:
    category: str
    command: str
    shell: str = None


#: The checks per OS. Every one is read-only. Kept lean and high-signal — the exact
#: inputs the privesc predicates need, not a linpeas-scale dump.
ENUM_PLAN = {
    LINUX: (
        EnumCheck("id", "id"),
        EnumCheck("sudo", "sudo -n -l 2>/dev/null"),   # -n: never prompt, never hang
        EnumCheck("suid", "find / -perm -4000 -type f 2>/dev/null"),
        EnumCheck("caps", "getcap -r / 2>/dev/null"),
        EnumCheck("kernel", "uname -a"),
    ),
    WINDOWS: (
        EnumCheck("priv", "whoami /priv"),
        EnumCheck("groups", "whoami /groups"),
        EnumCheck("aie", 'reg query "HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer" '
                         '/v AlwaysInstallElevated & reg query "HKCU\\Software\\Policies\\'
                         'Microsoft\\Windows\\Installer" /v AlwaysInstallElevated'),
        EnumCheck("services", "wmic service get name,pathname,startmode"),
    ),
}


@dataclass
class HostFacts:
    """Structured enumeration of one host. Empty fields = not enumerated / not present."""

    os: str = None
    # -- linux --
    user: str = None
    uid: int = None
    groups: set = field(default_factory=set)
    sudo_all: bool = False               # sudo -l grants full root
    sudo_nopasswd: bool = False
    sudo_binaries: set = field(default_factory=set)   # basenames allowed via sudo
    sudo_env_keep: set = field(default_factory=set)    # LD_PRELOAD / LD_LIBRARY_PATH kept
    suid: set = field(default_factory=set)             # basenames of SUID files
    caps: dict = field(default_factory=dict)           # binary basename -> capability
    kernel: str = None                                 # version, e.g. "5.15.0"
    # -- windows --
    privs: set = field(default_factory=set)            # SeImpersonatePrivilege, ...
    win_groups: set = field(default_factory=set)        # Administrators, Backup Operators, ...
    always_install_elevated: bool = False
    unquoted_services: list = field(default_factory=list)  # (service_or_None, path)

    @property
    def is_root(self):
        return self.uid == 0


# --------------------------------------------------------------------------- run

@dataclass
class EnumReport:
    host: str = None
    ran: list = field(default_factory=list)      # categories captured
    failed: list = field(default_factory=list)    # (category, reason)
    blocked: str = None                           # set if no transport / gated out entirely


def run_enum(store, host, cred, *, run=None, on_event=None, allow="read-only"):
    """Run the OS-appropriate enum on ``host`` as ``cred``, capturing each check.

    Returns an :class:`EnumReport`. A host with no known OS cannot be planned — spray
    it (its banner sets the OS) or set it with ``add hosts --os`` first.
    """
    report = EnumReport(host=host["ip"])
    plan = ENUM_PLAN.get(host["os"])
    if plan is None:
        report.blocked = (f"{host['ip']}: OS unknown — cannot pick an enum plan; "
                          "spray it or `add hosts --os windows|linux`")
        return report
    for check in plan:
        action = Action(host=host, cred=cred, command=check.command,
                        label=f"enum:{check.category}", safety="read-only",
                        shell=check.shell)
        res = execute(store, action, run=run, allow=allow, on_event=on_event)
        if res.blocked:
            report.blocked = res.blocked      # a transport problem hits every check equally
            return report
        if res.ok:
            report.ran.append(check.category)
        else:
            report.failed.append((check.category, res.run.error if res.run else "no result"))
    return report


# ------------------------------------------------------------------------- parse

def facts_for(store, host_id):
    """Reparse a host's captured enum steps into :class:`HostFacts`."""
    host = store.conn.execute("SELECT * FROM host WHERE id = ?", (host_id,)).fetchone()
    facts = HostFacts(os=host["os"] if host else None)
    outputs = {}
    for step in store.steps(host_id=host_id):
        if step["label"] and step["label"].startswith("enum:"):
            outputs[step["label"][len("enum:"):]] = step["output"] or ""
    for category, text in outputs.items():
        parser = _PARSERS.get(category)
        if parser:
            parser(facts, text)
    return facts


# -- linux parsers ---------------------------------------------------------

def _p_id(facts, text):
    m = re.search(r"uid=(\d+)\(([^)]+)\)", text)
    if m:
        facts.uid, facts.user = int(m.group(1)), m.group(2)
    g = re.search(r"groups=(.+)", text)
    if g:
        facts.groups = set(re.findall(r"\d+\(([^)]+)\)", g.group(1)))


def _p_sudo(facts, text):
    if re.search(r"\(ALL(\s*:\s*ALL)?\)\s+(NOPASSWD:\s*)?ALL\b", text):
        facts.sudo_all = True
    if "NOPASSWD" in text:
        facts.sudo_nopasswd = True
    for env in re.findall(r"env_keep\+=(\w+)", text):
        facts.sudo_env_keep.add(env)
    # allowed-command lines: "(runas) [NOPASSWD:] /path/to/bin args"
    for line in text.splitlines():
        for path in re.findall(r"(/[^\s,]+)", line.split(")", 1)[-1] if ")" in line else ""):
            if "/" in path:
                facts.sudo_binaries.add(path.rsplit("/", 1)[-1])


def _p_suid(facts, text):
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("/"):
            facts.suid.add(line.rsplit("/", 1)[-1])


def _p_caps(facts, text):
    # both getcap forms: "/usr/bin/python3.8 cap_setuid+ep" and ".../python3.8 = cap_setuid+ep"
    for path, caps in re.findall(r"(/\S+)\s+(?:=\s+)?(cap_[\w,+ep]+)", text):
        name = path.rsplit("/", 1)[-1]
        for cap in re.findall(r"cap_\w+", caps):
            facts.caps[name] = cap


def _p_kernel(facts, text):
    m = re.search(r"\b(\d+\.\d+\.\d+)", text)
    if m:
        facts.kernel = m.group(1)


# -- windows parsers -------------------------------------------------------

def _p_priv(facts, text):
    for priv in re.findall(r"(Se\w+Privilege)", text):
        facts.privs.add(priv)


def _p_groups(facts, text):
    for known in ("Administrators", "Backup Operators", "Remote Management Users",
                  "Remote Desktop Users", "Server Operators"):
        if known.lower() in text.lower():
            facts.win_groups.add(known)


def _p_aie(facts, text):
    # both HKLM and HKCU must be 0x1 for AlwaysInstallElevated to apply.
    facts.always_install_elevated = len(re.findall(r"AlwaysInstallElevated\s+REG_DWORD\s+0x1",
                                                   text, re.I)) >= 2


def _p_services(facts, text):
    for line in text.splitlines():
        m = re.search(r"([A-Za-z]:\\[^\"]*?\.exe)", line)
        if not m:
            continue
        path = m.group(1)
        # unquoted (the raw line did not wrap it in quotes) + a space before the exe +
        # not under C:\Windows = a plant-a-hijack candidate.
        quoted = f'"{path}"' in line
        if not quoted and " " in path and not path.lower().startswith("c:\\windows"):
            facts.unquoted_services.append((None, path))


_PARSERS = {
    "id": _p_id, "sudo": _p_sudo, "suid": _p_suid, "caps": _p_caps, "kernel": _p_kernel,
    "priv": _p_priv, "groups": _p_groups, "aie": _p_aie, "services": _p_services,
}
