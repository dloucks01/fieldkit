"""Weaponization catalog — the loader shapes, evasion techniques,
syscall frameworks, encoders, and delivery channels an operator can
pick from when fieldkit's analyze/escalate loop demands a payload.

**What this is.** A metadata catalog. Each entry describes a
weaponization option — what it is, what OPSEC profile it carries,
what platform it targets, what pre-reqs the operator needs — so a
report / plan / recommendation can cite it by name without the operator
having to remember the full taxonomy. Think "pick-list reference", not
"code generator".

**What this is NOT.** A code generator. fieldkit stays stdlib-only; it
does not compile reflective loaders or build ConfuserEx-obfuscated
payloads inline. That stays in :mod:`fieldkit.arsenal` where the
operator-owned toolchain lives.

The catalog is the operator-facing projection of axis-3 of the
roadmap — loader catalog, AMSI/ETW bypass catalog, direct & indirect
syscall framework, encoding/obfuscation pipeline, delivery channels —
all surfaced through one lookup."""
import os
from dataclasses import dataclass
from typing import Tuple


@dataclass(frozen=True)
class WeaponizationTechnique:
    """One technique in the catalog.

    ``key`` is the stable identifier a plan / report cites.
    ``category`` groups by axis-3 deliverable (``loader``, ``bypass``,
    ``syscall``, ``encoder``, ``delivery``).
    ``platform`` is the OS tag (``windows``, ``linux``, ``cross``).
    ``name`` is a human-readable label.
    ``description`` is a short paragraph describing the technique.
    ``opsec`` is one of ``quiet`` / ``moderate`` / ``loud`` — same scale
    as :class:`privesc.Vector.detection`, so ranking math already applies.
    ``prereqs`` is a tuple of operator prerequisites (what the arsenal
    must carry, what tools the host must have, etc.).
    ``references`` is a tuple of short refs (MITRE ATT&CK IDs, blog
    canonical links, tool names).
    ``template`` names a reference template file under ``fieldkit/loaders/``
    the operator can inspect (filename only, no path). Empty when no
    reference template exists for this entry."""
    key: str
    category: str
    platform: str
    name: str
    description: str
    opsec: str
    prereqs: Tuple[str, ...] = ()
    references: Tuple[str, ...] = ()
    template: str = ""


_LOADERS_DIR = os.path.join(os.path.dirname(__file__), "loaders")


def template_path(key):
    """Return the absolute path to the reference template for ``key``,
    or ``None`` if the catalog entry has no template OR the file is
    missing from the loaders directory."""
    t = by_key(key)
    if t is None or not t.template:
        return None
    p = os.path.join(_LOADERS_DIR, t.template)
    return p if os.path.exists(p) else None


def template_body(key):
    """Read + return the reference template body for ``key``, or
    ``None`` if no template exists. Pure file-read helper."""
    p = template_path(key)
    if p is None:
        return None
    with open(p, "r") as fh:
        return fh.read()


# ---------------------------------------------------------------- loaders


_LOADERS = (
    WeaponizationTechnique(
        key="reflective-dotnet",
        category="loader", platform="windows",
        name="Reflective .NET assembly load",
        description=(
            "Load a C#/.NET assembly directly from memory via "
            "``System.Reflection.Assembly.Load(byte[])``. No file on "
            "disk, so AV file-scan rules don't fire. Classic Cobalt-"
            "Strike ``execute-assembly`` primitive."),
        opsec="quiet",
        prereqs=("CLR 4+ on target", "assembly compiled attacker-side",
                 "process with CLR loaded (powershell.exe or dedicated .exe host)"),
        references=("T1620", "ATT&CK", "execute-assembly"),
        template="reflective_dotnet.cs.j2"),
    WeaponizationTechnique(
        key="reflective-dll",
        category="loader", platform="windows",
        name="Reflective DLL injection",
        description=(
            "Load a native DLL from memory via a bootstrap stub that "
            "walks the PE headers, allocates RWX, maps sections, applies "
            "relocations, and calls DllMain — all without "
            "LoadLibrary. Stephen Fewer's classic 2008 primitive, still "
            "a cornerstone."),
        opsec="moderate",
        prereqs=("DLL compiled attacker-side", "writable RWX allocation"),
        references=("T1055", "Stephen Fewer reflective_dll")),
    WeaponizationTechnique(
        key="module-stomping",
        category="loader", platform="windows",
        name="Module stomping",
        description=(
            "LoadLibrary a benign signed DLL into the target process, "
            "then overwrite its .text section with shellcode. The "
            "process's module list still shows the benign DLL — a "
            "memory scanner that trusts the module name misses it."),
        opsec="quiet",
        prereqs=("benign signed DLL present on target",
                 "write-primitive to overlay .text"),
        references=("T1055.001", "DarkSide module stomping")),
    WeaponizationTechnique(
        key="process-hollowing",
        category="loader", platform="windows",
        name="Process hollowing (RunPE)",
        description=(
            "CreateProcess suspended, unmap its primary module, write "
            "attacker payload into the hollowed address space, resume. "
            "The process reports the benign path (``svchost.exe``, "
            "``explorer.exe``), executes attacker code."),
        opsec="moderate",
        prereqs=("payload compiled attacker-side",
                 "SeDebugPrivilege not required (child process)"),
        references=("T1055.012",)),
    WeaponizationTechnique(
        key="apc-injection",
        category="loader", platform="windows",
        name="APC queue injection",
        description=(
            "Queue an alertable APC into a target thread; when the "
            "thread calls an alertable Win32 wait, the APC fires + runs "
            "attacker code in-thread. Variants: UuidFromStringA (classic), "
            "early-bird (pre-main-thread-start), NtQueueApcThreadEx on "
            "modern kernels."),
        opsec="quiet",
        prereqs=("payload compiled attacker-side", "handle to target thread",
                 "target thread goes alertable"),
        references=("T1055.004",)),
    WeaponizationTechnique(
        key="clr-hosting",
        category="loader", platform="windows",
        name="CLR hosting from unmanaged",
        description=(
            "Unmanaged binary (C/C++/Rust) hosts the CLR via "
            "ICLRMetaHost → ICLRRuntimeHost::ExecuteInDefaultAppDomain. "
            "Lets a non-managed launcher execute a managed payload "
            "without pre-loading the CLR into a shared process."),
        opsec="moderate",
        prereqs=("unmanaged binary", "managed payload DLL",
                 ".NET framework present"),
        references=("T1620",)),
    WeaponizationTechnique(
        key="lolbas-rundll32",
        category="loader", platform="windows",
        name="LOLBAS rundll32 export execution",
        description=(
            "Call an attacker-controlled DLL export via rundll32.exe. "
            "Living-off-the-land — the parent process is a signed "
            "Microsoft binary; AV rules keying on parent chain often "
            "pass. Variations: regsvr32 (COM registration), mshta "
            "(JScript via HTA), InstallUtil (.NET)."),
        opsec="loud",
        prereqs=("DLL on disk or SMB", "DLL exports attacker function"),
        references=("T1218", "LOLBAS Project")),
    WeaponizationTechnique(
        key="clm-bypass",
        category="loader", platform="windows",
        name="Constrained Language Mode bypass",
        description=(
            "WDAC / Device Guard enforces PowerShell Constrained "
            "Language Mode — ``$ExecutionContext.SessionState.Language"
            "Mode`` returns ``ConstrainedLanguage``. Bypasses: downgrade "
            "to PS v2, invoke via COM-ScriptControl, use a signed "
            "assembly loader + ``Add-Type``, or runspace-pool escape "
            "via ``PsRunspace``."),
        opsec="moderate",
        prereqs=("PowerShell session (possibly constrained)",
                 "signed loader available"),
        references=("T1562.006",)),
    WeaponizationTechnique(
        key="wsl-pivot",
        category="loader", platform="windows",
        name="WSL process pivot",
        description=(
            "Windows Subsystem for Linux processes run under lxss.sys / "
            "wsl.exe and bypass most Win32 EDR coverage (which hooks "
            "ntdll, not lxss). ``wsl.exe <linux-binary>`` executes "
            "attacker payload in a context most EDRs don't even enumerate. "
            "Prereq: WSL installed on target (increasingly common on dev "
            "and admin workstations)."),
        opsec="quiet",
        prereqs=("WSL installed", "a Linux-ELF payload"),
        references=("T1218",)),
    WeaponizationTechnique(
        key="chromium-extension",
        category="loader", platform="cross",
        name="Chromium extension side-load",
        description=(
            "A browser extension running as the user has access to every "
            "cookie, SSO token, and page the user visits. Side-load a "
            "custom extension by writing to the ``Preferences`` file in "
            "the Chromium profile dir + dropping the extension payload "
            "under ``Extensions/<id>/``. Persists across browser restarts; "
            "survives most EDR."),
        opsec="quiet",
        prereqs=("writable Chromium profile dir",
                 "attacker-authored extension package"),
        references=("T1176",)),
)


# ---------------------------------------------------------------- bypass


_BYPASSES = (
    WeaponizationTechnique(
        key="amsi-patch-memory",
        category="bypass", platform="windows",
        name="AMSI in-memory patch",
        description=(
            "Overwrite ``amsi.dll!AmsiScanBuffer`` prologue with a "
            "``mov eax, 0x80070057 ; ret`` stub so AMSI always returns "
            "E_INVALIDARG — Defender then passes the buffer through "
            "unchecked. Needs RWX on the module (VirtualProtect)."),
        opsec="moderate",
        prereqs=("in-process execution", "AMSI loaded in the host process"),
        references=("Rastamouse AMSI bypass",),
        template="amsi_patch.c.j2"),
    WeaponizationTechnique(
        key="amsi-provider-hijack",
        category="bypass", platform="windows",
        name="AMSI provider registration hijack",
        description=(
            "Register an attacker-controlled AMSI provider CLSID in "
            "HKLM\\Software\\Microsoft\\AMSI\\Providers — on next AMSI "
            "init, the attacker's provider loads first and short-"
            "circuits every scan. Needs admin to write the key but "
            "survives reboots and process restarts."),
        opsec="loud",
        prereqs=("local admin", "attacker-signed provider DLL"),
        references=("T1562.001",)),
    WeaponizationTechnique(
        key="etw-patch-memory",
        category="bypass", platform="windows",
        name="ETW provider patch",
        description=(
            "Overwrite ``ntdll!EtwEventWrite`` with a ``ret`` so every "
            "ETW event the process emits silently drops. EDR products "
            "that rely on ETW (Defender, Elastic Endpoint, SentinelOne "
            "detections) go blind for in-process behavior."),
        opsec="quiet",
        prereqs=("in-process execution", "RWX on ntdll"),
        references=("@Hasherezade EtwTi bypass",),
        template="etw_patch.c.j2"),
    WeaponizationTechnique(
        key="defender-cloud-blocking",
        category="bypass", platform="windows",
        name="Defender cloud submission blocking",
        description=(
            "Group Policy settings (``DisableBlockAtFirstSeen``, "
            "``DisableIOAVProtection``) + firewall rules blocking "
            "wdcp.microsoft.com / unitedstates.x.rtf.msofc.live.net "
            "neuter Defender's cloud-first classifications. Needs admin "
            "but is reversible via GP."),
        opsec="moderate",
        prereqs=("local admin"),
        references=("T1562.001", "MDE evasion")),
)


# ---------------------------------------------------------------- syscalls


_SYSCALLS = (
    WeaponizationTechnique(
        key="hells-gate",
        category="syscall", platform="windows",
        name="Hell's Gate — dynamic SSN resolution",
        description=(
            "Walk the Nt* exports in ntdll, parse the ``mov eax, SSN`` "
            "prologue, extract the syscall number dynamically. The "
            "generated stub then issues ``syscall`` directly — no user-"
            "land Nt* call, so EDR hooks on ntdll don't fire. First-"
            "generation technique; replaced in prod by indirect variants."),
        opsec="quiet",
        prereqs=("64-bit payload",
                 "no page-protection on ntdll (default)"),
        template="hells_gate.asm"),
    WeaponizationTechnique(
        key="halos-gate",
        category="syscall", platform="windows",
        name="Halo's Gate — hooked-neighbor resolution",
        description=(
            "Extension of Hell's Gate: when ntdll!NtAllocateVirtualMemory "
            "(or any Nt*) is hooked, the prologue doesn't match. Walk "
            "neighbor syscalls (SSN = neighbor_SSN ± offset) to recover "
            "the real SSN. Robust against user-mode hooks."),
        opsec="quiet",
        prereqs=("64-bit payload", "same-direction neighbor unhooked")),
    WeaponizationTechnique(
        key="tartarus-gate",
        category="syscall", platform="windows",
        name="Tartarus' Gate — Wow64 + x64 unified",
        description=(
            "32-bit Wow64 processes resolve SSNs differently from x64. "
            "Tartarus unifies the resolution across both architectures "
            "so one payload runs in both without arch-specific builds."),
        opsec="quiet",
        prereqs=("payload supporting both x86 and x64 code paths")),
    WeaponizationTechnique(
        key="freshy-calls",
        category="syscall", platform="windows",
        name="FreshyCalls — indirect syscall via ntdll gadget",
        description=(
            "Instead of ``syscall`` from attacker code (which EDR flags "
            "by RIP origin), find a ``syscall; ret`` gadget INSIDE ntdll "
            "and ``jmp`` to it. RIP during syscall is in ntdll — matches "
            "every legitimate syscall. Current prod standard."),
        opsec="quiet",
        prereqs=("64-bit payload", "ntdll gadget address resolved"),
        references=("Crummie5 FreshyCalls",),
        template="freshy_calls.c.j2"),
)


# ---------------------------------------------------------------- encoders


_ENCODERS = (
    WeaponizationTechnique(
        key="xor-roll",
        category="encoder", platform="cross",
        name="Rolling-XOR with multi-byte key",
        description=(
            "XOR the payload against a rolling 4-8 byte key; the "
            "decoder stub is 10-20 bytes of position-independent code. "
            "No fancy entropy — primary purpose is defeating signature "
            "matching on known shellcode patterns."),
        opsec="moderate",
        prereqs=("decoder stub attached to payload",),
        template="xor_decoder.c.j2"),
    WeaponizationTechnique(
        key="fnv-hash-apinames",
        category="encoder", platform="windows",
        name="FNV-1a hashed API resolution",
        description=(
            "Replace plaintext ``LoadLibraryA`` / ``GetProcAddress`` + "
            "export names with FNV-1a hashes resolved at runtime by "
            "walking the IAT. The payload has no readable strings — "
            "static scanners that key off import names (``VirtualAlloc``, "
            "``WriteProcessMemory``) go blind."),
        opsec="quiet",
        prereqs=("hash table attached to payload",)),
    WeaponizationTechnique(
        key="confuserex-dotnet",
        category="encoder", platform="windows",
        name="ConfuserEx .NET obfuscation",
        description=(
            "Apply ConfuserEx (anti-tamper, anti-debug, control-flow "
            "flattening, string encryption, invalid-metadata) to a "
            ".NET assembly. The IL becomes effectively unreadable by "
            "dnSpy without unpacking; stock YARA signatures miss."),
        opsec="moderate",
        prereqs=("ConfuserEx attacker-side", "the raw .NET assembly")),
    WeaponizationTechnique(
        key="pe-signature-cloning",
        category="encoder", platform="windows",
        name="PE signature cloning (sigthief)",
        description=(
            "Clone an Authenticode signature from a known-trusted "
            "signed binary onto an attacker PE. The signature "
            "verification FAILS (hash mismatch) but Windows's SmartScreen "
            "/ AppLocker publisher-reputation heuristics often look "
            "only at the signer-name field, not the verification result "
            "— a cloned Microsoft signature boosts the \"reputation\" "
            "even when the signature is formally invalid."),
        opsec="moderate",
        prereqs=("sigthief", "a signed donor binary"),
        references=("secretsquirrel/sigthief",)),
)


# ---------------------------------------------------------------- delivery


_DELIVERY = (
    WeaponizationTechnique(
        key="https-beacon",
        category="delivery", platform="cross",
        name="HTTPS beacon with jitter",
        description=(
            "Beacon issues POST requests to an operator-controlled HTTPS "
            "endpoint on a configurable interval + jitter window. Core "
            "C2 primitive — carries task IDs in query strings and task "
            "payloads in POST bodies. TLS cert pinning or domain-"
            "fronting shapes the signature."),
        opsec="moderate",
        prereqs=("TLS cert for the C2 domain",
                 "accessible C2 endpoint from target"),
        template="https_beacon.py.j2"),
    WeaponizationTechnique(
        key="smb-named-pipe",
        category="delivery", platform="windows",
        name="SMB named pipe C2",
        description=(
            "Peer-to-peer C2 over SMB named pipes: the pivot beacon "
            "proxies for isolated workstations that can't reach the "
            "operator's HTTPS endpoint directly. Egress-free lateral C2 "
            "— every target speaks SMB internally regardless of outbound "
            "firewall policy."),
        opsec="quiet",
        prereqs=("pivot beacon on reachable host",
                 "SMB open between pivot and isolated target")),
    WeaponizationTechnique(
        key="dns-tunnel",
        category="delivery", platform="cross",
        name="DNS tunnel C2",
        description=(
            "Encode task IDs + payloads into DNS TXT / A record queries "
            "against an operator-controlled authoritative nameserver. "
            "Low bandwidth but reaches targets with no HTTPS egress — "
            "DNS almost always traverses the perimeter. Signature: "
            "unusually long subdomain labels, unusually high query rate."),
        opsec="moderate",
        prereqs=("attacker-controlled authoritative nameserver",
                 "a disposable domain")),
    WeaponizationTechnique(
        key="doh-tunnel",
        category="delivery", platform="cross",
        name="DNS-over-HTTPS tunnel",
        description=(
            "Same shape as DNS tunnel but queries go through a public "
            "DoH resolver (Cloudflare, Google) over HTTPS — the "
            "perimeter sees TLS to 1.1.1.1 / 8.8.8.8 and can't inspect "
            "the DNS payload. Harder to signature than classic DNS "
            "tunneling but requires DoH to be reachable."),
        opsec="quiet",
        prereqs=("DoH-reachable public resolver",
                 "attacker-controlled authoritative")),
    WeaponizationTechnique(
        key="webdav-upload",
        category="delivery", platform="windows",
        name="WebDAV implant staging",
        description=(
            "Windows's SMB redirector will mount a remote WebDAV share "
            "transparently. Stage implants on ``\\\\attacker.local@80\\dav\\"
            "payload.exe`` — the client fetches it via HTTP + executes "
            "it as a local file. Signature: outbound ``PROPFIND`` + "
            "``GET`` from svchost.exe."),
        opsec="loud",
        prereqs=("WebDAV share reachable from target",
                 "WebClient service enabled on target")),
)


# ---------------------------------------------------------------- registry


CATALOG = _LOADERS + _BYPASSES + _SYSCALLS + _ENCODERS + _DELIVERY


_BY_KEY = {t.key: t for t in CATALOG}
_BY_CATEGORY = {}
for t in CATALOG:
    _BY_CATEGORY.setdefault(t.category, []).append(t)


def all_techniques():
    """Return the full catalog, in registration order."""
    return CATALOG


def by_key(key):
    """Return the :class:`WeaponizationTechnique` with the given key,
    or ``None`` if nothing matches."""
    return _BY_KEY.get(key)


def by_category(category):
    """Return every technique in a category: ``loader`` / ``bypass`` /
    ``syscall`` / ``encoder`` / ``delivery``. Empty list on an unknown
    category — never raises."""
    return list(_BY_CATEGORY.get(category, ()))


def by_platform(platform):
    """Return every technique on the given platform (``windows``,
    ``linux``, ``cross``). ``cross`` techniques match any platform
    query — they describe primitives that don't care which side of the
    wire."""
    out = []
    for t in CATALOG:
        if t.platform == platform or t.platform == "cross":
            out.append(t)
    return out


def categories():
    """Sorted list of distinct categories in the catalog."""
    return sorted(_BY_CATEGORY)
