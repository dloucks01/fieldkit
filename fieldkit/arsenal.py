"""Arsenal awareness — what is staged, and what each vector/technique needs.

fieldkit drives nxc + certipy itself, but most routes it *names* (a Potato for
SeImpersonate, an MSI for AlwaysInstallElevated, a kernel PoC, a payload exe/dll for a
service hijack) need an artifact the operator stages in ``exploits/`` or that fieldkit
**builds**. This module is the engine's awareness of that arsenal:

  * read ``exploits/manifest.tsv`` + scan what is actually staged on disk;
  * resolve an artifact by name (``GodPotato`` → its path);
  * for every privesc vector (by ``report_type``) and evasion technique, say what it
    needs — ``builtin`` (a native target command, nothing to stage), ``staged`` (an
    artifact that must be present), ``build`` (fieldkit produces it — see
    :mod:`fieldkit.poc`), or ``supplied`` (operator brings it, e.g. a BYOVD driver).

So ``fieldkit arsenal`` can show, per route, whether it is ready, needs a fetch, or
needs a build — and the ``run``/``poc`` paths use the same resolution to prepare the
right PoC for the target OS + service.
"""
import os
from dataclasses import dataclass

# resolution kinds
BUILTIN, STAGED, BUILD, SUPPLIED = "builtin", "staged", "build", "supplied"


def arsenal_dir():
    """Where the staged arsenal lives: ``$FIELDKIT_ARSENAL`` or ``<repo>/exploits``."""
    env = os.environ.get("FIELDKIT_ARSENAL")
    if env:
        return os.path.abspath(os.path.expanduser(env))
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "exploits")


# --------------------------------------------------------------------- manifest

@dataclass(frozen=True)
class Artifact:
    category: str
    name: str
    kind: str            # git | file | ghrelease
    url: str
    notes: str = ""


def parse_manifest(path=None):
    """Parse ``manifest.tsv`` into :class:`Artifact` rows (comments/blanks skipped)."""
    path = path or os.path.join(arsenal_dir(), "manifest.tsv")
    out = []
    if not os.path.exists(path):
        return out
    with open(path, errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 4:
                continue
            out.append(Artifact(parts[0], parts[1], parts[2], parts[3],
                                parts[4] if len(parts) > 4 else ""))
    return out


def staged(root=None):
    """Map of ``category -> [artifact names present on disk]``."""
    root = root or arsenal_dir()
    found = {}
    if not os.path.isdir(root):
        return found
    for cat in sorted(os.listdir(root)):
        catdir = os.path.join(root, cat)
        if not os.path.isdir(catdir):
            continue
        names = [n for n in sorted(os.listdir(catdir)) if not n.startswith(".")]
        if names:
            found[cat] = names
    return found


def find(name, root=None):
    """Path to a staged artifact by name (exact, then case-insensitive prefix), or None."""
    root = root or arsenal_dir()
    if not os.path.isdir(root):
        return None
    low = name.lower()
    prefix = None
    for cat in sorted(os.listdir(root)):
        catdir = os.path.join(root, cat)
        if not os.path.isdir(catdir):
            continue
        for n in sorted(os.listdir(catdir)):
            if n == name:
                return os.path.join(catdir, n)
            if prefix is None and n.lower().startswith(low):
                prefix = os.path.join(catdir, n)
    return prefix


# --------------------------------------------------------------- requirements

@dataclass(frozen=True)
class Need:
    """What a vector/technique requires to actually fire."""

    kind: str            # builtin | staged | build | supplied
    hint: str
    options: tuple = ()   # staged: acceptable artifact names (any one) ; build: the format
    category: str = ""    # staged-by-category (a build-matched PoC lives here, pick one)


#: privesc report_type -> Need. Built-ins run a native target command (nothing to
#: stage); staged needs an operator artifact; build is produced by fieldkit.poc.
PRIVESC_NEEDS = {
    "seimpersonate": Need(STAGED, "a Potato (SeImpersonate → SYSTEM)",
                          ("GodPotato", "PrintSpoofer", "JuicyPotatoNG", "SweetPotato",
                           "EfsPotato", "SharpEfsPotato", "GenericPotato")),
    "lsass": Need(BUILTIN, "comsvcs.dll MiniDump is native; procdump/nanodump optional",
                  ("procdump64.exe", "procdump.exe", "nanodump")),
    "sebackup": Need(BUILTIN, "reg save is native"),
    "alwaysinstallelevated": Need(BUILD, "a SYSTEM .msi", ("msi",)),
    "unquoted_service": Need(BUILD, "a payload .exe planted on the path", ("exe",)),
    "weak_service_perms": Need(BUILD, "a payload .exe", ("exe",)),
    "writable_service_binary": Need(BUILD, "a payload .exe", ("exe",)),
    "service_reg_imagepath": Need(BUILD, "a payload .exe", ("exe",)),
    "service_dll_hijack": Need(BUILD, "a payload .dll (search-order hijack)", ("dll",)),
    "seloaddriver": Need(SUPPLIED, "a vulnerable signed driver (loldrivers.io) + loader"),
    "setakeownership": Need(BUILTIN, "takeown/icacls are native"),
    "semanagevolume": Need(BUILD, "a payload .dll a SYSTEM service loads", ("dll",)),
    "localkernel_win": Need(STAGED, "a build-matched Windows LPE PoC (win-kernel/)",
                            category="win-kernel"),
    "printnightmare": Need(STAGED, "a PrintNightmare PoC (win-kernel/)",
                           ("printnightmare", "SharpPrintNightmare")),
    "kernel_cve": Need(STAGED, "a build-matched Linux kernel PoC (lin-kernel/)",
                       category="lin-kernel"),
    "gtfobins_sudo": Need(BUILTIN, "native sudo/GTFOBins"),
    "gtfobins_suid": Need(BUILTIN, "native SUID/GTFOBins"),
    "capability": Need(BUILTIN, "native capability abuse"),
    "sudo_misconfig": Need(BUILTIN, "native sudo"),
    "docker_group": Need(BUILTIN, "native docker"),
    "ld_preload": Need(BUILD, "a preload .so", ("so",)),
}

#: evasion technique key -> Need (the delivery it depends on).
EVASION_NEEDS = {
    "native-exe": Need(BUILD, "an XOR'd native .exe", ("exe",)),
    "native-dll": Need(BUILD, "an XOR'd native .dll", ("dll",)),
    "nc-revshell": Need(STAGED, "nc.exe", ("nc.exe",)),
    "inmem-fileless": Need(BUILD, "an AMSI-patched in-memory loader", ("ps1",)),
    "inmem-reflective": Need(BUILD, "an AMSI-patched reflective loader", ("ps1",)),
    "ps-amsi-revshell": Need(BUILD, "an AMSI-patched PowerShell revshell", ("ps1",)),
    "msi-aie": Need(BUILD, "a SYSTEM .msi", ("msi",)),
    "add-admin": Need(BUILTIN, "net user is native"),
    "ld-preload": Need(BUILD, "a preload .so", ("so",)),
    "kernel-poc": Need(STAGED, "a build-matched kernel PoC", category="lin-kernel"),
}


@dataclass
class Resolution:
    """Whether a Need is satisfiable right now."""

    key: str
    need: Need
    ready: bool
    detail: str
    path: str = None


def resolve(key, need, root=None):
    """Resolve a :class:`Need` against the staged arsenal → :class:`Resolution`."""
    if need.kind == BUILTIN:
        return Resolution(key, need, True, "native target command — nothing to stage")
    if need.kind == BUILD:
        fmt = need.options[0] if need.options else "?"
        return Resolution(key, need, True, f"fieldkit builds this ({fmt}) — `fieldkit poc`")
    if need.kind == SUPPLIED:
        return Resolution(key, need, False, "operator-supplied — not in the manifest")
    # STAGED: present if any acceptable option is on disk...
    for opt in need.options:
        p = find(opt, root)
        if p:
            return Resolution(key, need, True, f"staged: {opt}", p)
    # ...or, for a build-matched PoC, if its category has anything staged to pick from.
    if need.category:
        catdir = os.path.join(root or arsenal_dir(), need.category)
        names = [n for n in os.listdir(catdir)] if os.path.isdir(catdir) else []
        if names:
            return Resolution(key, need, True,
                              f"{len(names)} in {need.category}/ — match one to the target",
                              catdir)
        return Resolution(key, need, False, f"nothing staged in {need.category}/")
    if not need.options:
        return Resolution(key, need, False, "stage a matched artifact (see the hint)")
    return Resolution(key, need, False,
                      "not staged — fetch one of: " + ", ".join(need.options))
