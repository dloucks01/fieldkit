"""Preflight — are the external tools fieldkit drives present on PATH?

fieldkit is stdlib-only and drives the operator's kit; on a fresh box this says what's
installed before an engagement. netexec + impacket are the spine (required); the rest are
per-feature. Build-toolchain detail is `fieldkit poc --check`; staged exploits are
`fieldkit arsenal check`.
"""
import shutil

#: (name, purpose, [candidate binaries — first found wins], required-for-the-spine).
#: The ``name`` is the tool's canonical name — what shows up in a terse warning list
#: like "netexec, impacket". The ``purpose`` describes what fieldkit uses it for and
#: renders alongside the name only in the full ``fieldkit preflight`` table.
CHECKS = (
    ("netexec", "spray / exec / loot", ["nxc", "netexec"], True),
    ("impacket", "secretsdump / wmiexec", ["impacket-secretsdump", "secretsdump.py"], True),
    ("certipy", "ADCS (adcs find)", ["certipy", "certipy-ad"], False),
    ("evil-winrm", "WinRM shell", ["evil-winrm"], False),
    ("msfvenom", "poc exe/dll/ps1", ["msfvenom"], False),
    ("wixl", "poc msi", ["wixl"], False),
    ("gcc", "poc so", ["gcc"], False),
    ("mingw-w64", "poc from --source", ["x86_64-w64-mingw32-gcc"], False),
    ("pandoc", "report docx/pdf", ["pandoc"], False),
)


def check(which=shutil.which):
    """Resolve each tool → ``(name, purpose, found_binary_or_None, candidates, required)``."""
    out = []
    for name, purpose, alts, required in CHECKS:
        found = next((a for a in alts if which(a)), None)
        out.append((name, purpose, found, alts, required))
    return out


def missing_required(rows):
    """Rows whose tool is REQUIRED but not on PATH. Preserves the 5-tuple shape."""
    return [r for r in rows if r[4] and not r[2]]
