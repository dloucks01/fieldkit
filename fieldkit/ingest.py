"""Fold captured tool output back into state.

The credential loop runs on facts, and facts arrive as tool output — an nxc spray, a
secretsdump. This module turns that text into rows: valid credentials, the hosts they
work on, and who is admin where. It is split in two so the CLI can keep fieldkit's
confirm-before-write habit:

  * :func:`classify_nxc` is **pure** — text in, a :class:`NxcIntent` out, no store
    touched — so the CLI can show the operator exactly what it read;
  * :func:`apply_nxc` writes that intent in one transaction.

Everything a spray proves also enriches scope for free: the ``[*]`` banner nxc prints
on the way past a host fingerprints its OS, domain and DC-ness with no extra packet.
"""
from dataclasses import dataclass, field

from .creds import parse_credential
from .netexec import parse_output


@dataclass
class NxcIntent:
    """What an nxc capture would record: host enrichments + valid credentials.

    ``creds`` pairs each normalized :class:`~fieldkit.creds.Credential` with the
    :class:`~fieldkit.netexec.AuthResult` it came from, so the writer knows the host,
    protocol and admin verdict to attach to it.
    """

    hosts: list = field(default_factory=list)   # HostInfo
    creds: list = field(default_factory=list)    # (Credential, AuthResult)

    @property
    def admin(self):
        return [(c, r) for c, r in self.creds if r.admin]


#: the OS family a successful auth on a protocol implies, when no banner said otherwise.
_PROTO_OS = {"SSH": "linux", "SMB": "windows", "WINRM": "windows", "RDP": "windows",
             "MSSQL": "windows"}


def _os_from_banner(info):
    """Map an nxc banner to fieldkit's coarse OS label, or None if it does not say."""
    text = (info.os or "").lower()
    if text.startswith("windows") or info.proto in ("SMB", "WINRM"):
        return "windows"
    if "linux" in text or "unix" in text or info.proto == "SSH":
        return "linux"
    return None


def _credential_from_result(result):
    """Normalize an nxc ``[+]`` line into a stored credential.

    Reuses the one credential parser, so a hash echoed by a ``-H`` spray classifies
    as an NT hash exactly the way ``add cred`` would, and a local-auth spray (nxc
    prints the *hostname* where a domain would be) is kept as-is — the loop reuses
    the credential the same way nxc proved it.
    """
    if result.domain:
        spec = f"{result.domain}\\{result.username}:{result.secret}"
    else:
        spec = f"{result.username}:{result.secret}"
    return parse_credential(spec).credential


def classify_nxc(text):
    """Parse an nxc capture into an :class:`NxcIntent` without touching the store."""
    parsed = parse_output(text)
    creds = [(_credential_from_result(r), r) for r in parsed.valid]
    return NxcIntent(hosts=parsed.hosts, creds=creds)


@dataclass
class IngestReport:
    """Counts from an apply, for the operator line at the end."""

    hosts_added: int = 0
    hosts_enriched: int = 0
    creds_added: int = 0
    creds_reused: int = 0
    access_added: int = 0
    admin_added: int = 0


def apply_nxc(store, intent, source="spray"):
    """Write an :class:`NxcIntent` to the store in one transaction. Returns an
    :class:`IngestReport`."""
    rep = IngestReport()
    with store.transaction():
        for info in intent.hosts:
            _, created = store.add_host(
                info.ip, hostname=info.hostname, os_name=_os_from_banner(info),
                is_dc=True if info.is_dc else None)
            rep.hosts_added += created
            rep.hosts_enriched += not created

        for cred, result in intent.creds:
            cred_id, created = store.add_credential(cred, source=source)
            rep.creds_added += created
            rep.creds_reused += not created
            # A valid result may name a host no banner covered — ensure it exists, and
            # infer the OS family from the proto that authed (ssh→linux, smb/winrm→windows)
            # so a banner-less host (e.g. an ssh foothold) is still enum-plannable.
            host_id, host_created = store.add_host(
                result.ip, os_name=_PROTO_OS.get(result.proto))
            rep.hosts_added += host_created
            _, acreated = store.add_access(
                host_id, cred_id, method=result.proto.lower(), admin=result.admin)
            rep.access_added += acreated
            if acreated and result.admin:
                rep.admin_added += 1
    return rep
