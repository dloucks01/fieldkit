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
    """Normalize an nxc ``[+]`` line into a stored credential, or ``None``
    when the line's principal + secret can't form a well-shaped credential
    (empty user, empty secret, pure separators, etc. — garbage nxc sometimes
    emits around a crashing module). The caller drops ``None`` rows.

    Reuses the one credential parser, so a hash echoed by a ``-H`` spray
    classifies as an NT hash exactly the way ``add cred`` would, and a
    local-auth spray (nxc prints the *hostname* where a domain would be) is
    kept as-is — the loop reuses the credential the same way nxc proved it.
    """
    if result.domain:
        spec = f"{result.domain}\\{result.username}:{result.secret}"
    else:
        spec = f"{result.username}:{result.secret}"
    try:
        return parse_credential(spec).credential
    except Exception:                                            # noqa: BLE001
        # parse_credential raises CredentialError on empty user / empty secret /
        # unparseable shape. For an ingest stream we silently drop the row —
        # the alternative is to crash the whole ingest on one bad line from a
        # misbehaving tool, which the parser-fuzz tests prove can happen.
        return None


def classify_nxc(text):
    """Parse an nxc capture into an :class:`NxcIntent` without touching the store."""
    parsed = parse_output(text)
    creds = [(cred, r) for r in parsed.valid
             for cred in (_credential_from_result(r),) if cred is not None]
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
    #: IPs a nxc result named that fall outside the engagement scope — dropped as
    #: targets (never turned into host rows) and surfaced so the CLI can warn.
    out_of_scope: list = field(default_factory=list)


def apply_nxc(store, intent, source="spray"):
    """Write an :class:`NxcIntent` to the store in one transaction. Returns an
    :class:`IngestReport`."""
    rep = IngestReport()
    with store.transaction():
        for info in intent.hosts:
            # Scope is a rule-of-engagement boundary: an out-of-scope IP must never
            # become a live target, matching ingest.apply_nmap. Recovered credentials
            # (below) are still kept — they're knowledge, not targets.
            if not store.in_scope(info.ip):
                if info.ip not in rep.out_of_scope:
                    rep.out_of_scope.append(info.ip)
                continue
            _, created = store.add_host(
                info.ip, hostname=info.hostname, os_name=_os_from_banner(info),
                is_dc=True if info.is_dc else None)
            rep.hosts_added += created
            rep.hosts_enriched += not created

        for cred, result in intent.creds:
            cred_id, created = store.add_credential(cred, source=source)
            rep.creds_added += created
            rep.creds_reused += not created
            if not store.in_scope(result.ip):
                if result.ip not in rep.out_of_scope:
                    rep.out_of_scope.append(result.ip)
                continue
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
