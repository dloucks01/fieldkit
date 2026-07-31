"""Parse nmap XML → hosts + services, fold into state.

The dominant external tool for host discovery. Testers already run nmap and
save the XML; this reads it and populates the same host/service rows any
other fieldkit path would. Split the same way :mod:`ingest` is:

  * :func:`parse` is pure — XML in, an :class:`NmapIntent` out, no store
    touched — so the CLI can preview what will land;
  * :func:`apply` writes the intent in one transaction.

nmap output nuances handled:
  * ``<state state="up">`` — only up hosts land (down hosts pollute state).
  * ``<address addrtype="ipv4">`` — takes the ipv4 addr; ipv6 falls through.
  * ``<hostname>`` — takes the first PTR name if present.
  * ``<port state="open">`` — only OPEN ports land; filtered/closed drop.
  * ``<service name product version>`` — banner is best-effort from ``ostype``
    + ``extrainfo`` when they're there.
  * ``<os><osmatch>`` — coarse OS label (windows/linux/…) from the top match.
  * Scope enforcement is respected: an IP outside :meth:`Store.in_scope` is
    silently skipped, reported in the intent's ``out_of_scope`` list.

No dependency added — stdlib ``xml.etree.ElementTree`` handles it.
"""
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field


@dataclass
class NmapHost:
    ip: str
    hostname: str = None
    os: str = None                      # coarse: 'windows' | 'linux' | None
    services: list = field(default_factory=list)   # NmapService


@dataclass
class NmapService:
    port: int
    proto: str = "tcp"                  # tcp | udp
    product: str = None
    version: str = None
    banner: str = None


@dataclass
class NmapIntent:
    hosts: list = field(default_factory=list)       # NmapHost
    scanner: str = None                              # e.g. "nmap 7.94"
    args: str = None                                 # captured argv


def _coarse_os(osname):
    """Map an <osmatch name=...> string to fieldkit's coarse os label, or None."""
    if not osname:
        return None
    low = osname.lower()
    if "windows" in low:
        return "windows"
    if "linux" in low or "unix" in low or "bsd" in low or "solaris" in low:
        return "linux"
    return None


def _host_ip(host_elem):
    """Return the ipv4 address on a <host>, or None."""
    for addr in host_elem.findall("address"):
        if addr.get("addrtype") == "ipv4":
            return addr.get("addr")
    return None


def _host_name(host_elem):
    """First hostname (usually PTR), or None."""
    hostnames = host_elem.find("hostnames")
    if hostnames is None:
        return None
    for name in hostnames.findall("hostname"):
        if name.get("name"):
            return name.get("name")
    return None


def _host_os(host_elem):
    """Coarse OS label from the top <osmatch>, or None."""
    os_elem = host_elem.find("os")
    if os_elem is None:
        return None
    matches = os_elem.findall("osmatch")
    if not matches:
        return None
    # highest accuracy first (nmap sorts them but be defensive)
    top = max(matches, key=lambda m: int(m.get("accuracy", "0")))
    return _coarse_os(top.get("name"))


def _service_banner(svc_elem):
    """Best-effort banner from a <service> element: 'ostype extrainfo'."""
    if svc_elem is None:
        return None
    bits = [svc_elem.get("ostype"), svc_elem.get("extrainfo")]
    joined = " ".join(b for b in bits if b)
    return joined or None


def _host_services(host_elem):
    """Every OPEN service on a host — filtered/closed drop."""
    out = []
    ports_elem = host_elem.find("ports")
    if ports_elem is None:
        return out
    for port_elem in ports_elem.findall("port"):
        state_elem = port_elem.find("state")
        if state_elem is None or state_elem.get("state") != "open":
            continue
        try:
            port = int(port_elem.get("portid"))
        except (TypeError, ValueError):
            continue
        proto = port_elem.get("protocol") or "tcp"
        svc_elem = port_elem.find("service")
        product = svc_elem.get("product") if svc_elem is not None else None
        version = svc_elem.get("version") if svc_elem is not None else None
        out.append(NmapService(port=port, proto=proto,
                               product=product, version=version,
                               banner=_service_banner(svc_elem)))
    return out


def parse(text):
    """Parse nmap XML into an :class:`NmapIntent`. No I/O, no state.

    Returns an empty intent (with any scanner metadata we could read) rather
    than raising when the XML is malformed or empty — the CLI reports "no
    usable hosts" and the operator moves on.
    """
    intent = NmapIntent()
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return intent
    if root.tag != "nmaprun":
        return intent
    intent.scanner = f"{root.get('scanner', 'nmap')} {root.get('version', '')}".strip()
    intent.args = root.get("args") or None
    for host_elem in root.findall("host"):
        status = host_elem.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip = _host_ip(host_elem)
        if ip is None:
            continue
        intent.hosts.append(NmapHost(
            ip=ip, hostname=_host_name(host_elem), os=_host_os(host_elem),
            services=_host_services(host_elem)))
    return intent


@dataclass
class NmapIngestReport:
    hosts_added: int = 0
    hosts_enriched: int = 0
    services_added: int = 0
    services_enriched: int = 0
    out_of_scope: list = field(default_factory=list)


def apply(store, intent, source="nmap"):
    """Fold an :class:`NmapIntent` into the store in one transaction.

    Scope-aware — an IP outside :meth:`Store.in_scope` is silently dropped and
    named in ``report.out_of_scope`` so the CLI can surface it. The ``source``
    argument is retained for symmetry with ``ingest.apply_nxc``; nmap doesn't
    produce credentials, so it's currently only used for future audit.
    """
    _ = source     # reserved — nmap doesn't produce creds, but keep the signature
    rep = NmapIngestReport()
    with store.transaction():
        for h in intent.hosts:
            if not store.in_scope(h.ip):
                rep.out_of_scope.append(h.ip)
                continue
            host_id, created = store.add_host(
                h.ip, hostname=h.hostname or None, os_name=h.os)
            rep.hosts_added += created
            rep.hosts_enriched += not created
            for s in h.services:
                _, s_created = store.add_service(
                    host_id, s.port, proto=s.proto,
                    product=s.product, version=s.version, banner=s.banner)
                rep.services_added += s_created
                rep.services_enriched += not s_created
    return rep
