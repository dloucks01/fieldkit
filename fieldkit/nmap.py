"""Parse nmap output → hosts + services, fold into state.

The dominant external tool for host discovery. Testers save nmap output in one
of three native formats; this reads all of them (auto-detected) and populates
the same host/service rows any other fieldkit path would. Split the same way
:mod:`ingest` is:

  * :func:`parse` — auto-detects format and dispatches (XML / normal / grepable)
  * :func:`parse_xml`, :func:`parse_normal`, :func:`parse_grepable` — explicit
    per-format entry points, all pure (no store, no I/O), all return an
    :class:`NmapIntent`.
  * :func:`apply` writes the intent in one transaction.

Formats supported (`nmap -o<X|N|G|A>`):

  * ``-oX`` — XML; the richest (OS detection, script output, full metadata)
  * ``-oN`` — normal (human-readable); the default text output most testers save
  * ``-oG`` — grepable (single-line-per-host); scriptable, common in pipelines

nmap output nuances handled uniformly across formats:
  * only UP hosts land (down hosts pollute state)
  * only OPEN ports land (filtered/closed drop)
  * ipv4 only (ipv6 skipped; XML uses ``addrtype="ipv4"``, text formats infer)
  * hostname preserved when present
  * OS coarse-labeled to windows/linux from the top ``osmatch`` (XML only —
    normal and grepable don't include OS detection by default)
  * scope enforcement respected in :func:`apply` — out-of-scope IPs skipped
    silently, reported in the intent's ``out_of_scope`` list.

No dependency added — stdlib ``xml.etree.ElementTree`` handles XML; the text
formats parse with regex.
"""
import re
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


def parse_xml(text):
    """Parse ``nmap -oX`` XML into an :class:`NmapIntent`. No I/O, no state.

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


# ---------------------------------------------------------------- normal (-oN)
#
# Per-host block starts with "Nmap scan report for ...", ends at the next such
# marker or "Nmap done:". Ports are in a table:
#
#   Nmap scan report for app01 (10.0.0.5)
#   Host is up (0.0012s latency).
#   Not shown: 998 closed ports
#   PORT     STATE SERVICE VERSION
#   22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1
#   80/tcp   open  http    nginx 1.24.0

_NORMAL_HEADER = re.compile(r"# Nmap (\S+) scan initiated .* as:\s+(.*)$", re.M)
_NORMAL_HOST_MARKER = re.compile(
    r"^Nmap scan report for\s+(?:(\S+)\s+\(([\d.]+)\)|([\d.]+))\s*$", re.M)
_NORMAL_HOST_DOWN = re.compile(r"^Host seems down\.?|^Note: Host seems down\.", re.M)
#: Match ONE port line. Uses `[ \t]` explicitly, never `\s`, so the pattern
#: can't accidentally cross newlines and swallow the next port line's fields
#: (a real bug the smoke-test found in the first cut).
_NORMAL_PORT_LINE = re.compile(
    r"^(\d+)/(tcp|udp)[ \t]+(open|open\|filtered)[ \t]+(\S+)"
    r"(?:[ \t]+([^\r\n]*?))?[ \t]*$", re.M)


def parse_normal(text):
    """Parse ``nmap -oN`` normal (human-readable) output into an
    :class:`NmapIntent`. The default text format most testers save."""
    intent = NmapIntent()
    if not text:
        return intent
    m = _NORMAL_HEADER.search(text)
    if m:
        intent.scanner = f"nmap {m.group(1)}"
        intent.args = m.group(2).strip()

    # Split into per-host blocks on the marker.
    markers = list(_NORMAL_HOST_MARKER.finditer(text))
    for i, mk in enumerate(markers):
        hostname = mk.group(1) or None      # "for name (ip)" form
        ip = mk.group(2) or mk.group(3)     # named or bare
        if ip is None:
            continue
        # slice from this marker to the next (or end)
        end = markers[i + 1].start() if i + 1 < len(markers) else len(text)
        block = text[mk.end():end]
        if _NORMAL_HOST_DOWN.search(block):
            continue                        # host is DOWN in this block — skip
        services = []
        for pm in _NORMAL_PORT_LINE.finditer(block):
            port = int(pm.group(1))
            proto = pm.group(2)
            # service_name in group(4), everything after (product + version + info) in (5)
            product, version = None, None
            rest = (pm.group(5) or "").strip()
            if rest:
                # heuristic: everything up to a version-looking token is product,
                # the version-looking token and after is the version + info blob.
                v = re.search(r"\b(\d[\w.\-]+)\b", rest)
                if v:
                    product = rest[:v.start()].strip() or None
                    version = v.group(1)
                else:
                    product = rest
            services.append(NmapService(port=port, proto=proto,
                                         product=product, version=version,
                                         banner=None))
        intent.hosts.append(NmapHost(ip=ip, hostname=hostname,
                                      os=None, services=services))
    return intent


# ---------------------------------------------------------------- grepable (-oG)
#
# One host per line, two lines per host (Status + Ports). Format:
#
#   Host: 10.0.0.5 (app01)\tStatus: Up
#   Host: 10.0.0.5 (app01)\tPorts: 22/open/tcp//ssh//OpenSSH 8.9p1/, 80/open/tcp//http//nginx 1.24/
#
# Each port field is 7 slash-separated bits: PORT/STATE/PROTO/OWNER/SERVICE/RPC/VERSION

_GREP_HOST = re.compile(r"^Host:\s+(\S+)(?:\s+\(([^)]*)\))?\s+(.*)$", re.M)


def parse_grepable(text):
    """Parse ``nmap -oG`` grepable output into an :class:`NmapIntent`."""
    intent = NmapIntent()
    if not text:
        return intent
    m = _NORMAL_HEADER.search(text)     # grepable uses the same "# Nmap" preamble
    if m:
        intent.scanner = f"nmap {m.group(1)}"
        intent.args = m.group(2).strip()

    by_ip = {}                          # ip -> NmapHost (aggregate Status + Ports)
    for match in _GREP_HOST.finditer(text):
        ip = match.group(1)
        hostname = (match.group(2) or "").strip() or None
        rest = match.group(3)
        host = by_ip.setdefault(ip, NmapHost(ip=ip, hostname=hostname))
        if hostname and not host.hostname:
            host.hostname = hostname
        if rest.startswith("Status:"):
            if "Up" not in rest:
                by_ip.pop(ip, None)     # host down — drop
        elif rest.startswith("Ports:"):
            for port_field in rest[len("Ports:"):].strip().split(","):
                bits = port_field.strip().split("/")
                # PORT/STATE/PROTO/OWNER/SERVICE/RPC/VERSION
                if len(bits) < 5:
                    continue
                port_s, state, proto, _owner, service = bits[:5]
                if state != "open":
                    continue
                try:
                    port = int(port_s)
                except ValueError:
                    continue
                version = bits[6] if len(bits) > 6 else None
                host.services.append(NmapService(
                    port=port, proto=proto or "tcp",
                    product=service or None, version=version or None))
    intent.hosts.extend(by_ip.values())
    return intent


def parse(text):
    """Auto-detect nmap output format and parse it. Handles XML / normal /
    grepable transparently, so a CLI or ingest caller does not have to care
    which ``-o<X|N|G>`` the tester used.

    Detection is cheap — leading ``<?xml`` or ``<nmaprun`` → XML, presence of
    ``Host:.*Status:`` lines → grepable, otherwise normal. An empty or
    unrecognized input returns an empty intent.
    """
    if not text:
        return NmapIntent()
    head = text.lstrip()[:200]
    if head.startswith("<?xml") or head.startswith("<nmaprun"):
        return parse_xml(text)
    # grepable is unambiguous — "Host:" followed by "Status:" on the same line
    if re.search(r"^Host:\s+\S+.*Status:", text, re.M):
        return parse_grepable(text)
    if "Nmap scan report for" in text:
        return parse_normal(text)
    return NmapIntent()


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
