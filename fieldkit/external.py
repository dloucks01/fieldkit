"""External-exploit loop — the credential loop's external twin.

From nmap-ingested services (product + version + port, no foothold) it matches each
against fieldkit's shipped **service-CVE TTP library** (T1190 — a ``version_range``
predicate over ``services.<name>``), ranks the matches on the same
exploitability/safety/detection axes as the escalate loop, and records each as an
(unproven) ``exposed_service_cve`` finding carrying the vulnerable-version evidence and
the TTP playbook's exploit next-step.

It drives nothing itself — the playbook points at the operator's own PoC/arsenal;
fieldkit owns the match, the ranking and the report. The whole matching engine is
reused from :mod:`fieldkit.ttps.adapter` (the same ``version_range`` predicate the
on-host privesc path uses); this module only bridges nmap ``service`` rows into the
``facts.services`` shape the predicate reads, so a service-CVE fires from an *external*
scan the same way it does from *on-host* enumeration.
"""
from dataclasses import dataclass

from .hostenum import HostFacts
from .privesc import _Ctx
from .ttps import load_all
from .ttps.adapter import ttp_to_vectors

#: nmap product/banner keyword → the TTP ``services.<key>`` it maps to. Match is a
#: case-insensitive substring on the nmap product string + banner. Version-gating makes
#: a loose keyword match safe: a wrong product with an out-of-range version simply does
#: not fire. Extend as the TTP library grows.
_PRODUCT_KEYWORDS = {
    "exchange": ["exchange"],
    "apache": ["apache", "httpd"],
    "openssh": ["openssh"],
    "tomcat": ["tomcat"],
    "confluence": ["confluence"],
    "struts": ["struts"],
    "activemq": ["activemq"],
    "cups": ["cups"],
    "gitlab": ["gitlab"],
    "wordpress": ["wordpress"],
    "php": ["php"],
    "log4j": ["log4j"],
    "vcenter": ["vcenter"],
    "esxi": ["esxi", "vmware esx"],
    "zabbix": ["zabbix"],
    "teamcity": ["teamcity"],
    "roundcube": ["roundcube"],
    "screenconnect": ["screenconnect"],
    "netscaler": ["netscaler", "citrix"],
    "sonicos": ["sonicos", "sonicwall"],
    "coldfusion": ["coldfusion"],
    "fortigate": ["fortigate", "fortios"],
    "fortimanager": ["fortimanager"],
    "gaia": ["check point", "gaia"],
    "pan": ["pan-os", "palo alto", "globalprotect"],
    "secure": ["pulse secure", "ivanti connect", "ivanti secure"],
    "xe": ["ios xe"],
    "epm": ["ivanti epm", "endpoint manager"],
    "big": ["big-ip", "bigip", "f5 "],
    "github": ["github enterprise"],
    "netscaler_adc": ["adc"],
}


@dataclass
class ExternalReport:
    findings_added: int = 0
    matched: int = 0          # total (host, cve) opportunities matched (pre-dedup)


def _service_cve_ttps():
    """The shipped service-version CVE TTPs: a ``version_range`` predicate whose fields
    are all ``services.*`` (external service exploitation — excludes kernel/glibc LPE
    version_range TTPs, which are on-host)."""
    out = []
    for ttp in load_all():
        d = ttp.detect
        if d.kind != "version_range" or not isinstance(d.value, dict) or not d.value:
            continue
        if all(str(f).startswith("services.") for f in d.value):
            out.append(ttp)
    return out


def _referenced_keys(ttps):
    """The set of ``services.<key>`` names the given TTPs match on."""
    keys = set()
    for ttp in ttps:
        for field_name in ttp.detect.value:
            _, _, name = str(field_name).partition(".")
            if name:
                keys.add(name)
    return keys


def _service_versions(services, wanted_keys):
    """Map nmap ``service`` rows → ``{ttp_key: version}`` for the keys the TTP library
    cares about. A row contributes its version under every TTP key whose keyword appears
    in the row's product/banner (version-gating filters false keyword hits)."""
    out = {}
    for s in services:
        version = s["version"]
        if not version:
            continue
        hay = f"{s['product'] or ''} {s['banner'] or ''}".lower()
        for key in wanted_keys:
            keywords = _PRODUCT_KEYWORDS.get(key, [key])
            if any(kw in hay for kw in keywords):
                out.setdefault(key, version)
    return out


def match(store):
    """Every ``(host_row, Vector)`` opportunity from matching discovered services
    against the service-CVE TTP library, best-ranked first. Read-only — records
    nothing. The service's presence implies its platform, so each TTP is evaluated with
    ``facts.os`` aligned to the TTP's platform (the match itself is version-gated)."""
    ttps = _service_cve_ttps()
    keys = _referenced_keys(ttps)
    out = []
    for host in store.hosts():
        svc_versions = _service_versions(store.services(host["id"]), keys)
        if not svc_versions:
            continue
        ctx = _Ctx(host=host["ip"])
        for ttp in ttps:
            facts = HostFacts(
                os=(ttp.platform[0] if ttp.platform else None),
                services=dict(svc_versions))
            for vector in ttp_to_vectors(ttp, facts, ctx):
                out.append((host, vector))
    out.sort(key=lambda hv: (-hv[1].score, hv[0]["ip"], hv[1].key))
    return out


def apply(store):
    """Record each matched service-CVE as an (unproven) finding on its host. Returns an
    :class:`ExternalReport`. These are *observations* — a matched vulnerable version,
    not yet exploited — so they carry no proof step (``report --check`` treats an
    unproven finding as an observation, not a fabricated claim). Idempotent."""
    rep = ExternalReport()
    seen = set()
    with store.transaction():
        for host, vector in match(store):
            rep.matched += 1
            k = (host["id"], vector.report_type or "exposed_service_cve", vector.title)
            if k in seen:
                continue
            seen.add(k)
            _, created = store.add_finding(
                vector.report_type or "exposed_service_cve", vector.title,
                host_id=host["id"], evidence=(vector.evidence or vector.detail),
                proven=False)
            rep.findings_added += created
    return rep
