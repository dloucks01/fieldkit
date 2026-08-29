"""Ingest recce's fieldkit-export bundle — ``recce-bridge.json`` into state.

recce is the survey-plan-catch-report platform that hands fieldkit a prioritized
work-queue. ``recce fieldkit-export`` writes ``eng/fieldkit/recce-bridge.json`` — the
rich feed: per-host ports/service/version, recce's *confirmed* findings, the exact
generator recce recommends per host, severity-ranked. This module folds that into
fieldkit state so ``analyze`` promotes recce-confirmed hosts above unranked ones —
recce's confirmed findings become the exploitability axis fieldkit's ranking was
previously guessing at.

Split the same way :mod:`ingest` and :mod:`nmap` are — :func:`parse` is *pure*
(text/dict in, :class:`RecceIntent` out, no store touched) and :func:`apply` writes
the intent in one transaction. Idempotent — re-ingesting the same bridge does not
duplicate rows; recce updates its bridge as it scans, so operators will re-ingest.

Only the bare fact-shaped parts of the bridge become state:

  * a **host** row per bridge entry (ip, hostname, os) — enriched via
    :meth:`~fieldkit.state.Store.add_host` (never overwrites known fields);
  * a **service** row per open port (port, product, version) — enriched via
    :meth:`~fieldkit.state.Store.add_service`;
  * a **finding** row for each recce-CONFIRMED vuln
    (``vector_type="recce_confirmed_vuln"``);
  * a **finding** row for each version→CVE lookup route recce identified
    (``vector_type="recce_version_lookup"``) — a *lead* fieldkit's escalate loop
    should verify, not a proof.

What is NOT stored: recce's hand-authored ``access_cmds`` / ``suggested`` / plan-md
prose. Those are commands recce wrote for a human operator; fieldkit does not fire
them blindly. They will become fireable in Phase B when the TTP-as-data library
matures the primitive layer.

The bridge's ``users`` list is exposed on the intent for the CLI to hand off to
whatever consumes it (username-wordlist generation); this module never touches the
wordlist store directly, keeping the ingest boundary clean.

Version pinning: this module reads bridge major-version 1. An unknown major fails
loudly with a clear operator error rather than half-parsing.
"""
import json
from dataclasses import dataclass, field

BRIDGE_MAJOR = 1

#: fieldkit vector_type for a recce-confirmed vulnerability. The KB predicate in
#: :mod:`fieldkit.kb` reads this key; changing it means updating both.
VECTOR_CONFIRMED = "recce_confirmed_vuln"

#: fieldkit vector_type for a recce version→CVE lookup route (a lead, not a proof).
VECTOR_VERSION_ROUTE = "recce_version_lookup"

_SEV_NORM = {"critical": "critical", "high": "high", "medium": "medium",
             "low": "low", "info": "info"}


@dataclass
class RecceService:
    port: int
    product: str = None
    version: str = None
    service: str = None                       # nmap service label; kept for banner


@dataclass
class RecceFinding:
    """A recce-confirmed vuln we will store as a finding row.

    ``cves`` are joined into the evidence line so operators + the report see them
    at a glance without a schema change (the ``finding`` table has no refs column).
    """

    title: str
    severity: str                              # normalized lowercase or 'info'
    ports: list = field(default_factory=list)
    cves: list = field(default_factory=list)
    cwes: list = field(default_factory=list)
    source: str = ""                           # recce's own source tag (e.g. "vulners")


@dataclass
class RecceVersionRoute:
    """A version→CVE lookup route recce identified — a lead, unproven."""

    port: int
    service: str                               # e.g. "apache"
    version: str
    cves: list = field(default_factory=list)


@dataclass
class RecceHost:
    ip: str
    hostname: str = None
    os: str = None                             # kept verbatim; add_host stores it as-is
    services: list = field(default_factory=list)     # RecceService
    findings: list = field(default_factory=list)     # RecceFinding
    version_routes: list = field(default_factory=list)  # RecceVersionRoute


@dataclass
class RecceIntent:
    """What a bridge would record: hosts + confirmed vulns + version routes + users."""

    hosts: list = field(default_factory=list)        # RecceHost
    users: list = field(default_factory=list)        # bare usernames
    engagement: str = ""
    generated: str = ""


@dataclass
class RecceIngestReport:
    """Counts from an apply, for the operator line at the end."""

    hosts_added: int = 0
    hosts_enriched: int = 0
    services_added: int = 0
    services_enriched: int = 0
    confirmed_added: int = 0
    confirmed_seen: int = 0                    # re-ingested (already stored)
    version_routes_added: int = 0
    version_routes_seen: int = 0
    out_of_scope: list = field(default_factory=list)


class RecceBridgeError(ValueError):
    """Raised when the bridge is malformed or an unsupported major version."""


def _coerce_severity(sev):
    """Normalize recce's severity to fieldkit's canonical set."""
    return _SEV_NORM.get((sev or "").lower(), "info")


def parse(text_or_bytes):
    """Parse a ``recce-bridge.json`` payload into a :class:`RecceIntent`.

    Accepts a JSON string or bytes. Pins on bridge major version 1 — an unknown
    ``_recce_bridge`` fails loudly rather than half-parsing. Unknown fields in
    host/finding entries are ignored (forward-compat: a future recce that adds keys
    still parses on today's fieldkit, and the operator learns via the ingest report
    rather than a hard error).
    """
    if isinstance(text_or_bytes, bytes):
        text_or_bytes = text_or_bytes.decode("utf-8", errors="replace")
    try:
        doc = json.loads(text_or_bytes)
    except json.JSONDecodeError as exc:
        raise RecceBridgeError(f"not valid JSON: {exc}") from exc

    if not isinstance(doc, dict):
        raise RecceBridgeError("recce-bridge.json root must be an object")

    ver = doc.get("_recce_bridge")
    if ver is None:
        raise RecceBridgeError(
            "missing '_recce_bridge' field — this does not look like a recce bridge "
            "(is it a fieldkit findings.json instead? use `report --check` for those).")
    if not isinstance(ver, int) or ver != BRIDGE_MAJOR:
        raise RecceBridgeError(
            f"unsupported bridge version {ver!r}; this fieldkit reads major "
            f"{BRIDGE_MAJOR}. Upgrade fieldkit or export from an older recce.")

    intent = RecceIntent(
        engagement=str(doc.get("engagement") or ""),
        generated=str(doc.get("generated") or ""),
        users=[str(u) for u in (doc.get("users") or []) if str(u).strip()],
    )

    for hraw in doc.get("hosts") or []:
        if not isinstance(hraw, dict) or not hraw.get("ip"):
            continue
        h = RecceHost(
            ip=str(hraw["ip"]),
            hostname=(str(hraw["hostname"]).strip() or None) if hraw.get("hostname") else None,
            os=(str(hraw["os"]).strip() or None) if hraw.get("os") else None,
        )
        for praw in hraw.get("ports") or []:
            if not isinstance(praw, dict):
                continue
            try:
                port = int(praw.get("port"))
            except (TypeError, ValueError):
                continue
            h.services.append(RecceService(
                port=port,
                product=(praw.get("product") or None) or None,
                version=(praw.get("version") or None) or None,
                service=(praw.get("service") or None) or None,
            ))
        for fraw in hraw.get("findings") or []:
            if not isinstance(fraw, dict) or not fraw.get("title"):
                continue
            confidence = str(fraw.get("confidence") or "").lower()
            if confidence and confidence != "confirmed":
                # Only confirmed findings cross into fieldkit state — potentials are
                # recce's own follow-up, not a proven work-queue entry.
                continue
            h.findings.append(RecceFinding(
                title=str(fraw["title"]),
                severity=_coerce_severity(fraw.get("severity")),
                ports=[int(p) for p in (fraw.get("ports") or []) if isinstance(p, int)],
                cves=[str(c) for c in (fraw.get("cves") or []) if str(c).strip()],
                cwes=[str(c) for c in (fraw.get("cwes") or []) if str(c).strip()],
                source=str(fraw.get("source") or ""),
            ))
        for vraw in hraw.get("exploit_cmds") or []:
            if not isinstance(vraw, dict):
                continue
            try:
                port = int(vraw.get("port"))
            except (TypeError, ValueError):
                continue
            service = str(vraw.get("service") or "").strip()
            version = str(vraw.get("version") or "").strip()
            if not service or not version:
                continue
            h.version_routes.append(RecceVersionRoute(
                port=port, service=service, version=version,
                cves=[str(c) for c in (vraw.get("cves") or []) if str(c).strip()],
            ))
        intent.hosts.append(h)

    return intent


def _finding_title_confirmed(title):
    """Prefix the stored title so operators can spot recce-sourced findings at a
    glance in `fieldkit status`, without a schema change."""
    return f"[recce] {title}"


def _finding_title_version_route(service, version):
    return f"[recce] version→CVE lead: {service} {version}"


def _evidence_confirmed(f):
    """The evidence line recce-confirmed findings render with in the report."""
    parts = []
    if f.ports:
        parts.append("ports: " + ", ".join(str(p) for p in f.ports))
    if f.cves:
        parts.append("cves: " + ", ".join(f.cves))
    if f.cwes:
        parts.append("cwes: " + ", ".join(f.cwes))
    if f.source:
        parts.append(f"recce source: {f.source}")
    return " · ".join(parts) if parts else "recce confirmed"


def _evidence_version_route(v):
    parts = [f"port {v.port} ({v.service} {v.version})"]
    if v.cves:
        parts.append("cves: " + ", ".join(v.cves))
    return " · ".join(parts)


def apply(store, intent, source="recce"):
    """Fold a :class:`RecceIntent` into the store in one transaction.

    Scope-aware — an IP outside :meth:`Store.in_scope` is silently dropped and
    named in ``report.out_of_scope`` so the CLI can surface it. Idempotent —
    re-ingesting an updated bridge upserts host/service/finding rows without
    duplicating; the ``add_*`` methods key on their natural uniqueness.
    """
    _ = source  # reserved — matches nmap.apply's signature; no per-source branching yet
    rep = RecceIngestReport()
    with store.transaction():
        for h in intent.hosts:
            if not store.in_scope(h.ip):
                rep.out_of_scope.append(h.ip)
                continue
            host_id, host_created = store.add_host(
                h.ip, hostname=h.hostname, os_name=h.os)
            rep.hosts_added += host_created
            rep.hosts_enriched += not host_created

            for s in h.services:
                _, s_created = store.add_service(
                    host_id, s.port,
                    product=s.product or None,
                    version=s.version or None,
                    banner=s.service or None)
                rep.services_added += s_created
                rep.services_enriched += not s_created

            for f in h.findings:
                _, f_created = store.add_finding(
                    VECTOR_CONFIRMED,
                    _finding_title_confirmed(f.title),
                    host_id=host_id,
                    evidence=_evidence_confirmed(f),
                    severity=f.severity,
                )
                rep.confirmed_added += f_created
                rep.confirmed_seen += not f_created

            for v in h.version_routes:
                _, v_created = store.add_finding(
                    VECTOR_VERSION_ROUTE,
                    _finding_title_version_route(v.service, v.version),
                    host_id=host_id,
                    evidence=_evidence_version_route(v),
                    severity="medium" if v.cves else "info",
                )
                rep.version_routes_added += v_created
                rep.version_routes_seen += not v_created

    return rep
