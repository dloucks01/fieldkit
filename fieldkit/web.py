"""Web-application surface — the first non-host domain on the v9 asset model.

fieldkit is an orchestrator: it drives the operator's own web tools (``httpx`` for
live-endpoint discovery, ``nuclei`` for template-based vulnerability matching) through
the injected runner and folds their output into the same
``asset → finding → step (anti-fabrication) → report`` spine the AD side uses. It does
not scan or exploit anything itself — the tools own that; fieldkit owns state, capture
and reporting.

A web endpoint is an ``asset(kind="endpoint")`` (keyed by URL); a nuclei match is a
``finding`` attached to that asset and *proven* by the captured tool output, so
``report --check`` (a finding needs its command+output) holds exactly as for a host
finding. The subprocess runner is injected (``run=``) so the whole path is testable
against canned httpx/nuclei output without a packet.
"""
import json
from dataclasses import dataclass

from . import runner as runner_mod

ENDPOINT = "endpoint"

#: nuclei severity vocabulary → the report's Critical/High/Medium/Low/Info scale.
_SEV = {"critical": "Critical", "high": "High", "medium": "Medium",
        "low": "Low", "info": "Info", "unknown": "Info", "": "Info"}


@dataclass
class Endpoint:
    url: str
    status: int = None
    title: str = ""
    tech: tuple = ()
    host_ip: str = ""
    port: int = None


@dataclass
class WebVuln:
    template_id: str
    name: str
    severity: str        # report vocabulary (Critical/High/…)
    url: str             # the endpoint root the match belongs to
    matched_at: str      # the specific URL/parameter that matched
    description: str = ""


@dataclass
class WebReport:
    endpoints_added: int = 0
    endpoints_enriched: int = 0
    findings_added: int = 0
    aborted: str = None


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _json_lines(text):
    """Yield parsed JSON objects from JSONL output, skipping blank/non-JSON lines —
    httpx/nuclei interleave banners and progress on the same stream."""
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line[0] not in "{[":
            continue
        try:
            yield json.loads(line)
        except (ValueError, TypeError):
            continue


def parse_httpx(text):
    """Parse ``httpx -json`` output (one JSON object per line) into :class:`Endpoint`."""
    out = []
    for d in _json_lines(text):
        if not isinstance(d, dict):
            continue
        url = d.get("url") or d.get("input") or ""
        if not url:
            continue
        tech = d.get("tech") or d.get("technologies") or []
        if isinstance(tech, str):
            tech = [tech]
        out.append(Endpoint(
            url=url.strip(),
            status=_int(d.get("status_code") or d.get("status-code")),
            title=(d.get("title") or "").strip(),
            tech=tuple(tech),
            host_ip=(d.get("host") or "").strip(),
            port=_int(d.get("port"))))
    return out


def parse_nuclei(text):
    """Parse ``nuclei -jsonl`` output into :class:`WebVuln`."""
    out = []
    for d in _json_lines(text):
        if not isinstance(d, dict):
            continue
        info = d.get("info") or {}
        sev_raw = str(info.get("severity") or "unknown").lower()
        tid = (d.get("template-id") or d.get("templateID")
               or d.get("template") or "unknown")
        out.append(WebVuln(
            template_id=str(tid),
            name=(info.get("name") or tid or "web finding").strip(),
            severity=_SEV.get(sev_raw, "Info"),
            url=(d.get("host") or d.get("url") or "").strip(),
            matched_at=(d.get("matched-at") or d.get("matched")
                        or d.get("host") or "").strip(),
            description=(info.get("description") or "").strip()))
    return out


def apply_httpx(store, endpoints):
    """Fold discovered endpoints into state as ``endpoint`` assets, linking to a known
    host when the endpoint's IP matches one already in the engagement."""
    rep = WebReport()
    with store.transaction():
        for e in endpoints:
            host_id = None
            if e.host_ip:
                h = store.host_by_ip(e.host_ip)
                if h:
                    host_id = h["id"]
            _, created = store.add_asset(
                ENDPOINT, e.url, label=e.title or e.url, host_id=host_id,
                props={"status": e.status, "tech": list(e.tech), "port": e.port})
            rep.endpoints_added += created
            rep.endpoints_enriched += (not created)
    return rep


def apply_nuclei(store, vulns):
    """Fold nuclei matches into state as ``web_vuln`` findings attached to endpoint
    assets, each proven by the captured match (anti-fabrication)."""
    rep = WebReport()
    with store.transaction():
        for v in vulns:
            key = v.url or v.matched_at
            asset_id = None
            if key:
                asset_id, created = store.add_asset(ENDPOINT, key, label=key)
                rep.endpoints_added += created
            title = f"{v.name} — {v.matched_at or v.url}"
            fid, fcreated = store.add_finding(
                "web_vuln", title, asset_id=asset_id, proven=True,
                severity=v.severity, evidence=(v.description or v.name))
            # The proof of a nuclei finding is nuclei's own verbatim match. Capturing
            # it as a step is what lets `report --check` treat this like any other
            # proven finding — a web finding can't render without the tool output.
            store.add_step(
                cmd=f"nuclei -id {v.template_id} -u {v.url or v.matched_at}",
                output=(f"[{v.severity}] {v.template_id} matched at "
                        f"{v.matched_at or v.url}"
                        + (f"\n{v.description}" if v.description else "")),
                finding_id=fid, transport="nuclei")
            rep.findings_added += fcreated
    return rep


def _driver(run, timeout):
    return run or (lambda argv, env=None: runner_mod.run(argv, env_add=env,
                                                         timeout=timeout))


def probe(store, targets, *, run=None, timeout=300):
    """Drive ``httpx`` over ``targets``, folding live endpoints into state. Aborts
    cleanly (WebReport.aborted set) when the tool isn't installed."""
    run = _driver(run, timeout)
    argv = ["httpx", "-json", "-silent"]
    for t in targets:
        argv += ["-u", t]
    res = run(argv, None)
    if getattr(res, "error", None):
        return WebReport(aborted=res.error)
    return apply_httpx(store, parse_httpx(res.output))


def scan(store, targets, *, run=None, timeout=1800):
    """Drive ``nuclei`` over ``targets``, folding matches into state as findings."""
    run = _driver(run, timeout)
    argv = ["nuclei", "-jsonl", "-silent"]
    for t in targets:
        argv += ["-u", t]
    res = run(argv, None)
    if getattr(res, "error", None):
        return WebReport(aborted=res.error)
    return apply_nuclei(store, parse_nuclei(res.output))
