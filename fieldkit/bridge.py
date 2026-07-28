"""The recce bridge — proven findings flow back into recce's workbook + report.

fieldkit and [recce](https://github.com/dloucks01/recce) share a round-trip: recce's
enumeration seeds fieldkit's triage, and fieldkit's *proven* findings fold back into
recce. This is the fold-back half. It emits the JSON recce imports with
``recce fieldkit-import <file>`` — a self-contained payload where each finding carries
a ``_recce`` block with severity/CWE/remediation/risk already resolved from the KB, so
recce needs no copy of fieldkit's knowledge base.

The wire contract (kept green by the integration test) is exactly the v1 one:
``{"_recce_import": 1, "source": "fieldkit", "engagement": {...}, "findings": [{...,
"_recce": {...}}]}``. v2 only changes where the findings come from — the engagement
database instead of a hand-written file — so ip/hostname are read from state rather
than parsed out of a string.
"""
import re

from . import reportkb as kb


def _cves(*sources):
    """CVE ids from KB refs + a finding's references, de-duplicated, order-preserved."""
    ids = []
    for tok in re.split(r"[,\s]+", " ".join(str(s) for s in sources if s)):
        tok = tok.strip().rstrip(".;,")
        if tok.upper().startswith("CVE") and tok not in ids:
            ids.append(tok)
    return ids


def recce_block(finding):
    """The ``_recce`` enrichment for one finding, resolved from the KB by vector_type."""
    vt = finding.get("vector_type", "")
    k = kb.entry(vt)
    return {
        "ip": finding.get("ip", ""),
        "hostname": finding.get("hostname", ""),
        "port": None,
        "severity": (finding.get("severity") or k["sev"]).lower(),
        "cwe": k.get("cwe", ""),
        "cwes": [k["cwe"]] if k.get("cwe") else [],
        "remediation": k.get("rem", ""),
        "description": k.get("desc", ""),
        "risk": kb.risk_of(vt),
        "confidence": "confirmed",
        "ids": _cves(k.get("refs", ""), finding.get("references", "")),
    }


def export_payload(engagement, findings):
    """The full recce-import payload: original findings + a ``_recce`` block each."""
    enriched = []
    for f in findings:
        g = dict(f)
        g["_recce"] = recce_block(f)
        enriched.append(g)
    return {"_recce_import": 1, "source": "fieldkit",
            "engagement": engagement, "findings": enriched}
