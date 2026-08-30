"""The report — proven findings out of state, into a customer deliverable.

v1 rendered a hand-written ``findings.json``; v2 reads the engagement database, where
every finding already carries its captured proof (the ``step`` evidence the executor
recorded) and its cleanup artifacts. So the report is a *projection* of what fieldkit
actually did, and the anti-fabrication gate passes by construction: a finding cannot
reach the report without the verbatim command + output that proved it.

Three outputs, all from state:

  * :func:`render_markdown` — the customer report (exec summary + per-finding writeup
    with the full PoC trail), severity/CWE/description/remediation auto-filled from
    :mod:`fieldkit.reportkb` by ``vector_type``;
  * :func:`check` — the anti-fabrication / completeness gate (every proven finding has
    a command *and* captured output, no placeholders);
  * :func:`cleanup_manifest` — the INTERNAL artifact-removal checklist, from the
    ``artifact`` table + the KB's per-risk cleanup guidance.

Rendering is pure (dicts in, text out), so it is testable without a database; the CLI
assembles the dicts from state via :func:`build`.
"""
import os
import shutil
import tempfile
from datetime import datetime, timezone

from . import reportkb as kb
from . import runner as runner_mod

PLACEHOLDERS = ("<pid>", "<target>", "<service", "<youruser>", "<the-allowed",
                "/path/to", "example.com", "placeholder", "todo", "xxxx")


# ---------------------------------------------------------------- build from state

def _affected_host(host):
    if host is None:
        return "(unspecified host)", "", ""
    ip = host["ip"]
    bits = [b for b in (host["hostname"], host["os"]) if b]
    label = f"{ip} ({', '.join(bits)})" if bits else ip
    return label, ip, host["hostname"] or ""


def build(store, config, *, proven_only=True):
    """Assemble ``(engagement, findings)`` dicts from the engagement database."""
    row = store.require_engagement()
    hosts = {h["id"]: h for h in store.hosts()}
    client = config.get("client") or row["name"]
    # Credential lineage: everything that was RECOVERED during the assessment
    # (source != "manual"), grouped by source. This is the audit trail — the report
    # should say where each recovered login came from, not just that it exists.
    recovered = []
    for c in store.credentials():
        src = (c["source"] or "").strip()
        if src and src != "manual":
            recovered.append({
                "principal": (f"{c['domain']}\\{c['username']}"
                              if c["domain"] else c["username"]),
                "kind": c["secret_type"],
                "source": src,
            })
    engagement = {
        "client": client,
        "assessor": config.get("assessor") or "",
        "date": datetime.now(timezone.utc).date().isoformat(),
        "scope": "Authorized internal penetration test — access, lateral movement and "
                 "local privilege escalation.",
        "targets": [_affected_host(h)[0] for h in store.hosts()],
        "capture_method": "Every command fieldkit ran against a target was captured "
                          "verbatim (command, output and exit code) in the engagement "
                          "database as it executed.",
        "evidence_log": os.path.basename(store.path or "engagement.db"),
        "recovered_credentials": recovered,
    }
    findings = []
    for f in store.findings(proven_only=proven_only):
        host = hosts.get(f["host_id"])
        label, ip, hostname = _affected_host(host)
        steps = [{"cmd": s["cmd"], "output": s["output"] or "",
                  "transport": s["transport"]} for s in store.steps(finding_id=f["id"])]
        arts = [{"desc": a["description"], "remove": a["cleanup_cmd"]}
                for a in store.artifacts() if a["finding_id"] == f["id"]]
        # Attack-chain hint: the credential(s) that had access on this host.
        # Best-effort — the executor doesn't record cred_id per step, so we go by
        # "who has proven access on this host". Prefer admin; then whichever came
        # in first. When the auth cred was itself recovered, that's a real chain.
        reached_via = None
        if host is not None:
            access_rows = store.access_on(host["id"])
            # sort: admin first (already ordered by SQL), then oldest cred
            for a in access_rows:
                cred = store.credential_by_id(a["cred_id"])
                if cred is None:
                    continue
                principal = (f"{cred['domain']}\\{cred['username']}"
                             if cred["domain"] else cred["username"])
                reached_via = {
                    "principal": principal,
                    "method": a["method"],
                    "admin": bool(a["admin"]),
                    "source": (cred["source"] or "manual").strip() or "manual",
                }
                break
        findings.append({
            "title": f["title"],
            "vector_type": f["vector_type"],
            "affected_host": label,
            "ip": ip,
            "hostname": hostname,
            "proven": bool(f["proven"]),
            "evidence": f["evidence"] or "",
            "references": "",
            "steps": steps,
            "artifacts": arts,
            "reached_via": reached_via,
        })

    # C-arc + D-arc report surfaces — coerce chain walks + BloodHound
    # owned→high-value paths. Both are read-only reporting slots:
    # they surface work fieldkit's chain / bloodhound modules already
    # did; they don't change the finding set.
    engagement["chain_history"] = _collect_chain_history(store)
    engagement["bh_paths"] = _collect_bh_paths(store)

    # Cross-reference: attach the shipped TTPs whose report_type
    # matches each finding's vector_type. Lets the customer report
    # cite "See also: TTP key" so a reader can look up the standard
    # detection guidance + remediation pattern from the shipped
    # catalog without hunting through fieldkit source. Zero-cost
    # when the catalog can't load — findings just get empty lists.
    ttp_index = _collect_ttp_index()
    for f in findings:
        f["related_ttps"] = ttp_index.get(f["vector_type"], [])
    return engagement, findings


def _collect_ttp_index():
    """Load the shipped TTP catalog and return
    {vector_type: [ttp_key, ...]} for cross-referencing findings
    against the standard-detection TTPs that would have surfaced
    them. Returns {} on catalog import/load failure — cross-refs
    are a nice-to-have, not load-bearing for report rendering."""
    try:
        from .ttps import loader as ttp_loader
        out = {}
        for t in ttp_loader.load_all():
            out.setdefault(t.report.vector_type, []).append(t.key)
        return out
    except Exception:                                             # noqa: BLE001
        return {}


def _collect_chain_history(store):
    """Every recorded coerce_chain, newest first, with a compact
    per-chain summary suitable for the report. Empty when no chains
    were run in this engagement."""
    try:
        rows = store.chains()
    except Exception:                                             # noqa: BLE001
        return []
    out = []
    for row in rows:
        trail = []
        try:
            trail = store.chain_step_trail(row["id"])
        except Exception:                                         # noqa: BLE001
            pass
        out.append({
            "id": row["id"],
            "profile": row["profile"],
            "target": row["target"],
            "status": row["status"],
            "detection_debt": row["total_detection_cost"],
            "aborted_reason": row["aborted_reason"] or "",
            "started_at": row["started_at"] or "",
            "steps": [{"name": t["step_name"], "kind": t["step_kind"],
                       "outcome": t["outcome_kind"],
                       "cost": t["detection_cost"],
                       "evidence": t["evidence"]}
                      for t in trail],
        })
    return out


def _collect_bh_paths(store):
    """Owned → high-value control paths from the BloodHound graph
    ingested in this engagement. Empty when no graph was ingested or
    no path exists. Zero-cost when the bh_node table is empty."""
    try:
        from . import bloodhound as bh_mod
        return bh_mod.owned_paths(store)
    except Exception:                                             # noqa: BLE001
        return []


# ------------------------------------------------------------------- helpers

def _sev(f):
    return f.get("severity") or kb.entry(f.get("vector_type", ""))["sev"]


def _kb(f):
    return kb.entry(f.get("vector_type", ""))


# --------------------------------------------------------------------- --check

def check(findings):
    """Anti-fabrication / completeness gate. Returns ``(errors, warns)`` as
    ``(tag, message)`` lists — errors must be empty before a report is trustworthy.

    A **proven** finding must carry its captured proof (command + output) — that is the
    anti-fabrication spine. An **observation** (an unproven finding, ``proven=False``,
    surfaced by enumeration but not exploited) is *not* a claim of compromise, so it is
    not required to carry a PoC — a missing walkthrough is a note, not an error."""
    errors, warns = [], []
    for i, f in enumerate(findings, 1):
        tag = f.get("title") or f.get("vector_type") or f"finding #{i}"
        proven = f.get("proven", True)   # absent flag → treat as a proven finding
        vt = f.get("vector_type")
        if not vt:
            errors.append((tag, "missing vector_type"))
        elif vt not in kb.KB:
            warns.append((tag, f"unknown vector_type '{vt}' — generic remediation used"))
        if not f.get("affected_host"):
            errors.append((tag, "missing affected_host"))
        if not f.get("evidence"):
            warns.append((tag, "no evidence summary"))
        steps = f.get("steps", [])
        if not steps:
            (errors if proven else warns).append(
                (tag, "no proof-of-concept steps captured"
                 + ("" if proven else " (observation — not exploited)")))
        for n, s in enumerate(steps, 1):
            if not str(s.get("cmd", "")).strip():
                errors.append((tag, f"step {n}: empty command"))
            if not str(s.get("output", "")).strip():
                errors.append((tag, f"step {n}: NO output captured"))
            blob = (str(s.get("cmd", "")) + " " + str(s.get("output", ""))).lower()
            if any(p in blob for p in PLACEHOLDERS):
                warns.append((tag, f"step {n}: contains a placeholder token"))
    return errors, warns


# ------------------------------------------------------------------ markdown

SEV_MEAN = {
    "Critical": "trivially exploitable and leading to immediate, complete compromise of the affected host.",
    "High":     "reliably exploitable by a low-privileged user to obtain full administrative control (root / SYSTEM).",
    "Medium":   "exploitable under specific conditions, or granting partial elevation.",
    "Low":      "limited impact, or exploitable only in narrow circumstances.",
    "Info":     "informational — no direct escalation, but relevant to the overall posture.",
}

#: the business-impact narrative per severity — what an attacker actually gains.
IMPACT = {
    "Critical": "An attacker can take complete control of the affected host immediately "
                "and with high reliability. From there they can read or alter all data on "
                "the host, disable security controls, extract stored credentials, and pivot "
                "into the wider environment.",
    "High":     "An attacker holding only low-privileged access can obtain full "
                "administrative control of the affected host (SYSTEM on Windows, root on "
                "Linux). With that control they can read or modify all data on the host, "
                "disable endpoint security, harvest stored and cached credentials, and use "
                "the host as a foothold to move laterally toward domain compromise.",
    "Medium":   "An attacker can obtain partial elevation, or full elevation only under "
                "specific preconditions. This still meaningfully weakens the host's "
                "security boundary and is commonly chained with other issues.",
    "Low":      "Impact is limited, or the weakness is exploitable only in narrow "
                "circumstances, but it still erodes defence-in-depth.",
    "Info":     "No direct privilege escalation, but the item is relevant to the host's "
                "overall security posture.",
}


def _impact(f):
    return IMPACT.get(_sev(f), IMPACT["Info"])


def _reached_via(w, f):
    """Render the "Reached via" one-liner: which credential authenticated the
    exploitation, and — the audit-trail hook — where that credential came from.

    Skipped when nothing is known (a finding recorded before access was proven).
    A manual-source credential produces the terse form ("as jdoe (operator-provided)");
    a recovered credential shows the recovery source verbatim so the chain reads
    end-to-end when this section and the "Credentials recovered" table are read
    together.
    """
    via = f.get("reached_via")
    if not via:
        return
    admin_tag = " (admin)" if via.get("admin") else ""
    method = via.get("method") or "?"
    source = via.get("source") or "manual"
    if source == "manual":
        origin = "operator-provided"
    else:
        origin = f"recovered — `{source}`"
    w("### Reached via")
    w("")
    w(f"Authenticated to `{f.get('affected_host', '')}` over `{method}` as "
      f"`{via['principal']}`{admin_tag} ({origin}).")
    w("")


def _shot(w, caption):
    """A screenshot placeholder — fieldkit captures text; this marks where the operator
    should paste the matching terminal screenshot for the polished deliverable."""
    w(f"> 📷 **Screenshot for the report:** {caption}")
    w("")


def _glance(w, rows, kind):
    w(f"### {kind} at a glance")
    w("")
    w("| # | " + kind[:-1] + " | Severity | Affected host | CWE |")
    w("|---|------|----------|---------------|-----|")
    for i, f in enumerate(rows, 1):
        k = _kb(f)
        w(f"| {i} | {f.get('title') or k['name']} | {_sev(f)} | "
          f"{f.get('affected_host', '')} | {k['cwe']} |")
    w("")


def _render_finding(w, i, f):
    k = _kb(f)
    title = f.get("title") or k["name"]
    refs = ", ".join(x for x in [k.get("refs"), f.get("references")] if x)
    w(f"## Finding {i}. {title}")
    w("")
    w(f"**Severity:** {_sev(f)}  ")
    w(f"**Affected host:** {f.get('affected_host', '')}  ")
    w(f"**Classification:** {k['cwe']}" + (f" · {refs}" if refs else "") + "  ")
    w("")
    w("> **FINDING — proven.** This weakness was **exploited** during the assessment. "
      "The exact commands and their captured output are reproduced below so it can be "
      "independently reproduced and re-tested after remediation.")
    w("")
    w("### Description")
    w("")
    w(k["desc"])
    w("")
    _reached_via(w, f)
    w("### Impact")
    w("")
    w(_impact(f))
    w("")
    w("### Technical walkthrough")
    w("")
    steps = f.get("steps", [])
    if not steps:
        w("_(no reproduction steps recorded)_")
        w("")
    else:
        w(f"The following was executed against `{f.get('ip') or f.get('affected_host', '')}`. "
          "Each step shows the verbatim command and its captured output.")
        w("")
    proof_step = None
    for n, s in enumerate(steps, 1):
        via = f" _(via {s['transport']})_" if s.get("transport") else ""
        w(f"**Step {n} — command{via}:**")
        w("")
        w("```")
        w(str(s.get("cmd", "")).rstrip())
        w("```")
        if s.get("output"):
            proof_step = s
            w("")
            w("Observed result:")
            w("")
            w("```")
            w(str(s["output"]).rstrip())
            w("```")
            w("")
            _shot(w, "the terminal above — the command and its result.")
    # the decisive proof (money shot)
    proof = (f.get("evidence") or (proof_step or {}).get("output", "")).strip()
    if proof:
        w("### Proof of compromise")
        w("")
        w("The step above returned an elevated / privileged context, confirming the "
          "escalation succeeded:")
        w("")
        w("```")
        w(proof.rstrip())
        w("```")
        w("")
        _shot(w, "the elevated shell / identity output above — this is the single most "
                 "important screenshot for this finding.")
    if f.get("artifacts"):
        w("### Changes made during testing")
        w("")
        w("To validate this finding the following changes were made to the target and "
          "have been reverted (see the internal cleanup manifest):")
        for a in f["artifacts"]:
            w(f"- {a.get('desc', 'change') if isinstance(a, dict) else a}")
        w("")
    w("### Remediation")
    w("")
    w(k["rem"])
    w("")
    _render_related_ttps(w, f)
    w("---")
    w("")


def _render_related_ttps(w, f):
    """Render the "See also" cross-reference to shipped TTPs whose
    report_type matches this finding's vector_type. When populated,
    lets a customer reader trace back to the standard fieldkit TTP
    catalog entry (detection guidance + remediation pattern) that
    would have surfaced the finding. Renders nothing when empty."""
    refs = f.get("related_ttps") or []
    if not refs:
        return
    w("### See also — fieldkit TTP catalog")
    w("")
    w("This finding maps to the following standard-detection TTP(s) "
      "in fieldkit's shipped catalog. Each TTP entry documents the "
      "detection signals a defender would see + the operator's "
      "standard exploitation shape, so the customer's SOC / IT team "
      "can build a hunt package from the fieldkit reference.")
    w("")
    for ref in refs:
        w(f"- `{ref}`")
    w("")


def _render_observation(w, i, f):
    k = _kb(f)
    title = f.get("title") or k["name"]
    refs = ", ".join(x for x in [k.get("refs"), f.get("references")] if x)
    w(f"## Observation {i}. {title}")
    w("")
    w(f"**Potential severity:** {_sev(f)}  ")
    w(f"**Affected host:** {f.get('affected_host', '')}  ")
    w(f"**Classification:** {k['cwe']}" + (f" · {refs}" if refs else "") + "  ")
    w("")
    w("> ⚠️ **OBSERVATION — identified, not exploited.** This weakness was surfaced by "
      "enumeration/tooling but was **not** exercised during the assessment (out of scope, "
      "time, or to avoid disruption). The risk is real but **unconfirmed** — validate it "
      "before relying on the remediation, and do not treat it as a demonstrated compromise.")
    w("")
    w("### Description")
    w("")
    w(k["desc"])
    w("")
    w("### Potential impact (if exploited)")
    w("")
    w(_impact(f))
    w("")
    w("### How this was identified / how to confirm")
    w("")
    if f.get("evidence"):
        w("Identified from the following evidence:")
        w("")
        w("```")
        w(str(f["evidence"]).rstrip())
        w("```")
        w("")
    w("To confirm, exploit the weakness with the corresponding technique in a controlled "
      "window and capture the result (fieldkit: re-run enumeration, then `run`/`escalate`/"
      "`prep` the matching vector).")
    w("")
    w("### Recommended remediation")
    w("")
    w(k["rem"])
    w("")
    _render_related_ttps(w, f)
    w("---")
    w("")


def _render_chain_history(w, chains):
    """The per-chain summary section: profile, target, status, step
    trail, aggregate detection debt. Empty section (no output) when
    no chains were run — the report stays clean on engagements
    that never triggered a coerce chain."""
    if not chains:
        return
    w("# Coerce chain history")
    w("")
    w("Each chain below was walked during this engagement by "
      "`fieldkit chain run`. The **detection debt** is the aggregate "
      "signal-weighted cost of the steps that actually ran — event "
      "IDs, DCERPC opcodes, Kerberos ticket requests, and other "
      "defender-visible artifacts, weighted by their alert value on "
      "a mature SOC. The per-step trail is the same output "
      "`fieldkit chain show --signals` renders in the terminal.")
    w("")
    w("| # | Profile | Target | Status | Detection debt |")
    w("|---|---------|--------|--------|---------------:|")
    for ch in chains:
        w(f"| {ch['id']} | `{ch['profile']}` | `{ch['target']}` | "
          f"{ch['status']} | {ch['detection_debt']} |")
    w("")
    for ch in chains:
        w(f"### Chain #{ch['id']} — {ch['profile']} against {ch['target']}")
        w("")
        w(f"- Status: **{ch['status']}**")
        w(f"- Detection debt: {ch['detection_debt']} units")
        if ch.get("started_at"):
            w(f"- Started: {ch['started_at']}")
        if ch.get("aborted_reason"):
            w(f"- Aborted: {ch['aborted_reason']}")
        w("")
        if ch.get("steps"):
            w("Step trail:")
            w("")
            w("| # | Step | Kind | Outcome | Cost | Evidence |")
            w("|---|------|------|---------|-----:|----------|")
            for i, s in enumerate(ch["steps"]):
                evidence = (s.get("evidence") or "").replace("|", "\\|")
                if len(evidence) > 80:
                    evidence = evidence[:77] + "..."
                w(f"| {i} | `{s['name']}` | {s['kind']} | "
                  f"**{s['outcome']}** | {s['cost']} | {evidence} |")
            w("")


def _render_bh_paths(w, paths):
    """Owned → high-value control paths from the ingested BloodHound
    graph. Empty when no path finds or no graph ingested. Highest-
    value / shortest paths first."""
    if not paths:
        return
    w("# BloodHound — owned → high-value control paths")
    w("")
    w("The ingested SharpHound graph exposes the following control "
      "paths from a recovered credential to a high-value target. "
      "Each path is the *shortest* control-edge chain from the "
      "owned principal to the target; presence of a path means "
      "the target is reachable using existing AD ACLs + delegation. "
      "See the `fieldkit bloodhound path` output for the per-edge "
      "walkthrough.")
    w("")
    w("| # | Owned principal | High-value target | Hops |")
    w("|---|-----------------|-------------------|-----:|")
    for i, p in enumerate(paths, 1):
        owned = p.get("owned") or "?"
        target = p.get("target") or "?"
        hops = p.get("hops", "?")
        w(f"| {i} | `{owned}` | **{target}** | {hops} |")
    w("")


def render_markdown(engagement, findings):
    """The customer report as Markdown. Proven weaknesses render as **Findings** (with the
    full captured walkthrough + screenshot placeholders); unproven ones render as clearly
    labelled **Observations**."""
    L = []
    w = L.append
    eng = engagement
    proven = [f for f in findings if f.get("proven", True)]
    observations = [f for f in findings if not f.get("proven", True)]

    w(f"# Penetration Test Report — {eng.get('client', '')}")
    w("")
    w(f"**Assessor:** {eng.get('assessor') or '—'}  ")
    w(f"**Date:** {eng.get('date', '')}  ")
    w(f"**Scope:** {eng.get('scope', '')}  ")
    if eng.get("targets"):
        w(f"**Targets:** {', '.join(eng['targets'])}")
    w("")
    w("---")
    w("")

    counts = {}
    for f in proven:
        counts[_sev(f)] = counts.get(_sev(f), 0) + 1
    nhost = len({f.get("affected_host", "") for f in proven if f.get("affected_host")}) or 1
    top_sev = (min((_sev(f) for f in proven), key=lambda s: kb.SEV_ORDER.get(s, 9))
               if proven else "Info")
    full_control = sum(1 for f in proven if _sev(f) in ("Critical", "High"))

    w("## Executive summary")
    w("")
    if not proven and not observations:
        w("No privilege-escalation or access findings were proven within the authorized "
          "scope and time window. See *Assessment limitations* — absence of findings is "
          "not proof of security.")
        w("")
    else:
        if proven:
            extra = (f", and additionally identified **{len(observations)} observation(s)** "
                     "that were not exploited" if observations else "")
            w(f"The assessment **proved {len(proven)} finding(s)** across **{nhost} "
              f"in-scope host(s)**{extra}. By severity of the proven findings:")
            w("")
            for s in kb.SEV_ORDER:
                if s in counts:
                    w(f"- **{counts[s]} {s}** — {SEV_MEAN[s]}")
            w("")
        else:
            w(f"No findings were **proven**, but **{len(observations)} observation(s)** "
              "were identified — weaknesses seen but not exploited within scope and time. "
              "See *Observations*; absence of a proven finding is not proof of security.")
            w("")
        if full_control:
            w(f"The overall risk is assessed as **{top_sev}**. {full_control} of the "
              f"{len(proven)} proven finding(s) allow an attacker to obtain complete "
              "administrative control of the affected host — and with it the ability to "
              "read or alter all data, disable security controls, harvest credentials, "
              "and pivot into the wider environment.")
            w("")
        elif proven:
            w(f"The overall risk is assessed as **{top_sev}**. See each finding for impact.")
            w("")

        # Chain sentence: name one proven finding that was reached via a RECOVERED
        # credential — that's the demonstrated attack chain the exec summary should
        # lead with. Silently skipped when no proven finding used a recovered cred.
        chained = [f for f in proven
                   if f.get("reached_via") and f["reached_via"].get("source")
                   and f["reached_via"]["source"] != "manual"]
        if chained:
            f = chained[0]
            via = f["reached_via"]
            w(f"**Demonstrated attack chain:** authenticated to "
              f"`{f.get('affected_host', '')}` as `{via['principal']}` — a credential "
              f"recovered during testing (`{via['source']}`) — and proved "
              f"*{f.get('title', '')}*. See *Credentials recovered during testing* "
              "for the full audit trail and *Reached via* on each finding for the "
              "step-by-step chain.")
            w("")

    w("### How to read this report")
    w("")
    w("This report separates two kinds of result — the distinction is deliberate and "
      "load-bearing:")
    w("")
    w("- **Findings** are weaknesses we **proved by exploiting them**. Each carries the "
      "exact commands that were run and their captured output, so you can reproduce and "
      "re-test after remediation. A finding is a *demonstrated* compromise.")
    w("- **Observations** are weaknesses we **identified but did not exploit** within the "
      "authorized scope and time window. The risk is real but **unconfirmed** — treat them "
      "as prioritized areas to validate and fix, not as demonstrated compromises.")
    w("")

    w("### Methodology & completeness")
    w("")
    w("Each **finding** was **validated hands-on** — confirmed by execution, not inferred "
      "from version numbers — and the exact commands and their observed results are "
      "reproduced per writeup so the customer can independently re-test after "
      "remediation. Where a host exposed more than one path, **all are reported**: each "
      "is an independent weakness.")
    if eng.get("capture_method"):
        w("")
        w(eng["capture_method"]
          + (f" The raw evidence store (`{eng['evidence_log']}`) is retained and "
             "referenced per finding." if eng.get("evidence_log") else ""))
    w("")

    if proven:
        _glance(w, proven, "Findings")
    if observations:
        _glance(w, observations, "Observations")
    w("---")
    w("")

    if proven:
        w("# Findings (proven)")
        w("")
        for i, f in enumerate(proven, 1):
            _render_finding(w, i, f)

    if observations:
        w("# Observations (identified, not exploited)")
        w("")
        w("The items below were **surfaced during enumeration but not exploited**. They "
          "are not demonstrated compromises; each should be validated in a controlled "
          "window before it is relied upon as fixed.")
        w("")
        for i, f in enumerate(observations, 1):
            _render_observation(w, i, f)

    recovered = engagement.get("recovered_credentials") or []
    if recovered:
        w("# Credentials recovered during testing")
        w("")
        w("The credentials below were **recovered during the assessment** — the audit "
          "trail for how each one was obtained. Every recovery method here is a "
          "misconfiguration in its own right (cleartext storage, dumped hive, exposed "
          "share, promoted GPP cpassword, extracted MSSQL/PostgreSQL/MongoDB user); the "
          "corresponding remediations are covered under the Findings and Observations "
          "above.")
        w("")
        w("| # | Principal | Kind | Recovered from |")
        w("|---|-----------|------|----------------|")
        for n, c in enumerate(recovered, 1):
            w(f"| {n} | `{c['principal']}` | {c['kind']} | `{c['source']}` |")
        w("")
        w("Rotate every credential above; where reuse across systems is suspected, sweep "
          "adjacent hosts and services for the same login.")
        w("")

    _render_chain_history(w, engagement.get("chain_history") or [])
    _render_bh_paths(w, engagement.get("bh_paths") or [])

    w("## Assessment limitations")
    w("")
    w("- **Absence of findings is not proof of security.** This assessment enumerated a "
      "defined set of known vectors within the authorized scope and time window.")
    w("- **Observations are unconfirmed.** They indicate likely weaknesses but were not "
      "exploited; validate each before assuming impact or successful remediation.")
    w("- **Point-in-time.** Findings reflect the systems' state during the test window.")
    w("- **Remediation guidance is general** and must be validated against the client's "
      "environment before deployment.")
    w("")
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- cleanup manifest

def cleanup_manifest(engagement, findings):
    """The INTERNAL artifact-removal checklist (not for the client)."""
    C = []
    c = C.append
    c(f"# INTERNAL CLEANUP MANIFEST — {engagement.get('client', '')} — "
      f"{engagement.get('date', '')}")
    c("")
    c("> **INTERNAL USE ONLY — DO NOT DELIVER TO THE CLIENT.**")
    c("> Every item is a change made to a TARGET during testing. Remove/revert ALL of "
      "them before closing the engagement.")
    c("")
    by_host = {}
    for f in findings:
        by_host.setdefault(f.get("affected_host", "(unspecified host)"), []).append(f)
    any_artifact = False
    for host, fs in by_host.items():
        c(f"## Host: {host}")
        c("")
        for f in fs:
            rm = kb.risk_meta(f.get("vector_type", ""))
            c(f"### {f.get('title') or _kb(f)['name']}")
            c(f"*Exploit risk: **{kb.risk_of(f.get('vector_type', ''))}** — {rm['danger']}*")
            c("")
            c("Artifacts / changes to revert:")
            arts = f.get("artifacts", [])
            if not arts:
                c(f"- [ ] _(none recorded — confirm nothing was left; general guidance:)_ "
                  f"{rm['cleanup']}")
            else:
                any_artifact = True
                for a in arts:
                    line = f"- [ ] {a.get('desc', 'artifact')}" if isinstance(a, dict) else f"- [ ] {a}"
                    if isinstance(a, dict) and a.get("remove"):
                        line += f"  →  `{a['remove']}`"
                    c(line)
                c(f"- [ ] _General:_ {rm['cleanup']}")
            c("")
    if not findings:
        c("_(no findings — nothing recorded to clean up. Still confirm no staged files "
          "or probe accounts remain.)_")
        c("")
    c("---")
    c("**Final check:** re-run enumeration as the low-priv user to confirm no planted "
      "files, accounts, or config lines remain.")
    _ = any_artifact
    return "\n".join(C) + "\n"


# ------------------------------------------------------------------- export

def _have(tool):
    """True when ``tool`` is on PATH. ``shutil.which`` rather than a ``bash -lc`` probe:
    no shell string to build (rule 7), no child process, and no bash dependency."""
    return shutil.which(tool) is not None


def _convert(run, md_path, out, extra, label):
    """Drive one pandoc conversion through the injected runner. Returns one status line."""
    res = run(["pandoc", md_path, "-o", out, *extra])
    if res.error:
        return f"{label} FAILED: {res.error}"
    if res.timed_out:
        return f"{label} FAILED: pandoc timed out"
    if res.exit_code not in (0, None):
        return f"{label} FAILED: {(res.stderr or res.output or '').strip()[:200]}"
    return f"wrote {out}"


#: Minimal CSS embedded into the HTML export. Kept intentionally
#: readable-first: no external font dependencies, no color scheme
#: assumptions (works in both light + dark browser modes via the
#: default terminal-adjacent palette). Big enough to make tables +
#: code blocks + section headers legible; small enough to inline
#: without dominating the file.
_HTML_STYLE = """
<style>
  body { max-width: 850px; margin: 2em auto; padding: 0 1.5em;
         font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
                      Roboto, Helvetica, Arial, sans-serif;
         line-height: 1.5; color: #222; }
  @media (prefers-color-scheme: dark) {
    body { background: #111; color: #ddd; }
    a { color: #6cf; }
    code, pre { background: #222; color: #ddd; }
    table { border-color: #444; }
    th, td { border-color: #333; }
    th { background: #1a1a1a; }
  }
  h1, h2, h3 { line-height: 1.2; margin-top: 1.5em; }
  h1 { border-bottom: 2px solid currentColor; padding-bottom: 0.2em; }
  h2 { border-bottom: 1px solid #999; padding-bottom: 0.15em; }
  code, pre { font-family: "SF Mono", Menlo, Consolas, monospace;
              font-size: 0.9em; background: #f4f4f4; }
  pre { padding: 1em; overflow-x: auto; border-radius: 4px; }
  code { padding: 0.1em 0.3em; border-radius: 3px; }
  pre code { padding: 0; background: none; }
  table { border-collapse: collapse; margin: 1em 0; }
  th, td { border: 1px solid #ccc; padding: 0.4em 0.8em; text-align: left; }
  th { background: #f4f4f4; }
  blockquote { border-left: 4px solid #999; padding-left: 1em;
               margin: 1em 0; color: #666; }
</style>
""".strip()


def export(md_path, basename, formats, *, run=None, have=None):
    """Convert the Markdown to docx/pdf/html via pandoc. Returns
    operator-facing lines.

    ``run``/``have`` are injected for testing (rule 2 — the real spawn is
    :func:`fieldkit.runner.run`, never a bare ``subprocess`` call).

    Format support:
      * ``docx`` — pandoc default writer, no extra flags.
      * ``pdf`` — pandoc + weasyprint. Falls back to a hint line
        when either is missing.
      * ``html`` — pandoc's HTML writer with ``-s`` (standalone —
        wraps in <html><head><body>) + inline stylesheet via a
        temp CSS file. Renders offline in any browser with no
        external asset requests.
    """
    run = run or (lambda argv: runner_mod.run(argv, timeout=300))
    have = have or _have
    lines = []
    pandoc = have("pandoc")
    if "docx" in formats:
        if pandoc:
            lines.append(_convert(run, md_path, f"{basename}.docx", (), "docx"))
        else:
            lines.append(f"# docx: install pandoc, then: pandoc {md_path} -o {basename}.docx")
    if "pdf" in formats:
        if pandoc and have("weasyprint"):
            lines.append(_convert(run, md_path, f"{basename}.pdf",
                                  ("--pdf-engine=weasyprint",), "pdf"))
        else:
            lines.append(f"# pdf: install pandoc + weasyprint, then: "
                         f"pandoc {md_path} -o {basename}.pdf --pdf-engine=weasyprint")
    if "html" in formats:
        if pandoc:
            # Stash the embedded style in a temp file so pandoc's
            # -H (include-in-header) picks it up. Cleaned up
            # regardless of pandoc's exit — the file only holds our
            # own bytes.
            fd, css_path = tempfile.mkstemp(prefix="fk-html-",
                                              suffix=".css")
            try:
                os.write(fd, _HTML_STYLE.encode("utf-8"))
                os.close(fd)
                lines.append(_convert(run, md_path, f"{basename}.html",
                                       ("-s", "-H", css_path), "html"))
            finally:
                try: os.unlink(css_path)
                except OSError: pass
        else:
            lines.append(f"# html: install pandoc, then: "
                         f"pandoc {md_path} -s -o {basename}.html")
    return lines
