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
import subprocess
from datetime import datetime, timezone

from . import reportkb as kb

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
    }
    findings = []
    for f in store.findings(proven_only=proven_only):
        host = hosts.get(f["host_id"])
        label, ip, hostname = _affected_host(host)
        steps = [{"cmd": s["cmd"], "output": s["output"] or "",
                  "transport": s["transport"]} for s in store.steps(finding_id=f["id"])]
        arts = [{"desc": a["description"], "remove": a["cleanup_cmd"]}
                for a in store.artifacts() if a["finding_id"] == f["id"]]
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
        })
    return engagement, findings


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
    w("---")
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
    w("---")
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
    return subprocess.call(["bash", "-lc", f"command -v {tool} >/dev/null"]) == 0


def export(md_path, basename, formats):
    """Convert the Markdown to docx/pdf via pandoc. Returns operator-facing lines."""
    lines = []
    pandoc = _have("pandoc")
    if "docx" in formats:
        if pandoc:
            r = subprocess.run(["pandoc", md_path, "-o", f"{basename}.docx"],
                               capture_output=True, text=True)
            lines.append(f"wrote {basename}.docx" if r.returncode == 0
                         else f"docx FAILED: {r.stderr.strip()}")
        else:
            lines.append(f"# docx: install pandoc, then: pandoc {md_path} -o {basename}.docx")
    if "pdf" in formats:
        if pandoc and _have("weasyprint"):
            r = subprocess.run(["pandoc", md_path, "-o", f"{basename}.pdf",
                                "--pdf-engine=weasyprint"], capture_output=True, text=True)
            lines.append(f"wrote {basename}.pdf" if r.returncode == 0
                         else f"pdf FAILED: {r.stderr.strip()}")
        else:
            lines.append(f"# pdf: install pandoc + weasyprint, then: "
                         f"pandoc {md_path} -o {basename}.pdf --pdf-engine=weasyprint")
    return lines
