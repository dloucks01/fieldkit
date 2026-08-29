# fieldkit ⇄ recce

fieldkit and [**recce**](https://github.com/dloucks01/recce) split one engagement at the
trigger. **recce** is the survey-plan-catch-report platform: it sweeps the network, confirms
and prioritizes vulnerabilities (KEV/EPSS), synthesizes attack paths, catches and holds shells
(C2, SOCKS pivots), and writes the customer report — and by design it stops at the trigger, its
on-target work read-only and non-evasive. **fieldkit** is the half past the trigger: the
autonomous operator that walks recce's ranked plan, fires each move, mutates target state to
**prove** the compromise, prices every step in detection risk, and folds the proven findings
back. They round-trip through a small JSON contract so proven work flows into recce's workbook
and customer report.

```
recce (survey · confirm · rank · catch)  ──scope + ranked findings──▶  fieldkit
        ▲                                              (spray → escalate → prove, detection-priced)
        └────────  recce fieldkit-import  ◀── fieldkit export-recce ──┘
                    (proven findings, KB-enriched, confidence: confirmed)
```

## recce → fieldkit (scope in + the rich feed)

recce has already swept the network and confirmed vulnerable hosts. Feed the rich handoff
to fieldkit and run the loop:

```bash
recce fieldkit-export <engagement>                              # writes eng/fieldkit/
fieldkit ingest recce eng/fieldkit/recce-bridge.json            # rich feed: hosts + services
                                                                # + recce-confirmed findings
                                                                # + version→CVE leads
fieldkit add cred 'CORP/jdoe:Winter2025!'
fieldkit analyze                                                # recce-confirmed hosts float
                                                                # to the top of Opportunities
fieldkit spray smb                                              # ... escalate ...
```

fieldkit's `analyze` ranks the next move from what it has **proven** (access, loot, enum
facts) *plus* what recce has confirmed. recce's confirmed findings are the *exploitability*
input to fieldkit's three-axis ranking — not guesses to be re-proved, but a prioritized
work-queue: recce says *what is worth hitting and why*, fieldkit proves the *compromise* and
reports what it cost to detect.

Confirmed findings land as `vector_type=recce_confirmed_vuln` (high-priority Opportunities);
version→CVE leads land as `vector_type=recce_version_lookup` (verify before escalating).
Ingest is idempotent — re-run as recce updates its bridge. Fieldkit's own confirm-before-write
habit still holds (`-y` to skip in scripts).

> **Roadmap — session-as-transport (Phase A2).** Fieldkit can already run through nxc/ssh/
> mssql. The next integration step adds a `recce-session` transport that pipes fieldkit's
> argv through a recce-caught shell's tasking channel — so the escalate loop runs *through*
> recce's foothold and SOCKS pivot rather than fieldkit rebuilding C2. Needs one small route
> on recce's webui (~40 LoC); ships as fieldkit v3.0.0-a2.

## fieldkit → recce (proven findings back)

Every finding fieldkit proved carries its captured command + output. Export them for recce:

```bash
fieldkit report --check                     # anti-fabrication gate (proven findings)
fieldkit export-recce recce_findings.json   # KB-enriched, confidence: "confirmed"
recce fieldkit-import recce_findings.json -o <engagement>
```

recce folds each into its workbook and customer report — deduped against what it already
had, with severity/CWE/remediation from fieldkit's KB.

## The contract (do not break)

`export-recce` emits a self-contained payload; each finding carries a `_recce` block recce
imports directly:

```json
{
  "_recce_import": 1,
  "source": "fieldkit",
  "engagement": { "...": "..." },
  "findings": [
    { "...": "...",
      "_recce": {
        "ip": "10.0.0.7", "hostname": "WS02", "port": 0,
        "severity": "High", "cwe": "CWE-250", "cwes": ["CWE-250"],
        "remediation": "…", "description": "…", "risk": "reversible",
        "confidence": "confirmed", "ids": ["…"]
      } }
  ]
}
```

`confidence` is always **`confirmed`** — fieldkit only exports what it proved. The contract
is pinned by `tests/test_bridge.py`; change the shape only alongside recce's importer.

## Observations

fieldkit's report also lists **Observations** (weaknesses identified but not exploited).
Those are *not* exported to recce — only proven Findings cross the bridge, so recce's
imported set stays a set of demonstrated compromises. Carry observations in the fieldkit
report itself (`fieldkit report`, which includes them by default).
