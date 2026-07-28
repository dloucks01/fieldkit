# fieldkit ⇄ recce

fieldkit and [**recce**](https://github.com/dloucks01/recce) split one engagement:
**recce** does enumeration + reporting; **fieldkit** does access, lateral movement, and
privilege escalation. They round-trip through a small JSON contract so proven work flows
back into recce's workbook and customer report.

```
recce (enum + confirmed vulns)  ──scope/hosts──▶  fieldkit  (spray → escalate → prove)
        ▲                                                       │
        └────────  recce fieldkit-import  ◀── fieldkit export-recce ──┘
                    (proven findings, KB-enriched, confidence: confirmed)
```

## recce → fieldkit (scope in)

recce has already swept the network and confirmed vulnerable hosts. Feed that scope to
fieldkit and run the loop:

```bash
recce fieldkit-export <engagement>          # recce writes the in-scope hosts
fieldkit add hosts recce-scope.txt          # IPs / CIDRs / 'IP hostname' lines
fieldkit add cred 'CORP/jdoe:Winter2025!'
fieldkit spray smb                          # ... enum / analyze / escalate ...
```

fieldkit's `analyze` ranks the next move from what it has **proven** (access, loot, enum
facts) — you don't re-import recce's guesses; recce hands off the *scope*, fieldkit proves
the *compromise*.

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
