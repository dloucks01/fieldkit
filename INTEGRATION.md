# fieldkit ⇄ recce — enumeration-driven exploitation, findings back to the sheet

fieldkit is the **exploitation** half of an engagement; [**recce**](https://github.com/dloucks01/recce)
is the **enumeration + reporting** half (multi-subnet nmap → one tracked Excel workbook + report).
They round-trip cleanly, so you enumerate once and let each side feed the other:

```
recce enum/vulns ──fieldkit-export──▶  fieldkit sweep + generators  ──findings.json──▶ gen_report
       ▲    ▲                                                                          │
       │    └── recce ingest ◀── linpriv/winpriv enum NET-* block (interfaces/routes) ─┤
       │        (topology → recce's reachability + architecture maps)                  │
       └──────────────  recce fieldkit-import  ◀── gen_report.py --export-recce ──────────┘
        (proven findings land back in the recce workbook + report)
```

Both directions are **offline, deterministic, stdlib-only** — nothing here scans, connects, or
executes. recce prints commands into a datastore; fieldkit prints commands you paste. Authorized
engagements only.

---

## 1. recce → fieldkit: turn enumeration into a focused attack plan

On the recce side, after `recce enum` / `recce vulns` (see recce's docs):

```bash
recce fieldkit-export -o eng          # writes eng/fieldkit/
```

That folder is the handoff. Copy it next to your fieldkit checkout and feed **the richest one** into
mass triage:

```bash
python3 archive/access/network/sweep.py triage --recce eng/fieldkit/recce-bridge.json
```

`--recce` uses recce's open ports **and the vulnerabilities it already confirmed**, so the
scoreboard floats proven quick-wins to the very top and annotates each host with what recce proved
(`CONFIRM [CRITICAL] …`) plus the exact generator to run. It composes with the classic inputs:

```bash
python3 archive/access/network/sweep.py triage --nmap eng/fieldkit/ports.gnmap --nxc eng/fieldkit/smb-null.txt
```

| File in `eng/fieldkit/` | What it is | Consumed by |
|---|---|---|
| `recce-bridge.json` | ports + service/version + recce's **confirmed** findings + suggested generator + ready `gen_exploit`/`gen_shell`/`gen_spray` commands per host | `sweep.py triage --recce` (richest) |
| `ports.gnmap` | synthesized nmap-greppable (`-oG`) | `sweep.py triage --nmap` (zero-change path) |
| `smb-null.txt` | netexec-style lines for null/anonymous SMB hosts | `sweep.py triage --nxc` |
| `users.txt` | usernames recce enumerated (machine accounts dropped) | `gen_spray.py --users users.txt` |
| `creds.txt` | credentials recce captured (`domain/user:secret` / `hash:`) | `gen_shell.py` (reference) |
| `FIELDKIT.md` | human, severity-ranked "run **this** on **that** host, because …" plan | you |

`sweep.py triage --recce` prints, under each host, not just the port→generator route but recce's
**confirmed** findings and ready-to-paste commands it derived from what it enumerated:

- **`ver→cve`** — `gen_exploit.py find --service <p> --version <v>` for each service recce fingerprinted
  (any confirmed CVEs noted inline), so you jump straight from a known version to candidate exploits.
- **`cred`** — `gen_shell.py …` for each known credential that applies to the host, plus a
  `gen_spray.py --users users.txt …` line — the `users.txt` / `creds.txt` above are the material they use.

Run the named generator per host (`archive/access/services/gen_smb.py`, `archive/access/network/gen_shell.py`,
`services/gen_db.py --db redis`, …) as usual — the recce lines just pre-fill the target, service,
version, and credentials so you paste instead of retype.

## 2. fieldkit → recce: fold proven findings back into the sheet + report

Write up each **proven** finding in a `findings.json` the normal way (`gen_report.py --init`, fill in
`steps` from your session capture), then in addition to the client report, emit the recce feed:

```bash
python3 report/gen_report.py findings.json --check          # gate: every step has a real command + output
python3 report/gen_report.py findings.json                  # your customer report (md/docx/pdf)
python3 report/gen_report.py findings.json --export-recce   # -> recce_findings.json (KB-enriched)
```

`--export-recce` resolves each finding's severity, CWE, remediation and risk from `_report_kb.py` and
parses the host IP out of `affected_host`, into a self-contained `recce_findings.json` — recce needs
no copy of fieldkit's KB. Fold it in on the recce side:

```bash
recce fieldkit-import recce_findings.json -o eng
```

Every proven finding becomes a **confirmed** vulnerability in recce (source `fieldkit`) and lands in the
**Vulnerabilities** sheet, the HTML/Markdown report and the DOCX write-ups; the affected host is
marked *access-gained*. Re-importing is idempotent (deduped by title+host), so you can run it as you
prove each finding.

> The engagement now has one source of truth: recce's workbook tracks coverage (what was enumerated)
> **and** outcomes (what fieldkit proved), and recce's report reflects both.

## Feed host topology back for a real reachability map

fieldkit's on-target triage scripts (`archive/linpriv/enum.sh`, `archive/winpriv/enum.bat`) emit a machine
`NETWORK` block — this host's interfaces, routes, ARP neighbours and live TCP peers:

```
==== NETWORK ====
NET-IFACE eth0 10.0.20.5/24
NET-ROUTE default via 10.0.20.1 dev eth0
NET-NEIGH 10.0.10.10 aa:bb:cc:00:00:10
NET-PEER 10.0.10.10:445 ESTAB
==== END NETWORK ====
```

Bring that output back and fold it into recce:

```bash
recce ingest enum-output.txt --host <ip> -o eng
```

recce turns the ARP neighbours and live peers into a **ground-truth** host-to-host
reachability map (`network-reachability.svg`, embedded in the report) — a link is drawn
only because the compromised host *actually reached* the other end — and flags dual-homed
**pivots** that bridge network segments. This is the real lateral-movement picture, from
the inside, that an outside-in scan can never see.

## Tests

The two integration seams are smoke-tested (stdlib only — no pandoc/nmap/network needed):

```bash
python3 -m unittest discover -s tests      # from the repo root
```

`tests/test_integration_recce.py` drives `gen_report.py --export-recce` / `--check` and
`sweep.py triage --recce` (plus the classic `--nmap` / `plan` paths) via subprocess and asserts on
their output.
