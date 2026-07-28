# CLAUDE.md — architecture & working notes for the fieldkit v2 engine

fieldkit is a **stateful internal-AD execution engine** for **authorized** penetration
testing: from one credential/foothold it drives proven external tools (netexec,
impacket, evil-winrm, certipy) against a scope, runs the credential loop, escalates,
and reports only what it actually proved. Standalone — Python 3 **stdlib only**; the
tools it drives are the operator's existing kit. Authorized engagements only.

## Run & test

```bash
bin/fieldkit <command>          # shim for `python3 -m fieldkit` (run from a clone)
python3 -m pytest -q            # 355 tests, ~0.8s, no network/subprocess/tools needed
python3 -m pyflakes fieldkit/ tests/   # keep clean before committing
```

The DB defaults to `./engagement.db` (`--db` or `$FIELDKIT_DB` to override). Tests
drive `fieldkit.cli.main(argv)` in-process and inject fake runners — **never** shell
out to real tools. Nothing in the package does I/O at import time.

## The spine: the credential loop

```
add cred/hosts → spray (nxc) → parse (Pwn3d!) → loot admin hosts (SAM/LSA/NTDS/roast)
      ↑                                                        │
      └──────────────── promote recovered secrets ────────────┘
              → enum foothold → analyze (rank next moves) → run vector → report
```

Everything is a projection of one SQLite store. `spray` reuses each account's *own*
proven secret (lockout-safe by construction); `analyze` ranks what state proves;
`report` renders the captured evidence.

## Module map (`fieldkit/`)

| Layer | Modules | Role |
|---|---|---|
| Foundation | `state.py`, `config.py`, `creds.py`, `scope.py`, `errors.py` | SQLite store (+migrations), engagement config, the canonical credential model + per-tool renderers, scope parsing, one error family |
| Loop | `netexec.py`, `ingest.py`, `spray.py`, `dump.py`, `kb.py` | parse nxc `(Pwn3d!)`/`--pass-pol`; fold captures into state; the live spray loop; parse SAM/LSA/NTDS → loot→creds; the opportunity KB + three-axis ranking |
| Execution | `transport.py`, `executor.py`, `runner.py`, `hostenum.py`, `privesc.py` | run a command on a host (nxc `-x`/ssh); the safety gate + evidence capture; the one subprocess spawn; OS enum → `HostFacts`; privesc vectors (GTFOBins/caps/Se*/…) |
| AD depth | `kerberos.py`, `delegation.py`, `adcs.py`, `bloodhound.py` | roasting → loot; `--find-delegation`; certipy ESC1-16; SharpHound graph + owned→DA pathfinding |
| Evasion | `evasion.py`, `lab.py` | technique catalog + assume-caught model; Defender lab harness (EICAR-gated) |
| Reporting | `report.py`, `reportkb.py`, `bridge.py` | build+render+`--check`+cleanup from state; the remediation KB (~80 vector_types); the recce export contract |
| CLI | `cli.py` | thin argparse over the above — parse args, call in, print. No logic here. |

## Load-bearing design rules (keep these)

1. **Logic in modules, CLI is thin.** Every behavior lives in a testable function; `cli.py`
   only parses/prints. Add logic to a module, not a handler.
2. **Inject the subprocess runner.** `runner.run` is the *only* child-process spawn. Every
   driver (`spray`, `executor`, `kerberos`, `adcs`, …) takes `run=` so tests pass a fake
   `(argv, env) -> RunResult`. Pure parse functions are separated from the driver.
3. **Capture everything.** Commands run against a target go through `executor.execute`,
   which writes verbatim cmd/output/exit to the `step` table and cleanup actions to
   `artifact`. This is why `report --check` (anti-fabrication) passes by construction — a
   finding can't render without the proof that made it.
4. **Safety gate.** Actions declare `read-only < config-change < crash-risk`; the executor
   admits a prefix (`allow=`). Read-only runs freely; riskier needs explicit `--allow`.
5. **Assume-caught.** Evasion is a ranking axis. Every technique is red until a fresh
   Defender-lab result greens it (`evasion.resolve`); greens go stale after 14 days.
6. **Three-axis ranking.** `kb.score(exploitability, safety, detection)` orders both loop
   opportunities and privesc vectors — quiet/safe/high-impact/precondition-met floats up.
7. **One credential model.** `creds.Credential` is canonical; liberal parse in, strict
   argv-list renderers out (`render_nxc`/`render_impacket`/…). Never build shell strings.
8. **State is the single source of truth.** Enum facts, findings, evidence, the BH graph —
   all derive from state; re-running overwrites rather than duplicating. Insert methods are
   idempotent (`add_host`/`add_credential`/`add_access` dedupe; `access` upgrades non-admin→
   admin, never down).
9. **Canonical `vector_type`.** Privesc `Vector.report_type` and all AD findings use
   `reportkb.KB` keys, so a finding records → renders → bridges with no hand-mapping.

## Data model (schema v4, `PRAGMA user_version`)

`engagement` (1 row: name + config JSON) · `host` · `service` · `credential` · `access`
(who-is-admin-where) · `finding` · `step` (captured evidence, optional `finding_id`) ·
`artifact` (cleanup manifest) · `loot` (hashes/tickets pre-promotion) · `evasion` (lab
green/red) · `bh_node`/`bh_edge` (BloodHound graph).

Schema changes = append `(version, [sql])` to `MIGRATIONS`; never edit a shipped entry.
Older DBs upgrade in place on open. SQLite can't drop NOT NULL — rebuild the table (see
`_V2`).

## Extending

- **A privesc technique** → one entry in `privesc.GTFO`/`CAPS`/`WIN_PRIVS` or one driver in
  `privesc.DRIVERS`; set `report_type` to a `reportkb.KB` key.
- **An analyze opportunity** → append a predicate to `kb.PREDICATES` (reads store, yields
  `Opportunity`); AD modules already do this for roast/delegation/ADCS/BH.
- **An evasion technique** → a row in `evasion.TECHNIQUES` (+ a `lab.PROBES` probe if
  self-contained).
- **A report vector** → a `reportkb.KB` entry (+ `RISK`); the report/bridge pick it up.

## Recce contract (do not break)

`export-recce` emits `{"_recce_import": 1, "source": "fieldkit", "engagement": {...},
"findings": [{..., "_recce": {ip, hostname, port, severity, cwe, cwes, remediation,
description, risk, confidence: "confirmed", ids}}]}`. Pinned by `tests/test_bridge.py`
(v2) and `tests/test_integration_recce.py` (v1). Pairs with the recce tool
(`recce fieldkit-export` seeds triage; `recce fieldkit-import` folds findings back).

## v1 relationship

`archive/` holds the v1 print-only generator tree (~5,600 lines) — kept for reference and
as the knowledge source being ported phase by phase. `report/gen_report.py` (v1) still
runs and its recce test stays green. Don't add features to `archive/`; port knowledge into
the package (as `reportkb.py`, `privesc.py`, `evasion.py` already did).

## Conventions

Rich module docstrings explaining *why* (see any module top). Commit per coherent slice
with a body that says what changed and why. Confirm-before-write on anything that runs a
tool against the client (`_confirm`, `--yes` to skip). Convert relative dates to absolute
in any persisted text.
