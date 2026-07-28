# Supplied binaries — bring-your-own manifest

The kit **generates commands and compiles its own payloads**, but several routes need external binaries/PoCs it
does **not** ship (same model as any air-gapped toolkit). **Pre-stage everything below before an air-gapped
engagement** — `preflight.sh` checks your *tools*; this checklist covers the *artifacts*. Grab from source,
verify, and drop into the directory you serve (`python3 -m http.server 80`) or your no-net stager.

> **AV note:** items marked ⚠ are **flagged by hash** on any modern AV (public tools). **Recompile from source**
> (fresh hash) or use a maintained fork; do not drop the stock release on a monitored host. See the AV/EDR
> section in each `CHEATSHEET.md`.

## Windows — Potato exes (Route 1; pick per `TOOL`)
| Binary | Source | Notes |
|---|---|---|
| `GodPotato-NET4/-NET35/-NET2.exe` ⚠ | github.com/BeichenDream/GodPotato | default; match `-NET*` to target .NET |
| `EfsPotato.exe` ⚠ | github.com/zcgonvh/EfsPotato | LSASS/EFSRPC fallback |
| `SharpEfsPotato.exe` ⚠ | github.com/bugch3ck/SharpEfsPotato | EfsRpc fork |
| `PrintSpoofer64.exe` ⚠ | github.com/itm4n/PrintSpoofer | needs Spooler |
| `JuicyPotatoNG.exe` ⚠ | github.com/antonioCoco/JuicyPotatoNG | needs a COM CLSID |
| `SweetPotato.exe` ⚠ | github.com/CCob/SweetPotato | auto-picks technique |
| `RoguePotato.exe` ⚠ | github.com/antonioCoco/RoguePotato | + a socat OXID redirector |
| `GenericPotato.exe` ⚠ | github.com/micahvandeusen/GenericPotato | named-pipe/HTTP |
| `DCOMPotato` / `LocalPotato` ⚠ | zcgonvh/DCOMPotato · decoder-it/LocalPotato | situational |

## Windows — post-exploitation / enum (attacker- or target-side)
| Binary | Source | Used by |
|---|---|---|
| `nc.exe` ⚠ | classic / int0x33 nc.exe | `--revtype nc` (revshell without PowerShell) |
| `accesschk.exe`, `PsExec`, `procmon` | Sysinternals (Microsoft) | service/DLL enum (Routes 2/3) |
| `PowerUp.ps1` / `SharpUp` ⚠ | PowerSploit · GhostPack/SharpUp | service/priv enum |
| `winPEAS` (exe/bat) ⚠ | github.com/carlospolop/PEASS-ng | exhaustive enum backstop |
| `Invoke-Nightmare.ps1` / CVE-2021-1675 ⚠ | github.com/calebstewart/CVE-2021-1675 | `gen_winexploit printnightmare` |
| a vulnerable signed driver (e.g. `RTCore64.sys`) ⚠ | loldrivers.io | `gen_winexploit seloaddriver` (BYOVD) |
| `mimikatz` ⚠ | github.com/gentilkiwi/mimikatz | parse an LSASS dump ON Windows (alt to pypykatz) |
| `wes.py` (WES-NG) | github.com/bitsadmin/wesng | `gen_winexploit localkernel` (attacker-side) |
| `gpp-decrypt` | Kali / 10-line AES script | `gen_creds gpp` (attacker-side) |

## Linux — CVE PoCs (Route/Bucket 2; `gen_exploit`)
Name each source file `<exploit>.c` (or the binary `<exploit>` with `--prebuilt`) to match `gen_exploit.py list`.
| Exploit | Source |
|---|---|
| `pwnkit` (CVE-2021-4034) | github.com/berdav/CVE-2021-4034 |
| `dirtypipe` (CVE-2022-0847) | Blasty `dirtypipez.c` |
| `nftables` (CVE-2024-1086) | github.com/Notselwyn/CVE-2024-1086 |
| `netfilter` (CVE-2023-32233) | public PoC (needs libmnl/libnftnl) |
| `baronsamedit` (CVE-2021-3156) | github.com/worawit/CVE-2021-3156 |
| `looneytunables` (CVE-2023-4911) | public PoC |
| `dirtycow` (CVE-2016-5195) | FireFart `dirty.c` |
| `msqueue` (CVE-2021-22555) | github.com/google/security-research |
| `sequoia` (CVE-2021-33909) | Qualys PoC |
| `stackrot` (CVE-2023-3269) | github.com/lrh2000/StackRot |
| `gameoverlay` (CVE-2023-2640) | **pure shell — no binary needed** (built into `gen_exploit`) |

## Initial access — public-service exploit PoCs (`archive/access/network/gen_exploit`)
Metasploit-backed entries need only `msfconsole`; these need a **supplied public PoC** (version-match first):
| Exploit | Source |
|---|---|
| `log4shell` JNDI server | github.com/veracode-research/rogue-jndi (or JNDIExploit) |
| `citrix-3519` (CVE-2023-3519) | public PoC (search by CVE) |
| `fortios-ab` (CVE-2022-40684) | public PoC |
| `pulse` (CVE-2019-11510) | public PoC |
| `vcenter` (CVE-2021-21972) | public PoC (vROps webshell upload) |
| `zerologon` (CVE-2020-1472) ⚠ | github.com/dirkjanm/CVE-2020-1472 + impacket secretsdump — **intrusive, can break the DC** |
| `printnightmare` (CVE-2021-34527) | Invoke-Nightmare / CVE-2021-1675 (also in the Windows privesc list) |
Also: `sqlmap`, `nuclei`, `ysoserial`(.jar), `phpggc`, `tplmap`, `ysoserial.net` for the `archive/access/web/` module.

## Linux — recon (`gen_recon`)
| Binary | Source |
|---|---|
| `linpeas.sh` | github.com/carlospolop/PEASS-ng |
| `pspy64` ⚠ | github.com/DominicBreuker/pspy |

## Pre-flight ritual
1. `sh report/preflight.sh` → install any missing **tools**.
2. Stage every artifact above that your target's OS/versions call for (match kernel/.NET first — see `enum.sh`/`enum.bat`).
3. **Recompile the ⚠ items from source** (fresh hash) if the target has AV.
4. Verify each runs in a lab before you rely on it — a missing/wrong-version PoC is a false negative on the client.
