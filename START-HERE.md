# START HERE — which module, and when

> **v1 guide.** This is the decision guide for the print-only generator tree, which now lives under
> **`archive/`** — every path below is relative to it (`archive/access/network/…`, `archive/winpriv/…`).
> The v2 engine (`fieldkit init` / `add` / `spray` / `ingest` / `analyze` / `status` — the credential loop
> landed in Phase 1) is documented in [`README.md`](README.md); its knowledge is being lifted out of these modules
> phase by phase. `configure.sh` is gone — set LHOST/LPORT/domain with `fieldkit config set`, or edit the
> archived `_*_common.py` directly if you are running a v1 generator.

The toolkit is the full engagement funnel: **get in → escalate → report.** Pick a module by **what you found**,
not by guessing.

## 1. Getting IN — `access/` has three surfaces, and they DON'T overlap
All of initial access lives under **`access/`**. All three surfaces end in a shell, but each attacks a
different thing — this is the part people mix up:

| You found / have | Go to | It is… |
|---|---|---|
| a **credential/hash**, or an open **auth service** (SMB/RDP/WinRM/SSH/MSSQL) | **`access/network/`** | network + identity access |
| a **known-vuln product/version** (Exchange, Citrix, Log4j…) | **`access/network/`** (`gen_exploit`) | public-service CVE |
| an **AD segment with no creds** | **`access/network/`** (`gen_poison`→`gen_relay`→`gen_adcs`) | poison/relay/ADCS → DA |
| a **cloud tenant** (M365/Entra/Okta) | **`access/network/`** (`gen_cloud`) | cloud identity |
| a **web application** (login, params, upload, API) | **`access/web/`** | web-APP vulns (SQLi/LFI/RCE/upload/SSRF/JWT/API) |
| an **open service** (SMB share, NFS, FTP, SNMP, a DB, Docker, Tomcat) | **`access/services/`** | anonymous/default/misconfig access |
| a **custom binary** with no public CVE (research it) | **`novelre/`** | novel vuln discovery + exploit-dev |

> **Disambiguation (the common confusion):** `access/network/` = you have a *cred* or a *network/AD/cloud* way in ·
> `access/web/` = there's a *web app* to break · `access/services/` = a *service is wide open*. All → a shell.

**Many targets (e.g. 480 IPs)?** Start with `access/network/sweep.py plan` → run the scan → `access/network/sweep.py triage`.
It ranks every host by quick-win and **names the exact module/generator per host** so you don't guess.
(Or `sweep.py plan --oneshot > mass-scan.sh` emits a single runnable script that hits the whole scope in one kickoff.)

> **Enumerated with [recce](https://github.com/dloucks01/recce)?** Skip the scan: run `recce fieldkit-export`
> and feed its output straight in — `sweep.py triage --recce recce-bridge.json` ranks hosts using recce's
> **confirmed** findings. Proven results flow back with `gen_report.py --export-recce` → `recce fieldkit-import`.
> Full round-trip: [`INTEGRATION.md`](INTEGRATION.md).

## 2. After you have a shell — escalate
| Shell on… | Module | First step |
|---|---|---|
| Windows | **`winpriv/`** | paste `winpriv/enum.bat` (it names the route) |
| Linux | **`linpriv/`** | run `linpriv/enum.sh` (it names the route) |

## 3. Write it up
Every proven finding → **`report/`** (`gen_report.py`) → Markdown/DOCX/PDF + cleanup manifest.
**Rule everywhere:** one working vector ≠ done — enumerate and document *all* of them.

## The flow
```
sweep/enum → access/{network|web|services} | novelre → SHELL → winpriv | linpriv → report
   (find)          (get in)                              (escalate)      (write up)
```

## Before an (air-gapped) engagement
```bash
sh report/preflight.sh          # are the tools installed?
sh report/avcheck.sh            # do the payloads clear the AV static floor?
sh configure.sh <LHOST> <LPORT> [DOMAIN]     # set your callback everywhere at once
# + work through SUPPLIED-BINARIES.md (Potato exes, CVE PoCs, PEAS, drivers — you supply these)
```
Full per-module detail: each folder's `CHEATSHEET.md`.
