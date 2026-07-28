@echo off
setlocal enabledelayedexpansion
REM ===================================================================================================
REM  Windows privesc TRIAGE — read-only. Paste into a cmd foothold.
REM  Checks EVERY vector (not just the first). Each hit prints  ==> [#n] run <generator>  and is counted.
REM  ONE WORKING VECTOR != DONE — for an assessment, document ALL. Exploit the safest first.
REM ===================================================================================================
set /a HITS=0

echo ===== WHOAMI / CONTEXT =====
whoami
echo --- privileges ---
whoami /priv
echo.

echo ===== [ROUTE 1] SeImpersonate / SeAssignPrimaryToken  (Potato -^> SYSTEM) =====
whoami /priv | findstr /i "SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege" >nul && (set /a HITS+=1 & echo   ==^> [#!HITS!] gen_full.py ^| gen_forma.py ^| gen_nonet.py   ^(Potato to SYSTEM^)) || echo   (not held)
echo.

echo ===== [ROUTE 4] SeBackup / SeRestore / Backup Operators  (hive dump) =====
whoami /priv   | findstr /i "SeBackupPrivilege SeRestorePrivilege" >nul && (set /a HITS+=1 & echo   ==^> [#!HITS!] gen_hashdump.py) || echo   (priv not held)
whoami /groups | findstr /i "Backup Operators" >nul               && (set /a HITS+=1 & echo   ==^> [#!HITS!] in Backup Operators: gen_hashdump.py)
echo.

echo ===== [gen_creds] SeDebug  (LSASS dump) =====
whoami /priv | findstr /i "SeDebugPrivilege" >nul && (set /a HITS+=1 & echo   ==^> [#!HITS!] gen_creds.py --mode lsass) || echo   (not held)
echo.

echo ===== [gen_winexploit] other dangerous privileges =====
whoami /priv | findstr /i "SeLoadDriverPrivilege SeTakeOwnershipPrivilege SeManageVolumePrivilege SeTcbPrivilege SeCreateTokenPrivilege" >nul && (set /a HITS+=1 & echo   ==^> [#!HITS!] gen_winexploit.py map  ^(names the route per privilege^)) || echo   (none held)
echo.

echo ===== [ROUTE 5] AlwaysInstallElevated  (need BOTH keys = 0x1) =====
set _AIE=
reg query "HKLM\Software\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated 2>nul | findstr /i "0x1" >nul && reg query "HKCU\Software\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated 2>nul | findstr /i "0x1" >nul && set _AIE=1
if defined _AIE (set /a HITS+=1 & echo   ==^> [#!HITS!] gen_msi.py) else (echo   (not both set - route closed))
echo.

echo ===== [ROUTE 2] services: unquoted paths / non-Windows services (eyeball a space + no quotes) =====
wmic service get name,displayname,pathname,startmode 2>nul | findstr /i /v "C:\Windows\\" | findstr /i ".exe"
echo   note: a path with a SPACE and NO quotes -^> gen_service.py --binpath "..."   (count it as a vector)
echo   note: weak perms via accesschk -uwcqv %USERNAME% * -^> gen_service.py --mode binpath^|writable_binary^|reg_imagepath
echo.

echo ===== [ROUTE 3b] scheduled tasks as SYSTEM (writable exe/xml?) + PATH intercept =====
schtasks /query /fo LIST /v 2>nul | findstr /i "TaskName Run As User: Task To Run" | findstr /iv "\Microsoft\Windows\ "
echo   note: a SYSTEM task whose exe you can overwrite -^> gen_winmisc.py schtask   (count it)
echo   note: a svc/task calling a RELATIVE binary + a writable %%PATH%% dir -^> gen_winmisc.py pathhijack
echo.

echo ===== [UAC] are we a (filtered) local admin? =====
whoami /groups | findstr /i "S-1-5-32-544" >nul && (set /a HITS+=1 & echo   ==^> [#!HITS!] in Administrators: if medium-integrity, gen_uac.py) || echo   (not a local admin)
echo.

echo ===== [gen_creds --mode hunt] quick stored-cred spots =====
cmdkey /list 2>nul | findstr /i "Target:" && (set /a HITS+=1 & echo   ==^> [#!HITS!] saved creds: runas /savecred or gen_creds.py --mode hunt)
dir /s /b C:\*unattend*.xml C:\Windows\Panther\*.xml 2>nul && (set /a HITS+=1 & echo   ==^> [#!HITS!] unattend file: gen_creds.py --mode hunt)
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword 2>nul && (set /a HITS+=1 & echo   ==^> [#!HITS!] AutoLogon password: gen_creds.py --mode hunt)
echo   note: full sweep (PuTTY/WinSCP/browser/DPAPI/GPP) -^> gen_creds.py --mode hunt
echo.

echo ===== [gen_winexploit localkernel] OS / build =====
ver
echo   note: feed systeminfo to wesng -^> gen_winexploit.py localkernel   ^| PrintNightmare if Spooler up ^> sc query Spooler
echo.

echo ====================================================================================
echo ===== NETWORK / ROUTING (this host) =====
echo ====================================================================================
echo --- interfaces ---
ipconfig ^| findstr /i /c:"adapter" /c:"IPv4" /c:"Subnet" /c:"Default Gateway"
echo --- routing table (gateways + the segments this host can reach) ---
route print -4 2>nul ^| findstr /r /c:"Network Destination" /c:"^ *[0-9]"
echo --- ARP neighbours (hosts this box has actually talked to) ---
arp -a 2>nul ^| findstr /r /c:"^  [1-9]"
echo # --- machine block (recce folds this into its reachability + architecture map) ---
echo ==== NETWORK ====
where powershell >nul 2>&1
if !errorlevel!==0 (
  powershell -NoProfile -NonInteractive -Command "Get-NetIPAddress -AddressFamily IPv4 -EA 0 | Where-Object {$_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*'} | ForEach-Object {'NET-IFACE '+($_.InterfaceAlias -replace ' ','_')+' '+$_.IPAddress+'/'+$_.PrefixLength}; Get-NetRoute -AddressFamily IPv4 -EA 0 | ForEach-Object {'NET-ROUTE '+$_.DestinationPrefix+' via '+$_.NextHop+' dev '+($_.InterfaceAlias -replace ' ','_')}; Get-NetNeighbor -AddressFamily IPv4 -EA 0 | Where-Object {($_.State -match 'Reachable|Stale|Permanent') -and $_.LinkLayerAddress} | ForEach-Object {'NET-NEIGH '+$_.IPAddress+' '+$_.LinkLayerAddress}; Get-NetTCPConnection -State Established -EA 0 | Where-Object {$_.RemoteAddress -notmatch ':' -and $_.RemoteAddress -notlike '127.*'} | ForEach-Object {'NET-PEER '+$_.RemoteAddress+':'+$_.RemotePort}"
) else (
  for /f "tokens=1,2" %%a in ('arp -a ^| findstr /r /c:"^  [1-9]"') do echo NET-NEIGH %%a %%b
  for /f "tokens=2,3" %%a in ('netstat -n -p TCP ^| findstr "ESTABLISHED"') do echo NET-PEER %%b
)
echo ==== END NETWORK ====
echo.

echo ====================================================================================
echo ===== FINDINGS SUMMARY =====
echo ====================================================================================
echo Counted !HITS! privilege/cred vector(s) above (the ==^> [#n] lines). Plus eyeball the
echo ROUTE 2 / ROUTE 3b service+task lists (not auto-counted).
echo ONE WORKING VECTOR != DONE. Exploit the safest first, but DOCUMENT ALL for the assessment.
echo After you reach SYSTEM, re-run to catch what was only visible as admin.
echo (full route picker + variants: CHEATSHEET.md)
endlocal
