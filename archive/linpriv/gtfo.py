#!/usr/bin/env python3
"""BUCKET 1 -- GTFOBins SUID/sudo abuse lookup (the SeImpersonate-token analog).
No delivery needed: these binaries are already on the box; you just need the right incantation.

Usage:
  python3 gtfo.py                     # print the whole table (suid + sudo)
  python3 gtfo.py find                # both forms for one binary
  python3 gtfo.py python sudo         # just the sudo form
  python3 gtfo.py --scan '<sudo -l or find-SUID output>'   # match your enum output to abuse primitives
"""
import sys
import _linpriv_common as P

def show(binname, mode=None):
    e = P.GTFOBINS.get(binname)
    if not e:
        print(f"{binname}: not in the built-in table — check abuse.gtfobins.github.io/gtfobins/{binname}/")
        return
    for m in (["suid", "sudo"] if mode is None else [mode]):
        if e.get(m):                 # skip forms that aren't a clean primitive (empty string)
            print(f"  [{m}] {e[m]}")

args = sys.argv[1:]
if not args:
    print("GTFOBins SUID/sudo abuse — suid keeps -p (owner usually root); sudo runs as root already.\n")
    for b in sorted(P.GTFOBINS):
        print(b)
        show(b)
        print()
    print("Capabilities (getcap -r /):")
    for c, v in P.CAP_ABUSE.items():
        print(f"  {c:<22} {v}")
elif args[0] == "--caps":
    print("Capabilities (getcap -r / 2>/dev/null) — +ep on the FILE = effective on exec, no sudo needed:\n")
    for c, v in P.CAP_ABUSE.items():
        print(f"  {c:<22} {v}")
elif args[0] == "--sudo-tricks":
    print("Sudo misconfigurations (from `sudo -l`):\n")
    for k, t in P.SUDO_TRICKS.items():
        print(f"  [{k}]\n    when: {t['when']}\n    cmd : {t['cmd']}\n    note: {t['note']}\n")
elif args[0] == "--scan":
    blob = args[1] if len(args) > 1 else sys.stdin.read()
    hits = [b for b in P.GTFOBINS if b in blob]
    if not hits:
        print("no known-abusable binary matched. Manually check abuse.gtfobins.github.io.")
    for b in hits:
        mode = "sudo" if "NOPASSWD" in blob or "(ALL)" in blob or "sudo" in blob.lower() else None
        print(b); show(b, mode); print()
else:
    show(args[0], args[1] if len(args) > 1 else None)
