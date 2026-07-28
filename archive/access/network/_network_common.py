"""Shared config + helpers for the initial-access module (standalone, like winpriv/linpriv).

The generators PRINT commands you run on the ATTACKER box (they drive nmap/nuclei/netexec/impacket/
evil-winrm) — nothing here touches a target on its own. The FOOTHOLD they produce feeds straight into
the privesc kits (paste enum.bat/enum.sh) and the report/ pipeline.

Authorized engagements ONLY. Spraying can lock accounts + service exploits can crash hosts — see the
safety notes in each generator and CHEATSHEET.md.
"""
import base64

# ================= EDIT THESE =================
LHOST, LPORT = "10.10.14.7", 443          # attacker: revshell catcher / redirector
DOMAIN       = ""                         # AD domain (blank = local auth / workgroup)
# wordlists (operator supplies; SecLists is the usual source — pre-stage for air-gap)
USERLIST = "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"
PASSLIST = "/usr/share/wordlists/rockyou.txt"
# =============================================

# Common ports -> the enum follow-up + which access bucket they point to.
SERVICES = {
    21:   ("ftp",    "anon login? `ftp <t>`; else spray"),
    22:   ("ssh",    "spray (gen_spray --proto ssh) -> gen_shell --proto ssh"),
    80:   ("http",   "web enum (enum_net --web) -> gen_web"),
    443:  ("https",  "web enum -> gen_web"),
    445:  ("smb",    "null session, shares, users; spray -> gen_shell --proto smb"),
    1433: ("mssql",  "spray -> gen_shell --proto mssql (xp_cmdshell = Route 1 privesc entry)"),
    3306: ("mysql",  "spray; creds -> query/UDF"),
    3389: ("rdp",    "spray CAREFULLY (lockout) -> gen_shell --proto rdp"),
    5985: ("winrm",  "spray -> gen_shell --proto winrm (evil-winrm)"),
    5986: ("winrm-s","winrm over TLS"),
    88:   ("kerberos","AS-REP roast / user enum (AD)"),
    389:  ("ldap",   "anonymous bind? domain/user enum"),
    139:  ("netbios","legacy SMB; null session"),
    25:   ("smtp",   "user enum (VRFY/RCPT); open relay"),
    27017:("mongodb","auth? unauth access = data"),
    6379: ("redis",  "unauth? -> RCE via module/cron/ssh-key"),
    2049: ("nfs",    "showmount -e <t>; no_root_squash"),
}

def b64(s):
    return base64.b64encode(s.encode()).decode()

def targets(arg):
    """Return a target expression for a tool: a single host, a CIDR, or @file (netexec/nmap accept these)."""
    return arg
