# access/services — anonymous / default / misconfig service access → shell
> **Which access surface?** You're in `access/services/` — a **service left open** (anon/default/misconfig). Siblings: `../network/` (**cred / network / AD / cloud**) · `../web/` (a **web app**). (See `../../START-HERE.md`.)

**For each open port, the way in that needs NO cracked cred, NO CVE, and NO web app** — the low-hanging fruit
checked on every engagement. Sister to `../network/` (creds/CVE/AD/cloud) and `../web/` (web app exploitation).
Generators run on YOUR box and *print* commands; the shell/loot feeds the privesc kits + `report/`.
Find the open ports first with `../network/enum_net.py` (or `../network/sweep.py` for a target LIST). **Authorized engagements only.**

**Reading the steps:** `<x>` = you supply · `needs:` = precondition · `-> ok:` = what confirms it worked. **Check EVERY exposed service, not just the first foothold** — each anonymous/default/misconfig service is its own finding; document them all in `report/` even after you're in. For a target list, `sweep.py triage` flags which hosts have these services so you hit them all.

## Port → generator
```
445  SMB      → gen_smb.py    (null-session loot · writable-share SCF/LNK hash capture · RID-cycle)
2049 NFS      → gen_nfs.py    (mount → loot → authorized_keys/webshell/cron · no_root_squash→privesc)
21   FTP      → gen_ftp.py    (anonymous → read creds / write webshell to webroot)
161  SNMP     → gen_snmp.py   (community strings → users/procs/creds · RW → NET-SNMP-EXTEND RCE)
DBs           → gen_db.py     (--db mongo|elastic|couchdb|memcached|redis|mysql|postgres|oracle)
2375 Docker   → gen_container.py docker   (exposed API → mount host → root)
6443/10250 K8s→ gen_container.py k8s      (anonymous kubelet exec / API)
8080 Tomcat   → gen_container.py tomcat|jboss|weblogic  (manager default creds → WAR)
873  rsync    → gen_remote.py rsync   ·  5900 VNC → gen_remote.py vnc
23   Telnet   → gen_remote.py telnet  ·  25 SMTP → gen_remote.py smtp
```

## Highlights (highest-hit-rate)
- **SMB null session** → read shares → creds in configs/scripts/GPP; **writable share** → drop an SCF/LNK → Responder captures NetNTLMv2 → crack/relay (`../network/gen_poison`/`gen_relay`).
- **NFS export** → mount → SSH keys/creds, or **writable export** → `authorized_keys`/webshell/cron.
- **Redis unauth** → `config set dir/dbfilename` → webshell / SSH key / cron. **Docker API 2375** → `run -v /:/mnt … chroot` → **root on the host** (one of the fastest footholds there is).
- **Tomcat manager default creds** → deploy a WAR → shell. **SNMP RW community** → NET-SNMP-EXTEND → RCE.
- **unauth Mongo/Elastic/CouchDB/Memcached** → data + app creds → reuse (`../network/gen_shell`).

## After a foothold
Upgrade to a PTY, then `../../winpriv/enum.bat` or `../../linpriv/enum.sh`. Log the finding (`anon_access` · `unauth_database` · `exposed_docker_api` · `default_credentials`).

## Safety / AV / OPSEC
- **Loot is sensitive client data** — handle per ROE. **Writable-share/NFS/DB writes, deployed WARs, created containers, added SSH keys are ARTIFACTS to remove** (record → `report --cleanup`).
- **msfvenom WARs and webshells are AV-signatured** — prefer a hand-written JSP/PHP; recompile ⚠ tooling.
- **Authorized scope only.** Anonymous DB/API reads can pull large amounts of data — take only what proves the finding.
