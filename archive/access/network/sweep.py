#!/usr/bin/env python3
"""MASS TRIAGE across a target LIST (e.g. 480 IPs/hostnames) -> a ranked scoreboard of WHICH hosts to
focus on. Two steps: (1) `plan` prints the fast mass-scan command sequence to run across the whole list;
(2) `triage` parses the scan output and ranks every host by likely quick-win, mapping each to the
generator that exploits it. Authorized scope ONLY — this scans your defined engagement range.

Usage:
  python3 sweep.py plan   --targets targets.txt                 # print the mass-scan commands
  python3 sweep.py plan   --targets targets.txt --oneshot       # emit ONE runnable mass-scan.sh
      #   ... --oneshot > mass-scan.sh && sh mass-scan.sh        # one kickoff, whole scope
  python3 sweep.py triage --nmap ports.gnmap [--nxc smb.txt]    # parse -> scoreboard (focus list)
  python3 sweep.py triage --recce recce-bridge.json             # use recce's enumeration + CONFIRMED
                                                                 #   findings (from `recce fieldkit-export`)

The --recce feed comes from the companion enumeration tool: run `recce fieldkit-export -o <eng>` and
point --recce at the emitted `fieldkit/recce-bridge.json`. It carries recce's open ports AND the
vulnerabilities it already CONFIRMED, so the scoreboard floats proven quick-wins to the very top and
annotates each host with what recce proved. It composes with --nmap/--nxc (union of both).
"""
import sys, re, json

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

arg = sys.argv[1] if len(sys.argv) > 1 else "plan"

# port -> (label, quick-win note + which generator, juiciness 0=best)
WINS = {
    2375: ("docker-api",  "UNAUTH → root on host: services/gen_container.py docker",        0),
    2376: ("docker-tls",  "Docker API (TLS): services/gen_container.py docker",              1),
    6379: ("redis",       "often UNAUTH → RCE: services/gen_db.py --db redis",              0),
    27017:("mongodb",     "often UNAUTH → data/creds: services/gen_db.py --db mongo",       1),
    9200: ("elastic",     "UNAUTH REST → data (+old RCE): services/gen_db.py --db elastic", 1),
    5984: ("couchdb",     "UNAUTH → add-admin+RCE: services/gen_db.py --db couchdb",        1),
    11211:("memcached",   "UNAUTH → sessions/creds: services/gen_db.py --db memcached",     2),
    445:  ("smb",         "null-session/relay/EternalBlue: services/gen_smb + access/gen_relay", 1),
    2049: ("nfs",         "exports → loot/keys: services/gen_nfs.py",                        1),
    21:   ("ftp",         "anon login? services/gen_ftp.py anon",                            2),
    161:  ("snmp",        "community strings: services/gen_snmp.py (UDP — nmap -sU)",        2),
    873:  ("rsync",       "anon modules: services/gen_remote.py rsync",                      2),
    5900: ("vnc",         "no-auth/weak: services/gen_remote.py vnc",                        2),
    23:   ("telnet",      "default creds: services/gen_remote.py telnet",                    3),
    8080: ("http-alt",    "Tomcat/JBoss mgr / web: services/gen_container.py tomcat · web/", 1),
    80:   ("http",        "web app → access/web/ (nuclei/ffuf first)",                         2),
    443:  ("https",       "web app → access/web/",                                             2),
    3389: ("rdp",         "spray CAREFULLY (lockout): access/gen_spray.py --proto rdp",      3),
    5985: ("winrm",       "cred → shell: access/gen_shell.py --proto winrm",              3),
    1433: ("mssql",       "SQLi/spray → xp_cmdshell: access/gen_shell --proto mssql",     2),
    3306: ("mysql",       "spray → UDF/OUTFILE: services/gen_db.py --db mysql",              2),
    5432: ("postgres",    "COPY…PROGRAM RCE: services/gen_db.py --db postgres",              2),
    1521: ("oracle",      "SID/creds (ODAT): services/gen_db.py --db oracle",                2),
    389:  ("ldap",        "anon bind? domain enum: access/enum_net --ad",                    2),
    88:   ("kerberos",    "AS-REP roast / kerbrute: access/gen_spray --proto kerberos",      2),
    25:   ("smtp",        "user-enum/relay: services/gen_remote.py smtp",                    3),
}

if arg == "plan" and "--oneshot" in sys.argv:
    # ONE kickoff for the whole scope: print a single runnable script that chains every
    # mass-scannable step. fieldkit stays print-only — you save + run it:
    #   python3 sweep.py plan --targets scope.txt --oneshot > mass-scan.sh && sh mass-scan.sh
    tf = opt("--targets", "targets.txt")
    print(f"""#!/bin/sh
# MASS TRIAGE — one kickoff across the whole scope ({tf}). AUTHORIZED SCOPE ONLY.
# Chains: live-host discovery -> port scan -> SMB null-session sweep -> web/CVE sweep ->
# service/version. Tool-tolerant (skips a step whose tool is absent). Outputs feed
# `sweep.py triage` and recce. Run:  sh mass-scan.sh
set -u
TARGETS="{tf}"
have(){{ command -v "$1" >/dev/null 2>&1; }}
[ -f "$TARGETS" ] || {{ echo "!! $TARGETS not found (one IP/host/CIDR per line)"; exit 1; }}

echo "== 1/5 live hosts =="
if have nmap; then nmap -sn -iL "$TARGETS" -oG live.gnmap >/dev/null 2>&1; grep -a Up live.gnmap | cut -d' ' -f2 > live.txt; else cp "$TARGETS" live.txt; fi
echo "   $(wc -l < live.txt 2>/dev/null) live host(s) -> live.txt"

echo "== 2/5 port scan (this is the file triage parses) =="
if have masscan; then masscan -iL live.txt -p1-65535 --rate 5000 -oG ports.gnmap >/dev/null 2>&1
elif have nmap; then nmap -Pn -iL live.txt --top-ports 200 --open --min-rate 2000 -oG ports.gnmap >/dev/null 2>&1
else echo "   (no masscan/nmap - skipped)"; fi

echo "== 3/5 SMB sweep (null session + signing + relay list) =="
if have nxc; then nxc smb live.txt > smb.txt 2>&1; nxc smb live.txt --shares -u '' -p '' >> smb.txt 2>&1; nxc smb live.txt --gen-relay-list relay_targets.txt >/dev/null 2>&1
else echo "   (nxc/netexec absent - skipped)"; fi

echo "== 4/5 web + known-CVE sweep =="
grep -aE '(:| )(80|443|8080|8443)/open' ports.gnmap 2>/dev/null | cut -d' ' -f2 | sort -u > web.txt
have httpx  && httpx  -l web.txt -title -tech-detect -sc -o web_httpx.txt >/dev/null 2>&1
have nuclei && nuclei -l web.txt -severity critical,high -o nuclei.txt >/dev/null 2>&1

echo "== 5/5 service/version (for CVE matching) =="
have nmap && nmap -Pn -sCV -iL live.txt --open -oA services >/dev/null 2>&1

echo
echo "DONE. Next:"
echo "  python3 access/network/sweep.py triage --nmap ports.gnmap --nxc smb.txt"
echo "  (or fold into recce:  recce import services.xml -o eng)"
""")
    sys.exit(0)

if arg == "plan":
    tf = opt("--targets", "targets.txt")
    print(f"# MASS TRIAGE plan for {tf}. Run top-to-bottom (each step feeds the next); outputs feed `sweep.py triage`.")
    print(f"#   ( one kickoff instead of the steps below:  python3 sweep.py plan --targets {tf} --oneshot > mass-scan.sh && sh mass-scan.sh )")
    print(f"# needs: {tf} = your authorized scope, one IP/host/CIDR per line (<x> = you supply this file).\n")
    print(f"# 1) live hosts (skip if you already know they're up):")
    print(f"nmap -sn -iL {tf} -oG live.gnmap; grep Up live.gnmap | cut -d' ' -f2 > live.txt")
    print(f"#    -> ok: live.txt now holds the responding hosts (used by every step below).\n")
    print(f"# 2) FAST port scan across all (masscan is faster for 480; nmap greppable for triage):")
    print(f"nmap -Pn -iL live.txt --top-ports 200 --open --min-rate 2000 -oG ports.gnmap")
    print(f"#    (or:  masscan -iL live.txt -p1-65535 --rate 5000 -oG ports.gnmap)")
    print(f"#    -> ok: ports.gnmap is written with each host's open ports — this is the file triage parses.\n")
    print(f"# 3) SMB sweep (null session + signing + OS, all hosts at once):")
    print(f"nxc smb live.txt > smb.txt ; nxc smb live.txt --shares -u '' -p '' >> smb.txt")
    print(f"nxc smb live.txt --gen-relay-list relay_targets.txt      # signing-OFF = relay candidates")
    print(f"#    -> ok: smb.txt captures names/OS/signing + any null-session shares; relay_targets.txt = relay list.\n")
    print(f"# 4) web + known-CVE sweep (pull web hosts, then httpx/nuclei):")
    print(f"grep -E '(80|443|8080|8443)/open' ports.gnmap | cut -d' ' -f2 > web.txt")
    print(f"httpx -l web.txt -title -tech-detect -sc -o web_httpx.txt")
    print(f"nuclei -l web.txt -severity critical,high -o nuclei.txt")
    print(f"#    -> ok: nuclei.txt lists any critical/high findings across the web hosts.\n")
    print(f"# 5) service/version on the open set (for CVE matching):")
    print(f"nmap -Pn -sCV -iL live.txt -oA services --open\n")
    print(f"# -> then:  python3 sweep.py triage --nmap ports.gnmap --nxc smb.txt")

elif arg == "triage":
    ng = opt("--nmap"); nxc = opt("--nxc"); rc = opt("--recce")
    if not ng and not rc:
        print("need --nmap ports.gnmap (from `sweep.py plan` step 2) or --recce recce-bridge.json "
              "(from `recce fieldkit-export`)"); sys.exit(1)
    # needs: --nmap = the greppable scan from `plan` step 2; --nxc (optional) = the SMB sweep from step 3;
    #        --recce (optional) = recce's enumeration + confirmed findings.
    hosts = {}   # ip -> {"name":.., "ports":set()}
    if ng:
        for line in open(ng):
            m = re.search(r"Host:\s+(\S+)\s+\(([^)]*)\)", line)
            if not m or "Ports:" not in line: continue
            ip, name = m.group(1), m.group(2)
            h = hosts.setdefault(ip, {"name": name, "ports": set()})
            for pm in re.finditer(r"(\d+)/open/", line):
                h["ports"].add(int(pm.group(1)))
    # fold in nxc null-session hits (optional)
    null_shares = set()
    if nxc:
        for line in open(nxc):
            if re.search(r"(READ|WRITE)", line) and "\\\\" in line or "Enumerated shares" in line:
                mm = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if mm: null_shares.add(mm.group(1))
    # fold in the recce bridge (optional): open ports + CONFIRMED findings per host.
    recce = {}   # ip -> {"os":.., "roles":[..], "findings":[..], "access":bool}
    SEVW = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    if rc:
        try:
            data = json.load(open(rc))
        except Exception as e:
            print(f"cannot read {rc}: {e}"); sys.exit(1)
        for e in data.get("hosts", []):
            ip = e.get("ip")
            if not ip: continue
            h = hosts.setdefault(ip, {"name": e.get("hostname", ""), "ports": set()})
            if not h["name"]: h["name"] = e.get("hostname", "")
            for p in e.get("ports", []):
                if p.get("port"): h["ports"].add(int(p["port"]))
            if e.get("null_smb"): null_shares.add(ip)
            recce[ip] = {"os": e.get("os", ""), "roles": e.get("roles", []),
                         "findings": e.get("findings", []), "access": e.get("access_gained", False),
                         "exploit_cmds": e.get("exploit_cmds", []), "access_cmds": e.get("access_cmds", [])}
    # score each host = best (lowest) win among its ports; a recce-confirmed critical/high wins hard.
    rows = []
    for ip, h in hosts.items():
        wins = [(WINS[p][2], p, WINS[p]) for p in h["ports"] if p in WINS]
        wins.sort()
        rf = recce.get(ip, {}).get("findings", [])
        top_find = min((SEVW.get(f.get("severity", "info"), 5) for f in rf), default=9)
        if not wins and not rf:
            continue                                       # nothing actionable on this host
        base = wins[0][0] if wins else 3
        best = base - (1 if ip in null_shares else 0) - (2 if top_find <= 1 else 0)
        rows.append((best, ip, h["name"], wins, ip in null_shares, rf))
    rows.sort()
    src = " + ".join(x for x in [("nmap" if ng else ""), ("recce" if rc else "")] if x)
    print(f"# TRIAGE SCOREBOARD ({src}) — {len(hosts)} hosts, {len(rows)} with a quick-win. Focus top-down.\n")
    for score, ip, name, wins, nulls, rf in rows:
        tag = " [NULL-SESSION]" if nulls else ""
        if recce.get(ip, {}).get("access"): tag += " [ACCESS]"
        info = recce.get(ip, {})
        meta = " · ".join(x for x in [info.get("os", ""),
                                      ("roles: " + ", ".join(info["roles"])) if info.get("roles") else ""] if x)
        print(f"═══ {ip}  {('('+name+')') if name else ''}{tag}")
        if meta:
            print(f"    {'':<6}{'':<12}{meta}")
        for f in sorted(rf, key=lambda f: SEVW.get(f.get("severity", "info"), 5)):
            cves = (" — " + ", ".join(f["cves"])) if f.get("cves") else ""
            print(f"    {'CONFIRM':<6}{('['+f.get('severity','?').upper()+']'):<12}{f.get('title','')}{cves}")
        for _, p, (label, note, _j) in wins:
            print(f"    {p:<6}{label:<12}{note}")
        for e in info.get("exploit_cmds", []):
            cve = ("  # recce confirmed " + ", ".join(e["cves"])) if e.get("cves") else ""
            print(f"    {'ver→cve':<6}{'':<12}{e.get('cmd','')}{cve}")
        for c in info.get("access_cmds", []):
            print(f"    {'cred':<6}{'':<12}{c}")
    print(f"\n# -> ok: hosts are ranked top-down; the top rows are the exposed-RCE/unauth quick-wins to hit first.")
    print(f"# work the top of the list first (0=exposed-RCE/unauth, higher=needs-creds).")
    if rc:
        print(f"# CONFIRM lines = findings recce already PROVED — verify + exploit these first, then log -> report/.")
    print(f"# each line names the generator to run on that host. Log everything you confirm -> report/.")
else:
    print("use: plan --targets <file> | triage --nmap <ports.gnmap> [--nxc <smb.txt>]"); sys.exit(1)
