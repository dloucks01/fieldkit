#!/bin/sh
# ===================================================================================================
# Linux privesc TRIAGE — read-only. Run on the target foothold.
# It checks EVERY vector (not just the first). Each hit prints  ==> run <generator>  and is tallied
# in the FINDINGS SUMMARY at the bottom.  ONE WORKING VECTOR != DONE — for an assessment, document ALL.
# Exploit the SAFEST first (token/misconfig can't crash the box; kernel CVEs can) — but enumerate everything.
# ===================================================================================================
FOUND=""
note(){ echo "  ==> $1"; FOUND="$FOUND
  - $1"; }

echo "===== WHOAMI / CONTEXT ====="; id; echo "groups: $(groups)"; hostname; uname -a; cat /etc/os-release 2>/dev/null | head -2
echo "--- staging: writable+exec dir? (/tmp noexec breaks .so/.ko/compiled-PoC) ---"
mount 2>/dev/null | grep -E ' /tmp | /dev/shm | /var/tmp ' | grep noexec && note "noexec mount above: pass --stagedir <exec dir> (try /var/tmp or \$HOME) to gen_preload/gen_exploit/gen_misc, or set STAGE in _linpriv_common.py"
echo "--- shell for revshell: bash+/dev/tcp present? (else use --revtype mkfifo|python|perl|nc) ---"
{ [ -x /bin/bash ] && echo "  bash: yes (default --revtype bash ok)"; } || echo "  bash MISSING -> --revtype python|perl|mkfifo|nc"

echo "\n===== [BUCKET 1] token/misconfig (safest to exploit — check + record ALL) ====="
echo "--- sudo -l (the #1 check) ---"
SUDO="$(sudo -n -l 2>/dev/null)"; if [ -n "$SUDO" ]; then echo "$SUDO"; else echo "  (needs a password / not allowed)"; fi
echo "$SUDO" | grep -qi 'LD_PRELOAD'        && note "sudo env_keep LD_PRELOAD: gen_preload.py --mode ldpreload"
echo "$SUDO" | grep -qi 'LD_LIBRARY_PATH'   && note "sudo env_keep LD_LIBRARY_PATH: gen_preload.py --mode ldlib"
echo "$SUDO" | grep -qiE 'sudoedit|sudo -e' && note "sudoedit rule: SUDO_TRICKS sudoedit_cve_2023_22809 (if sudo<=1.9.12p1)"
echo "$SUDO" | grep -qi '(ALL, !root)'      && note "Runas excludes root: SUDO_TRICKS runas_neg1 (sudo -u#-1 ...)"
[ -n "$SUDO" ]                              && note "any allowed binary: gtfo.py --scan \"\$(sudo -l)\"  (sudo form)"

echo "--- SUID binaries (cross-ref EACH, not just one) ---"; find / -perm -4000 -type f 2>/dev/null
[ -n "$(find / -perm -4000 -type f 2>/dev/null)" ] && note "SUID present: gtfo.py <name> for each non-default one (suid form)"
echo "--- SGID binaries ---"; find / -perm -2000 -type f 2>/dev/null | head -30
echo "--- capabilities (getcap) ---"; CAPS="$(getcap -r / 2>/dev/null)"; echo "$CAPS"
[ -n "$CAPS" ] && note "capabilities set: gtfo.py --caps (map EACH: setuid/dac_read/sys_admin/sys_module...)"
echo "--- interesting groups ---"; G=$(id | grep -oE 'docker|lxd|disk|adm|wheel|sudo')
echo "$G"; echo "$G" | grep -qE 'docker|lxd' && note "docker/lxd group == instant root: gtfo.py docker"
echo "$G" | grep -qw disk && note "disk group: read/write the raw block device -> dump/edit any file"
echo "--- world-writable sensitive files ---"; ls -l /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null
[ -w /etc/passwd ]  && note "/etc/passwd WRITABLE: append a UID-0 line -> su"
[ -w /etc/shadow ]  && note "/etc/shadow WRITABLE/readable: crack or blank root"
[ -w /etc/ld.so.preload ] && note "/etc/ld.so.preload WRITABLE: gen_preload.py --mode globalpreload"
[ -w /etc/sudoers.d ] && note "/etc/sudoers.d WRITABLE: gen_misc.py sudoersd"

echo "\n===== misconfig actioning (writable units/cron/motd — record EACH) ====="
cat /etc/crontab 2>/dev/null; ls -la /etc/cron.* 2>/dev/null | grep -v '^d'
systemctl list-timers --all 2>/dev/null | head -10
WCRON="$(find /etc/cron* /etc/update-motd.d /etc/systemd/system -writable -type f 2>/dev/null)"
[ -n "$WCRON" ] && { echo "writable scheduled/motd/unit files:"; echo "$WCRON"; note "writable cron/motd/unit: gen_misc.py cron|motd|systemd (per file above)"; }
find / -writable -type f 2>/dev/null | grep -E '\.sh$|/opt/|/usr/local/' | grep -v '^/proc' | head -20
note "also check: a root job doing '<tar/chown/rsync> *' -> gen_misc.py wildcard ; pspy to see root cron: gen_recon.py pspy --fetch"

echo "\n===== [BUCKET 2] kernel/service versions (LAST resort — a wrong exploit panics the box) ====="
echo "kernel : $(uname -r)   <-- dirtypipe 5.8-5.16 | dirtycow <4.8 | overlayfs 5.x | nf_tables 5.14-6.6 | msqueue 2.6-5.11 | stackrot 6.1-6.4"
echo "sudo   : $(sudo --version 2>/dev/null | head -1)   <-- baron 1.8.2-1.9.5p1 | runas-neg1 <1.8.28"
echo "pkexec : $(pkexec --version 2>/dev/null)   <-- pwnkit <0.120"
echo "glibc  : $(ldd --version 2>/dev/null | head -1)   <-- looney 2.34+"
echo "userns : clone=$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null) max=$(cat /proc/sys/user/max_user_namespaces 2>/dev/null)   <-- nftables/netfilter/msqueue/stackrot need it"
note "version-match a CVE: gen_exploit.py list  (exploit AFTER exhausting bucket 1)"

echo "\n===== creds / loot (a reused cred is its own finding) ====="
ls -la ~/.ssh 2>/dev/null; find / -name 'id_rsa' 2>/dev/null | head
grep -rIE 'password|passwd|secret|api[_-]?key' /var/www /opt /home 2>/dev/null | head -15
note "full sweep: gen_loot.py  |  exhaustive: gen_recon.py linpeas --fetch"

echo "\n===== NETWORK / ROUTING (this host) ====="
echo "--- interfaces ---"; { ip -brief -4 addr 2>/dev/null || ifconfig -a 2>/dev/null; } | sed 's/^/  /'
echo "--- routing table (gateways + the segments this host can reach) ---"
{ ip route 2>/dev/null || netstat -rn 2>/dev/null || route -n 2>/dev/null; } | sed 's/^/  /'
DGW="$(ip route 2>/dev/null | awk '/^default/{print $3; exit}')"; [ -n "$DGW" ] && echo "  default gateway: $DGW"
[ "$(ip -o -4 addr show 2>/dev/null | grep -vc ' lo ')" -gt 1 ] 2>/dev/null && note "MULTIPLE interfaces/subnets -> this host is a PIVOT into another segment (see routes above)"
echo "\n# --- machine block (recce folds this into its reachability + architecture map) ---"
echo "==== NETWORK ===="
if command -v ip >/dev/null 2>&1; then
  ip -o -4 addr show 2>/dev/null | awk '{print "NET-IFACE "$2" "$4}'
  ip -o route 2>/dev/null | awk '{d=$1;g="";v="";for(i=1;i<=NF;i++){if($i=="via")g=$(i+1);if($i=="dev")v=$(i+1)}printf "NET-ROUTE %s",d;if(g!="")printf " via %s",g;if(v!="")printf " dev %s",v;print ""}'
  ip -o neigh 2>/dev/null | awk '/lladdr/{print "NET-NEIGH "$1" "$5}'
else
  ifconfig -a 2>/dev/null | awk '/inet .*netmask/{print "NET-IFACE if "$2"/24  # prefix approx (no ip(8))"}'
  netstat -rn 2>/dev/null | awk 'NR>2 && $1 ~ /^[0-9]/{print "NET-ROUTE "$1" via "$2}'
  arp -an 2>/dev/null | awk '{gsub(/[()]/,"",$2); if($2 ~ /^[0-9]/)print "NET-NEIGH "$2}'
fi
if command -v ss >/dev/null 2>&1; then
  ss -tan 2>/dev/null | awk '/ESTAB/{print "NET-PEER "$5}'
else
  netstat -tan 2>/dev/null | awk '/ESTABLISHED/{print "NET-PEER "$5}'
fi
echo "==== END NETWORK ===="

echo "\n===================================================================================="
echo "===== FINDINGS SUMMARY — EVERY line below is a SEPARATE privesc vector ====="
echo "===================================================================================="
echo "ONE WORKING VECTOR != DONE. Exploit the safest first (token/misconfig > kernel CVE),"
echo "but for the assessment DOCUMENT ALL of these. After you're root, re-run to catch the rest."
if [ -n "$FOUND" ]; then printf "%s\n" "$FOUND"; else echo "  (nothing from fast triage — run gen_recon.py linpeas for the deep sweep)"; fi
echo "\n(full route picker + variants: CHEATSHEET.md)"
