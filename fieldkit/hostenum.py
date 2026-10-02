"""Host enumeration — read the box, structure what it says.

Escalation is only as good as the enumeration under it. This module runs the same
checks the v1 ``enum.sh`` / ``enum.bat`` printed, but now it *executes* them through
the read-only executor (so every check is captured evidence) and *parses* the output
into a :class:`HostFacts` the privesc predicates match against — the ``whoami /priv``
→ route mapping the v1 batch file did by eye, done in code.

Two halves:

  * :data:`ENUM_PLAN` + :func:`run_enum` — the per-OS command set, executed and
    captured (all ``read-only``: nothing here changes the target);
  * :func:`facts_for` — reparse a host's captured enum steps into structured facts,
    so detection reads a :class:`HostFacts`, never raw text.

Facts are derived from the ``step`` evidence, not stored separately: the captured
output is the single source of truth, and re-enumerating simply overwrites it.
"""
import re
from dataclasses import dataclass, field

from .executor import Action, execute

WINDOWS, LINUX = "windows", "linux"


@dataclass(frozen=True)
class EnumCheck:
    category: str
    command: str
    shell: str = None


#: The checks per OS. Every one is read-only. Kept lean and high-signal — the exact
#: inputs the privesc predicates need, not a linpeas-scale dump.
ENUM_PLAN = {
    LINUX: (
        EnumCheck("id", "id"),
        EnumCheck("sudo", "sudo -n -l 2>/dev/null"),   # -n: never prompt, never hang
        EnumCheck("suid", "find / -perm -4000 -type f 2>/dev/null"),
        EnumCheck("caps", "getcap -r / 2>/dev/null"),
        EnumCheck("kernel", "uname -a"),
        # component versions the kernel/local-LPE matcher gates on — several staged PoCs
        # target sudo/polkit/glibc, not the kernel, so matching on `uname` alone would be
        # guessing. All three are read-only version prints (`-V`/`--version` never prompt).
        EnumCheck("versions", "sudo -V 2>/dev/null | head -1; "
                              "pkexec --version 2>/dev/null | head -1; "
                              "ldd --version 2>/dev/null | head -1"),
        # Container context: is this foothold inside a container, and if so
        # what escape-relevant sockets/tokens are reachable? All three probes
        # are read-only file checks with defensive `2>/dev/null` so a bare-
        # metal host produces empty output rather than errors.
        EnumCheck("container",
                  "test -e /.dockerenv && echo 'FK-DOCKERENV'; "
                  "test -e /run/.containerenv && echo 'FK-CONTAINERENV'; "
                  "grep -qE 'docker|containerd|kubepods|/lxc/|/machine.slice/' "
                  "  /proc/1/cgroup 2>/dev/null && echo 'FK-CGROUP-CONTAINER'; "
                  "test -w /var/run/docker.sock && echo 'FK-DOCKER-SOCK'; "
                  "test -r /var/run/secrets/kubernetes.io/serviceaccount/token "
                  "  && echo 'FK-K8S-TOKEN'; "
                  # cgroup v1: memory/pids/cpu controllers appear as subdirs.
                  # cgroup v2 has a single unified hierarchy with cgroup.controllers.
                  "test -d /sys/fs/cgroup/memory && echo 'FK-CGROUP-V1'; "
                  # hostPID: /proc/1 is a well-known host init, not a container init.
                  "read comm < /proc/1/comm 2>/dev/null && "
                  "  case \"$comm\" in systemd|init|systemd-init) "
                  "    echo 'FK-HOSTPID' ;; esac; "
                  # hostNetwork: host-only interfaces (docker0, cni*, br-*,
                  # flannel*, weave*, cali*, tunl*) inside a container mean
                  # the network namespace is shared with the host.
                  "ls /sys/class/net 2>/dev/null | grep -qE "
                  "  '^(docker0|cni|flannel|br-|weave|cali|tunl)' "
                  "  && echo 'FK-HOSTNETWORK'"),
        # Hygiene / writable-config scan (axis 1). One SSH round-trip gathers
        # five independent privesc / persistence primitives: each `test -w`
        # tag emits a known marker so :func:`_p_hygiene` can set the right
        # fact without ambiguity. Expensive directory walks (sudoers.d /
        # pam / udev / systemd user units) are capped at 1 level + 20 hits
        # so a weird / huge /etc doesn't stall the shell.
        EnumCheck("hygiene",
                  "test -w /etc/ld.so.preload && echo 'FK-LDSP-WRITE'; "
                  "test -w /etc/passwd && echo 'FK-PASSWD-WRITE'; "
                  "find /etc/sudoers.d -maxdepth 1 -type f -writable 2>/dev/null "
                  "  | head -20 | sed 's/^/FK-SUDOERSD /'; "
                  "find /lib/x86_64-linux-gnu/security /lib/security "
                  "     /usr/lib/x86_64-linux-gnu/security /usr/lib/security "
                  "     -maxdepth 1 -type f -writable 2>/dev/null "
                  "  | head -20 | sed 's/^/FK-PAM /'; "
                  "find /etc/udev/rules.d /lib/udev/rules.d "
                  "     -maxdepth 1 -type f -writable 2>/dev/null "
                  "  | head -20 | sed 's/^/FK-UDEV /'; "
                  "find \"$HOME/.config/systemd/user\" -maxdepth 2 -type f -writable "
                  "     \\( -name '*.service' -o -name '*.timer' \\) 2>/dev/null "
                  "  | head -20 | sed 's/^/FK-SYSD-USER /'"),
        # Cloud-SDK token hunt (axis 1 — cred loot). Walks the standard
        # per-user caches that most CLI tooling drops long-lived tokens into.
        # Each hit emits ``FK-TOKEN <provider> <path>`` for the parser to
        # route into facts.cloud_sdk_tokens. Terraform / Jenkins are called
        # out separately because their paths are less user-local.
        EnumCheck("cloud_tokens",
                  "for p in \"$HOME/.docker/config.json\" "
                  "         \"$HOME/.kube/config\" "
                  "         \"$HOME/.aws/credentials\" "
                  "         \"$HOME/.aws/config\" "
                  "         \"$HOME/.config/gcloud/application_default_credentials.json\" "
                  "         \"$HOME/.config/doctl/config.yaml\" "
                  "         \"$HOME/.azure/accessTokens.json\"; do "
                  "  [ -r \"$p\" ] && echo \"FK-TOKEN $p\"; "
                  "done; "
                  "[ -d \"$HOME/.aws/sso/cache\" ] && ls \"$HOME/.aws/sso/cache\" 2>/dev/null "
                  "  | sed \"s|^|FK-TOKEN $HOME/.aws/sso/cache/|\"; "
                  "find / -maxdepth 5 -type f -name '*.tfstate' -readable 2>/dev/null "
                  "  | head -10 | sed 's/^/FK-TFSTATE /'; "
                  "find /var/lib/jenkins /var/jenkins_home /home/jenkins "
                  "     -maxdepth 3 -type f -name 'credentials.xml' -readable 2>/dev/null "
                  "  | head -5 | sed 's/^/FK-JENKINS /'"),
        # SSH-env / lateral primitives (axis 1 — lateral movement). Captures
        # SSH_AUTH_SOCK (agent hijack), writable foreign authorized_keys
        # (key-plant lateral), ControlMaster sockets (session hijack), and
        # the user's known_hosts (lateral-target enumeration).
        EnumCheck("ssh_env",
                  "[ -S \"$SSH_AUTH_SOCK\" ] && [ -r \"$SSH_AUTH_SOCK\" ] "
                  "  && echo 'FK-SSHAGENT'; "
                  "for ak in /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys; do "
                  "  [ -w \"$ak\" ] && echo \"FK-AUTHKEYS $ak\"; "
                  "done; "
                  "ls ~/.ssh/control-* 2>/dev/null | sed 's/^/FK-CONTROLPATH /'; "
                  "[ -r \"$HOME/.ssh/known_hosts\" ] "
                  "  && awk -F'[ ,]' '/^[^#|]/{print \"FK-KNOWNHOST \" $1}' "
                  "       \"$HOME/.ssh/known_hosts\" 2>/dev/null | head -30"),
        # Browser-profile discovery (axis 1 slice 2 — loot). Enumerates
        # Chrome/Chromium/Edge profile dirs + Firefox profile dirs under
        # the foothold user's home. Each hit emits ``FK-CHROME <path>`` or
        # ``FK-FIREFOX <path>``; parser routes into facts.chrome_profiles
        # / facts.firefox_profiles for the per-browser loot TTPs.
        EnumCheck("browsers",
                  "for d in \"$HOME/.config/google-chrome\" "
                  "         \"$HOME/.config/chromium\" "
                  "         \"$HOME/.config/microsoft-edge\" "
                  "         \"$HOME/.config/BraveSoftware/Brave-Browser\"; do "
                  "  [ -d \"$d\" ] && find \"$d\" -maxdepth 2 -type f "
                  "    -name 'Login Data' 2>/dev/null "
                  "    | head -5 | sed 's/^/FK-CHROME /'; "
                  "done; "
                  "find \"$HOME/.mozilla/firefox\" -maxdepth 2 -type f "
                  "  -name 'key4.db' 2>/dev/null "
                  "  | head -5 | sed 's/^/FK-FIREFOX /'"),
        # Process-capability + privileged-container-escape primitives (axis
        # 1 slice 2 — container escape depth). CapEff is a hex bitmask —
        # the parser decodes it to a lowercase-cap-name set. Also tests the
        # writable-uevent-helper primitive (write a path, trigger a uevent,
        # kernel runs it as root).
        EnumCheck("proc_caps",
                  "grep -E '^CapEff:' /proc/self/status 2>/dev/null; "
                  "test -w /sys/kernel/uevent_helper && echo 'FK-UEVENT-WRITE'"),
        # NFS lateral surface (axis 1 slice 2). Mounted remote filesystems
        # the foothold already uses + any readable /etc/exports listing
        # exports we can bind-mount from a sibling box with the right UID.
        EnumCheck("nfs_env",
                  "awk '$3==\"nfs\" || $3==\"nfs4\"{print \"FK-NFS-MOUNT \" $1 \" \" $2}' "
                  "   /proc/mounts 2>/dev/null | head -20; "
                  "[ -r /etc/exports ] && grep -v '^#' /etc/exports 2>/dev/null "
                  "  | sed 's/^/FK-NFS-EXPORT /' | head -20"),
        # Desktop keyrings (slice 3). gnome-keyring and kwallet both expose the
        # whole password store once their user session is attached. Detection
        # is cheap — pgrep the daemon + D-Bus name probe.
        EnumCheck("keyrings",
                  "pgrep -ax gnome-keyring-daemon 2>/dev/null "
                  "  | awk 'NR==1{print \"FK-KEYRING gnome\"}'; "
                  "pgrep -ax kwalletd 2>/dev/null "
                  "  | awk 'NR==1{print \"FK-KEYRING kwallet\"}'; "
                  "pgrep -ax kwalletd5 2>/dev/null "
                  "  | awk 'NR==1{print \"FK-KEYRING kwallet\"}'"),
        # Writable release_agent (slice 3). cgroup v1 escape — write a path,
        # kernel runs it as root when the cgroup empties.
        EnumCheck("cgroup_v1_escape",
                  "for f in $(find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null); do "
                  "  if [ -w \"$f\" ]; then echo \"FK-RELEASE-AGENT $f\"; fi; done | head -5"),
        # at(1) spool writable (slice 3). Writing a job file schedules it as root.
        EnumCheck("at_spool",
                  "for d in /var/spool/cron/atjobs /var/spool/at /var/spool/atjobs; do "
                  "  if [ -w \"$d\" ]; then echo \"FK-AT-SPOOL $d\"; fi; done"),
        # X11 cookie (slice 3). ~/.Xauthority existing + non-empty is the pivot
        # into the user's live GUI session.
        EnumCheck("xauth",
                  "if [ -r \"$HOME/.Xauthority\" ] && [ -s \"$HOME/.Xauthority\" ]; then "
                  "  echo \"FK-XAUTH $HOME/.Xauthority\"; fi; "
                  "[ -r /tmp/xauth-$UID ] && echo \"FK-XAUTH /tmp/xauth-$UID\""),
        # sudo PATH preservation (slice 3). env_keep PATH, !secure_path, or a
        # relative command in a NOPASSWD rule — all leak execution to our PATH.
        EnumCheck("sudo_path",
                  "sudo -n -l 2>/dev/null "
                  "  | grep -E 'env_keep.*PATH|!secure_path|^[[:space:]]*\\([^)]+\\)[[:space:]]+NOPASSWD.*[[:space:]][^/]' "
                  "  | sed 's/^/FK-SUDO-PATH /'"),
        # ~/.ssh/rc (slice 3). Classic persistence slot.
        EnumCheck("ssh_rc",
                  "if [ -w \"$HOME/.ssh/rc\" ] 2>/dev/null; then "
                  "  echo \"FK-SSH-RC $HOME/.ssh/rc\"; fi; "
                  "if [ -d \"$HOME/.ssh\" ] && [ -w \"$HOME/.ssh\" ] "
                  "  && [ ! -e \"$HOME/.ssh/rc\" ]; then "
                  "  echo \"FK-SSH-RC-CREATE $HOME/.ssh/rc\"; fi"),
        # XDG autostart (slice 3). Writable .desktop in autostart = user-session persistence.
        EnumCheck("xdg_autostart",
                  "for d in \"$HOME/.config/autostart\" /etc/xdg/autostart "
                  "         /usr/share/gnome/autostart; do "
                  "  if [ -w \"$d\" ]; then echo \"FK-XDG-AUTOSTART-DIR $d\"; fi; "
                  "  for f in \"$d\"/*.desktop; do "
                  "    [ -w \"$f\" ] 2>/dev/null && echo \"FK-XDG-AUTOSTART-FILE $f\"; "
                  "  done; done 2>/dev/null | head -20"),
        # Shell-init of OTHER users (slice 3). ~/.bashrc / ~/.zshrc of a
        # higher-value account writable by our UID = next-login hijack.
        EnumCheck("shell_init",
                  "for u in $(getent passwd 2>/dev/null | awk -F: '$3>=1000 && $3<70000 {print $6}'); do "
                  "  for f in \"$u/.bashrc\" \"$u/.profile\" \"$u/.bash_profile\" \"$u/.zshrc\"; do "
                  "    [ -w \"$f\" ] 2>/dev/null && echo \"FK-SHELL-INIT $f\"; "
                  "  done; done | head -20"),
        # User crontabs writable (slice 3). /var/spool/cron/crontabs with
        # loose perms (common on dev boxes / fresh builds).
        EnumCheck("user_crontabs",
                  "for d in /var/spool/cron/crontabs /var/spool/cron; do "
                  "  for f in \"$d\"/*; do "
                  "    [ -w \"$f\" ] 2>/dev/null && echo \"FK-USER-CRONTAB $(basename $f):$f\"; "
                  "  done; done 2>/dev/null | head -10"),
        # SUID /proc/<pid>/environ readable (slice 3). Captures env secrets
        # the parent shell passed to the setuid binary.
        EnumCheck("suid_environ",
                  "for p in $(ls -d /proc/[0-9]* 2>/dev/null); do "
                  "  exe=$(readlink \"$p/exe\" 2>/dev/null); "
                  "  if [ -n \"$exe\" ] && [ -u \"$exe\" ] && [ -r \"$p/environ\" ]; then "
                  "    echo \"FK-SUID-ENVIRON $(basename $p):$exe\"; "
                  "  fi; done | head -10"),
        # Slice 4 — SysV init writable (legacy persist slot, still present on
        # CentOS 7, Oracle Linux, several appliances via systemd-sysv-compat).
        EnumCheck("sysv_init",
                  "for f in /etc/init.d/* /etc/rc.d/init.d/* 2>/dev/null; do "
                  "  [ -w \"$f\" ] 2>/dev/null && echo \"FK-SYSV-INIT $f\"; "
                  "done | head -20"),
        # Slice 4 — writable systemd generator (pre-login root execution).
        EnumCheck("systemd_generators",
                  "for d in /lib/systemd/system-generators /usr/lib/systemd/system-generators "
                  "         /etc/systemd/system-generators /run/systemd/system-generators; do "
                  "  if [ -w \"$d\" ]; then echo \"FK-SYSTEMD-GENERATOR-DIR $d\"; fi; "
                  "  for f in \"$d\"/*; do "
                  "    [ -w \"$f\" ] 2>/dev/null && echo \"FK-SYSTEMD-GENERATOR-FILE $f\"; "
                  "  done; done 2>/dev/null | head -10"),
        # Slice 4 — NIS/LDAP centralized auth in use.
        EnumCheck("directory_auth",
                  "grep -E '^(passwd|group|shadow):.*\\b(nis|ldap|sss)\\b' /etc/nsswitch.conf 2>/dev/null "
                  "  | sed 's/^/FK-DIR-AUTH /'; "
                  "command -v ypcat >/dev/null 2>&1 "
                  "  && ypcat passwd 2>/dev/null | head -1 | sed 's/^/FK-NIS-PASSWD /'"),
        # Slice 6 — AWS SSO token cache (~/.aws/sso/cache/*.json)
        EnumCheck("aws_sso_cache",
                  "for f in $HOME/.aws/sso/cache/*.json; do "
                  "  [ -r \"$f\" ] && echo \"FK-AWS-SSO $f\"; "
                  "done 2>/dev/null | head -20"),
        # Slice 6 — D-Bus policies that allow broad principals privileged
        # method calls. Look for allow send_destination= on known
        # privileged interfaces, with user= specifying wide users.
        EnumCheck("dbus_policy",
                  "for f in /etc/dbus-1/system.d/*.conf /usr/share/dbus-1/system.d/*.conf; do "
                  "  [ -r \"$f\" ] || continue; "
                  "  awk 'BEGIN{p=0} /<policy context=\"default\"/{p=1} /<policy user=\"@(anyone|everyone)@\"/{p=1} "
                  "       p && /allow send_destination=/ {print FILENAME\":\"$0; p=0} '"
                  "       \"$f\" 2>/dev/null; "
                  "  grep -lE '<policy user=\"nobody\"|<policy context=\"default\".*allow' \"$f\" 2>/dev/null "
                  "    | sed 's/^/FK-DBUS-POLICY /'; "
                  "done | head -20"),
        # Slice 4 — cgroup v2 misconfig escape (the container's own cgroup is
        # writable at the cgroup.procs level, enabling host-cgroup pivot).
        EnumCheck("cgroup_v2_escape",
                  "if [ -r /proc/1/cgroup ] && grep -q '^0::' /proc/1/cgroup 2>/dev/null; then "
                  "  own=$(awk -F: '/^0::/{print $3}' /proc/self/cgroup 2>/dev/null); "
                  "  if [ -n \"$own\" ] && [ -w \"/sys/fs/cgroup$own/cgroup.procs\" ]; then "
                  "    echo \"FK-CGROUP-V2-DELEGATE $own\"; "
                  "  fi; "
                  "fi"),
    ),
    WINDOWS: (
        EnumCheck("priv", "whoami /priv"),
        EnumCheck("groups", "whoami /groups"),
        # OS build + installed hotfixes — feeds the Windows kernel-CVE matcher.
        # `systeminfo` prints OS Name, Version (build), Product ID and Install Date;
        # `wmic qfe get HotFixID` lists every KB installed. Both are read-only and
        # ship natively on every Windows build fieldkit targets.
        EnumCheck("sysinfo", "systeminfo"),
        EnumCheck("hotfixes", "wmic qfe get HotFixID /format:list"),
        EnumCheck("aie", 'reg query "HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer" '
                         '/v AlwaysInstallElevated & reg query "HKCU\\Software\\Policies\\'
                         'Microsoft\\Windows\\Installer" /v AlwaysInstallElevated'),
        EnumCheck("services", "wmic service get name,pathname,startmode"),
        # per-service: the security descriptor (reconfigurable?) + icacls on the binary
        # (overwritable?) and its directory (DLL-plantable?).
        EnumCheck("svcperms",
                  "Get-CimInstance Win32_Service|%{$n=$_.Name;$p=$_.PathName;"
                  "'SVC|'+$n+'|'+$p+'|'+((sc.exe sdshow $n)-join'');"
                  "$i=$p.ToLower().IndexOf('.exe');if($i -gt 0){"
                  "$e=$p.Substring(0,$i+4).Trim('\"');"
                  "'ACL|'+$n+'|'+$e+'|'+((icacls $e 2>$null)-join';');"
                  "$d=Split-Path $e;'DIR|'+$n+'|'+$d+'|'+((icacls $d 2>$null)-join';')}}",
                  shell="powershell"),
    ),
}


@dataclass
class HostFacts:
    """Structured enumeration of one host. Empty fields = not enumerated / not present."""

    os: str = None
    # -- linux --
    user: str = None
    uid: int = None
    groups: set = field(default_factory=set)
    sudo_all: bool = False               # sudo -l grants full root
    sudo_nopasswd: bool = False
    sudo_binaries: set = field(default_factory=set)   # basenames allowed via sudo
    sudo_env_keep: set = field(default_factory=set)    # LD_PRELOAD / LD_LIBRARY_PATH kept
    suid: set = field(default_factory=set)             # basenames of SUID files
    caps: dict = field(default_factory=dict)           # binary basename -> capability
    kernel: str = None                                 # version, e.g. "5.15.0"
    sudo_version: str = None                           # e.g. "1.8.31"   (CVE-2021-3156)
    pkexec_version: str = None                         # polkit, e.g. "0.105" (CVE-2021-4034)
    glibc_version: str = None                          # e.g. "2.35"     (CVE-2023-4911)
    #: Product name (canonicalized, lowercase, single-word) → version string
    #: for services running on / discovered on this host. Populated by
    #: :func:`facts_for` from the ``service`` table — recce's bridge ingest
    #: is the main source. Enables version-gated TTPs via the version_range
    #: predicate's dotted-path form (``services.apache``, ``services.openssh``).
    services: dict = field(default_factory=dict)
    #: True when the store has BloodHound graph data ingested AND at
    #: least one owned credential reaches a high-value target via the
    #: control edges the graph knows about. Populated by
    #: :func:`facts_for` via a lazy call to
    #: :func:`fieldkit.bloodhound.owned_paths`. Zero-cost when no graph
    #: is loaded (bloodhound.owned_paths returns [] fast when bh_node
    #: is empty). Feeds the `adroute:bh-owned-to-hv-path` TTP so
    #: analyze / escalate surface the finding without the operator
    #: having to open the BloodHound UI.
    bh_owned_reaches_hv: bool = False
    # -- linux · container context --
    #: `True` when the foothold is inside a container (docker / podman / k8s
    #: pod). Detected by the presence of /.dockerenv, /run/.containerenv, or
    #: `container:...` scope in /proc/1/cgroup. Container-escape TTPs gate on
    #: this so they don't misfire on a host that just happens to have docker
    #: installed. Ships as of Phase B5b.
    in_container: bool = False
    #: `True` when /var/run/docker.sock is readable+writable inside the
    #: container — one of the standard "escape via docker.sock" primitives.
    has_docker_sock: bool = False
    #: `True` when /var/run/secrets/kubernetes.io/serviceaccount/token
    #: exists — the pod is running with a mounted k8s service account.
    has_k8s_token: bool = False
    #: `True` when this host uses cgroup v1 (has /sys/fs/cgroup/memory or
    #: similar controller subdirs). Relevant to the release_agent escape
    #: which cgroup v2 patched out — v1 hosts remain exploitable.
    cgroup_v1: bool = False
    #: `True` when the container shares its PID namespace with the host,
    #: detected by /proc/1/comm being a well-known host init (systemd,
    #: init) rather than a container init (sh, pause, tini). Combined
    #: with root inside the container this enables nsenter-into-host.
    hostpid_visible: bool = False
    #: `True` when the container/pod shares the host's network namespace
    #: (`docker run --network=host` / k8s `hostNetwork: true`). Detected
    #: by the presence of host-only interface names (docker0, cni*,
    #: flannel*, br-*, weave, cali*, tunl*) inside the container — a
    #: normal container sees only lo + eth0. With hostNetwork the pod
    #: can sniff the node's traffic, hit localhost-bound services on the
    #: node (kubelet's 10248/10250), and reach cluster peers.
    has_hostnetwork: bool = False
    # -- linux · hygiene / writable-config primitives (axis 1) --
    #: ``True`` when ``/etc/ld.so.preload`` is writable by the foothold user —
    #: a one-line write there injects a shared library into every subsequent
    #: process on the box, root included. Root-equivalent LPE on next sudo.
    writable_ld_so_preload: bool = False
    #: ``True`` when ``/etc/passwd`` is writable — the classic "append a UID-0
    #: line with a known pass hash" primitive. Still happens on hardened
    #: appliances / NAS boxes with permissive defaults.
    writable_passwd: bool = False
    #: Writable paths under ``/etc/sudoers.d/`` the foothold can edit → add
    #: your own ``NOPASSWD: ALL`` entry. More subtle than writing /etc/passwd
    #: because sudoers.d is designed to be modular.
    writable_sudoers_d: list = field(default_factory=list)
    #: Writable PAM module paths (``pam_exec.so`` dropped into ``/lib/x86_64-
    #: linux-gnu/security/`` or similar) → every ``sudo`` / ``su`` / ``sshd``
    #: login runs the attacker command. Persistence primitive.
    writable_pam_modules: list = field(default_factory=list)
    #: Writable udev rule paths (``/etc/udev/rules.d/*.rules``) → persistence
    #: that triggers on hardware events (USB plug, device load).
    writable_udev_rules: list = field(default_factory=list)
    #: Writable per-user systemd unit paths (``~/.config/systemd/user/*``) →
    #: persistence surviving reboot without needing root.
    writable_systemd_user_units: list = field(default_factory=list)
    # -- linux · credential loot (axis 1) --
    #: ``True`` when ``$SSH_AUTH_SOCK`` is set + the socket is readable, so
    #: the foothold can hijack the agent (``ssh-add -L``, use for new
    #: outbound auths) without ever seeing the private key.
    ssh_agent_sock_hijackable: bool = False
    #: Readable cloud-SDK credential paths by provider (``docker`` →
    #: ``~/.docker/config.json``, ``kubectl`` → ``~/.kube/config``, ``aws``
    #: → ``~/.aws/sso/cache/*``, …). Each is a credential that typically
    #: outranks the foothold user's shell privs.
    cloud_sdk_tokens: dict = field(default_factory=dict)
    #: Terraform state files discovered — frequent source of long-lived
    #: cloud secrets left in cleartext under ``outputs`` or ``resources``.
    terraform_states: list = field(default_factory=list)
    #: Jenkins ``credentials.xml`` paths — contain encrypted creds + the
    #: master key sits beside them (``master.key`` + ``hudson.util.
    #: Secret``) so decryption is a local-only operation.
    jenkins_credentials: list = field(default_factory=list)
    # -- linux · lateral movement (axis 1) --
    #: Other-user ``~/.ssh/authorized_keys`` files writable by the current
    #: user — write our pubkey, SSH in as that user, chain further.
    writable_authorized_keys: list = field(default_factory=list)
    #: Hosts referenced in the foothold user's SSH ``known_hosts`` + each
    #: user's private-key existence (``~/.ssh/id_*``). Feeds a key-reuse
    #: map: a key that unlocks these hosts likely unlocks more.
    ssh_known_hosts: list = field(default_factory=list)
    #: Active SSH ``ControlMaster`` sockets (``~/.ssh/control-*``) — any
    #: process using the same control path piggybacks on an authenticated
    #: session WITHOUT re-authing (no password, no key prompt). Hijacks a
    #: logged-in session.
    ssh_controlpath_sockets: list = field(default_factory=list)
    # -- linux · browser profiles (axis 1 slice 2) --
    #: Chrome / Chromium profile paths (``~/.config/google-chrome/<profile>``,
    #: ``~/.config/chromium/<profile>``). Each profile owns a Login Data
    #: SQLite + a Local State master-key — read both to decrypt saved logins
    #: + cookies offline. The dedicated loot:chrome-browser TTP walks the
    #: profiles and prints key material location.
    chrome_profiles: list = field(default_factory=list)
    #: Firefox profile paths (``~/.mozilla/firefox/<profile>.default*``).
    #: logins.json carries encrypted passwords; key4.db stores the master
    #: key. Both-together → cleartext passwords via libnss offline.
    firefox_profiles: list = field(default_factory=list)
    # -- linux · process capabilities (container-escape gating) --
    #: Effective capabilities on THIS process (parsed from
    #: ``/proc/self/status`` ``CapEff``). Distinct from ``facts.caps``,
    #: which lists binary → cap set — container escapes need the current
    #: process's permission set, not binaries'. Cap names in lowercase
    #: without the ``cap_`` prefix for terseness (``sys_admin``,
    #: ``dac_read_search``, ``sys_ptrace``, ``sys_module``).
    proc_capabilities: set = field(default_factory=set)
    #: ``/sys/kernel/uevent_helper`` writable — kernel invokes it as root
    #: on every uevent (device insert / remove / rebind). Container escape
    #: with no coerce step.
    writable_uevent_helper: bool = False
    # -- linux · lateral: NFS pivot --
    #: NFS mount paths discoverable from the foothold (readable
    #: ``/etc/exports`` + mounted remote filesystems). Each entry is a
    #: ``server:/path`` string. Pivot via NFS: mount, drop a setuid root
    #: binary, trigger it from the exporting server.
    nfs_mountable: list = field(default_factory=list)
    # -- linux slice-3 extensions --
    #: Desktop keyring daemons running / sockets reachable. Values are
    #: short tokens: ``gnome`` (gnome-keyring-daemon), ``kwallet``,
    #: ``secret-service`` (D-Bus org.freedesktop.secrets). Any of them
    #: present is a loot primitive — the keyring stores every password
    #: a GUI app ever saved.
    desktop_keyrings: list = field(default_factory=list)
    #: ``/sys/fs/cgroup/.../release_agent`` on a container's own cgroup is
    #: writable (classic cgroup v1 escape). Kernel runs the path as root
    #: when the last task leaves the cgroup. cgroup v2 removed this —
    #: the field stays False on v2-only hosts.
    writable_release_agent: bool = False
    #: ``/var/spool/cron/atjobs`` or ``/var/spool/at/`` writable by the
    #: current UID — writing an at(1) job file schedules it as root.
    at_spool_writable: bool = False
    #: ``~/.Xauthority`` cookie path readable + non-empty, meaning the X11
    #: cookie that other users' sessions trust. Pivot lets us ``xdotool``
    #: and screenshot another user's live session.
    xauth_cookie_present: bool = False
    #: ``sudo -l`` output declares ``env_keep += PATH`` or ``!secure_path``
    #: or uses a relative command — any one of which lets the operator
    #: hijack ``PATH`` and land arbitrary code as the sudo target.
    sudo_preserves_path: bool = False
    #: ``~/.ssh/rc`` writable + readable (per-user SSH login hook; runs
    #: on every ssh-in with the user's shell). Classic persistence slot
    #: that most hunting tools miss because it isn't in ``~/.bashrc``.
    writable_ssh_rc: bool = False
    #: XDG autostart dirs with user-writable ``.desktop`` entries —
    #: ``~/.config/autostart``, ``/etc/xdg/autostart``, GNOME's
    #: ``/usr/share/gnome/autostart``. GUI-session persistence.
    writable_xdg_autostart: list = field(default_factory=list)
    #: Shell-init files owned by other users that we can WRITE to
    #: (``.bashrc`` / ``.profile`` / ``.bash_profile`` / ``.zshrc`` of a
    #: higher-value account). Classic shell-init hijack for lateral/esc
    #: pivot — the target's next login runs our code.
    writable_shell_init: list = field(default_factory=list)
    #: Per-user crontab path writable by the current UID (e.g. a stale
    #: ``/var/spool/cron/crontabs/root`` with loose perms). Each entry
    #: is a ``user:path`` tuple surfaced by enum.
    writable_user_crontabs: list = field(default_factory=list)
    #: SUID binaries whose running process we can READ /proc/<pid>/environ
    #: for — captures secrets the parent passed as environment variables
    #: (DB passwords, API keys set by a shell wrapper around a setuid).
    readable_suid_proc_environ: list = field(default_factory=list)
    # -- linux slice 4 — axis-1 finish --
    #: Writable scripts under /etc/init.d (SysV init). On SysV-style
    #: boots or systemd-sysv-compat hosts, these run as root on service
    #: start — classic persistence slot that still exists on CentOS 7,
    #: Oracle Linux, several appliance OSes.
    writable_sysv_init: list = field(default_factory=list)
    #: Writable systemd generator binaries / dirs
    #: (``/lib/systemd/system-generators``, ``/etc/systemd/system-generators``
    #: etc). systemd runs generators at EVERY boot before any unit — a
    #: writable generator is pre-login root execution.
    writable_systemd_generators: list = field(default_factory=list)
    #: NIS / LDAP centralized authentication is in use (``/etc/nsswitch.conf``
    #: lists ``nis`` or ``ldap`` for passwd/group OR ``ypcat passwd`` works).
    #: Credential-reuse pivot — the same username/password pair likely
    #: reaches every host that joins the same directory.
    nis_or_ldap_auth: bool = False
    #: cgroup v2 misconfig escape — the container's own cgroup directory
    #: is writable, enabling direct cgroup.procs manipulation to move a
    #: shell into the host cgroup namespace. Modern (post-release_agent)
    #: container escape class.
    writable_cgroup_delegate: bool = False
    # -- slice 6 — axis-1 tail --
    #: ``~/.aws/sso/cache`` directory containing short-lived SSO tokens
    #: for AWS. Each JSON file holds an accessToken that `aws sso login`
    #: minted; readable from the user's home + still-valid tokens are
    #: direct AWS console / API access.
    aws_sso_cache: list = field(default_factory=list)
    #: D-Bus system policy files declaring broad principals as having
    #: privileged method call rights. Entries look like
    #: ``policy_file:interface:method``; a readable + broad allow is a
    #: direct privesc channel to whatever the service does.
    dbus_broad_policies: list = field(default_factory=list)
    # -- windows --
    privs: set = field(default_factory=set)            # SeImpersonatePrivilege, ...
    win_groups: set = field(default_factory=set)        # Administrators, Backup Operators, ...
    always_install_elevated: bool = False
    unquoted_services: list = field(default_factory=list)  # (service_or_None, path)
    #: service name -> its raw binPath, for services whose ACL grants a broad principal
    #: SERVICE_CHANGE_CONFIG (reconfigure the binPath to a command that runs as SYSTEM).
    reconfigurable_services: dict = field(default_factory=dict)
    writable_service_bins: dict = field(default_factory=dict)   # name -> exe (overwritable)
    writable_service_dirs: dict = field(default_factory=dict)   # name -> dir (DLL-plantable)
    win_build: str = None                                       # e.g. "10.0.19045" (systeminfo)
    win_edition: str = None                                     # e.g. "Windows Server 2019 Datacenter"
    win_arch: str = None                                        # x64 | x86 | ARM
    hotfixes: set = field(default_factory=set)                  # {'KB5031364', ...}

    @property
    def is_root(self):
        return self.uid == 0

    # --- `has_*` convenience booleans so TTPs can write a one-liner
    # `facts_match: {has_X: true}` predicate instead of needing a new
    # per-list adapter rule. Each is cheap (truthiness of the backing
    # list / dict) and the strict-equality facts_match semantics work
    # with properties fine via getattr().
    @property
    def has_writable_sudoers_d(self):      return bool(self.writable_sudoers_d)
    @property
    def has_writable_pam_modules(self):    return bool(self.writable_pam_modules)
    @property
    def has_writable_udev_rules(self):     return bool(self.writable_udev_rules)
    @property
    def has_writable_systemd_user(self):   return bool(self.writable_systemd_user_units)
    @property
    def has_cloud_sdk_tokens(self):        return bool(self.cloud_sdk_tokens)
    @property
    def has_terraform_states(self):        return bool(self.terraform_states)
    @property
    def has_jenkins_credentials(self):     return bool(self.jenkins_credentials)
    @property
    def has_writable_authorized_keys(self): return bool(self.writable_authorized_keys)
    @property
    def has_ssh_controlpath_sockets(self): return bool(self.ssh_controlpath_sockets)
    @property
    def has_ssh_known_hosts(self):         return bool(self.ssh_known_hosts)
    @property
    def has_chrome_profiles(self):         return bool(self.chrome_profiles)
    @property
    def has_firefox_profiles(self):        return bool(self.firefox_profiles)
    @property
    def has_nfs_mountable(self):           return bool(self.nfs_mountable)
    @property
    def has_cap_sys_admin(self):           return "sys_admin" in self.proc_capabilities
    @property
    def has_cap_sys_module(self):          return "sys_module" in self.proc_capabilities
    @property
    def has_cap_sys_ptrace(self):          return "sys_ptrace" in self.proc_capabilities
    @property
    def has_cap_dac_read_search(self):     return "dac_read_search" in self.proc_capabilities
    @property
    def has_desktop_keyrings(self):        return bool(self.desktop_keyrings)
    @property
    def has_gnome_keyring(self):           return "gnome" in self.desktop_keyrings
    @property
    def has_kwallet(self):                 return "kwallet" in self.desktop_keyrings
    @property
    def has_writable_xdg_autostart(self):  return bool(self.writable_xdg_autostart)
    @property
    def has_writable_shell_init(self):     return bool(self.writable_shell_init)
    @property
    def has_writable_user_crontabs(self):  return bool(self.writable_user_crontabs)
    @property
    def has_readable_suid_proc_environ(self): return bool(self.readable_suid_proc_environ)
    @property
    def has_writable_sysv_init(self):       return bool(self.writable_sysv_init)
    @property
    def has_writable_systemd_generators(self): return bool(self.writable_systemd_generators)
    @property
    def has_aws_sso_cache(self):            return bool(self.aws_sso_cache)
    @property
    def has_dbus_broad_policies(self):      return bool(self.dbus_broad_policies)


# --------------------------------------------------------------------------- run

@dataclass
class EnumReport:
    host: str = None
    ran: list = field(default_factory=list)      # categories captured
    failed: list = field(default_factory=list)    # (category, reason)
    blocked: str = None                           # set if no transport / gated out entirely


def run_enum(store, host, cred, *, run=None, on_event=None, allow="read-only"):
    """Run the OS-appropriate enum on ``host`` as ``cred``, capturing each check.

    Returns an :class:`EnumReport`. A host with no known OS cannot be planned — spray
    it (its banner sets the OS) or set it with ``add hosts --os`` first.
    """
    report = EnumReport(host=host["ip"])
    plan = ENUM_PLAN.get(host["os"])
    if plan is None:
        report.blocked = (f"{host['ip']}: OS unknown — cannot pick an enum plan; "
                          "spray it or `add hosts --os windows|linux`")
        return report
    for check in plan:
        action = Action(host=host, cred=cred, command=check.command,
                        label=f"enum:{check.category}", safety="read-only",
                        shell=check.shell)
        res = execute(store, action, run=run, allow=allow, on_event=on_event)
        if res.blocked:
            # a check whose shell has no proven transport (e.g. the powershell svcperms
            # check over an MSSQL/xp_cmdshell-only foothold) is skipped, not fatal — other
            # checks still run. Only if nothing at all runs is it a real transport problem.
            report.failed.append((check.category, res.blocked))
            continue
        if res.ok:
            report.ran.append(check.category)
        else:
            report.failed.append((check.category, res.run.error if res.run else "no result"))
    # After the target-command enum, run the nxc-probe suite for Windows hosts —
    # ``--shares``, ``--loggedon-users``, ``--sessions``, ``-M laps``, ``-M gpp_password``.
    # These reveal facts nxc's exec transport can't (readable/writable shares, active
    # sessions on the remote host, LAPS passwords, GPP cpasswords in SYSVOL). Failures
    # are per-probe (an nxc-version-drift or crash in one module skips only that one).
    if host["os"] == WINDOWS:
        from . import nxc_probes  # local import: keeps hostenum import graph small
        methods = {r["method"] for r in store.access_on(host["id"])
                   if r["cred_id"] == cred["id"]}
        is_admin = any(r["admin"] for r in store.access_on(host["id"])
                       if r["cred_id"] == cred["id"])
        if "smb" in methods:
            probe_rep = nxc_probes.run_probes(store, host, cred, is_admin=is_admin,
                                              run=run, on_event=on_event)
            for key, _ in probe_rep.ran:
                report.ran.append(f"probe:{key}")
            for key, reason in probe_rep.skipped:
                report.failed.append((f"probe:{key}", reason))
    if not report.ran:
        report.blocked = report.failed[0][1] if report.failed else "no checks ran"
    return report


# ------------------------------------------------------------------------- parse

#: Pure vendor tokens — skipped when canonicalizing a service product name.
#: Apache is NOT here — "Apache" IS the product name for httpd, so
#: `_canon_product("Apache httpd")` should return `"apache"`, not `"httpd"`.
_PRODUCT_VENDORS = frozenset({
    "microsoft", "openbsd", "gnu", "the",
    # Composite-vendor names — nmap outputs "Atlassian Confluence" /
    # "Palo Alto Networks PAN-OS" / "Networks"; canon should pick the
    # trailing product, not the vendor prefix.
    "atlassian", "palo", "alto", "networks",
    # Vendor-only prefixes on edge-network products. "Cisco IOS XE"
    # → xe / ios (latter is used for CVE-2023-20198). "Ivanti Connect
    # Secure" and "Pulse Secure" both → secure (shared codebase, same
    # CVE-2023-46805 + CVE-2024-21887 applicability).
    "cisco", "ivanti", "pulse",
})
#: Words that don't identify a product (they describe the shape of one).
_PRODUCT_GENERIC = frozenset({
    "httpd", "server", "service", "daemon",
    # Edition-name suffixes common on nmap product strings
    # ("GitLab Community Edition", "Elastic Enterprise", "Postgres
    # Community"). Without these here the last-token rule picks
    # "edition"/"community"/"enterprise" and version-gated TTPs
    # keyed on the real product name silently miss.
    "community", "enterprise", "edition",
})


def _canon_product(name):
    """Turn a service product string into a lowercase single-word key for
    facts.services. Prefers the LAST non-vendor non-generic token when
    there are multiple candidates — a compound name like "Apache Tomcat"
    or "Apache ActiveMQ" maps to the specific product (tomcat / activemq),
    not the shared "apache" prefix. This matters for CVE matching:
    Tomcat CVEs, ActiveMQ CVEs, and Struts CVEs are all distinct from
    Apache httpd's. Where the first token IS the product (bare "Apache",
    httpd generic-filtered out), the candidate list collapses to one and
    the rule degenerates to "return the only candidate."

    Examples:

      "Apache httpd"          → "apache"      (httpd is generic → skipped)
      "Apache Tomcat"         → "tomcat"      (last candidate wins over "apache")
      "Apache ActiveMQ"       → "activemq"
      "Apache Struts"         → "struts"
      "Atlassian Confluence"  → "confluence"
      "Palo Alto PAN-OS"      → "pan-os"
      "OpenSSH"               → "openssh"
      "Microsoft IIS httpd"   → "iis"         (microsoft vendor + httpd generic)
      "Microsoft SQL Server"  → "sql"         (best-effort; TTP matches "sql")
      "nginx"                 → "nginx"

    Returns "" for anything unrecognizable so callers can skip.
    """
    if not name:
        return ""
    candidates = []
    for token in name.lower().split():
        token = token.strip("()[]{}")
        if token and token not in _PRODUCT_VENDORS \
                and token not in _PRODUCT_GENERIC:
            candidates.append(token)
    return candidates[-1] if candidates else ""


def facts_for(store, host_id):
    """Reparse a host's captured enum steps into :class:`HostFacts`."""
    host = store.conn.execute("SELECT * FROM host WHERE id = ?", (host_id,)).fetchone()
    facts = HostFacts(os=host["os"] if host else None)
    outputs = {}
    for step in store.steps(host_id=host_id):
        if step["label"] and step["label"].startswith("enum:"):
            outputs[step["label"][len("enum:"):]] = step["output"] or ""
    for category, text in outputs.items():
        parser = _PARSERS.get(category)
        if parser:
            parser(facts, text)
    # Fold in service-version data from the store — recce-bridge ingest
    # populates these; other paths (nmap ingest) also add rows. The
    # canonicalized product name becomes a facts.services key.
    if host is not None:
        for svc in store.services(host_id=host_id):
            product = _canon_product(svc["product"] or svc["banner"] or "")
            version = (svc["version"] or "").strip()
            if product and version:
                # Preserve the first version encountered per product — a host
                # running the same service on multiple ports usually reports
                # the same version; a discrepancy would be an operator-facing
                # oddity to surface elsewhere, not a TTP-predicate concern.
                facts.services.setdefault(product, version)
    # BloodHound-owned-to-highvalue check — one call, zero-cost when
    # no graph is loaded (bh_node table empty → returns [] fast).
    # Lazy import to avoid pulling bloodhound into every facts_for
    # caller when the store has nothing to look at.
    try:
        from . import bloodhound as bh_mod
        facts.bh_owned_reaches_hv = bool(bh_mod.owned_paths(store))
    except Exception:                                             # noqa: BLE001
        # bloodhound import/query failure is non-fatal — a facts
        # snapshot without the graph flag is still useful for every
        # non-BloodHound-gated TTP.
        pass
    return facts


# -- linux parsers ---------------------------------------------------------

def _p_id(facts, text):
    m = re.search(r"uid=(\d+)\(([^)]+)\)", text)
    if m:
        facts.uid, facts.user = int(m.group(1)), m.group(2)
    g = re.search(r"groups=(.+)", text)
    if g:
        facts.groups = set(re.findall(r"\d+\(([^)]+)\)", g.group(1)))


def _p_sudo(facts, text):
    if re.search(r"\(ALL(\s*:\s*ALL)?\)\s+(NOPASSWD:\s*)?ALL\b", text):
        facts.sudo_all = True
    if "NOPASSWD" in text:
        facts.sudo_nopasswd = True
    for env in re.findall(r"env_keep\+=(\w+)", text):
        facts.sudo_env_keep.add(env)
    # allowed-command lines: "(runas) [NOPASSWD:] /path/to/bin args"
    for line in text.splitlines():
        for path in re.findall(r"(/[^\s,]+)", line.split(")", 1)[-1] if ")" in line else ""):
            if "/" in path:
                facts.sudo_binaries.add(path.rsplit("/", 1)[-1])


def _p_suid(facts, text):
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("/"):
            facts.suid.add(line.rsplit("/", 1)[-1])


def _p_caps(facts, text):
    # both getcap forms: "/usr/bin/python3.8 cap_setuid+ep" and ".../python3.8 = cap_setuid+ep"
    for path, caps in re.findall(r"(/\S+)\s+(?:=\s+)?(cap_[\w,+ep]+)", text):
        name = path.rsplit("/", 1)[-1]
        for cap in re.findall(r"cap_\w+", caps):
            facts.caps[name] = cap


def _p_kernel(facts, text):
    m = re.search(r"\b(\d+\.\d+\.\d+)", text)
    if m:
        facts.kernel = m.group(1)


def _p_container(facts, text):
    """Populate the container-context flags from the sentinel-tagged output
    of the `container` enum check. Sentinels are unique strings (`FK-...`)
    so we don't false-positive on a host that happens to have literal words
    like `docker` in an unrelated command's output."""
    if "FK-DOCKERENV" in text or "FK-CONTAINERENV" in text \
            or "FK-CGROUP-CONTAINER" in text:
        facts.in_container = True
    if "FK-DOCKER-SOCK" in text:
        facts.has_docker_sock = True
        # a writable docker socket ONLY matters inside a container context;
        # a bare-metal box with docker installed has the socket by design.
        # But we set the flag regardless — the TTP predicate is
        # `facts_match: {has_docker_sock: True, in_container: True}` so
        # the combination is required.
    if "FK-K8S-TOKEN" in text:
        facts.has_k8s_token = True
        facts.in_container = True     # k8s tokens only appear inside pods
    if "FK-CGROUP-V1" in text:
        facts.cgroup_v1 = True
    if "FK-HOSTPID" in text:
        facts.hostpid_visible = True
    if "FK-HOSTNETWORK" in text:
        facts.has_hostnetwork = True


def _p_hygiene(facts, text):
    """``hygiene`` check output → set the five writable-config facts. Each
    primitive gets its own ``FK-...`` marker so one line of grep output
    corresponds to exactly one fact — no inference from blank-vs-not-blank."""
    for line in text.splitlines():
        line = line.strip()
        if line == "FK-LDSP-WRITE":
            facts.writable_ld_so_preload = True
        elif line == "FK-PASSWD-WRITE":
            facts.writable_passwd = True
        elif line.startswith("FK-SUDOERSD "):
            facts.writable_sudoers_d.append(line[len("FK-SUDOERSD "):])
        elif line.startswith("FK-PAM "):
            facts.writable_pam_modules.append(line[len("FK-PAM "):])
        elif line.startswith("FK-UDEV "):
            facts.writable_udev_rules.append(line[len("FK-UDEV "):])
        elif line.startswith("FK-SYSD-USER "):
            facts.writable_systemd_user_units.append(line[len("FK-SYSD-USER "):])


#: Credential-loot path → provider name. The ``cloud_tokens`` enum output
#: carries ``FK-TOKEN <path>`` lines; we classify by path prefix so a
#: ``~/.aws/sso/cache/xyz.json`` groups under ``aws`` the same way a
#: ``~/.aws/credentials`` would.
_CLOUD_SDK_PATHS = (
    ("docker",     ".docker/config.json"),
    ("kubectl",    ".kube/config"),
    ("aws",        ".aws/"),
    ("gcloud",     ".config/gcloud/"),
    ("doctl",      ".config/doctl/"),
    ("azure",      ".azure/"),
)


def _p_cloud_tokens(facts, text):
    """``cloud_tokens`` check output → set ``facts.cloud_sdk_tokens``,
    ``.terraform_states``, ``.jenkins_credentials``. One shell round-trip
    hunts every known per-user long-lived credential cache; the parser
    routes each hit to the right field by its marker prefix."""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("FK-TOKEN "):
            path = line[len("FK-TOKEN "):]
            # Classify by sdk path fragment — a single provider may have
            # several hit paths (aws/credentials + aws/config + aws/sso/
            # cache/*), so we accumulate into a list under the key.
            for provider, needle in _CLOUD_SDK_PATHS:
                if needle in path:
                    facts.cloud_sdk_tokens.setdefault(provider, []).append(path)
                    break
        elif line.startswith("FK-TFSTATE "):
            facts.terraform_states.append(line[len("FK-TFSTATE "):])
        elif line.startswith("FK-JENKINS "):
            facts.jenkins_credentials.append(line[len("FK-JENKINS "):])


def _p_ssh_env(facts, text):
    """``ssh_env`` check output → SSH-centric lateral-movement facts.
    SSH_AUTH_SOCK presence (agent hijack), writable foreign authorized_keys
    (key-plant lateral), ControlMaster sockets (session piggyback),
    known_hosts entries (where this foothold has already SSHed)."""
    for line in text.splitlines():
        line = line.strip()
        if line == "FK-SSHAGENT":
            facts.ssh_agent_sock_hijackable = True
        elif line.startswith("FK-AUTHKEYS "):
            facts.writable_authorized_keys.append(line[len("FK-AUTHKEYS "):])
        elif line.startswith("FK-CONTROLPATH "):
            facts.ssh_controlpath_sockets.append(line[len("FK-CONTROLPATH "):])
        elif line.startswith("FK-KNOWNHOST "):
            facts.ssh_known_hosts.append(line[len("FK-KNOWNHOST "):])


def _p_browsers(facts, text):
    """``browsers`` check output → Chrome/Chromium/Edge + Firefox profile
    paths. The TTPs read the actual Login Data / key4.db + Local State at
    fire time (so a stale enum capture doesn't drive loot against an
    already-removed profile)."""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("FK-CHROME "):
            # ``Login Data`` sits inside the profile dir — the profile path
            # is one level up. Deduplicate per profile so running Chrome +
            # Chromium side-by-side doesn't produce N copies of each.
            lp = line[len("FK-CHROME "):]
            prof = lp.rsplit("/", 1)[0] if "/" in lp else lp
            if prof not in facts.chrome_profiles:
                facts.chrome_profiles.append(prof)
        elif line.startswith("FK-FIREFOX "):
            lp = line[len("FK-FIREFOX "):]
            prof = lp.rsplit("/", 1)[0] if "/" in lp else lp
            if prof not in facts.firefox_profiles:
                facts.firefox_profiles.append(prof)


#: Linux capability bit → short lowercase name, keyed by bit position in
#: the ``CapEff`` bitmask under ``/proc/<pid>/status``. We only name the
#: caps that container-escape TTPs predicate on; new TTPs that need other
#: caps can extend the table.
_CAP_BITS = {
    0: "chown", 1: "dac_override", 2: "dac_read_search", 7: "setuid",
    8: "setpcap", 12: "net_admin", 13: "net_raw", 14: "ipc_lock",
    16: "sys_module", 17: "sys_rawio", 18: "sys_chroot", 19: "sys_ptrace",
    21: "sys_admin", 22: "sys_boot", 23: "sys_nice", 27: "mknod",
    31: "setfcap", 32: "mac_override", 36: "block_suspend",
    38: "perfmon", 39: "bpf", 40: "checkpoint_restore",
}


def _decode_capeff(mask_hex):
    """Decode a hex ``CapEff`` bitmask (as printed by ``/proc/<pid>/status``)
    to a set of lowercase cap names. Returns the empty set on garbage."""
    try:
        mask = int(mask_hex, 16)
    except (TypeError, ValueError):
        return set()
    return {_CAP_BITS[b] for b in _CAP_BITS if mask & (1 << b)}


def _p_proc_caps(facts, text):
    """``proc_caps`` check output → ``facts.proc_capabilities`` set +
    ``facts.writable_uevent_helper`` boolean. The CapEff line in
    ``/proc/self/status`` is a single hex bitmask — decode via the
    :data:`_CAP_BITS` table."""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("CapEff:"):
            parts = line.split()
            if len(parts) >= 2:
                facts.proc_capabilities = _decode_capeff(parts[1])
        elif line == "FK-UEVENT-WRITE":
            facts.writable_uevent_helper = True


def _p_nfs_env(facts, text):
    """``nfs_env`` check output → ``facts.nfs_mountable`` list.
    ``FK-NFS-MOUNT <server:/path> <local_mount_point>`` for already-mounted
    exports (reachable via the local path) + ``FK-NFS-EXPORT <line>`` for
    discoverable export declarations we could point sibling boxes at."""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("FK-NFS-MOUNT "):
            facts.nfs_mountable.append(line[len("FK-NFS-MOUNT "):])
        elif line.startswith("FK-NFS-EXPORT "):
            facts.nfs_mountable.append(line[len("FK-NFS-EXPORT "):])


def _p_keyrings(facts, text):
    """``keyrings`` check output → ``facts.desktop_keyrings``. One token per
    daemon detected (``gnome``, ``kwallet``). Deduplicated — running kwalletd
    + kwalletd5 side-by-side only promotes one ``kwallet`` entry."""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("FK-KEYRING "):
            tok = line[len("FK-KEYRING "):].strip()
            if tok and tok not in facts.desktop_keyrings:
                facts.desktop_keyrings.append(tok)


def _p_cgroup_v1_escape(facts, text):
    """``cgroup_v1_escape`` check → ``facts.writable_release_agent``.
    Single-bit field — any release_agent writable from the container
    is a one-shot escape, so the ``True`` edge is all the TTPs need."""
    for line in text.splitlines():
        if line.strip().startswith("FK-RELEASE-AGENT "):
            facts.writable_release_agent = True
            return


def _p_at_spool(facts, text):
    """``at_spool`` check → ``facts.at_spool_writable``."""
    for line in text.splitlines():
        if line.strip().startswith("FK-AT-SPOOL "):
            facts.at_spool_writable = True
            return


def _p_xauth(facts, text):
    """``xauth`` check → ``facts.xauth_cookie_present``."""
    for line in text.splitlines():
        if line.strip().startswith("FK-XAUTH "):
            facts.xauth_cookie_present = True
            return


def _p_sudo_path(facts, text):
    """``sudo_path`` check → ``facts.sudo_preserves_path``. Any match
    (env_keep += PATH, !secure_path, relative command in a NOPASSWD rule)
    sets the flag — the TTP's command surfaces WHICH primitive at fire time."""
    for line in text.splitlines():
        if line.strip().startswith("FK-SUDO-PATH "):
            facts.sudo_preserves_path = True
            return


def _p_ssh_rc(facts, text):
    """``ssh_rc`` check → ``facts.writable_ssh_rc``. True both when ``rc``
    already exists and is writable, and when it does not exist but the
    parent ``.ssh/`` dir is writable (we can create it)."""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("FK-SSH-RC ") or line.startswith("FK-SSH-RC-CREATE "):
            facts.writable_ssh_rc = True
            return


def _p_xdg_autostart(facts, text):
    """``xdg_autostart`` check → ``facts.writable_xdg_autostart`` list.
    Includes both ``FK-XDG-AUTOSTART-DIR`` (we can drop new .desktop files)
    and ``FK-XDG-AUTOSTART-FILE`` (we can edit an existing autostart entry
    — safer, since the owner is the one it runs as)."""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("FK-XDG-AUTOSTART-DIR "):
            facts.writable_xdg_autostart.append(line[len("FK-XDG-AUTOSTART-DIR "):])
        elif line.startswith("FK-XDG-AUTOSTART-FILE "):
            facts.writable_xdg_autostart.append(line[len("FK-XDG-AUTOSTART-FILE "):])


def _p_shell_init(facts, text):
    """``shell_init`` check → ``facts.writable_shell_init`` list. Each entry
    is an absolute path to another user's shell-init file we can WRITE —
    writing an exec line turns their next login into our code."""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("FK-SHELL-INIT "):
            facts.writable_shell_init.append(line[len("FK-SHELL-INIT "):])


def _p_user_crontabs(facts, text):
    """``user_crontabs`` check → ``facts.writable_user_crontabs`` list of
    ``user:path`` entries. One per writable crontab in /var/spool/cron/."""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("FK-USER-CRONTAB "):
            facts.writable_user_crontabs.append(line[len("FK-USER-CRONTAB "):])


def _p_suid_environ(facts, text):
    """``suid_environ`` check → ``facts.readable_suid_proc_environ`` list of
    ``pid:exe`` entries. Each represents a live SUID process whose /proc/pid/
    environ our UID can read — a secret-exfil primitive without a crash."""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("FK-SUID-ENVIRON "):
            facts.readable_suid_proc_environ.append(line[len("FK-SUID-ENVIRON "):])


def _p_sysv_init(facts, text):
    """``sysv_init`` check → ``facts.writable_sysv_init`` list of writable
    /etc/init.d (or /etc/rc.d/init.d) script paths."""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("FK-SYSV-INIT "):
            facts.writable_sysv_init.append(line[len("FK-SYSV-INIT "):])


def _p_systemd_generators(facts, text):
    """``systemd_generators`` check → ``facts.writable_systemd_generators``
    list. Both writable DIRS (we can drop a new generator) and writable
    FILES (we can edit an existing generator) are promoted — the TTP
    renders both branches."""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("FK-SYSTEMD-GENERATOR-DIR "):
            facts.writable_systemd_generators.append(line[len("FK-SYSTEMD-GENERATOR-DIR "):])
        elif line.startswith("FK-SYSTEMD-GENERATOR-FILE "):
            facts.writable_systemd_generators.append(line[len("FK-SYSTEMD-GENERATOR-FILE "):])


def _p_directory_auth(facts, text):
    """``directory_auth`` check → ``facts.nis_or_ldap_auth``. True if
    either nsswitch names NIS/LDAP/SSSD for passwd/group OR ypcat passwd
    returns data."""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("FK-DIR-AUTH ") or line.startswith("FK-NIS-PASSWD "):
            facts.nis_or_ldap_auth = True
            return


def _p_cgroup_v2_escape(facts, text):
    """``cgroup_v2_escape`` check → ``facts.writable_cgroup_delegate``.
    One-bit field — writable cgroup.procs on this task's own cgroup is a
    container-escape primitive on cgroup v2 hosts."""
    for line in text.splitlines():
        if line.strip().startswith("FK-CGROUP-V2-DELEGATE "):
            facts.writable_cgroup_delegate = True
            return


def _p_aws_sso_cache(facts, text):
    """``aws_sso_cache`` check → ``facts.aws_sso_cache`` list of readable
    cache file paths."""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("FK-AWS-SSO "):
            facts.aws_sso_cache.append(line[len("FK-AWS-SSO "):])


def _p_dbus_policy(facts, text):
    """``dbus_policy`` check → ``facts.dbus_broad_policies`` list of
    ``<policy_file>:<matched line>`` or just the file for broad default
    policies."""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("FK-DBUS-POLICY "):
            facts.dbus_broad_policies.append(line[len("FK-DBUS-POLICY "):])
        elif ":" in line and ("allow send_destination" in line.lower() or "<policy" in line.lower()):
            # The awk branch — unprefixed, includes path:match
            facts.dbus_broad_policies.append(line)


def _p_versions(facts, text):
    """sudo/pkexec(polkit)/glibc versions from the combined version print."""
    m = re.search(r"Sudo version\s+(\S+)", text, re.I)
    if m:
        facts.sudo_version = m.group(1)
    m = re.search(r"pkexec version\s+(\S+)", text, re.I)
    if m:
        facts.pkexec_version = m.group(1)
    # "ldd (Ubuntu GLIBC 2.35-0ubuntu3) 2.35" — the trailing bare version is the reliable one
    m = re.search(r"^ldd .*?(\d+\.\d+)\s*$", text, re.I | re.M)
    if m:
        facts.glibc_version = m.group(1)


# -- windows parsers -------------------------------------------------------

def _p_priv(facts, text):
    for priv in re.findall(r"(Se\w+Privilege)", text):
        facts.privs.add(priv)


def _p_groups(facts, text):
    for known in ("Administrators", "Backup Operators", "Remote Management Users",
                  "Remote Desktop Users", "Server Operators"):
        if known.lower() in text.lower():
            facts.win_groups.add(known)


def _p_aie(facts, text):
    # both HKLM and HKCU must be 0x1 for AlwaysInstallElevated to apply.
    facts.always_install_elevated = len(re.findall(r"AlwaysInstallElevated\s+REG_DWORD\s+0x1",
                                                   text, re.I)) >= 2


def _p_sysinfo(facts, text):
    """systeminfo output: OS build (e.g. 10.0.19045 or 6.3.9600), edition, install date."""
    # "OS Name: Microsoft Windows Server 2019 Datacenter"
    m = re.search(r"OS Name:\s*(.+?)$", text, re.M)
    if m:
        facts.win_edition = m.group(1).strip()
    # "OS Version: 10.0.19045 N/A Build 19045"  -- the numeric prefix is what matters
    m = re.search(r"OS Version:\s*(\d+\.\d+\.\d+)", text)
    if m:
        facts.win_build = m.group(1)
    # architecture ("System Type: x64-based PC")
    m = re.search(r"System Type:\s*(x64|X64|x86|X86|ARM)", text)
    if m:
        facts.win_arch = m.group(1).lower().replace("x86", "x86").replace("x64", "x64")


def _p_hotfixes(facts, text):
    """Extract KB IDs from Windows hotfix output — format-flexible.

    Handles three shapes fieldkit or a tester might feed:
      * ``wmic qfe get HotFixID /format:list`` — ``HotFixID=KB1234567`` per line
        (what fieldkit issues; deterministic).
      * ``wmic qfe list brief`` — tabular; KB is in a column.
      * ``Get-HotFix`` PowerShell — tabular; KB in the ``HotFixID`` column.

    We accept any ``KBnnnnnnn`` token (7+ digits) that isn't clearly inside a URL
    or path — this covers all three formats without being tricked by a URL like
    ``http://.../?kbid=5031364`` (that lacks the KB prefix and is not matched).
    """
    for m in re.finditer(r"\bKB(\d{6,})\b", text):
        facts.hotfixes.add("KB" + m.group(1))


def _p_services(facts, text):
    for line in text.splitlines():
        m = re.search(r"([A-Za-z]:\\[^\"]*?\.exe)", line)
        if not m:
            continue
        path = m.group(1)
        # unquoted (the raw line did not wrap it in quotes) + a space before the exe +
        # not under C:\Windows = a plant-a-hijack candidate.
        quoted = f'"{path}"' in line
        if not quoted and " " in path and not path.lower().startswith("c:\\windows"):
            # `wmic ... get name,pathname,startmode` puts Name first (columns are
            # alphabetical), so the text before the path is the service name.
            name = line[:m.start()].strip() or None
            facts.unquoted_services.append((name, path))


#: SDDL abbreviations for principals a non-admin foothold is typically a member of.
_BROAD_SIDS = {"AU", "BU", "WD", "IU", "DU", "S-1-1-0", "S-1-5-11", "S-1-5-32-545"}


def _grants_change_config(rights):
    """True when a service ACE's rights include SERVICE_CHANGE_CONFIG (DC) — letters,
    GENERIC_ALL (GA), or a hex mask with the 0x0002 bit set."""
    r = rights.strip()
    if "DC" in r or "GA" in r:
        return True
    if r.startswith("0x"):
        try:
            return bool(int(r, 16) & 0x0002)
        except ValueError:
            return False
    return False


#: icacls principals a non-admin foothold is typically inside.
_ICACLS_BROAD = ("everyone", "\\users", "authenticated users", "interactive",
                 "\\domain users")
#: icacls permission tokens that let you write/replace a file.
_ICACLS_WRITE = {"F", "M", "W", "GW", "GA", "WD", "AD"}


def _icacls_writable(acl):
    """True when icacls output grants a broad principal a write-capable mask (F/M/W/…).
    ``acl`` is the icacls text with entries joined by ';'. Each entry is
    ``<principal>:(perm)(perm)`` — matched by anchoring on ``:(`` so the drive-letter
    colon in the leading path doesn't split a principal."""
    for who, perms in re.findall(r"([^\s:;][^:;]*):(\([^;]*)", acl):
        if not any(b in who.lower() for b in _ICACLS_BROAD):
            continue
        for grp in re.findall(r"\(([^)]*)\)", perms):
            if _ICACLS_WRITE & set(re.split(r"[,\s]+", grp)):
                return True
    return False


def _p_svcperms(facts, text):
    for line in text.splitlines():
        parts = line.split("|", 3)
        if len(parts) < 4 or not parts[1]:
            continue
        kind, name, target, detail = parts
        if kind == "SVC":
            # ACE = (type;flags;rights;object;inherit;sid). A broad principal granted
            # SERVICE_CHANGE_CONFIG can repoint binPath to a SYSTEM command.
            for rights, sid in re.findall(r"\(A;[^;]*;([^;]*);[^;]*;[^;]*;([^)]+)\)", detail):
                if sid.strip() in _BROAD_SIDS and _grants_change_config(rights):
                    facts.reconfigurable_services[name] = target.strip()
                    break
        elif kind == "ACL" and _icacls_writable(detail):
            facts.writable_service_bins[name] = target.strip()
        elif kind == "DIR" and _icacls_writable(detail):
            facts.writable_service_dirs[name] = target.strip()


_PARSERS = {
    "id": _p_id, "sudo": _p_sudo, "suid": _p_suid, "caps": _p_caps, "kernel": _p_kernel,
    "versions": _p_versions, "container": _p_container,
    # axis 1 — Linux depth: hygiene + credential loot + SSH-env probes
    "hygiene": _p_hygiene, "cloud_tokens": _p_cloud_tokens, "ssh_env": _p_ssh_env,
    # axis 1 slice 2 — browser loot + container caps + NFS lateral
    "browsers": _p_browsers, "proc_caps": _p_proc_caps, "nfs_env": _p_nfs_env,
    # axis 1 slice 3 — desktop keyrings, cgroup v1 release_agent, at(1) spool,
    # X11 xauth, sudo PATH preservation, ~/.ssh/rc, XDG autostart, other-user
    # shell-init, writable user crontabs, SUID /proc/*/environ.
    "keyrings": _p_keyrings, "cgroup_v1_escape": _p_cgroup_v1_escape,
    "at_spool": _p_at_spool, "xauth": _p_xauth, "sudo_path": _p_sudo_path,
    "ssh_rc": _p_ssh_rc, "xdg_autostart": _p_xdg_autostart,
    "shell_init": _p_shell_init, "user_crontabs": _p_user_crontabs,
    "suid_environ": _p_suid_environ,
    # axis 1 slice 4 — SysV init, systemd generators, NIS/LDAP, cgroup v2
    "sysv_init": _p_sysv_init,
    "systemd_generators": _p_systemd_generators,
    "directory_auth": _p_directory_auth,
    "cgroup_v2_escape": _p_cgroup_v2_escape,
    # axis 1 slice 6 — AWS SSO cache + D-Bus policy
    "aws_sso_cache": _p_aws_sso_cache,
    "dbus_policy": _p_dbus_policy,
    "priv": _p_priv, "groups": _p_groups, "aie": _p_aie, "services": _p_services,
    "sysinfo": _p_sysinfo, "hotfixes": _p_hotfixes,
    "svcperms": _p_svcperms,
}
