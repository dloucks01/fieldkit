# fieldkit — capability-depth roadmap

Where fieldkit's pitch currently runs thinner than the vision (full-chain
weaponization engine, better than Havoc / Nemesis / PlumHound). Each axis
tracks what's missing and what's shipped. Tick a box when its commit
lands in `main`.

**Vision statement.** fieldkit is the one engine that runs the full
chain — ingest → analyze → weaponize → deliver → own → persist → report —
with one SQLite state layer as the backbone so every step is reproducible
and defensible. It covers in one engine what Havoc, Nemesis and PlumHound
each do in isolation.

---

## Axis 1 — Linux parity with Windows depth

Current: ~45 Linux TTPs (GTFOBins, 10 kernel LPE, 10 container escapes,
7 loot primitives, 3 persistence patterns). Windows side has ~110.

### Credential loot
- [ ] Chrome / Chromium `Login Data` SQLite + `Local State` master-key decrypt
- [ ] Firefox `logins.json` + `key4.db` decrypt
- [ ] GNOME Keyring / KWallet dump via D-Bus
- [ ] PAM module injection passthrough logging (persist overlap)
- [x] SSH agent socket hijack (`SSH_AUTH_SOCK`) → signing primitive
- [x] `~/.docker/config.json` + registry auth tokens
- [x] `~/.kube/config` + exec-plugin tokens
- [ ] `~/.aws/sso/cache` expansion of existing cloud-credentials TTP
- [x] Jenkins `credentials.xml` + master key
- [ ] GitLab runner `config.toml`
- [x] Terraform state (`*.tfstate` + `.terraform.lock.hcl` for provider versions)
- [ ] Ansible vault keys + playbook secrets
- [ ] CI runner artifact dirs
- [ ] Browser cookies → SSO-replay `Cookie:` headers

### Privilege escalation depth
- [x] `LD_PRELOAD` via sudo `env_keep`
- [x] `LD_AUDIT` variant via sudo `env_keep`
- [x] Writable `/etc/ld.so.preload`
- [ ] PATH hijack when sudo preserves PATH / uses relative paths
- [x] Writable other-user `~/.ssh/authorized_keys`
- [ ] Readable other-user `/proc/*/environ` on setuid processes
- [ ] Writable `~/.bashrc` / `~/.profile` of a sudo-target user
- [ ] `at` / `atd` writable spool
- [ ] D-Bus policy mis-config → privileged method call
- [ ] polkit v109 variants beyond PwnKit
- [ ] NFS no_root_squash → setuid planting
- [x] Writable `/etc/sudoers.d/*`
- [x] Writable `/etc/passwd`

### Kernel LPE breadth
- [ ] CVE-2024-26925 nf_tables commit race
- [ ] CVE-2023-32233 nftables adjacent
- [ ] CVE-2022-32250 nftables set
- [ ] CVE-2021-4154 fuse mount race
- [ ] CVE-2017-16995 eBPF verifier (legacy but still common)
- [ ] io_uring exploitation path (CVE-2022-29582 family)
- [ ] polkit pkexec v109 variant chain (beyond PwnKit)

### Container escape depth
- [ ] cgroup v2 writable `release_agent` variants
- [ ] Writable `/sys/kernel/uevent_helper`
- [ ] Privileged container `/dev/*` host-disk mount → chroot escape
- [ ] `CAP_DAC_READ_SEARCH` + `open_by_handle_at` (Shocker)
- [ ] `CAP_SYS_PTRACE` + host-process attach
- [ ] `CAP_SYS_ADMIN` → loopback mount from host
- [ ] `--privileged` + modprobe → kernel module load
- [ ] K8s SA token → full cluster-admin via permissive ClusterRole
- [ ] K8s secret enumeration via SA token

### Persistence
- [x] systemd user unit (survives reboot without root)
- [ ] User-level cron / anacron variants
- [ ] Shell init hijack (`.bashrc`, `.profile`, `.bash_logout`, `.inputrc`)
- [ ] `~/.ssh/rc` + `~/.ssh/config` ProxyCommand
- [x] PAM module (`pam_exec.so` writable path)
- [ ] XDG autostart desktop file
- [ ] SysV init `/etc/init.d/` writable
- [ ] systemd generator (older distros)
- [x] udev rules writable

### Lateral movement
- [x] SSH key reuse pivot (sweep `authorized_keys` + `known_hosts`)
- [x] SSH ControlPath hijack (shared multiplex sockets)
- [ ] X11 forwarding abuse (xauth cookie theft)
- [ ] NFS mount pivot
- [ ] Shared NIS / LDAP account reuse
- [ ] Docker socket → sibling container exec
- [ ] K8s SA token → `kubectl exec` into other pods

---

## Axis 2 — NXC module coverage

Current: 1 wrapped module (`spider_plus`) + 5 added recently
(`shares`, `loggedon-users`, `sessions`, `laps`, `gpp_password`).

### Credential-promoting probes
- [ ] `-M laps` v2 (newer encrypted LAPS)
- [ ] `-M gpp_autologin` (SYSVOL AutoLogin passwords)
- [x] `-M veeam` (Veeam backup creds)
- [x] `-M teams_localdb` (Teams-cached tokens)
- [ ] `-M chrome` (browser login DB over SMB)
- [ ] `-M firefox` (profile dump)
- [ ] `-M keepass_discover` + `-M keepass_trigger`
- [x] `-M nanodump` / `-M lsassy` / `-M procdump` (LSASS dumping variants)
- [ ] `-M masky` (Kerberos pre-auth via ADCS)
- [ ] `-M shadowcredentials` (msDS-KeyCredentialLink injection)
- [ ] `-M rdcman` (saved RDP creds)
- [ ] `-M drop-sc` (ScreenConnect config dump)
- [ ] `-M scuffy` (scheduled-task persist via URL)

### Finding-generating probes
- [x] `-M ms17-010` (EternalBlue scan)
- [ ] `-M spooler` (Print Spooler service enumeration — feeds coerce chain)
- [x] `-M coerce_plus` (multi-protocol auth-coercer)
- [ ] `-M ldap-checker` (LDAP signing / channel binding)
- [ ] `-M obsolete_nt_hash_users` (users with pre-2004 NT hashes)
- [ ] `-M pre2k` (pre-2000 compat computer accounts)

### Asset-enum probes
- [ ] `-M get-network` (internal subnet enum from AD)
- [ ] `-M groupmembership` (membership of specific groups)
- [ ] `--rid-brute` wrapper (user/group enum when LDAP is restricted)
- [ ] `--users` + `--computers` systematic snapshot

---

## Axis 3 — Weaponization layer (payload / loader / evasion)

**Not started.** Highest technical ambition. Deliverables noted in planning:

- [ ] Modular loader catalog (reflective .NET, reflective DLL, module
  stomping, process hollowing, APC injection, CLR hosting, LOLBAS,
  CLM bypass, WSL abuse, Chromium extension side-load)
- [ ] AMSI / ETW / Defender bypass catalog
- [ ] Direct & indirect syscall framework (Hell's/Halo's/Tartarus's/Freshy)
- [ ] Encoding + obfuscation pipeline (XOR, FNV, ConfuserEx integration,
  PE signature cloning)
- [ ] Delivery channels (HTTPS beacon, SMB named pipe, DNS, DOH, WebDAV)

**Architecture decision pending:** stdlib-only invariant for engine
vs. vendored TLS stack for in-engine HTTPS. Current lean: keep
stdlib-only, templated loaders in `fieldkit/loaders/*.c.j2`-style.

---

## Axis 4 — C2 / beacon / implant (OPTIONAL)

**Not started.** Only pursue if we want to displace Havoc directly.
Current pitch delegates to recce for session management; this axis
reverses that. Deliverables:

- [ ] Minimal single-file beacon generator per OS
- [ ] HTTP/HTTPS/DNS transport, operator-picked
- [ ] Encrypted sleep (XOR + AES-GCM on wire)
- [ ] 3-5 built-in commands (shell/upload/download/kill/sleep)
- [ ] Beacon tasking in SQLite; check-ins become step rows
- [ ] Per-build mutation seed for reproducible-but-unique binaries

---

## Axis 5 — Analysis depth (Nemesis parity)

**Not started.** Deliverables:

- [ ] `fieldkit/enrich.py` — entity extractor over step.output (IPs,
  usernames, emails, hashes, cred-shape detection, AWS keys, PATs)
- [ ] Automatic hashcat mode suggestion on hash promotion
- [ ] Cross-engagement correlation (credential reuse, same username
  across cloud/AD/SaaS)
- [ ] Service version → offline CVE lookup (NVD + ExploitDB mirror)
- [ ] Confidence scoring per finding
- [ ] `fieldkit timeline` + `fieldkit narrative` subcommands

---

## Axis 6 — Reporting polish (PlumHound parity)

**Not started.** Deliverables:

- [ ] Interactive HTML report with embedded SVG attack path, filters,
  collapsible per-host, dark/light theme
- [ ] Executive summary (`fieldkit report --exec-summary`)
- [ ] PPTX exec deck (`fieldkit report --format pptx`)
- [ ] CVSS v3.1 vector derivation (`fieldkit/cvss.py`)
- [ ] `fieldkit diff --compare prev.db` trend reporting
- [ ] Branded DOCX / PPTX templates bundled

---

## Current priorities (execution order)

1. **Axis 2** — NXC modules wiring (fastest ROI/week)
2. **Axis 1** — Linux credential loot + privesc + persistence depth
3. **Axis 5** — Analysis enrichment
4. **Axis 6** — Reporting polish
5. **Axis 3** — Weaponization (biggest ambition)
6. **Axis 4** — C2 / beacon (optional — only if displacing Havoc)

Axes 1 + 2 are currently in flight; the two feed each other (an nxc
probe produces evidence that enum / escalate consume; a new Linux TTP
needs an enum predicate the hostenum already supports).
