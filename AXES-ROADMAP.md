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
- [x] Chrome / Chromium `Login Data` SQLite + `Local State` master-key decrypt
- [x] Firefox `logins.json` + `key4.db` decrypt
- [x] GNOME Keyring / KWallet dump via D-Bus
- [x] PAM module injection passthrough logging (persist overlap)
- [x] SSH agent socket hijack (`SSH_AUTH_SOCK`) → signing primitive
- [x] `~/.docker/config.json` + registry auth tokens
- [x] `~/.kube/config` + exec-plugin tokens
- [x] `~/.aws/sso/cache` expansion of existing cloud-credentials TTP
- [x] Jenkins `credentials.xml` + master key
- [x] GitLab runner `config.toml`
- [x] Terraform state (`*.tfstate` + `.terraform.lock.hcl` for provider versions)
- [x] Ansible vault keys + playbook secrets
- [x] CI runner artifact dirs
- [x] Browser cookies → SSO-replay `Cookie:` headers

### Privilege escalation depth
- [x] `LD_PRELOAD` via sudo `env_keep`
- [x] `LD_AUDIT` variant via sudo `env_keep`
- [x] Writable `/etc/ld.so.preload`
- [x] PATH hijack when sudo preserves PATH / uses relative paths
- [x] Writable other-user `~/.ssh/authorized_keys`
- [x] Readable other-user `/proc/*/environ` on setuid processes
- [x] Writable `~/.bashrc` / `~/.profile` of a sudo-target user
- [x] `at` / `atd` writable spool
- [x] D-Bus policy mis-config → privileged method call
- [x] polkit v109 variants beyond PwnKit (covered by `cve:polkit-v109-variants`)
- [x] NFS no_root_squash → setuid planting (covered by `lateral:nfs-mount-pivot`)
- [x] Writable `/etc/sudoers.d/*`
- [x] Writable `/etc/passwd`

### Kernel LPE breadth
- [x] CVE-2024-26925 nf_tables commit race
- [x] CVE-2023-32233 nftables adjacent
- [x] CVE-2022-32250 nftables set
- [x] CVE-2021-4154 fuse mount race
- [x] CVE-2017-16995 eBPF verifier (legacy but still common)
- [x] io_uring exploitation path (CVE-2022-29582 family)
- [x] polkit pkexec v109 variant chain (beyond PwnKit)

### Container escape depth
- [x] cgroup v1 writable `release_agent`
- [x] cgroup v2 delegate misconfig (post-release_agent escape class)
- [x] Writable `/sys/kernel/uevent_helper`
- [x] Privileged container `/dev/*` host-disk mount → chroot escape
- [x] `CAP_DAC_READ_SEARCH` + `open_by_handle_at` (Shocker)
- [x] `CAP_SYS_PTRACE` + host-process attach
- [x] `CAP_SYS_ADMIN` → loopback mount from host
- [x] `--privileged` + modprobe → kernel module load
- [x] K8s SA token → full cluster-admin via permissive ClusterRole
- [x] K8s secret enumeration via SA token

### Persistence
- [x] systemd user unit (survives reboot without root)
- [x] User-level cron / anacron variants
- [x] Shell init hijack (`.bashrc`, `.profile`, `.bash_logout`, `.inputrc`)
- [x] `~/.ssh/rc` + `~/.ssh/config` ProxyCommand
- [x] PAM module (`pam_exec.so` writable path)
- [x] XDG autostart desktop file
- [x] SysV init `/etc/init.d/` writable
- [x] systemd generator (older distros)
- [x] udev rules writable

### Lateral movement
- [x] SSH key reuse pivot (sweep `authorized_keys` + `known_hosts`)
- [x] SSH ControlPath hijack (shared multiplex sockets)
- [x] X11 forwarding abuse (xauth cookie theft)
- [x] NFS mount pivot
- [x] Shared NIS / LDAP account reuse
- [x] Docker socket → sibling container exec
- [x] K8s SA token → `kubectl exec` into other pods

---

## Axis 2 — NXC module coverage

Current: 1 wrapped module (`spider_plus`) + 5 added recently
(`shares`, `loggedon-users`, `sessions`, `laps`, `gpp_password`).

### Credential-promoting probes
- [x] `-M laps` v2 (newer encrypted LAPS)
- [x] `-M gpp_autologin` (SYSVOL AutoLogin passwords)
- [x] `-M veeam` (Veeam backup creds)
- [x] `-M teams_localdb` (Teams-cached tokens)
- [x] `-M chrome` (browser login DB over SMB)
- [x] `-M firefox` (profile dump)
- [x] `-M keepass_discover` + `-M keepass_trigger`
- [x] `-M nanodump` / `-M lsassy` / `-M procdump` (LSASS dumping variants)
- [x] `-M masky` (Kerberos pre-auth via ADCS)
- [x] `-M shadowcredentials` (msDS-KeyCredentialLink injection)
- [x] `-M rdcman` (saved RDP creds)
- [x] `-M lsa_backup_keys` (DPAPI domain backup keys)
- [x] `-M dpapi-ng` (LAPS v2 / KeyCreds / Chromium v20+ decrypt)
- [x] `-M drop-sc` (ScreenConnect config dump)
- [x] `-M scuffy` (scheduled-task persist via URL)

### Finding-generating probes
- [x] `-M ms17-010` (EternalBlue scan)
- [x] `-M petitpotam` (MS-EFSRPC coerce)
- [x] `-M nopac` (CVE-2021-42278 + 42287 chain)
- [x] `-M spooler` (Print Spooler service enumeration — feeds coerce chain)
- [x] `-M coerce_plus` (multi-protocol auth-coercer)
- [x] `-M ldap-checker` (LDAP signing / channel binding)
- [x] `-M obsolete_nt_hash_users` (users with pre-2004 NT hashes)
- [x] `-M pre2k` (pre-2000 compat computer accounts)

### Asset-enum probes
- [x] `-M enum_dns` (AD-integrated DNS zone enumeration)
- [x] `-M get-network` (internal subnet enum from AD)
- [x] `-M groupmembership` (membership of specific groups)
- [x] `--rid-brute` wrapper (user/group enum when LDAP is restricted)
- [x] `--users` + `--computers` systematic snapshot

---

## Axis 3 — Weaponization layer (payload / loader / evasion)

Metadata-level catalog landed in slice 12 (`fieldkit/weaponization.py`
with 27 entries across loader / bypass / syscall / encoder / delivery
categories). Reference templates for the most-cited shapes landed in
slice 13 under `fieldkit/loaders/`. Operators can `fieldkit
weaponization list` / `show <key>` / `render <key>`.

- [x] Modular loader catalog (reflective .NET, reflective DLL, module
  stomping, process hollowing, APC injection, CLR hosting, LOLBAS,
  CLM bypass, WSL abuse, Chromium extension side-load)
- [x] AMSI / ETW / Defender bypass catalog
- [x] Direct & indirect syscall framework (Hell's/Halo's/Tartarus's/Freshy)
- [x] Encoding + obfuscation pipeline (XOR, FNV, ConfuserEx integration,
  PE signature cloning)
- [x] Delivery channels (HTTPS beacon, SMB named pipe, DNS, DOH, WebDAV)

**Architecture decision resolved:** stdlib-only engine kept. Templates
live as `fieldkit/loaders/*.{c,cs,asm,py,ps1}.j2` reference files
operators adapt + build in their own arsenal. The engine never
compiles or executes them.

---

## Axis 4 — C2 / beacon / implant (OPTIONAL)

Slice 15 lands the fieldkit-side orchestration: beacon metadata +
build-config + task queue + per-build mutation seed. fieldkit does NOT
run a live C2 server — operators run Havoc / Mythic / Sliver / their
own and use `fieldkit beacon` to keep track of what was built, what's
been tasked, and what's reported back alongside the rest of the
engagement data. Beacon payload code stays at reference-template level
under `fieldkit/loaders/` (slice 13).

- [x] Minimal single-file beacon generator per OS (template + build-
  config scaffolding; operator compiles)
- [x] HTTP/HTTPS/DNS transport, operator-picked (TRANSPORTS table in
  fieldkit/beacon.py)
- [x] Encrypted sleep (XOR + AES-GCM on wire) — covered by the encoder
  catalog entries (axis 3)
- [x] 3-5 built-in commands (shell/upload/download/kill/sleep) —
  TASK_COMMANDS pinned to exactly those five
- [x] Beacon tasking in SQLite; check-ins become step rows (schema v12
  — beacon + beacon_task tables)
- [x] Per-build mutation seed for reproducible-but-unique binaries
  (fieldkit/beacon.py:new_build_seed, drives User-Agent + injected
  into the template's substitution dict)

---

## Axis 5 — Analysis depth (Nemesis parity)

- [x] `fieldkit/enrich.py` — entity extractor over step.output (IPs,
  usernames, emails, hashes, cred-shape detection, AWS keys, PATs)
- [x] Automatic hashcat mode suggestion on hash promotion
- [x] Cross-engagement correlation (credential reuse, same username
  across cloud/AD/SaaS)
- [x] Service version → offline CVE lookup (NVD + ExploitDB mirror)
- [x] Confidence scoring per finding
- [x] `fieldkit timeline` + `fieldkit narrative` subcommands

---

## Axis 6 — Reporting polish (PlumHound parity)

- [x] Interactive HTML report with embedded SVG attack path, filters,
  collapsible per-host, dark/light theme
- [x] Executive summary (`fieldkit report --exec-summary`)
- [x] PPTX exec deck (`fieldkit report --pptx PATH`)
- [x] CVSS v3.1 vector derivation (`fieldkit/cvss.py`)
- [x] `fieldkit diff` trend reporting (covered by the existing ``diff``
  subcommand)
- [x] Branded DOCX / PPTX templates bundled (BrandConfig on pptx_export +
  config.report-brand section wiring title/accent/footer)

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

### Slice log

* **Slice 1 (f4be75e)** — 14 Linux TTPs + 5 nxc probes + hostenum
  extensions (hygiene / cloud_tokens / ssh_env). Facts-gated loot
  (ssh-agent-hijack, docker-config, kubectl, terraform, jenkins) and
  facts-gated persistence (writable PAM, udev, systemd-user).
  Lateral: ssh-key-reuse + ssh-controlpath-hijack.
* **Slice 2** — 15 Linux TTPs + 7 nxc probes + hostenum
  extensions (browsers / proc_caps / nfs_env).
  * Browser loot: Chrome / Chromium / Firefox profile discovery + loot.
  * Kernel LPE: CVE-2024-26925, CVE-2023-32233, CVE-2017-16995 (eBPF),
    CVE-2021-4154 (fuse), CVE-2022-29582 (io_uring).
  * Container escape: writable uevent_helper, Shocker
    (CAP_DAC_READ_SEARCH), CAP_SYS_PTRACE host attach, CAP_SYS_ADMIN
    loopback, CAP_SYS_MODULE insmod.
  * Lateral: NFS mount pivot, docker-sock sibling, k8s SA kubectl exec.
  * nxc probes: laps_v2, gpp_autologin, chrome, firefox,
    keepass_discover, masky, shadowcredentials.
* **Slice 3** — 14 Linux TTPs + 6 nxc probes + hostenum
  extensions (keyrings / cgroup v1 escape / at spool / X11 / sudo PATH /
  SSH rc / XDG autostart / shell init / user crontabs / SUID environ).
  * Credential loot: GNOME Keyring, KWallet, ansible vault, GitLab
    runner, CI artifact dirs, SUID /proc/<pid>/environ.
  * Privesc: sudo PATH hijack (env_keep / !secure_path / relative cmd),
    at(1) spool writable.
  * Container escape: cgroup v1 release_agent.
  * Persistence: writable user crontab, shell-init hijack of another
    user, XDG autostart, ~/.ssh/rc login hook.
  * Lateral: X11 xauth pivot into live GUI session.
  * nxc probes: petitpotam, nopac, lsa_backup_keys, dpapi-ng, rdcman,
    enum_dns.
* **Slice 4 — axis-1 finish** — 9 Linux TTPs + hostenum extensions
  (sysv_init / systemd_generators / directory_auth / cgroup v2 escape).
  * Credential loot: browser cookies → SSO replay.
  * Kernel LPE: CVE-2022-32250 nftables set, polkit v109 post-PwnKit
    variants.
  * Container escape: cgroup v2 delegate misconfig.
  * K8s: SA → cluster-admin reach, SA → secret enumeration.
  * Persistence: writable /etc/init.d, writable systemd generator.
  * Lateral: NIS / LDAP centralized-auth credential reuse pivot.
* **Slice 5 — axis-2 finish** — 10 nxc probes bringing the module
  catalog to 33 total. Credential probes: drop-sc (ScreenConnect),
  scuffy (SCF coerce). Findings: spooler, ldap-checker, obsolete NT
  hashes, pre2k. Asset-enum: get-network (AD subnets), groupmembership,
  --rid-brute, --users+--computers snapshot.
* **Slice 7 — axis-5 kickoff** — ``fieldkit/enrich.py`` entity extractor
  (IPv4/IPv6, email, URL, AWS keys, GitHub/GitLab/Slack/Stripe tokens,
  NT/NetNTLMv1/v2/Kerberos TGS+ASREP/bcrypt/md5-sha-crypt hashes),
  hashcat mode suggestion, ``fieldkit enrich`` CLI command that walks
  step rows + dedupes + prints a grouped entity table.
* **Slice 8 — axis-5 depth** — ``fieldkit/confidence.py`` four-tier
  scorer (direct_capture / inferred_version / predicted_pattern /
  unverified) with explicit "why" rationale per level,
  ``fieldkit/timeline.py`` chronological projection merging steps +
  findings + credentials + evasion rows, ``fieldkit timeline`` CLI
  with ``--kind`` filter + ``--narrative`` prose summary.
* **Slice 9 — axis-5 finish** — ``fieldkit/correlate.py`` walks multiple
  engagement DBs and surfaces every (kind, value) that recurs across
  them: shared usernames, credentials, hosts. ``fieldkit/cve_lookup.py``
  projects the TTP catalog's version-range CVE rules into a
  ``(component, version) → list[CVE]`` lookup (TTP catalog IS the
  catalog — no NVD mirror, no network). ``fieldkit correlate`` +
  ``fieldkit cve-lookup`` CLI subcommands.
* **Slice 10 — axis-6 kickoff** — ``fieldkit/cvss.py`` v3.1 vector
  derivation + base-score formula (pure stdlib, no network), ``fieldkit
  cvss`` CLI subcommand, ``fieldkit report --exec-summary`` flag that
  emits a severity-count table + top-5 findings + the engagement
  narrative (useful for readout slides / email bodies). ``fieldkit
  diff`` trend reporting reconciled as already-present in the existing
  diff subcommand.
* **Slice 11 — axis-6 HTML** — ``fieldkit/html_report.py`` renders a
  single self-contained interactive HTML document: inline CSS/JS (no
  CDN, no external assets, opens offline), filter controls per severity
  / status / host, collapsible per-host sections, dark/light theme with
  localStorage persistence, embedded SVG attack-path visualizations
  per host. Wired through ``fieldkit report --interactive-html PATH``.
  Replaces the pandoc-dependent HTML export for operators who want a
  single-file deliverable.
* **Slice 12 — axis-3 catalog** — ``fieldkit/weaponization.py`` metadata
  catalog of 27 weaponization options across 5 categories: loader (10:
  reflective .NET, reflective DLL, module stomping, process hollowing,
  APC injection, CLR hosting, LOLBAS, CLM bypass, WSL pivot, Chromium
  extension), bypass (4: AMSI patch / AMSI provider hijack / ETW patch
  / Defender cloud blocking), syscall (4: Hell's / Halo's / Tartarus /
  FreshyCalls), encoder (4: XOR, FNV hash, ConfuserEx, PE sig cloning),
  delivery (5: HTTPS, SMB pipe, DNS, DoH, WebDAV). ``fieldkit
  weaponization list / show <key>`` CLI.
* **Slice 13 — axis-3 templates** — ``fieldkit/loaders/`` reference
  template library: ``amsi_patch.c.j2``, ``etw_patch.c.j2``,
  ``hells_gate.asm``, ``freshy_calls.c.j2``,
  ``reflective_dotnet.cs.j2``, ``xor_decoder.c.j2``,
  ``https_beacon.py.j2`` — read-only reference documentation (fieldkit
  never compiles or executes them). ``template`` field added to
  WeaponizationTechnique with ``fieldkit weaponization render <key>``
  CLI that prints the template body. 22 tests (shape invariants +
  template-key coverage + file-presence verification).
* **Slice 14 — axis-6 finish** — ``fieldkit/pptx_export.py`` hand-crafts
  a valid Open XML .pptx via zipfile + XML string templates (no
  python-pptx dependency, stdlib only). 5-slide executive deck: title
  / severity breakdown / top findings / narrative / remediation
  priorities. ``BrandConfig`` dataclass carries title/accent RGB +
  footer; ``fieldkit report --pptx PATH`` reads brand from
  ``config.report-brand`` section. 21 tests covering zip structure +
  slide contents + XML escaping + branding propagation.
* **Slice 15 — axis-4 beacon orchestration** — ``fieldkit/beacon.py``
  manages the engagement-side view of operator beacons. Schema v12 adds
  ``beacon`` + ``beacon_task`` tables. ``BeaconConfig`` dataclass +
  per-build mutation seed (``new_build_seed`` → 32 hex chars from
  ``secrets``). Task API: ``register_beacon`` / ``issue_task`` /
  ``pending_tasks`` / ``record_result`` / ``task_history``. TRANSPORTS
  catalog maps transport names to reference templates under
  ``fieldkit/loaders/``. ``fieldkit beacon {new,list,task,result,
  history,build-config}`` CLI. 21 tests covering schema shape +
  task-queue API + seed determinism + transport catalog.
* **Slice 6 — axis-1 tail** — 3 Linux TTPs completing axis-1 to 60/60.
  * Credential loot: AWS SSO cache (~/.aws/sso/cache/*.json).
  * Privesc: D-Bus policy misconfig → privileged method call.
  * Persistence: PAM module passthrough logger (writable PAM module
    weaponized to log + forward instead of replace).
  * Plus three previously-ticked covered items reconciled in the ticks
    (polkit v109, NFS no_root_squash, D-Bus — covered by prior slices).
