# AGENTS.md — fieldkit project doc for LLM collaborators

Read this file when starting work in this repo. It captures the
load-bearing project stance, architecture invariants, and
conventions that don't live in code but a fresh assistant would
need to know before touching anything substantial.

## What fieldkit is

An offensive security CLI + TUI tool for **authorized** penetration
testing. From a credential, foothold, or scan it drives the operator's
existing tools (netexec, impacket, certipy, bloodhound, httpx, nuclei,
…) against the scope, finds the paths to compromise, and delivers a
report built from captured evidence (not fabricated writeups).

AD is the spine (the credential loop → escalate → SYSTEM/root → DA
paths), but the same store → capture → anti-fabrication-report core is
**multi-domain**: web, external-service (CVE-TTP matching), cloud-IAM
and Kubernetes-RBAC domains ride the shared **asset model** (`asset` /
`asset_edge`) and the shared `assetgraph` pathfinder. A non-AD finding
flows through `report --check` exactly like an AD one. When adding a
domain, add a thin driver that reuses the spine — don't fork it.

The stance is:

- **Assume-caught.** Every technique is red until a Defender lab
  proves it clean; live catches surface via evasion feedback.
- **Anti-fabrication.** A finding cannot render into a report
  without the verbatim commands + output that proved it. This is
  a construction-time guarantee, not a manual check.
- **Defender-signal-aware.** Every chain step ships a detection
  signal catalog (`SIGNALS_*` in chain.py) so the operator sees
  the debt each step accumulates + the report cites the
  defender-visible artifacts.

## Architecture invariants

These are checked mechanically in `tests/test_report.py::ArchitectureTest`
— don't break them. If a change requires touching one, the
invariant test should be updated in the same commit with a
docstring note explaining why.

1. **Only `fieldkit/runner.py` spawns subprocesses.** Every other
   module imports it and calls `runner.run(argv, timeout=…)` /
   `runner.spawn(argv)` / `runner.spawn_detached(argv, cwd=…)`.
   The `test_runner_is_the_only_child_process_spawn` walks the
   whole tree recursively; a bare `import subprocess` outside
   runner.py fails the invariant.
2. **No module does I/O at import time.** `fieldkit --help` (and
   every test) imports everything; a rogue `open()` /
   `urlopen()` / `mkdir()` at module scope fails the invariant.
3. **State goes through `fieldkit/state.py`.** Every read + write
   goes through a `Store` method; no raw SQL scattered across
   handlers.
4. **Only `runner.run` is the shell-out entry point in production
   code**; tests inject a fake `runner.run` when they need to
   exercise a code path without shelling out. The `--yes` flag
   pattern is the standard bypass for tests that hit
   `_confirm()`.

## Layout

```
fieldkit/
├── cli.py            # every subcommand handler, argparse tree
├── state.py          # Store — SQLite engagement DB (schema v12)
├── config.py         # per-engagement config
├── runner.py         # THE subprocess spawn
├── report.py         # markdown + docx/pdf/html render
├── chain.py          # coerce-chain state machine + 5 shipped profiles
├── chain_yaml.py     # user-defined chains from YAML
├── chainlint.py      # coverage audit of the profile catalog
├── bloodhound.py     # BH graph → owned→high-value + chain suggestions
├── doctor.py         # health check (tools + chain lint + engagement + TTPs)
├── session.py        # opt-in JSONL recording + replay
├── ttps/             # 216 shipped TTP YAMLs (T1548-*, T1068-*, T1190-*, …)
│   ├── loader.py     # parse YAML → TTP
│   ├── schema.py     # dataclass shapes
│   └── adapter.py    # TTP → Vector via _d_ttp_yaml
│
│ # analysis depth (axis 5)
├── enrich.py         # entity extractor + hashcat mode suggestion
├── confidence.py     # four-tier scoring (direct_capture → unverified)
├── timeline.py       # chronological event ribbon + prose narrative
├── correlate.py      # cross-engagement overlap (users/creds/hosts)
├── cve_lookup.py     # offline CVE lookup from TTP catalog version ranges
│
│ # reporting polish (axis 6)
├── cvss.py           # CVSS v3.1 vector + base score derivation
├── html_report.py    # self-contained interactive HTML (SVG attack path)
├── pptx_export.py    # stdlib-only hand-crafted Open XML exec deck
│
│ # weaponization + beacon (axes 3, 4)
├── weaponization.py  # 27-entry metadata catalog (loader/bypass/syscall/…)
├── loaders/          # reference templates per catalog entry (.c.j2/.cs.j2/.asm/.py.j2)
├── beacon.py         # beacon metadata + task queue (fieldkit tracks state only)
│
├── tui/              # 8 Textual screens (dashboard/analyze/watch/...
│   └── vendor/       # vendored Textual — DO NOT AUDIT
└── vendor/           # vendored YAML — DO NOT AUDIT
tests/                # 100+ test files; pytest, unittest, subTest (2,456 tests)
```

## Conventions

- **Commit prefixes**: conventional-commits. `feat(scope): message`
  for new capabilities, `fix(scope): message` for real bug fixes,
  `refactor(scope):` / `chore:` / `docs:` / `test:` for the rest.
  `fieldkit changelog` groups by prefix.
- **Arc naming**: "C13" / "C14" style comments in commit messages
  reference multi-slice arcs (e.g. "C14 slice 3"). Individual
  commits carry the slice detail; the arc name is retrospective.
- **Slice granularity**: one commit per user-visible surface, with
  its tests in the same commit. A user says "let's do 5" and each
  gets its own commit + own tests. Full test suite runs at arc end,
  not after each slice.
- **Test isolation**: chain-profile tests that register synthetic
  profiles MUST snapshot + restore `chain._PROFILES` via
  `addCleanup` — otherwise pollution across tests trips downstream
  assertions like `chain lint` and `doctor`'s shipped-catalog pins.
- **Tool-not-found paths**: TTP actions that shell out use
  `shutil.which(...)`; test the manual-fallback branch by
  monkey-patching `shutil.which = lambda _: None` in setUp with
  addCleanup. Test the live branch by monkey-patching
  `runner_mod.run = lambda argv, timeout=None: canned_result`.

## Running

```bash
# Full test suite (100+ files; ~2 min)
python3 -m pytest

# Fast subset while iterating
python3 -m pytest tests/test_chain.py -q

# Live commands (all read-only)
python3 -m fieldkit doctor              # health check
python3 -m fieldkit chain lint          # audit the shipped profile catalog
python3 -m fieldkit ttps validate fieldkit/ttps/  # schema-validate the catalog
python3 -m fieldkit changelog --since HEAD~20  # git-log → markdown
python3 -m fieldkit engagements list    # cross-engagement view
```

## The 2 pre-existing test failures

`tests/test_cli.py::InitTest::test_init_runs_preflight_inline` +
`tests/test_cli.py::OneShotSprayTest::test_hosts_flag_scopes_in_before_spraying`
have been failing since long before the current arc — they depend
on system state (which tools are installed on the test-runner box)
that varies between environments. **Do not touch them** unless the
user asks explicitly. Every other test is expected to pass.

## What to do first

If the user asks something ambiguous:
1. Run `python3 -m fieldkit doctor` — one command gives you the
   whole install + engagement state in ~3 seconds.
2. Read the module they're asking about (`fieldkit/<module>.py`)
   before making assumptions — most modules have a header
   docstring that explains the stance.
3. Check `git log --oneline -20` to see what's been shipping
   recently — the arc context often makes the next-step
   obvious.
