# fieldkit integration tests

The unit tests in `tests/*.py` are hermetic — every subprocess
mocked, every network call intercepted. That's fast (1700+ tests
in ~2 min) but blind to real-world bugs like:

- impacket arg-name drift between versions
- recce-bridge schema changes
- canon mismatches on real nmap output
- KDC error strings that don't match our marker patterns

Integration tests fire against a lab environment recce
provisions + populates. They live in `tests/integration/` and
are gated by an env var pointing at the lab folder.

## The natural flow

Recce provisions the lab + stashes everything in one engagement
folder:

```
lab-eng/
├── lab.yaml               # identity + expectations
├── recce-bridge.json      # THE authoritative bridge
├── nmap/                  # raw nmap outputs
│   └── scan.xml
├── nxc/                   # optional capture logs
│   └── spray.log
├── bloodhound/            # optional SharpHound zip
│   └── 20260901.zip
├── loot/                  # optional cracked hashes
│   └── hashcat.potfile
└── dpapi/                 # optional DPAPI staging
    ├── mkey-<guid>
    └── cred-<guid>
```

Fieldkit reads it via `fieldkit sync <folder>` — one command
ingests every recognized artifact. Integration tests point at
the same folder + assert what should be true post-sync.

## lab.yaml — identity + expectations

The only hand-authored file. Everything else recce writes.

```yaml
dc:
  ip: 10.99.0.10
  hostname: DC01
  domain: LAB.LOCAL
  ca_hostname: ca01.lab.local     # optional; used by esc8 test
  listener_ip: 10.99.0.100        # attacker box for relay

low_priv_cred:
  user: lab_user
  password: 'Winter2025!'
  domain: LAB.LOCAL

vulnerable_services:              # optional; drives ttp-matching test
  - host: 10.99.0.20
    product: Confluence
    version: 8.5.3
    expected_cve_key: service_cve:2023-22515
  - host: 10.99.0.21
    product: log4j
    version: 2.14.1
    expected_cve_key: service_cve:2021-44228

dpapi:                            # optional; drives dpapi test
  sid: S-1-5-21-1000-1000-1000-1001
  password: 'DpapiTest!'
  # mkey_path/cred_blob_path auto-detected from <lab-folder>/dpapi/mkey-* / cred-*

expectations:                     # optional; per-test outcome pins
  sync_hosts_min: 5
  chain_run_esc8: proven
  chain_run_nopac: proven         # or 'aborted' if lab is patched
```

## Running

```bash
# Bare pytest — unit tests only, no lab needed
pytest

# Integration tests — set env to the lab folder
export FIELDKIT_INTEGRATION_LAB=/path/to/lab-eng
pytest tests/integration/ -m integration --override-ini "addopts="

# Just the sync round-trip (safe to run against any lab folder)
pytest tests/integration/test_lab_recce_bridge.py -m integration \
       --override-ini "addopts="
```

The `--override-ini "addopts="` clears the default `-m "not
integration"` filter in `pytest.ini`. Without it, integration
tests are excluded from every `pytest` invocation.

## The handoff contract

- **recce owns** the folder + populating it (bridge, raw scans,
  BH zips, cracked hashes, DPAPI staging when applicable) +
  writing lab.yaml with the correct addresses + credentials +
  expected outcomes.
- **fieldkit owns** the `sync` mechanics + the assertions each
  test makes ("chain esc8 walks to proven against this DC after
  sync").
- A test failure means one of two things: fieldkit regressed,
  OR the lab drifted from the expected state. The error message
  names which fixture it needed + which artifact was missing,
  so recce can diagnose.

## Tests currently shipped

- `test_lab_recce_bridge.py` — sync round-trip: bridge
  processes, idempotency, host-count floor, vector_types map
  to reportkb.
- `test_lab_ttp_matching.py` — declared-vulnerable services
  surface their expected CVE keys via analyze.
- `test_lab_chain_esc8.py` — esc8 chain walks against real DC
  → status matches expectation.
- `test_lab_chain_nopac.py` — nopac chain walks against real
  DC → status matches expectation (proven vulnerable / aborted
  patched).
- `test_lab_dpapi.py` — masterkey + credential decrypt against
  staged artifacts.

Extend by adding `test_lab_<surface>.py` — every test in this
dir MUST carry `@pytest.mark.integration` or the gate won't
skip it during a bare pytest run.

## CI

`.github/workflows/integration.yml` fires on manual dispatch
only (never on push — labs are billed + carry live creds). The
runner needs the `FIELDKIT_INTEGRATION_LAB_YAML` secret with
the lab.yaml content (fieldkit writes it into a tmp folder;
you'd also need a way to sync the folder's other artifacts —
easiest: recce hosts the folder + the workflow rsyncs it before
running).
