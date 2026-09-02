# fieldkit integration tests

The unit tests in `tests/*.py` are hermetic — every subprocess is
mocked, every network call is intercepted. That's fast (1700+
tests in ~2 min) but blind to real-world bugs like:

- impacket arg-name drift between versions
- recce-bridge schema changes
- canon mismatches on real nmap output
- KDC error strings that don't match our marker patterns
- AV behavior on the delivery ladder

Integration tests fire against a live lab environment provisioned
by recce (or the operator). They live in `tests/integration/` and
are gated by an env var so a bare `pytest` never touches
infrastructure.

## Running

```bash
# Bare pytest — unit tests only, no lab needed
pytest

# Integration tests — needs a lab.yaml
export FIELDKIT_INTEGRATION_LAB=/path/to/lab.yaml
pytest tests/integration/ -m integration --override-ini "addopts="

# Or just the tests that don't need the full AD lab:
pytest tests/integration/test_lab_recce_bridge.py -m integration --override-ini "addopts="
```

The `--override-ini "addopts="` clears the default `-m "not
integration"` filter in `pytest.ini`. Without it, the integration
marker is excluded from every `pytest` run.

## lab.yaml schema

The lab config is a single YAML file — recce (or whoever
provisions the lab) writes it, points `FIELDKIT_INTEGRATION_LAB`
at it, and fieldkit's fixtures parse it. Every top-level key is
optional; tests that need a key skip when it's absent.

```yaml
# Full example — omit sections you don't have
dc:
  ip: 10.99.0.10
  hostname: DC01
  domain: LAB.LOCAL

low_priv_cred:
  user: lab_user
  password: 'Winter2025!'
  domain: LAB.LOCAL

recce_bridge: /tmp/recce/lab-scan-bridge.json

vulnerable_services:
  - host: 10.99.0.20
    product: Confluence
    version: 8.5.3
    expected_cve_key: service_cve:2023-22515
  - host: 10.99.0.21
    product: log4j
    version: 2.14.1
    expected_cve_key: service_cve:2021-44228

dpapi_host:
  ip: 10.99.0.30
  user: alice
  password: 'DpapiTest!'
  sid: S-1-5-21-...
  mkey_path: /tmp/staged/mkey-guid       # copied from target
  cred_blob_path: /tmp/staged/cred-blob  # copied from target

# Optional: pin expected outcomes per test key. Tests read via
# lab_expectations fixture. Falls back to test-default when
# unspecified.
expectations:
  chain_run_esc8: proven
  chain_run_nopac: proven
  chain_run_rbcd: aborted    # if lab has SMB signing enabled
  ingest_recce_hosts_min: 5
```

## Handoff contract

- **fieldkit owns** the fixture shape (this file's `## lab.yaml
  schema`) + the assertions each test makes ("chain esc8 walks
  to proven against this DC").
- **recce owns** the lab provisioning + writing lab.yaml with
  the correct addresses + credentials + expected outcomes for
  the environment it stood up.
- A test failure means one of two things: fieldkit regressed, OR
  the lab drifted from the expected state. The test's error
  message names which fixture it needed so recce can diagnose.

## What lives in this directory

- `conftest.py` — fixtures (lab_dc, lab_low_priv_cred,
  lab_recce_bridge, lab_vulnerable_services, lab_windows_dpapi_host,
  lab_expectations, fresh_engagement_db). Every one skips when
  its lab.yaml key is absent.
- `test_lab_recce_bridge.py` — recce → fieldkit bridge round-trip.
- `test_lab_ttp_matching.py` — version-range TTPs against a real
  vulnerable services lab.
- `test_lab_chain_esc8.py` — esc8 chain walks against a real DC.
- `test_lab_chain_nopac.py` — nopac chain walks against a real DC.
- `test_lab_dpapi.py` — DPAPI decrypt end-to-end.

Extend by adding `test_lab_<surface>.py` — every test in this
dir MUST carry the `@pytest.mark.integration` marker or it
won't be gated by the env var.

## CI

`.github/workflows/integration.yml` fires on manual dispatch
only (never on push — labs are billed). Set the
`FIELDKIT_INTEGRATION_LAB` secret to a lab.yaml the runner can
read, then trigger the workflow from the Actions tab.
