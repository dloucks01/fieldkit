"""Pytest fixtures for fieldkit integration tests — folder-first.

Recce provisions a lab + stashes every artifact in a single
engagement folder with a canonical layout. Fieldkit reads it
via `fieldkit sync <folder>`; integration tests read the same
folder + assert what should be true after a sync.

The env var is ``FIELDKIT_INTEGRATION_LAB`` and it points at the
folder root. A single-file lab.yaml sits inside the folder to
declare the lab's identity (dc.ip, low_priv_cred, expectations)
— everything else fixtures learn by walking the folder shape.

Folder layout (recce writes this; fieldkit reads it):

    <lab-folder>/
    ├── lab.yaml               # dc.ip, low_priv_cred, expectations
    ├── recce-bridge.json      # authoritative bridge
    ├── nmap/                  # optional raw scans
    ├── nxc/                   # optional capture logs
    ├── bloodhound/            # optional SharpHound zip/JSON
    ├── loot/                  # optional hashcat potfiles
    ├── dpapi/                 # optional staged DPAPI artifacts
    │   ├── mkey-<guid>
    │   ├── cred-<guid>
    └── notes.md               # ignored — for operator use

A missing section skips only the tests that ask for it.
Provisioning is out of scope for fieldkit — recce owns the
folder + its contents; fieldkit owns the sync + assertions.
"""
import os
import pytest


ENV_VAR = "FIELDKIT_INTEGRATION_LAB"


def _load_lab_root():
    """Read + validate the lab folder referenced by the env var."""
    root = os.environ.get(ENV_VAR, "").strip()
    if not root:
        return None
    if not os.path.isdir(root):
        pytest.fail(
            f"{ENV_VAR} points at {root!r} which isn't a directory. "
            "Point it at the engagement folder root, not a file.")
    return root


def _load_lab_yaml(root):
    """Read + parse <root>/lab.yaml — the identity declaration."""
    path = os.path.join(root, "lab.yaml")
    if not os.path.isfile(path):
        pytest.fail(
            f"{root}/lab.yaml is missing — recce should write it "
            "with dc.ip, low_priv_cred, expectations (see "
            "tests/integration/README.md).")
    from fieldkit.vendor import yaml
    try:
        with open(path) as fh:
            doc = yaml.safe_load(fh)
    except Exception as exc:                                # noqa: BLE001
        pytest.fail(f"{path}: cannot parse: {exc}")
    if not isinstance(doc, dict):
        pytest.fail(f"{path}: must be a top-level mapping")
    return doc


@pytest.fixture(scope="session")
def lab_folder():
    """Absolute path to the engagement folder root — the primary
    fixture; every other fixture derives from it or lab.yaml
    inside it."""
    root = _load_lab_root()
    if root is None:
        pytest.skip(f"integration test — set {ENV_VAR} to enable")
    return root


@pytest.fixture(scope="session")
def lab_config(lab_folder):
    """Parsed lab.yaml — the identity declaration."""
    return _load_lab_yaml(lab_folder)


@pytest.fixture(scope="session")
def lab_dc(lab_config):
    """DC identity: {ip, hostname, domain}. Skips when absent."""
    dc = lab_config.get("dc")
    if not dc or not dc.get("ip"):
        pytest.skip("lab.yaml has no dc.ip — DC-scoped test skipped")
    return dc


@pytest.fixture(scope="session")
def lab_domain(lab_dc):
    """AD domain string."""
    d = lab_dc.get("domain")
    if not d:
        pytest.skip("lab.yaml has no dc.domain")
    return d


@pytest.fixture(scope="session")
def lab_low_priv_cred(lab_config):
    """{user, password, domain} — a low-priv AD account the lab
    guarantees works."""
    cred = lab_config.get("low_priv_cred")
    if not cred or not cred.get("user") or not cred.get("password"):
        pytest.skip("lab.yaml has no low_priv_cred")
    return cred


@pytest.fixture(scope="session")
def lab_expectations(lab_config):
    """Per-test pinned outcomes from lab.yaml — falls back to
    empty dict when the operator didn't pin."""
    return lab_config.get("expectations") or {}


@pytest.fixture(scope="session")
def lab_dpapi_artifacts(lab_folder, lab_config):
    """DPAPI staging inside the lab folder: expects
    <lab-folder>/dpapi/mkey-* and cred-* to exist, plus
    lab.yaml.dpapi.sid + password. Skips when either side missing."""
    dpapi_cfg = lab_config.get("dpapi") or {}
    if not dpapi_cfg.get("sid") or not dpapi_cfg.get("password"):
        pytest.skip("lab.yaml has no dpapi.sid + dpapi.password")
    dpapi_dir = os.path.join(lab_folder, "dpapi")
    if not os.path.isdir(dpapi_dir):
        pytest.skip(f"{dpapi_dir}/ missing — recce should stage a "
                    "DPAPI master key + credential blob there")
    import glob
    mkeys = sorted(glob.glob(os.path.join(dpapi_dir, "mkey-*")))
    blobs = sorted(glob.glob(os.path.join(dpapi_dir, "cred-*")))
    if not mkeys or not blobs:
        pytest.skip(f"{dpapi_dir}/ has no mkey-* or cred-* files")
    return {**dpapi_cfg,
            "mkey_path": mkeys[0],
            "cred_blob_path": blobs[0]}


@pytest.fixture(scope="session")
def lab_vulnerable_services(lab_config):
    """Declared vulnerable services — each {host, product,
    version, expected_cve_key}. Empty list skips."""
    svcs = lab_config.get("vulnerable_services") or []
    if not svcs:
        pytest.skip("lab.yaml has no vulnerable_services")
    return svcs


@pytest.fixture
def fresh_engagement_db(tmp_path):
    """Function-scoped isolated engagement DB — every test gets
    a fresh Store so state mutations don't cross-contaminate."""
    from fieldkit.state import Store
    db = tmp_path / "eng.db"
    s = Store.create(str(db))
    s.init_engagement("integration-test")
    yield s
    s.close()


@pytest.fixture
def synced_engagement(fresh_engagement_db, lab_folder):
    """A fresh engagement with `fieldkit sync <lab_folder>`
    already applied. Most integration tests want this — they
    care about assertions post-sync, not the sync mechanics."""
    from fieldkit import engagement_sync
    engagement_sync.sync_folder(fresh_engagement_db, lab_folder)
    return fresh_engagement_db
