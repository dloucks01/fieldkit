"""Pytest fixtures for fieldkit integration tests.

Every fixture reads from a lab.yaml file whose path is in the
``FIELDKIT_INTEGRATION_LAB`` env var. Without the env var, every
integration test skips — a normal ``pytest`` run doesn't touch
lab infrastructure.

The lab.yaml schema is documented in tests/integration/README.md
and validated per-fixture: a missing ``dc_ip`` key skips only
the tests that ask for that fixture, not every integration
test.

Provisioning is out of scope for fieldkit — recce (or whoever
stands the lab up) writes lab.yaml + points the env var. The
handoff contract is the YAML shape; fixtures here parse it.
"""
import os
import pytest
import tempfile


ENV_VAR = "FIELDKIT_INTEGRATION_LAB"


def _load_lab_config():
    """Read + parse the lab config referenced by
    :data:`ENV_VAR`. Returns the parsed dict, or None when
    the env is unset."""
    path = os.environ.get(ENV_VAR, "").strip()
    if not path:
        return None
    if not os.path.isfile(path):
        pytest.fail(f"{ENV_VAR} points at {path!r} but it doesn't exist")
    from fieldkit.vendor import yaml
    try:
        with open(path) as fh:
            doc = yaml.safe_load(fh)
    except Exception as exc:                                # noqa: BLE001
        pytest.fail(f"{path}: cannot parse lab config: {exc}")
    if not isinstance(doc, dict):
        pytest.fail(f"{path}: lab config must be a top-level mapping")
    return doc


@pytest.fixture(scope="session")
def lab_config():
    """Full lab.yaml — every test may key into it directly, but
    prefer the more specific fixtures below which enforce
    per-key skip behavior."""
    cfg = _load_lab_config()
    if cfg is None:
        pytest.skip(f"integration test — set {ENV_VAR} to enable")
    return cfg


@pytest.fixture(scope="session")
def lab_dc(lab_config):
    """The lab's DC row: {ip, hostname, domain}. Skips when
    the lab.yaml doesn't declare one."""
    dc = lab_config.get("dc")
    if not dc or not dc.get("ip"):
        pytest.skip("lab.yaml has no dc.ip — DC-scoped test skipped")
    return dc


@pytest.fixture(scope="session")
def lab_domain(lab_dc):
    """AD domain string (e.g. 'CORP.LOCAL')."""
    d = lab_dc.get("domain")
    if not d:
        pytest.skip("lab.yaml has no dc.domain")
    return d


@pytest.fixture(scope="session")
def lab_low_priv_cred(lab_config):
    """A low-priv domain credential the lab guarantees exists.
    Shape: {user, password, domain}."""
    cred = lab_config.get("low_priv_cred")
    if not cred or not cred.get("user") or not cred.get("password"):
        pytest.skip("lab.yaml has no low_priv_cred — auth-scoped test skipped")
    return cred


@pytest.fixture(scope="session")
def lab_recce_bridge(lab_config):
    """Path (or URL) to a recce-bridge.json the lab provides."""
    b = lab_config.get("recce_bridge")
    if not b:
        pytest.skip("lab.yaml has no recce_bridge — recce integration skipped")
    return b


@pytest.fixture(scope="session")
def lab_vulnerable_services(lab_config):
    """List of {host, product, version, expected_cve_key}
    entries the lab guarantees vulnerable. Empty list skips."""
    svcs = lab_config.get("vulnerable_services") or []
    if not svcs:
        pytest.skip("lab.yaml has no vulnerable_services")
    return svcs


@pytest.fixture(scope="session")
def lab_windows_dpapi_host(lab_config):
    """Windows host with staged DPAPI artifacts. Shape:
    {ip, user, password, mkey_path, cred_blob_path, sid}."""
    host = lab_config.get("dpapi_host")
    if not host or not host.get("ip"):
        pytest.skip("lab.yaml has no dpapi_host")
    return host


@pytest.fixture(scope="session")
def lab_expectations(lab_config):
    """Test-specific outcome expectations from lab.yaml. Each
    integration test looks up its own key here (see the README
    for the naming convention). Empty dict when the operator
    didn't pin outcomes — tests then fall back to their own
    defaults."""
    return lab_config.get("expectations") or {}


@pytest.fixture
def fresh_engagement_db(tmp_path):
    """A fresh Store with an initialized engagement. Function-
    scoped so each test gets an isolated DB — integration tests
    that mutate state don't cross-contaminate."""
    from fieldkit.state import Store
    db = tmp_path / "eng.db"
    s = Store.create(str(db))
    s.init_engagement("integration-test")
    yield s
    s.close()
