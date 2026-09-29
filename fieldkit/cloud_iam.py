"""Cloud IAM privilege-escalation pathing — "BloodHound for cloud" on the asset graph.

The third domain on the asset model. From an enumerated cloud-IAM graph (principals +
the escalation edges between them — ``sts:AssumeRole``, ``iam:PassRole``,
``iam:CreatePolicyVersion``, k8s RBAC bindings, …) it finds the shortest path from a
principal you own to an **admin** principal, and records each reachable path as an
(unproven) ``cloud_privesc`` finding.

Principals are ``asset(kind="cloud_principal")``; escalation edges are ``asset_edge``
rows. The pathfinder is the SAME BFS the AD BloodHound side uses
(:func:`fieldkit.bloodhound._bfs`) — the v10 asset graph lets that owned→high-value
search run over cloud identities with zero new graph code.

fieldkit does not call cloud APIs itself: it ingests a normalized IAM graph (the
operator produces it from their own enumerator — prowler / ScoutSuite / an ``aws iam``
dump / a custom script), the same tool-agnostic handoff as the recce bridge. This
module owns the modelling, the pathfinding and the report.
"""
import json
from dataclasses import dataclass

from . import assetgraph

CLOUD_PRINCIPAL = "cloud_principal"


@dataclass
class CloudReport:
    principals_added: int = 0
    edges_added: int = 0
    paths_found: int = 0
    findings_added: int = 0
    aborted: str = None


def parse_iam(text):
    """Parse a normalized cloud-IAM graph (JSON) into ``(provider, principals, edges)``.

    Shape::

        {"provider": "aws",
         "principals": [{"arn": "...", "name": "...", "type": "user|role",
                         "admin": false, "owned": true}, ...],
         "edges": [{"src": "<arn>", "dst": "<arn>", "kind": "sts:AssumeRole"}, ...]}

    Raises :class:`CloudIamError` on invalid JSON / shape."""
    try:
        doc = json.loads(text) if isinstance(text, str) else text
    except (ValueError, TypeError) as exc:
        raise CloudIamError(f"not valid JSON: {exc}") from None
    if not isinstance(doc, dict):
        raise CloudIamError("expected a JSON object with principals/edges")
    provider = str(doc.get("provider") or "cloud")
    principals, edges = [], []
    for p in doc.get("principals") or []:
        arn = (p.get("arn") or p.get("id") or "").strip()
        if not arn:
            continue
        principals.append({
            "arn": arn,
            "name": (p.get("name") or arn).strip(),
            "type": (p.get("type") or "principal").strip(),
            "admin": bool(p.get("admin")),
            "owned": bool(p.get("owned"))})
    for e in doc.get("edges") or []:
        src, dst = (e.get("src") or "").strip(), (e.get("dst") or "").strip()
        if src and dst:
            edges.append({"src": src, "dst": dst,
                          "kind": (e.get("kind") or "assume").strip()})
    return provider, principals, edges


class CloudIamError(ValueError):
    """A cloud-IAM graph that could not be parsed."""


def apply_iam(store, text):
    """Fold a normalized cloud-IAM graph into state (``cloud_principal`` assets +
    ``asset_edge`` rows) and record a ``cloud_privesc`` finding per owned→admin path.
    Idempotent. The graph persistence + pathfinding + finding-recording is the shared
    :mod:`fieldkit.assetgraph` engine — this module only speaks the cloud-IAM dialect."""
    provider, principals, edges = parse_iam(text)
    graph_principals = [{"key": p["arn"], "name": p["name"], "type": p["type"],
                         "admin": p["admin"], "owned": p["owned"]} for p in principals]
    rep = CloudReport()
    rep.principals_added, rep.edges_added = assetgraph.ingest_graph(
        store, CLOUD_PRINCIPAL, provider, graph_principals, edges)
    rep.findings_added, paths = assetgraph.record_paths(
        store, CLOUD_PRINCIPAL, "cloud_privesc", label="Cloud IAM")
    rep.paths_found = len(paths)
    return rep


def escalation_paths(store, *, max_depth=8):
    """Every shortest owned→admin escalation path in the cloud asset graph."""
    return assetgraph.escalation_paths(store, CLOUD_PRINCIPAL, label="Cloud IAM",
                                       max_depth=max_depth)
