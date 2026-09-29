"""Kubernetes RBAC privilege-escalation pathing — the fourth domain on the asset model.

From an enumerated RBAC graph (subjects — service accounts / users / groups — plus the
escalation edges between them: ``pods/create`` to mount another SA's token, the ``bind``
verb to grant yourself a role, ``impersonate``, ``secrets/get`` to read a token, the
``escalate`` verb, …) it finds the shortest path from a subject you control to a
cluster-admin-equivalent subject, and records each reachable path as an (unproven)
``k8s_privesc`` finding.

It is a thin dialect over :mod:`fieldkit.assetgraph`: subjects are
``asset(kind="k8s_subject")``, RBAC escalation relationships are ``asset_edge`` rows,
and the owned→admin search is the SAME :func:`fieldkit.bloodhound._bfs` the AD and cloud
sides use. fieldkit calls no cluster APIs itself — it ingests a normalized RBAC graph
the operator produces from their own enumerator (``kubectl auth can-i --list`` output,
rbac-tool, kubiscan, a custom script), the same tool-agnostic handoff as recce.
"""
import json
from dataclasses import dataclass

from . import assetgraph

K8S_SUBJECT = "k8s_subject"


class K8sRbacError(ValueError):
    """A k8s RBAC graph that could not be parsed."""


@dataclass
class K8sReport:
    subjects_added: int = 0
    edges_added: int = 0
    paths_found: int = 0
    findings_added: int = 0


def parse_rbac(text):
    """Parse a normalized k8s RBAC graph (JSON) into ``(cluster, subjects, edges)``.

    Shape::

        {"cluster": "prod",
         "subjects": [{"id": "sa:ns/name", "name": "...", "kind": "serviceaccount",
                       "admin": false, "owned": true}, ...],
         "edges": [{"src": "sa:ns/a", "dst": "sa:ns/b", "kind": "pods/create"}, ...]}

    ``admin`` marks a cluster-admin-equivalent subject (the high-value target);
    ``owned`` marks a subject the assessment controls (a foothold pod's SA). Raises
    :class:`K8sRbacError` on invalid JSON / shape."""
    try:
        doc = json.loads(text) if isinstance(text, str) else text
    except (ValueError, TypeError) as exc:
        raise K8sRbacError(f"not valid JSON: {exc}") from None
    if not isinstance(doc, dict):
        raise K8sRbacError("expected a JSON object with subjects/edges")
    cluster = str(doc.get("cluster") or "cluster")
    subjects, edges = [], []
    for s in doc.get("subjects") or []:
        sid = (s.get("id") or s.get("name") or "").strip()
        if not sid:
            continue
        subjects.append({
            "key": sid,
            "name": (s.get("name") or sid).strip(),
            "type": (s.get("kind") or "serviceaccount").strip(),
            "admin": bool(s.get("admin")),
            "owned": bool(s.get("owned"))})
    for e in doc.get("edges") or []:
        src, dst = (e.get("src") or "").strip(), (e.get("dst") or "").strip()
        if src and dst:
            edges.append({"src": src, "dst": dst,
                          "kind": (e.get("kind") or "rbac").strip()})
    return cluster, subjects, edges


def apply_rbac(store, text):
    """Fold a normalized k8s RBAC graph into state and record each owned→admin
    escalation path as a ``k8s_privesc`` finding. Idempotent. Delegates the graph
    persistence, pathfinding and recording to :mod:`fieldkit.assetgraph`."""
    cluster, subjects, edges = parse_rbac(text)
    rep = K8sReport()
    rep.subjects_added, rep.edges_added = assetgraph.ingest_graph(
        store, K8S_SUBJECT, cluster, subjects, edges)
    rep.findings_added, paths = assetgraph.record_paths(
        store, K8S_SUBJECT, "k8s_privesc", label="Kubernetes RBAC")
    rep.paths_found = len(paths)
    return rep


def escalation_paths(store, *, max_depth=8):
    """Every shortest owned→admin RBAC escalation path in the k8s subject graph."""
    return assetgraph.escalation_paths(store, K8S_SUBJECT, label="Kubernetes RBAC",
                                       max_depth=max_depth)
