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


#: The synthetic high-value node self-escalation primitives point at. A subject that can
#: grant itself cluster-admin (or run as a subject that can) reaches this; paths render
#: as ``app -bind clusterroles-> cluster-admin-equivalent``.
ADMIN_EQUIV_ID = "k8s:cluster-admin-equivalent"

#: Well-known Kubernetes RBAC privilege-escalation primitives: holding these
#: ``(verb, resource)`` grants lets a subject reach cluster-admin. Each rule is
#: (label, [(verb, resource), … all required]).
_K8S_PRIVESC_RULES = [
    ("*/*", [("*", "*")]),                                     # explicit cluster-admin
    ("bind clusterroles", [("bind", "clusterroles")]),         # bind an admin role to self
    ("escalate clusterroles", [("escalate", "clusterroles")]),
    ("create clusterrolebindings", [("create", "clusterrolebindings")]),
    ("create rolebindings", [("create", "rolebindings")]),
    ("impersonate users", [("impersonate", "users")]),
    ("impersonate groups", [("impersonate", "groups")]),
    ("impersonate serviceaccounts", [("impersonate", "serviceaccounts")]),
    ("get secrets", [("get", "secrets")]),                     # read SA tokens
    ("list secrets", [("list", "secrets")]),
    ("create pods", [("create", "pods")]),                     # mount a privileged SA token
    ("create pods/exec", [("create", "pods/exec")]),
    ("create daemonsets", [("create", "daemonsets")]),
    ("create deployments", [("create", "deployments")]),
]


def _rbac_holds(held, verb, resource):
    """True when the grant set covers ``(verb, resource)``, honoring the `*` wildcard on
    either the verb or the resource (RBAC allows ``verbs: ["*"]`` / ``resources: ["*"]``)."""
    return any(f"{v} {r}" in held
               for v in (verb, "*") for r in (resource, "*"))


def derive_edges(subjects):
    """Derive self-escalation-to-cluster-admin edges from each subject's grants, using
    :data:`_K8S_PRIVESC_RULES`. Returns ``(edges, admin_equiv_needed)`` — edges point at
    :data:`ADMIN_EQUIV_ID`. First matching primitive per subject wins."""
    edges, needed = [], False
    for s in subjects:
        held = {" ".join(x.lower().split()) for x in (s.get("permissions") or [])}
        if not held:
            continue
        for label, required in _K8S_PRIVESC_RULES:
            if all(_rbac_holds(held, v, r) for v, r in required):
                edges.append({"src": s["key"], "dst": ADMIN_EQUIV_ID, "kind": label})
                needed = True
                break
    return edges, needed


def rules():
    """The RBAC privesc primitives the derivation recognizes: ``[(label, [(verb, resource)])]``. Exposed so `fieldkit cloud rules` / `k8s rules` can show an operator
    exactly what the permission-derivation checks for."""
    return list(_K8S_PRIVESC_RULES)


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
                       "admin": false, "owned": true,
                       "permissions": ["create pods", "bind clusterroles", ...]}, ...],
         "edges": [{"src": "sa:ns/a", "dst": "sa:ns/b", "kind": "pods/create"}, ...]}

    ``admin`` marks a cluster-admin-equivalent subject (the high-value target);
    ``owned`` marks a subject the assessment controls (a foothold pod's SA).
    ``permissions`` is optional — ``"<verb> <resource>"`` grants (e.g. from
    ``kubectl auth can-i --list``); when present, escalation edges are *derived* from
    it (see :func:`derive_edges`) so you can feed a raw grants dump instead of a
    pre-computed graph. ``edges`` are still honored and merged. Raises
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
            "owned": bool(s.get("owned")),
            "props": s.get("props") or {},
            "permissions": [str(x) for x in (s.get("permissions") or [])]})
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
    derived, admin_needed = derive_edges(subjects)
    if admin_needed and not any(s["key"] == ADMIN_EQUIV_ID for s in subjects):
        subjects.append({
            "key": ADMIN_EQUIV_ID, "name": "cluster-admin-equivalent (self-grant)",
            "type": "synthetic", "admin": True, "owned": False})
    rep = K8sReport()
    rep.subjects_added, rep.edges_added = assetgraph.ingest_graph(
        store, K8S_SUBJECT, cluster, subjects, edges + derived)
    rep.findings_added, paths = assetgraph.record_paths(
        store, K8S_SUBJECT, "k8s_privesc", label="Kubernetes RBAC")
    rep.paths_found = len(paths)
    return rep


def escalation_paths(store, *, max_depth=8):
    """Every shortest owned→admin RBAC escalation path in the k8s subject graph."""
    return assetgraph.escalation_paths(store, K8S_SUBJECT, label="Kubernetes RBAC",
                                       max_depth=max_depth)
