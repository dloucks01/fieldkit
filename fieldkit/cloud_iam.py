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

from .bloodhound import _bfs

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
    """Fold a normalized cloud-IAM graph into state: principals → ``cloud_principal``
    assets, escalation relationships → ``asset_edge`` rows. Idempotent. Then run the
    pathfinder and record a ``cloud_privesc`` finding per owned→admin path."""
    provider, principals, edges = parse_iam(text)
    rep = CloudReport()
    id_by_arn = {}
    with store.transaction():
        for p in principals:
            aid, created = store.add_asset(
                CLOUD_PRINCIPAL, p["arn"], label=p["name"],
                props={"provider": provider, "type": p["type"],
                       "admin": p["admin"], "owned": p["owned"]})
            id_by_arn[p["arn"]] = aid
            rep.principals_added += created
        for e in edges:
            src, dst = id_by_arn.get(e["src"]), id_by_arn.get(e["dst"])
            if src is None or dst is None:
                continue   # edge references a principal not in the graph — skip
            _, created = store.add_asset_edge(src, dst, e["kind"])
            rep.edges_added += created
    # record findings for reachable owned→admin paths
    for path in escalation_paths(store):
        with store.transaction():
            _, created = store.add_finding(
                "cloud_privesc", path["title"], asset_id=path["start_id"],
                evidence=path["evidence"], proven=False)
            rep.findings_added += created
        rep.paths_found += 1
    return rep


def escalation_paths(store, *, max_depth=8):
    """Every shortest owned→admin escalation path in the cloud asset graph, via the
    shared BFS. Returns a list of ``{start_id, start, target, hops, title, evidence}``.

    "owned" = a principal flagged owned (we hold its credential / it's our foothold);
    "admin" (high-value) = a principal flagged admin. Read-only."""
    principals = store.assets(CLOUD_PRINCIPAL)
    if not principals:
        return []
    by_id = {a["id"]: a for a in principals}
    # nodes/adj in the exact shape bloodhound._bfs expects: keyed by asset id.
    nodes, adj = {}, {}
    for a in principals:
        props = json.loads(a["props_json"] or "{}")
        nodes[a["id"]] = {"high_value": bool(props.get("admin")),
                          "name": a["label"] or a["key"]}
    for e in store.asset_edges():
        if e["src_id"] in nodes and e["dst_id"] in nodes:
            adj.setdefault(e["src_id"], []).append((e["dst_id"], e["kind"]))
    out = []
    for a in principals:
        props = json.loads(a["props_json"] or "{}")
        if not props.get("owned"):
            continue
        target, hops = _bfs(a["id"], adj, nodes, max_depth)
        if target is None:
            continue
        chain = _render_chain(by_id, nodes, a["id"], hops)
        out.append({
            "start_id": a["id"],
            "start": nodes[a["id"]]["name"],
            "target": nodes[target]["name"],
            "hops": hops,
            "title": f"Cloud IAM escalation: {nodes[a['id']]['name']} → "
                     f"{nodes[target]['name']} (admin)",
            "evidence": chain})
    out.sort(key=lambda p: (len(p["hops"]), p["start"]))
    return out


def _render_chain(by_id, nodes, start_id, hops):
    """`dev -sts:AssumeRole-> deploy -iam:PassRole-> admin`."""
    parts = [nodes[start_id]["name"]]
    for kind, dst in hops:
        parts.append(f"-{kind}-> {nodes[dst]['name']}")
    return " ".join(parts)
