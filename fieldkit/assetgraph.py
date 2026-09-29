"""Generic owned→admin escalation pathing over the asset graph.

The engine behind cloud IAM (``cloud_principal``) and k8s RBAC (``k8s_subject``), and
any future "principal A can become principal B" domain. A principal is an ``asset`` of
some ``kind`` carrying ``owned`` / ``admin`` flags in its props; escalation
relationships are ``asset_edge`` rows. This finds the shortest path from an owned
principal to an admin one — reusing :func:`fieldkit.bloodhound._bfs`, the SAME
owned→high-value BFS the AD BloodHound side uses, over the ``kind``-subgraph.

A domain module (``cloud_iam``, ``k8s``) parses its own enumerator output into a common
``(principals, edges)`` shape, calls :func:`ingest_graph` to persist it, then
:func:`record_paths` to find + record the escalation findings. Zero graph code per
domain.
"""
import json
from collections import deque

from .bloodhound import _bfs

#: Priority scoring. A path's score rewards a SHORT chain (fewer hops = less that can
#: fail, faster to execute) and a LARGE blast radius (how many further principals the
#: admin target dominates downstream — its lateral reach once compromised), plus a
#: target-privilege term for landing on an admin-equivalent node. The exact weights are
#: a transparent heuristic: what matters is the *ordering* (worst-first) and the band.
#: See :func:`_score_path` / :func:`_priority_band`.
_EASE_FLOOR = 1
_EASE_BASE = 6      # ease = max(FLOOR, BASE - hop_count): 1 hop → 5 … ≥5 hops → 1
_W_EASE = 100
_W_BLAST = 5
_W_ADMIN = 50


def _score_path(hop_count, blast_radius, target_admin):
    """Blast-radius priority score for an owned→admin path (higher = act first)."""
    ease = max(_EASE_FLOOR, _EASE_BASE - hop_count)
    return ease * _W_EASE + blast_radius * _W_BLAST + (_W_ADMIN if target_admin else 0)


def _priority_band(score):
    """Map a score to an operator-facing band."""
    if score >= 500:
        return "Critical"
    if score >= 350:
        return "High"
    if score >= 200:
        return "Medium"
    return "Low"


def _downstream_reach(adj, start):
    """Count of distinct principals reachable *from* ``start`` (its blast radius —
    the lateral footprint an attacker inherits on compromising it). Excludes start."""
    seen, q = set(), deque([start])
    while q:
        sid = q.popleft()
        for dst, _ in adj.get(sid, []):
            if dst not in seen:
                seen.add(dst)
                q.append(dst)
    seen.discard(start)
    return len(seen)


def ingest_graph(store, kind, provider, principals, edges):
    """Persist a principal/edge graph as ``asset(kind)`` + ``asset_edge`` rows.

    ``principals``: ``[{"key", "name", "type", "admin", "owned", ...extra props}]``.
    ``edges``: ``[{"src", "dst", "kind"}]`` (src/dst are principal keys).
    Idempotent. Returns ``(principals_added, edges_added)``."""
    p_added = e_added = 0
    id_by_key = {}
    with store.transaction():
        for p in principals:
            key = p["key"]
            props = {"provider": provider, "type": p.get("type"),
                     "admin": bool(p.get("admin")), "owned": bool(p.get("owned"))}
            props.update(p.get("props") or {})
            aid, created = store.add_asset(kind, key, label=p.get("name") or key,
                                           props=props)
            id_by_key[key] = aid
            p_added += created
        for e in edges:
            src, dst = id_by_key.get(e["src"]), id_by_key.get(e["dst"])
            if src is None or dst is None:
                continue   # edge references a principal not in the graph — skip
            _, created = store.add_asset_edge(src, dst, e.get("kind") or "escalate")
            e_added += created
    return p_added, e_added


def escalation_paths(store, kind, *, label, max_depth=8):
    """Every shortest owned→admin escalation path in the ``kind`` subgraph, via the
    shared BFS. Returns ``[{start_id, start, target, hops, hop_count, blast_radius,
    score, priority, title, evidence}]``, ranked worst-first (highest score).

    "owned" = a principal flagged owned (our foothold); "admin" (high-value) = a
    principal flagged admin. ``label`` names the domain in the finding title
    (e.g. "Cloud IAM", "Kubernetes RBAC"). Each path also carries a blast-radius
    priority (see :func:`_score_path`): short chains onto high-reach targets rank
    first. Read-only."""
    principals = store.assets(kind)
    if not principals:
        return []
    nodes, adj = {}, {}
    for a in principals:
        props = json.loads(a["props_json"] or "{}")
        nodes[a["id"]] = {"high_value": bool(props.get("admin")),
                          "name": a["label"] or a["key"],
                          "owned": bool(props.get("owned"))}
    for e in store.asset_edges():
        if e["src_id"] in nodes and e["dst_id"] in nodes:
            adj.setdefault(e["src_id"], []).append((e["dst_id"], e["kind"]))
    out = []
    for a in principals:
        if not nodes[a["id"]]["owned"]:
            continue
        target, hops = _bfs(a["id"], adj, nodes, max_depth)
        if target is None:
            continue
        blast = _downstream_reach(adj, target)
        score = _score_path(len(hops), blast, nodes[target]["high_value"])
        out.append({
            "start_id": a["id"],
            "start": nodes[a["id"]]["name"],
            "target": nodes[target]["name"],
            "hops": hops,
            "hop_count": len(hops),
            "blast_radius": blast,
            "score": score,
            "priority": _priority_band(score),
            "title": f"{label} escalation: {nodes[a['id']]['name']} → "
                     f"{nodes[target]['name']} (admin)",
            "evidence": _render_chain(nodes, a["id"], hops)})
    # worst-first: highest score, then shortest chain, then stable by name
    out.sort(key=lambda p: (-p["score"], p["hop_count"], p["start"]))
    return out


def record_paths(store, kind, vector_type, *, label):
    """Record each owned→admin path as an (unproven) ``vector_type`` finding on its
    start principal. Observations — a reachable path, not yet walked — so
    ``report --check`` treats them as observations. Idempotent. Returns
    ``(findings_added, paths)``."""
    paths = escalation_paths(store, kind, label=label)
    added = 0
    for p in paths:
        with store.transaction():
            _, created = store.add_finding(
                vector_type, p["title"], asset_id=p["start_id"],
                evidence=p["evidence"], proven=False)
            added += created
    return added, paths


def _render_chain(nodes, start_id, hops):
    """`app -pods/create-> ci -bind-> cluster-admin`."""
    parts = [nodes[start_id]["name"]]
    for kind, dst in hops:
        parts.append(f"-{kind}-> {nodes[dst]['name']}")
    return " ".join(parts)
