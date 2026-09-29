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


# ===================================================================================
# Cross-domain stitching — one graph across ALL domains.
#
# Each domain (cloud IAM, k8s RBAC, SaaS/IdP, web endpoints, …) records its principals
# and edges into the SAME `asset` / `asset_edge` tables, but the per-domain pathfinders
# above search only their own `kind`-subgraph. The real payoff of one asset model is
# linking those islands: an Entra user that federates into an AWS role, a web app whose
# compromise yields a cloud instance role, a cloud node-group role that is a k8s node.
# `cross_domain_paths` runs the SAME owned→high-value BFS over the *whole* graph, so a
# single path can traverse several domains; `derive_pivots` infers the cross-kind links
# that make that possible from shared identity.
# ===================================================================================

#: asset_edge.kind prefix marking a cross-domain pivot (vs. an intra-domain edge).
PIVOT_PREFIX = "pivot:"

#: Extra score for a path that actually crosses domains — an equal-length cross-domain
#: chain outranks a single-domain one (it defeats a domain boundary a defender assumed).
_W_CROSS = 75


def _identity_tokens(row):
    """(props, identity-token-set) for an asset: its key, label, name and any declared
    ``aliases``, lowercased — the strings by which the same identity can be recognised
    across domains."""
    props = json.loads(row["props_json"] or "{}")
    toks = set()
    for v in (row["key"], row["label"], props.get("name")):
        if v:
            toks.add(str(v).strip().lower())
    for a in props.get("aliases") or []:
        if a:
            toks.add(str(a).strip().lower())
    return props, toks


def derive_pivots(store):
    """Infer cross-domain (cross-**kind**) pivot edges linking the same identity across
    domains, so :func:`cross_domain_paths` can traverse from one domain into another.

    Two sources, both conservative:

    * **alias** — a principal carrying an ``aliases`` prop that names an identity in
      another domain gets a directed ``pivot:alias`` edge to it (operator-declared,
      zero-heuristic);
    * **federated identity** — a ``saas_principal`` whose email/UPN (an ``@`` token)
      also names a cloud/k8s principal gets a directed ``pivot:federated identity`` edge
      to it (owning the IdP identity yields the federated one).

    Directed from the identity you would own first (the IdP / alias holder) into the
    linked principal. Synthetic admin-equivalent nodes are skipped. Idempotent. Returns
    the number of pivot edges added."""
    meta = {}
    for a in store.assets():
        props, toks = _identity_tokens(a)
        if props.get("type") == "synthetic":
            continue
        meta[a["id"]] = {
            "kind": a["kind"], "toks": toks,
            "emails": {t for t in toks if "@" in t},
            "aliases": {str(x).strip().lower() for x in (props.get("aliases") or []) if x}}
    added = 0
    for i, mi in meta.items():
        for j, mj in meta.items():
            if i == j or mi["kind"] == mj["kind"]:
                continue                                   # cross-KIND edges only
            if mi["aliases"] & mj["toks"]:
                link = PIVOT_PREFIX + "alias"
            elif mi["kind"] == "saas_principal" and mi["emails"] & mj["emails"]:
                link = PIVOT_PREFIX + "federated identity"
            else:
                continue
            _, created = store.add_asset_edge(i, j, link)
            added += int(created)
    return added


def add_pivot(store, src_kind, src_key, dst_kind, dst_key, label="manual"):
    """Record one explicit cross-domain pivot edge between two existing assets
    (referenced by kind+key). The ``label`` is prefixed ``pivot:``. Returns
    ``(created, error)`` — ``error`` is a message when an endpoint asset is missing."""
    src = store.asset_by_key(src_kind, src_key)
    if src is None:
        return False, f"no {src_kind} asset with key {src_key!r}"
    dst = store.asset_by_key(dst_kind, dst_key)
    if dst is None:
        return False, f"no {dst_kind} asset with key {dst_key!r}"
    if not label.startswith(PIVOT_PREFIX):
        label = PIVOT_PREFIX + label
    _, created = store.add_asset_edge(src["id"], dst["id"], label)
    return created, None


def _bfs_to_other_domain(start, start_kind, adj, nodes, max_depth):
    """Shortest path from ``start`` to a high-value node in a DIFFERENT domain (kind).
    Unlike :func:`fieldkit.bloodhound._bfs`, it steps over a nearer in-domain admin —
    the cross-domain question is 'from this foothold, can I reach admin in another
    domain?', so an in-domain admin is not a valid target. Returns ``(target, hops)``
    or ``(None, [])``."""
    q = deque([(start, [])])
    seen = {start}
    while q:
        sid, path = q.popleft()
        node = nodes.get(sid)
        if node and node["high_value"] and node["kind"] != start_kind and path:
            return sid, path
        if len(path) >= max_depth:
            continue
        for dst, kind in adj.get(sid, []):
            if dst not in seen:
                seen.add(dst)
                q.append((dst, path + [(kind, dst)]))
    return None, []


def cross_domain_paths(store, *, max_depth=10):
    """Every shortest owned→admin escalation path that **crosses a domain boundary**,
    over the unified asset graph (all kinds, all edges incl. pivots). Reaches an admin
    in a domain different from the foothold's (stepping over any nearer in-domain admin),
    scored with the same blast-radius model plus a cross-domain bump; each path carries
    ``domains`` (the ordered kinds it traverses) and renders every node's domain in the
    chain. Ranked worst-first. Read-only."""
    assets = store.assets()
    if not assets:
        return []
    nodes, adj = {}, {}
    for a in assets:
        props = json.loads(a["props_json"] or "{}")
        nodes[a["id"]] = {"high_value": bool(props.get("admin")),
                          "name": a["label"] or a["key"],
                          "kind": a["kind"],
                          "owned": bool(props.get("owned"))}
    for e in store.asset_edges():
        if e["src_id"] in nodes and e["dst_id"] in nodes:
            adj.setdefault(e["src_id"], []).append((e["dst_id"], e["kind"]))
    out = []
    for a in assets:
        nid = a["id"]
        if not nodes[nid]["owned"]:
            continue
        target, hops = _bfs_to_other_domain(
            nid, nodes[nid]["kind"], adj, nodes, max_depth)
        if target is None:
            continue
        kinds = [nodes[nid]["kind"]] + [nodes[d]["kind"] for _, d in hops]
        domains = []
        for k in kinds:
            if k not in domains:
                domains.append(k)
        if len(domains) < 2:
            continue                                       # single-domain — skip
        blast = _downstream_reach(adj, target)
        score = _score_path(len(hops), blast, nodes[target]["high_value"]) + _W_CROSS
        out.append({
            "start_id": nid,
            "start": nodes[nid]["name"],
            "target": nodes[target]["name"],
            "hops": hops,
            "hop_count": len(hops),
            "blast_radius": blast,
            "score": score,
            "priority": _priority_band(score),
            "cross_domain": True,
            "domains": domains,
            "title": f"Cross-domain escalation: {nodes[nid]['name']} ({domains[0]}) → "
                     f"{nodes[target]['name']} (admin, {domains[-1]})",
            "evidence": _render_cross_chain(nodes, nid, hops)})
    out.sort(key=lambda p: (-p["score"], p["hop_count"], p["start"]))
    return out


def record_cross_domain(store):
    """Derive pivots, find cross-domain escalation paths, and record each as an
    (unproven) ``cross_domain_privesc`` finding on its start asset. Idempotent. Returns
    ``(pivots_added, findings_added, paths)``."""
    pivots = derive_pivots(store)
    paths = cross_domain_paths(store)
    added = 0
    for p in paths:
        with store.transaction():
            _, created = store.add_finding(
                "cross_domain_privesc", p["title"], asset_id=p["start_id"],
                evidence=p["evidence"], proven=False)
            added += int(created)
    return pivots, added, paths


def _render_cross_chain(nodes, start_id, hops):
    """`helga [saas] -pivot:federated identity-> helga-aws [cloud] -iam:*-> admin [cloud]`."""
    parts = [f"{nodes[start_id]['name']} [{nodes[start_id]['kind']}]"]
    for kind, dst in hops:
        parts.append(f"-{kind}-> {nodes[dst]['name']} [{nodes[dst]['kind']}]")
    return " ".join(parts)
