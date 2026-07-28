"""BloodHound ingest — turn the graph into "can what I own reach Domain Admin?".

SharpHound collects the AD graph; BloodHound draws it. fieldkit does not need the UI —
it needs one answer the engagement turns on: *does a principal I already own reach a
high-value target, and by what path?* This module ingests SharpHound JSON, stores the
control graph (MemberOf, AdminTo, and the dangerous ACEs — GenericAll, WriteDacl,
AddKeyCredentialLink, …), and path-finds from fieldkit's *owned* credentials to any
high-value node (Domain/Enterprise Admins, BUILTIN\\Administrators, or anything
BloodHound flagged high-value).

The result surfaces in ``analyze`` as a concrete next move — "jdoe →MemberOf→ IT
Admins →GenericAll→ Domain Admins" — grounded in credentials fieldkit actually holds.
Loading is pure; pathfinding runs over the persisted graph, so it stays correct as the
credential set grows.
"""
import json
import os
import zipfile
from collections import deque

#: ACE rights that let the holder take over the target object — the edges worth pathing.
DANGEROUS_ACES = {
    "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns", "AddMember",
    "ForceChangePassword", "AllExtendedRights", "AddKeyCredentialLink",
    "AddAllowedToAct", "WriteAccountRestrictions", "AddSelf",
}

#: domain-relative RIDs / well-known SIDs that are high-value by definition.
_PRIV_RIDS = {"512", "519", "518", "516", "520"}   # DA, EA, Schema, DC, GPCO
_WELLKNOWN_HV = {"S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-551"}

_NTYPE = {"users": "User", "groups": "Group", "computers": "Computer",
          "domains": "Domain", "ous": "OU", "gpos": "GPO", "containers": "Container"}


def _is_high_value(sid, props):
    if props.get("highvalue") is True:
        return True
    if sid in _WELLKNOWN_HV:
        return True
    return sid.rsplit("-", 1)[-1] in _PRIV_RIDS


def _read_docs(path):
    """Yield parsed SharpHound JSON documents from a .zip, a directory, or a .json."""
    if os.path.isdir(path):
        for fn in sorted(os.listdir(path)):
            if fn.endswith(".json"):
                with open(os.path.join(path, fn), errors="replace") as fh:
                    yield json.load(fh)
    elif zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                if name.endswith(".json"):
                    yield json.loads(z.read(name))
    elif path.endswith(".json"):
        with open(path, errors="replace") as fh:
            yield json.load(fh)
    else:
        raise ValueError(f"{path}: not a SharpHound .zip, directory, or .json")


def load(path):
    """Parse SharpHound output into ``(nodes, edges)`` — pure, no store.

    ``nodes`` are ``{sid, name, ntype, high_value}``; ``edges`` are ``{src, dst, kind}``
    in the direction control flows (a member points at its group, an admin at its
    computer, an ACE holder at its target).
    """
    nodes, edges = {}, []
    for doc in _read_docs(path):
        ntype = _NTYPE.get((doc.get("meta") or {}).get("type", ""), "")
        for obj in doc.get("data") or []:
            sid = obj.get("ObjectIdentifier")
            if not sid:
                continue
            props = obj.get("Properties") or {}
            nodes[sid] = {"sid": sid, "name": props.get("name") or sid,
                          "ntype": ntype, "high_value": _is_high_value(sid, props)}
            for ace in obj.get("Aces") or []:
                if ace.get("RightName") in DANGEROUS_ACES and ace.get("PrincipalSID"):
                    edges.append({"src": ace["PrincipalSID"], "dst": sid,
                                  "kind": ace["RightName"]})
            for m in obj.get("Members") or []:
                if m.get("ObjectIdentifier"):
                    edges.append({"src": m["ObjectIdentifier"], "dst": sid,
                                  "kind": "MemberOf"})
            la = obj.get("LocalAdmins")
            results = la.get("Results") if isinstance(la, dict) else la
            for r in results or []:
                if r.get("ObjectIdentifier"):
                    edges.append({"src": r["ObjectIdentifier"], "dst": sid,
                                  "kind": "AdminTo"})
    return list(nodes.values()), edges


def import_graph(store, path):
    """Replace the stored graph with SharpHound data at ``path``. Returns counts."""
    nodes, edges = load(path)
    store.bh_reset()
    with store.transaction():
        for n in nodes:
            store.bh_add_node(n["sid"], n["name"], n["ntype"], n["high_value"])
        for e in edges:
            store.bh_add_edge(e["src"], e["dst"], e["kind"])
    return store.bh_counts()


# ------------------------------------------------------------------ pathfinding

def _owned_sids(store, nodes_by_name):
    """Map fieldkit's credentials to graph node SIDs by principal name."""
    owned = {}
    for c in store.credentials():
        user = c["username"].upper()
        dom = (c["domain"] or "").upper()
        sid = nodes_by_name.get(f"{user}@{dom}")
        if not sid and dom:
            label = dom.split(".")[0]
            for name, s in nodes_by_name.items():
                nu, _, nd = name.partition("@")
                if nu == user and nd.split(".")[0] == label:
                    sid = s
                    break
        if not sid:
            sid = nodes_by_name.get(user)  # last resort: bare name
        if sid and sid not in owned:
            owned[sid] = c
    return owned


def owned_paths(store, *, max_depth=8):
    """Shortest control path from each owned principal to a high-value target.

    Returns a list of dicts: ``{owned, target, hops, path, cred_id}``. Empty if no
    graph is loaded or nothing owned reaches a high-value node.
    """
    nodes = {n["sid"]: n for n in store.bh_nodes()}
    if not nodes:
        return []
    by_name = {}
    for sid, n in nodes.items():
        if n["name"]:
            by_name.setdefault(n["name"].upper(), sid)
    adj = {}
    for src, dst, kind in store.bh_edges():
        adj.setdefault(src, []).append((dst, kind))

    def name(sid):
        n = nodes.get(sid)
        return n["name"] if n and n["name"] else sid

    results = []
    for start, cred in _owned_sids(store, by_name).items():
        target, hops = _bfs(start, adj, nodes, max_depth)
        if target is None:
            continue
        steps = [name(start)] + [f"-{kind}-> {name(dst)}" for kind, dst in hops]
        results.append({"owned": name(start), "target": name(target),
                        "hops": len(hops), "path": " ".join(steps),
                        "cred_id": cred["id"]})
    results.sort(key=lambda r: r["hops"])
    return results


def _bfs(start, adj, nodes, max_depth):
    """Shortest path from ``start`` to a high-value node. Returns ``(target_sid, hops)``
    where hops is ``[(kind, dst), ...]``, or ``(None, [])``."""
    q = deque([(start, [])])
    seen = {start}
    while q:
        sid, path = q.popleft()
        node = nodes.get(sid)
        if node and node["high_value"] and path:
            return sid, path
        if len(path) >= max_depth:
            continue
        for dst, kind in adj.get(sid, []):
            if dst not in seen:
                seen.add(dst)
                q.append((dst, path + [(kind, dst)]))
    return None, []
