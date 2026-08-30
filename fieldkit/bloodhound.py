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


#: Edge-kind → best-fit chain-profile mapping. Kept as tuples of
#: (edge_kinds, profile, rationale) so a single edge-kind hit
#: earlier in the path wins over a weaker one later. Ordered from
#: strongest heuristic to weakest.
_EDGE_HINTS = (
    (("AllowedToActOnBehalfOfOtherIdentity",
      "AllowedToDelegate"),          "rbcd",
     "path traverses an RBCD / delegation edge — rbcd chain "
     "writes msDS-AllowedToActOnBehalfOfOtherIdentity then S4U2Self"),
    (("AddSelf",),                    "rbcd",
     "path uses AddSelf to a group — the rbcd chain's write-primitive "
     "abuses this same permission shape"),
    (("WriteDacl", "GenericAll",
      "GenericWrite"),                "rbcd",
     "path holds a dangerous ACE on a Computer object — rbcd chain "
     "writes the RBCD attribute using that ACE"),
    (("AdminTo",),                    "smb-relay-exec",
     "path lands as local admin on a Computer — if SMB signing is "
     "disabled there, smb-relay-exec drops a shell via relayed auth"),
)


def suggest_chain(path_entry, nodes_by_sid=None):
    """Suggest the best-fit chain profile for one owned→high-value path.

    Returns ``{"profile", "target", "rationale"}`` or ``None`` when
    no shipped chain profile is a clean fit. ``nodes_by_sid`` is
    optional context (from :meth:`Store.bh_nodes`) used to pick a
    meaningful chain target from the path — the final Computer
    node when the target itself isn't a Computer.

    Heuristics (first match wins):

      * Target is a Computer with ``high_value`` set (usually a
        DC) → suggest ``esc8`` against that Computer's name.
        Assumes ADCS is in the environment; the rationale spells
        this out so the operator can verify with
        ``fieldkit adcs find`` before committing.
      * Path traverses an RBCD/delegation edge → ``rbcd`` targeting
        the Computer the delegation is written to.
      * Path holds ``AddSelf``/``WriteDacl``/``GenericAll``/
        ``GenericWrite`` on a Computer → ``rbcd`` (same write
        primitive, different discovery angle).
      * Path uses ``AdminTo`` on a Computer → ``smb-relay-exec``
        against that Computer (contingent on SMB signing disabled).
    """
    path_str = path_entry.get("path", "")
    target_name = path_entry.get("target", "")

    def _final_computer():
        """Return the last Computer node name mentioned in the path,
        or the target name as fallback."""
        if nodes_by_sid is None:
            return target_name
        # path tokens include "-EdgeKind-> NAME" pairs; strip the
        # arrow markers and look up ntype for each name.
        candidates = []
        for tok in path_str.split():
            if tok.startswith("-") or tok.endswith("->"):
                continue
            for _sid, n in nodes_by_sid.items():
                if n["name"] == tok and (n["ntype"] or "").lower() == "computer":
                    candidates.append(tok)
                    break
        return candidates[-1] if candidates else target_name

    # Rule 1: high-value Computer target → esc8. DCs are the
    # canonical case; the rationale calls out the ADCS assumption.
    if nodes_by_sid is not None:
        for _sid, n in nodes_by_sid.items():
            if (n["name"] == target_name
                    and (n["ntype"] or "").lower() == "computer"
                    and n["high_value"]):
                return {
                    "profile": "esc8",
                    "target": target_name,
                    "rationale": (
                        "target is a high-value Computer (usually a "
                        "DC); esc8 coerces its machine account to "
                        "auth a relay against the enterprise CA and "
                        "lands a DC cert. Verify ADCS is exposed "
                        "first: `fieldkit adcs find`."),
                }

    # Rules 2-4: match against edge-kind hints in path order.
    for edge_kinds, profile, rationale in _EDGE_HINTS:
        for ek in edge_kinds:
            if f"-{ek}->" in path_str:
                return {
                    "profile": profile,
                    "target": _final_computer(),
                    "rationale": rationale,
                }
    return None


def suggest_chains(store, *, max_depth=8):
    """Enumerate every :func:`owned_paths` entry and attach a
    ``suggestion`` dict where a shipped chain profile fits.

    Returns the same list :func:`owned_paths` returns, with an
    additional ``suggestion`` key on each entry (or ``None`` when
    no chain fits). Empty when no graph is loaded.
    """
    paths = owned_paths(store, max_depth=max_depth)
    if not paths:
        return []
    nodes_by_sid = {n["sid"]: n for n in store.bh_nodes()}
    for p in paths:
        p["suggestion"] = suggest_chain(p, nodes_by_sid)
    return paths


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
