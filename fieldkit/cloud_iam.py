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
                         "admin": false, "owned": true,
                         "permissions": ["iam:CreatePolicyVersion", ...]}, ...],
         "edges": [{"src": "<arn>", "dst": "<arn>", "kind": "sts:AssumeRole"}, ...]}

    ``permissions`` is optional — when present, self-escalation-to-admin edges are
    *derived* from it (see :func:`derive_edges`), so you can feed a raw permissions dump
    from your enumerator instead of pre-computing the escalation graph. ``edges`` (e.g.
    AssumeRole chains) are still honored and merged. Raises :class:`CloudIamError` on
    invalid JSON / shape."""
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
            "owned": bool(p.get("owned")),
            "permissions": [str(x) for x in (p.get("permissions") or [])]})
    for e in doc.get("edges") or []:
        src, dst = (e.get("src") or "").strip(), (e.get("dst") or "").strip()
        if src and dst:
            edges.append({"src": src, "dst": dst,
                          "kind": (e.get("kind") or "assume").strip()})
    return provider, principals, edges


class CloudIamError(ValueError):
    """A cloud-IAM graph that could not be parsed."""


#: The synthetic high-value node self-escalation primitives point at. A principal that
#: can grant itself administrative access reaches this; paths render as
#: ``dev -iam:CreatePolicyVersion-> admin-equivalent``.
ADMIN_EQUIV_ARN = "arn:fieldkit:iam:admin-equivalent"

#: Well-known AWS IAM privilege-escalation primitives (Rhino Security's canonical set):
#: holding these permissions lets a principal grant itself — or an identity it fully
#: controls — administrative access. Each rule is (label, [all-required perms]); the
#: PassRole rules pair the pass with a compute-launch that runs code as the passed role.
_IAM_PRIVESC_RULES = [
    ("iam:CreatePolicyVersion", ["iam:createpolicyversion"]),
    ("iam:SetDefaultPolicyVersion", ["iam:setdefaultpolicyversion"]),
    ("iam:AttachUserPolicy", ["iam:attachuserpolicy"]),
    ("iam:AttachRolePolicy", ["iam:attachrolepolicy"]),
    ("iam:AttachGroupPolicy", ["iam:attachgrouppolicy"]),
    ("iam:PutUserPolicy", ["iam:putuserpolicy"]),
    ("iam:PutRolePolicy", ["iam:putrolepolicy"]),
    ("iam:PutGroupPolicy", ["iam:putgrouppolicy"]),
    ("iam:CreateAccessKey", ["iam:createaccesskey"]),
    ("iam:UpdateLoginProfile", ["iam:updateloginprofile"]),
    ("iam:CreateLoginProfile", ["iam:createloginprofile"]),
    ("iam:AddUserToGroup", ["iam:addusertogroup"]),
    ("iam:PassRole+ec2:RunInstances", ["iam:passrole", "ec2:runinstances"]),
    ("iam:PassRole+lambda:CreateFunction",
     ["iam:passrole", "lambda:createfunction", "lambda:invokefunction"]),
    ("iam:PassRole+cloudformation:CreateStack",
     ["iam:passrole", "cloudformation:createstack"]),
    ("iam:PassRole+glue:CreateDevEndpoint", ["iam:passrole", "glue:createdevendpoint"]),
    ("iam:PassRole+sagemaker:CreateNotebookInstance",
     ["iam:passrole", "sagemaker:createnotebookinstance"]),
]


def _perm_holds(held, required):
    """True when the held permission set satisfies ``required``, honoring `*` and
    `<service>:*` wildcards (an IAM policy can grant `iam:*` or `*`)."""
    if "*" in held or required in held:
        return True
    return f"{required.split(':', 1)[0]}:*" in held


def derive_edges(principals):
    """Derive self-escalation-to-admin edges from each principal's permissions, using
    :data:`_IAM_PRIVESC_RULES`. Returns ``(edges, admin_equiv_needed)`` — edges point at
    :data:`ADMIN_EQUIV_ARN` (the caller adds that synthetic admin node when needed).
    The first matching primitive per principal wins (one is enough to reach admin)."""
    edges, needed = [], False
    for p in principals:
        held = {x.lower() for x in (p.get("permissions") or [])}
        if not held:
            continue
        for label, required in _IAM_PRIVESC_RULES:
            if all(_perm_holds(held, r) for r in required):
                edges.append({"src": p["arn"], "dst": ADMIN_EQUIV_ARN, "kind": label})
                needed = True
                break
    return edges, needed


def apply_iam(store, text):
    """Fold a normalized cloud-IAM graph into state (``cloud_principal`` assets +
    ``asset_edge`` rows) and record a ``cloud_privesc`` finding per owned→admin path.
    Idempotent. The graph persistence + pathfinding + finding-recording is the shared
    :mod:`fieldkit.assetgraph` engine — this module only speaks the cloud-IAM dialect."""
    provider, principals, edges = parse_iam(text)
    graph_principals = [{"key": p["arn"], "name": p["name"], "type": p["type"],
                         "admin": p["admin"], "owned": p["owned"]} for p in principals]
    # Derive self-escalation edges from raw permissions, and add the synthetic admin
    # node they target (unless the graph already defines it).
    derived, admin_needed = derive_edges(principals)
    if admin_needed and not any(p["key"] == ADMIN_EQUIV_ARN for p in graph_principals):
        graph_principals.append({
            "key": ADMIN_EQUIV_ARN, "name": "admin-equivalent (self-grant)",
            "type": "synthetic", "admin": True, "owned": False})
    rep = CloudReport()
    rep.principals_added, rep.edges_added = assetgraph.ingest_graph(
        store, CLOUD_PRINCIPAL, provider, graph_principals, edges + derived)
    rep.findings_added, paths = assetgraph.record_paths(
        store, CLOUD_PRINCIPAL, "cloud_privesc", label="Cloud IAM")
    rep.paths_found = len(paths)
    return rep


def escalation_paths(store, *, max_depth=8):
    """Every shortest owned→admin escalation path in the cloud asset graph."""
    return assetgraph.escalation_paths(store, CLOUD_PRINCIPAL, label="Cloud IAM",
                                       max_depth=max_depth)
