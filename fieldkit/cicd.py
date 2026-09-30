"""CI/CD pipeline privilege-escalation pathing — the seventh domain on the asset model.

The build system is an escalation surface in its own right: a repo you can push to (or a
workflow you can edit) runs as the *pipeline's* identity, which typically holds deploy
credentials, cloud OIDC federation, and read access to secrets — so write access to a
repo can become production/cloud admin (the "Poisoned Pipeline Execution" class). This
maps onto the SAME asset graph as the other domains: CI principals (repos, pipelines,
runners, service connections/OIDC identities) are ``asset(kind="cicd_principal")``,
escalation relationships are ``asset_edge`` rows, and the owned→admin search is the shared
:func:`fieldkit.bloodhound._bfs`.

fieldkit calls no CI APIs itself — it ingests a normalized principal graph the operator
produces from their own enumerator (a ``gh api`` dump, a GitLab export, a workflow audit),
the same tool-agnostic handoff as the other graph domains. Supply each principal's held
capabilities and the escalation edges are *derived* from a built-in primitive ruleset
(:func:`derive_edges`). Because a pipeline commonly federates into cloud via OIDC, a CI
principal carrying the assumed cloud role as an ``aliases`` prop stitches CI→cloud in the
cross-domain pathfinder.

The primitives below are public CI/CD attack tradecraft (OWASP Top 10 CI/CD Security
Risks, "Poisoned Pipeline Execution" research), not novel technique.
"""
import json
from dataclasses import dataclass

from . import assetgraph

CICD_PRINCIPAL = "cicd_principal"


class CicdError(ValueError):
    """A CI/CD graph that could not be parsed."""


#: The synthetic high-value node self-escalation primitives point at. A principal that
#: can run code as the pipeline / reach the deploy identity reaches this; paths render as
#: ``dev -write workflow-> deploy-admin-equivalent``.
ADMIN_EQUIV_ID = "cicd:deploy-admin-equivalent"

#: Well-known CI/CD privilege-escalation primitives: holding one of these capabilities
#: lets a principal run code in — or take over — the pipeline, and thus reach its deploy
#: credentials / cloud federation / secrets. Each rule is (label, [all-required tokens]);
#: tokens are matched case-insensitively against the principal's held capabilities.
_CICD_PRIVESC_RULES = [
    ("*", ["*"]),                                              # full control
    ("admin repo", ["admin"]),                                 # edit workflows + secrets
    ("write workflow", ["write workflow"]),                    # inject CI code (PPE)
    ("push protected branch", ["push protected"]),
    ("modify pipeline", ["write pipeline"]),
    ("pull_request_target injection", ["pull_request_target"]),
    ("approve deployment", ["approve deployment"]),
    ("register self-hosted runner", ["register runner"]),      # capture other jobs
    ("read secrets", ["read secrets"]),                        # deploy creds live here
    ("deploy production", ["deploy"]),
    ("manage service connection", ["manage service connection"]),
]


def _cicd_holds(held, token):
    """True when the held capability set covers ``token`` (or holds ``*``)."""
    return "*" in held or token in held


def derive_edges(principals):
    """Derive self-escalation-to-deploy-admin edges from each principal's held
    capabilities, using :data:`_CICD_PRIVESC_RULES`. Returns
    ``(edges, admin_equiv_needed)`` — edges point at :data:`ADMIN_EQUIV_ID`. First
    matching primitive per principal wins."""
    edges, needed = [], False
    for p in principals:
        held = {x.lower().strip() for x in (p.get("permissions") or [])}
        if not held:
            continue
        for label, required in _CICD_PRIVESC_RULES:
            if all(_cicd_holds(held, t) for t in required):
                edges.append({"src": p["key"], "dst": ADMIN_EQUIV_ID, "kind": label})
                needed = True
                break
    return edges, needed


def rules():
    """The CI/CD privesc primitives the derivation recognizes:
    ``[(label, [required tokens])]``. Exposed so `fieldkit cicd rules` can show an
    operator exactly what the capability-derivation checks for."""
    return list(_CICD_PRIVESC_RULES)


@dataclass
class CicdReport:
    principals_added: int = 0
    edges_added: int = 0
    paths_found: int = 0
    findings_added: int = 0


def parse_cicd(text):
    """Parse a normalized CI/CD graph (JSON) into ``(platform, principals, edges)``.

    Shape::

        {"platform": "github",
         "principals": [{"id": "...", "name": "...", "type": "repo|pipeline|runner|identity",
                         "admin": false, "owned": true,
                         "permissions": ["write workflow", "read secrets", ...],
                         "props": {"aliases": ["arn:aws:iam::1:role/deploy"]}}, ...],
         "edges": [{"src": "...", "dst": "...", "kind": "triggers"}, ...]}

    ``admin`` marks a deploy-admin-equivalent principal (the high-value target); ``owned``
    marks a principal the assessment controls. ``permissions`` (held capabilities) is
    optional — when present, escalation edges are *derived* from it (see
    :func:`derive_edges`). ``props.aliases`` naming a cloud role lets the cross-domain
    pathfinder stitch CI→cloud (OIDC). Raises :class:`CicdError` on invalid JSON / shape.
    """
    try:
        doc = json.loads(text) if isinstance(text, str) else text
    except (ValueError, TypeError) as exc:
        raise CicdError(f"not valid JSON: {exc}") from None
    if not isinstance(doc, dict):
        raise CicdError("expected a JSON object with principals/edges")
    platform = str(doc.get("platform") or doc.get("provider") or "cicd")
    principals, edges = [], []
    for p in doc.get("principals") or []:
        pid = (p.get("id") or p.get("name") or "").strip()
        if not pid:
            continue
        # Preserve top-level ``aliases`` / ``roles`` into props (see cloud_iam.parse_iam
        # for the rationale) so cross-domain stitching can match this principal against
        # a federated identity in another domain.
        props = dict(p.get("props") or {})
        for extra in ("aliases", "roles"):
            if extra in p and extra not in props:
                props[extra] = p[extra]
        principals.append({
            "key": pid,
            "name": (p.get("name") or pid).strip(),
            "type": (p.get("type") or "repo").strip(),
            "admin": bool(p.get("admin")),
            "owned": bool(p.get("owned")),
            "props": props,
            "permissions": [str(x) for x in (p.get("permissions") or [])]})
    for e in doc.get("edges") or []:
        src, dst = (e.get("src") or "").strip(), (e.get("dst") or "").strip()
        if src and dst:
            edges.append({"src": src, "dst": dst,
                          "kind": (e.get("kind") or "triggers").strip()})
    return platform, principals, edges


def apply_cicd(store, text):
    """Fold a normalized CI/CD graph into state and record each owned→admin escalation
    path as a ``cicd_privesc`` finding. Idempotent. Delegates graph persistence,
    pathfinding and recording to :mod:`fieldkit.assetgraph`."""
    platform, principals, edges = parse_cicd(text)
    derived, admin_needed = derive_edges(principals)
    if admin_needed and not any(p["key"] == ADMIN_EQUIV_ID for p in principals):
        principals.append({
            "key": ADMIN_EQUIV_ID, "name": "deploy-admin-equivalent (pipeline takeover)",
            "type": "synthetic", "admin": True, "owned": False})
    rep = CicdReport()
    rep.principals_added, rep.edges_added = assetgraph.ingest_graph(
        store, CICD_PRINCIPAL, platform, principals, edges + derived)
    rep.findings_added, paths = assetgraph.record_paths(
        store, CICD_PRINCIPAL, "cicd_privesc", label="CI/CD")
    rep.paths_found = len(paths)
    return rep


def escalation_paths(store, *, max_depth=8):
    """Every shortest owned→admin escalation path in the CI/CD principal graph."""
    return assetgraph.escalation_paths(store, CICD_PRINCIPAL, label="CI/CD",
                                       max_depth=max_depth)
