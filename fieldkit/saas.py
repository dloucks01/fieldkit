"""SaaS / identity-provider privilege-escalation pathing — the sixth domain on the
asset model.

Modern estates are not only AD, cloud and clusters — the identity provider (Entra ID /
Azure AD, Okta) is its own escalation surface. A user, group or service principal that
holds a role like *Global Administrator*, *Privileged Role Administrator* or *Application
Administrator* — or a Microsoft Graph app permission like ``RoleManagement.ReadWrite.
Directory`` — can grant itself, or an identity it controls, tenant-wide admin. This maps
onto the SAME asset graph as cloud IAM and k8s RBAC: principals are
``asset(kind="saas_principal")``, escalation relationships are ``asset_edge`` rows, and
the owned→admin search is the shared :func:`fieldkit.bloodhound._bfs`.

fieldkit calls no IdP APIs itself — it ingests a normalized principal graph the operator
produces from their own enumerator (AzureHound / ROADtools / a `az rest` or Okta API
dump), the same tool-agnostic handoff as the other graph domains. Supply each
principal's held roles/permissions and the escalation edges are *derived* from a
built-in primitive ruleset (:func:`derive_edges`).
"""
import json
from dataclasses import dataclass

from . import assetgraph

SAAS_PRINCIPAL = "saas_principal"


class SaasError(ValueError):
    """A SaaS / IdP graph that could not be parsed."""


#: The synthetic high-value node self-escalation primitives point at. A principal that
#: holds a tenant-admin-equivalent role (or a Graph permission that grants one) reaches
#: this; paths render as ``helpdesk -Privileged Role Administrator-> global-admin``.
ADMIN_EQUIV_ID = "saas:global-admin-equivalent"

#: Well-known Entra ID (Azure AD) and Okta privilege-escalation primitives: holding one
#: of these roles or Microsoft Graph app permissions lets a principal reach tenant admin.
#: Each rule is (label, [all-required tokens]); tokens are matched case-insensitively
#: against the principal's held roles/permissions. Public tradecraft (AzureHound /
#: ROADtools / Okta docs), not novel technique.
_SAAS_PRIVESC_RULES = [
    ("*", ["*"]),                                                  # explicit all
    # Entra ID directory roles
    ("Global Administrator", ["global administrator"]),
    ("Privileged Role Administrator", ["privileged role administrator"]),
    ("Privileged Authentication Administrator",
     ["privileged authentication administrator"]),      # reset any admin's creds
    ("Application Administrator", ["application administrator"]),  # add creds to any app
    ("Cloud Application Administrator", ["cloud application administrator"]),
    ("Hybrid Identity Administrator", ["hybrid identity administrator"]),
    ("Partner Tier2 Support", ["partner tier2 support"]),
    # Microsoft Graph app permissions (service-principal escalation)
    ("RoleManagement.ReadWrite.Directory", ["rolemanagement.readwrite.directory"]),
    ("AppRoleAssignment.ReadWrite.All", ["approleassignment.readwrite.all"]),
    ("Application.ReadWrite.All", ["application.readwrite.all"]),
    ("Directory.ReadWrite.All", ["directory.readwrite.all"]),
    # Okta admin roles
    ("Super Administrator", ["super administrator"]),
    ("Organization Administrator", ["organization administrator"]),
]


def _saas_holds(held, token):
    """True when the held role/permission set covers ``token`` (or holds ``*``)."""
    return "*" in held or token in held


def derive_edges(principals):
    """Derive self-escalation-to-tenant-admin edges from each principal's held
    roles/permissions, using :data:`_SAAS_PRIVESC_RULES`. Returns
    ``(edges, admin_equiv_needed)`` — edges point at :data:`ADMIN_EQUIV_ID`. First
    matching primitive per principal wins."""
    edges, needed = [], False
    for p in principals:
        held = {x.lower().strip() for x in (p.get("permissions") or [])}
        if not held:
            continue
        for label, required in _SAAS_PRIVESC_RULES:
            if all(_saas_holds(held, t) for t in required):
                edges.append({"src": p["key"], "dst": ADMIN_EQUIV_ID, "kind": label})
                needed = True
                break
    return edges, needed


def rules():
    """The SaaS/IdP privesc primitives the derivation recognizes:
    ``[(label, [required tokens])]``. Exposed so `fieldkit saas rules` can show an
    operator exactly what the permission-derivation checks for."""
    return list(_SAAS_PRIVESC_RULES)


@dataclass
class SaasReport:
    principals_added: int = 0
    edges_added: int = 0
    paths_found: int = 0
    findings_added: int = 0


def parse_saas(text):
    """Parse a normalized SaaS/IdP graph (JSON) into ``(tenant, principals, edges)``.

    Shape::

        {"tenant": "contoso.onmicrosoft.com",
         "principals": [{"id": "...", "name": "...", "type": "user|group|serviceprincipal",
                         "admin": false, "owned": true,
                         "permissions": ["Application Administrator",
                                         "RoleManagement.ReadWrite.Directory", ...]}, ...],
         "edges": [{"src": "...", "dst": "...", "kind": "owns app"}, ...]}

    ``admin`` marks a tenant-admin-equivalent principal (the high-value target);
    ``owned`` marks a principal the assessment controls. ``permissions`` is optional —
    held directory-role names / Graph permissions; when present, escalation edges are
    *derived* from it (see :func:`derive_edges`). Explicit ``edges`` (group membership,
    app ownership) are honored and merged. Raises :class:`SaasError` on invalid
    JSON / shape."""
    try:
        doc = json.loads(text) if isinstance(text, str) else text
    except (ValueError, TypeError) as exc:
        raise SaasError(f"not valid JSON: {exc}") from None
    if not isinstance(doc, dict):
        raise SaasError("expected a JSON object with principals/edges")
    tenant = str(doc.get("tenant") or doc.get("provider") or "tenant")
    principals, edges = [], []
    for p in doc.get("principals") or []:
        pid = (p.get("id") or p.get("name") or "").strip()
        if not pid:
            continue
        # Preserve top-level ``aliases`` / ``roles`` into props (see cloud_iam.parse_iam
        # for the rationale) so cross-domain stitching can match this identity against
        # a federated principal in another domain.
        props = dict(p.get("props") or {})
        for extra in ("aliases", "roles"):
            if extra in p and extra not in props:
                props[extra] = p[extra]
        principals.append({
            "key": pid,
            "name": (p.get("name") or pid).strip(),
            "type": (p.get("type") or "user").strip(),
            "admin": bool(p.get("admin")),
            "owned": bool(p.get("owned")),
            "props": props,
            "permissions": [str(x) for x in (p.get("permissions") or [])]})
    for e in doc.get("edges") or []:
        src, dst = (e.get("src") or "").strip(), (e.get("dst") or "").strip()
        if src and dst:
            edges.append({"src": src, "dst": dst,
                          "kind": (e.get("kind") or "grants").strip()})
    return tenant, principals, edges


def apply_saas(store, text):
    """Fold a normalized SaaS/IdP graph into state and record each owned→admin
    escalation path as a ``saas_privesc`` finding. Idempotent. Delegates the graph
    persistence, pathfinding and recording to :mod:`fieldkit.assetgraph`."""
    tenant, principals, edges = parse_saas(text)
    derived, admin_needed = derive_edges(principals)
    if admin_needed and not any(p["key"] == ADMIN_EQUIV_ID for p in principals):
        principals.append({
            "key": ADMIN_EQUIV_ID, "name": "global-admin-equivalent (self-grant)",
            "type": "synthetic", "admin": True, "owned": False})
    rep = SaasReport()
    rep.principals_added, rep.edges_added = assetgraph.ingest_graph(
        store, SAAS_PRINCIPAL, tenant, principals, edges + derived)
    rep.findings_added, paths = assetgraph.record_paths(
        store, SAAS_PRINCIPAL, "saas_privesc", label="SaaS/IdP")
    rep.paths_found = len(paths)
    return rep


def escalation_paths(store, *, max_depth=8):
    """Every shortest owned→admin escalation path in the SaaS/IdP principal graph."""
    return assetgraph.escalation_paths(store, SAAS_PRINCIPAL, label="SaaS/IdP",
                                       max_depth=max_depth)
