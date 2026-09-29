"""Enumerator adapters — turn native tool output into the normalized cloud/k8s
graph the ingest path already consumes.

`ingest cloud` / `ingest k8s` accept a hand-shaped graph JSON (principals/subjects
with ``permissions``, from which the privesc rulesets derive the escalation edges).
That is a chore to produce by hand. These adapters convert the raw output an operator
already has — an ``aws iam get-account-authorization-details`` dump, a ``kubectl auth
can-i --list`` — into that same shape, so the workflow is `tool | fieldkit ingest`.

Each adapter returns a dict in the exact shape :func:`fieldkit.cloud_iam.parse_iam` /
:func:`fieldkit.k8s.parse_rbac` accept, so nothing downstream changes.

The cloud adapter builds a **candidate-permission** view: it collects *Allow* actions
(inline + attached-managed policies, and for users their group policies) but does NOT
evaluate ``Deny`` / ``NotAction`` / conditions / resource scoping. That is deliberate
— it over-approximates so the privesc rules surface every *potential* path for the
operator to confirm, exactly as an enumerator would.
"""
import json
import re

_ROLE_URL_ROW = re.compile(r"^(\S+)\s+\[.*?\]\s+\[.*?\]\s+\[(.*?)\]\s*$")


class AdapterError(ValueError):
    """Native tool output that could not be adapted."""


# --------------------------------------------------------------------------- AWS

def _statements(doc):
    """A policy document's Statement as a list (IAM allows a single dict or a list)."""
    st = (doc or {}).get("Statement") or []
    return st if isinstance(st, list) else [st]


def _allow_actions(doc):
    """Allow-effect Action strings from one policy document (verbatim; cased later)."""
    out = []
    for s in _statements(doc):
        if not isinstance(s, dict) or str(s.get("Effect", "")).lower() != "allow":
            continue
        acts = s.get("Action") or []
        if isinstance(acts, str):
            acts = [acts]
        out.extend(str(a) for a in acts)
    return out


def _assume_edges(role, arn):
    """sts:AssumeRole edges from a role's trust policy: every AWS principal ARN
    permitted to assume it → an edge to the role. Service/federated principals and
    ``*`` are skipped (no concrete source principal to start a path from)."""
    edges = []
    for s in _statements(role.get("AssumeRolePolicyDocument") or {}):
        if not isinstance(s, dict) or str(s.get("Effect", "")).lower() != "allow":
            continue
        princ = s.get("Principal")
        aws = princ.get("AWS") if isinstance(princ, dict) else None
        if not aws:
            continue
        for src in ([aws] if isinstance(aws, str) else aws):
            src = str(src).strip()
            if src and src != "*" and src.startswith("arn:"):
                edges.append({"src": src, "dst": arn, "kind": "sts:AssumeRole"})
    return edges


def _cloud_principal(arn, name, ptype, actions, owned_set):
    perms = sorted(set(actions))
    return {
        "arn": arn,
        "name": name or arn,
        "type": ptype,
        # "*" (AdministratorAccess) makes this principal a high-value target too
        "admin": "*" in perms,
        "owned": arn in owned_set or (name or "") in owned_set,
        "permissions": perms,
    }


def aws_authorization_details(text, *, owned=()):
    """Adapt ``aws iam get-account-authorization-details`` JSON into a cloud-IAM graph.

    Resolves each user's / role's effective Allow actions (inline policies, attached
    managed policies via the top-level ``Policies`` list, and — for users — their
    group policies), emits sts:AssumeRole edges from role trust policies, and marks a
    principal ``owned`` when its ARN or name is in ``owned``. Groups are not emitted as
    principals (you do not *become* a group) — their permissions flow to member users.
    Raises :class:`AdapterError` on invalid JSON / shape."""
    try:
        doc = json.loads(text) if isinstance(text, str) else text
    except (ValueError, TypeError) as exc:
        raise AdapterError(f"not valid JSON: {exc}") from None
    if not isinstance(doc, dict) or not any(
            k in doc for k in ("UserDetailList", "RoleDetailList", "GroupDetailList")):
        raise AdapterError(
            "expected the JSON from `aws iam get-account-authorization-details` "
            "(UserDetailList / RoleDetailList / GroupDetailList)")

    managed = {}          # policy ARN -> default-version Allow actions
    for pol in doc.get("Policies") or []:
        ver = next((v for v in pol.get("PolicyVersionList") or []
                    if v.get("IsDefaultVersion")), None)
        if pol.get("Arn") and ver:
            managed[pol["Arn"]] = _allow_actions(ver.get("Document"))

    def resolve(entity, inline_key):
        acts = []
        for ip in entity.get(inline_key) or []:
            acts += _allow_actions(ip.get("PolicyDocument"))
        for ap in entity.get("AttachedManagedPolicies") or []:
            acts += managed.get(ap.get("PolicyArn"), [])
        return acts

    group_acts = {g.get("GroupName"): resolve(g, "GroupPolicyList")
                  for g in doc.get("GroupDetailList") or []}
    owned_set = {o.strip() for o in owned if o and o.strip()}

    principals, edges = [], []
    for u in doc.get("UserDetailList") or []:
        acts = resolve(u, "UserPolicyList")
        for gname in u.get("GroupList") or []:
            acts += group_acts.get(gname, [])
        principals.append(_cloud_principal(
            u.get("Arn"), u.get("UserName"), "user", acts, owned_set))
    for r in doc.get("RoleDetailList") or []:
        principals.append(_cloud_principal(
            r.get("Arn"), r.get("RoleName"), "role",
            resolve(r, "RolePolicyList"), owned_set))
        edges += _assume_edges(r, r.get("Arn"))

    principals = [p for p in principals if p["arn"]]
    return {"provider": "aws", "principals": principals, "edges": edges}


# --------------------------------------------------------------------------- k8s

def _norm_resource(res):
    """kubectl prints ``clusterroles.rbac.authorization.k8s.io`` / ``pods`` / ``*.*``;
    the privesc ruleset keys on the short resource name (``clusterroles`` / ``pods`` /
    ``*``). Strip the API group suffix."""
    res = res.strip()
    if res in ("*.*", "*"):
        return "*"
    return res.split(".", 1)[0]


def kubectl_can_i(text, *, subject="self", cluster="cluster", owned=True):
    """Adapt ``kubectl auth can-i --list`` output into a single-subject k8s RBAC graph.

    The command lists the grants of whoever ran it — your foothold service account — so
    it yields one subject (``owned`` by default). Each table row's verbs are expanded
    against its resource into ``"<verb> <resource>"`` grants; non-resource-URL rows are
    skipped (privesc is resource-based). ``subject`` names the subject in the graph.
    Raises :class:`AdapterError` when no grant rows parse."""
    perms = []
    for line in (text or "").splitlines():
        m = _ROLE_URL_ROW.match(line)
        if not m:
            continue                       # header / blank / non-resource-URL row
        resource = _norm_resource(m.group(1))
        if resource.startswith("/"):
            continue                       # a non-resource URL, not an RBAC resource
        verbs = [v for v in m.group(2).split() if v]
        for v in verbs:
            perms.append(f"{v} {resource}")
    if not perms:
        raise AdapterError(
            "no grant rows parsed — expected `kubectl auth can-i --list` output "
            "(a 'Resources / Verbs' table)")
    sid = subject if subject.startswith("sa:") else f"sa:{subject}"
    return {"cluster": cluster,
            "subjects": [{"id": sid, "name": subject, "kind": "serviceaccount",
                          "owned": bool(owned), "permissions": sorted(set(perms))}]}


# --------------------------------------------------------------------------- SaaS / IdP

_ENTRA_KIND = {
    "#microsoft.graph.user": "user",
    "#microsoft.graph.group": "group",
    "#microsoft.graph.serviceprincipal": "serviceprincipal",
}


def entra_role_assignments(text, *, owned=()):
    """Adapt Microsoft Graph directory role assignments into a SaaS/IdP graph.

    Expects the JSON from::

        az rest --method GET --url "https://graph.microsoft.com/v1.0/roleManagement/\
directory/roleAssignments?$expand=principal,roleDefinition"

    (an object with a ``value`` list of ``{principal, roleDefinition}`` entries). Groups
    the assignments by principal, so each principal carries the directory-role names it
    holds as ``permissions`` — from which the SaaS privesc ruleset derives the paths.
    A principal holding *Global Administrator* is marked ``admin``; ``owned`` marks a
    principal (by id, displayName or userPrincipalName). Raises :class:`AdapterError`
    on invalid JSON / shape."""
    try:
        doc = json.loads(text) if isinstance(text, str) else text
    except (ValueError, TypeError) as exc:
        raise AdapterError(f"not valid JSON: {exc}") from None
    if not isinstance(doc, dict) or "value" not in doc:
        raise AdapterError(
            "expected Microsoft Graph roleAssignments JSON (an object with a 'value' "
            "list of {principal, roleDefinition} entries)")
    owned_set = {o.strip() for o in owned if o and o.strip()}
    by_id = {}
    for a in doc.get("value") or []:
        princ = a.get("principal") or {}
        pid = (princ.get("id") or "").strip()
        role = ((a.get("roleDefinition") or {}).get("displayName") or "").strip()
        if not pid or not role:
            continue
        name = (princ.get("displayName") or princ.get("userPrincipalName")
                or pid).strip()
        upn = (princ.get("userPrincipalName") or "").strip()
        p = by_id.setdefault(pid, {
            "id": pid, "name": name,
            "type": _ENTRA_KIND.get(str(princ.get("@odata.type", "")).lower(), "user"),
            "owned": bool(owned_set & {pid, name, upn}),
            "roles": set()})
        p["roles"].add(role)
    principals = []
    for p in by_id.values():
        roles = sorted(p.pop("roles"))
        p["permissions"] = roles
        p["admin"] = any(r.lower() == "global administrator" for r in roles)
        principals.append(p)
    return {"tenant": "entra", "principals": principals}


# --------------------------------------------------------------------------- CI/CD

def github_collaborators(text, *, owned=()):
    """Adapt ``gh api repos/{owner}/{repo}/collaborators`` JSON into a CI/CD graph.

    Each collaborator becomes a ``cicd_principal`` whose held capabilities derive from
    their repo permission: **admin** ⇒ full repo control (edit workflows + secrets);
    **maintain / push** (write) ⇒ workflow injection (a write collaborator can add a
    malicious workflow — Poisoned Pipeline Execution); triage/pull grant nothing that
    escalates. ``owned`` marks a collaborator by login. Raises :class:`AdapterError` on
    invalid JSON / shape."""
    try:
        data = json.loads(text) if isinstance(text, str) else text
    except (ValueError, TypeError) as exc:
        raise AdapterError(f"not valid JSON: {exc}") from None
    if not isinstance(data, list):
        raise AdapterError(
            "expected a JSON list from `gh api repos/{owner}/{repo}/collaborators`")
    owned_set = {o.strip() for o in owned if o and o.strip()}
    principals = []
    for c in data:
        login = (c.get("login") or "").strip()
        if not login:
            continue
        perms = c.get("permissions") or {}
        caps = []
        if perms.get("admin"):
            caps.append("admin")
        elif perms.get("maintain") or perms.get("push"):
            caps.append("write workflow")
        principals.append({
            "id": f"gh:{login}", "name": login, "type": "user",
            "owned": login in owned_set, "permissions": caps})
    return {"platform": "github", "principals": principals}


#: Native formats each ingest command understands, mapped to their adapter.
CLOUD_FORMATS = {"aws-authdetails": aws_authorization_details}
K8S_FORMATS = {"kubectl": kubectl_can_i}
SAAS_FORMATS = {"entra-roles": entra_role_assignments}
CICD_FORMATS = {"github-collaborators": github_collaborators}
