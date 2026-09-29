"""Bridge the AD / host world into the asset graph.

The AD credential loop lives in the ``host`` / ``credential`` / ``access`` tables,
separate from the ``asset`` / ``asset_edge`` graph the other domains use. That keeps
the AD core out of :mod:`fieldkit.assetgraph`'s cross-domain stitching — a recovered
credential that is *also* a cloud or SaaS identity can't be followed across the boundary.

:func:`bridge_ad` projects the relevant AD state into the asset graph (idempotently, a
one-way reflection — the AD tables stay the source of truth):

* every host becomes an ``ad_host`` asset — ``owned`` when we hold admin on it,
  high-value (``admin``) when it is a domain controller;
* every recovered credential becomes an ``ad_principal`` asset — ``owned`` (we hold the
  secret), high-value when it is admin on a DC (domain-admin-equivalent), carrying
  ``aliases`` (``user@domain`` UPN, ``DOMAIN\\user``) so the shared-identity pivot
  derivation can match it to a cloud/SaaS/k8s principal;
* ``access`` rows become edges: ``ad_principal -local admin/authenticates-> ad_host``
  (own the principal ⇒ reach the host) and, for hosts we already admin,
  ``ad_host -dumps credential-> ad_principal`` (own the host ⇒ recover creds present on
  it — the lateral loop).

With AD in the graph, :func:`fieldkit.assetgraph.cross_domain_paths` can stitch e.g.
*recovered domain account → (federated) cloud role → cloud admin*, and AD-internal
lateral moves (own host → dump cred → cred admits elsewhere) become graph edges too.
This does not replace the BloodHound ACL pathing — it reflects the credential/access
loop fieldkit itself tracks.
"""
from dataclasses import dataclass

AD_HOST = "ad_host"
AD_PRINCIPAL = "ad_principal"


@dataclass
class BridgeReport:
    hosts_added: int = 0
    principals_added: int = 0
    edges_added: int = 0


def _principal_key(domain, username):
    return f"{domain}\\{username}" if domain else username


def _principal_aliases(domain, username):
    """Identity strings by which this account can be matched to another domain — the
    ``user@domain`` UPN (matches a cloud/SaaS email when the domain is an FQDN) and the
    ``DOMAIN\\user`` form. The bare username is deliberately excluded (too generic —
    every domain has an ``administrator``)."""
    if not domain:
        return []
    return [f"{username}@{domain}", f"{domain}\\{username}"]


def bridge_ad(store):
    """Reflect the AD/host state into the asset graph. Idempotent. Returns a
    :class:`BridgeReport`."""
    rep = BridgeReport()
    admin_host_ids = {h["id"] for h in store.admin_hosts()}
    da_cred_ids = {r["cred_id"] for r in store.admin_on_dcs() if r["cred_id"] is not None}

    host_asset = {}
    for h in store.hosts():
        props = {"owned": h["id"] in admin_host_ids,
                 "admin": bool(h["is_dc"]),
                 "is_dc": bool(h["is_dc"])}
        aid, created = store.add_asset(
            AD_HOST, h["ip"], label=(h["hostname"] or h["ip"]),
            host_id=h["id"], props=props)
        host_asset[h["id"]] = aid
        rep.hosts_added += int(created)

    cred_asset = {}
    for c in store.credentials():
        domain, user = c["domain"] or "", c["username"]
        key = _principal_key(domain, user)
        props = {"owned": True,                       # we recovered/hold this secret
                 "admin": c["id"] in da_cred_ids,     # admin on a DC ⇒ domain-admin-equiv
                 "aliases": _principal_aliases(domain, user),
                 "domain": domain}
        aid, created = store.add_asset(AD_PRINCIPAL, key, label=key, props=props)
        cred_asset[c["id"]] = aid
        rep.principals_added += int(created)

    for h in store.hosts():
        h_aid = host_asset[h["id"]]
        for a in store.access_on(h["id"]):
            cid = a["cred_id"]
            p_aid = cred_asset.get(cid)
            if p_aid is None:
                continue
            _, c1 = store.add_asset_edge(
                p_aid, h_aid, "local admin" if a["admin"] else "authenticates")
            rep.edges_added += int(c1)
            if h["id"] in admin_host_ids:             # own the host ⇒ dump its creds
                _, c2 = store.add_asset_edge(h_aid, p_aid, "dumps credential")
                rep.edges_added += int(c2)
    return rep
