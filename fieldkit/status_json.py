"""JSON projection of ``fieldkit status`` — the machine-readable dashboard.

The TUI (Phase A3d) and any external scripting consume this shape instead of
scraping the human status output. Pure function over the store: no printing, no
I/O besides the SQLite reads, no side effects. The caller decides what to do
with the dict (dump it, feed it to a screen, cache it).

The shape mirrors what the human ``fieldkit status`` renders, restructured for
easy consumption. Adding a field is safe (consumers tolerate unknown keys);
removing or renaming a field is a breaking change and requires a bump of
:data:`PROJECTION_VERSION`.
"""
from . import config as config_mod
from . import preflight as preflight_mod

#: Bump on any breaking shape change (field removal/rename). Consumers may
#: refuse an unsupported version rather than half-parsing.
PROJECTION_VERSION = 1


def status_dict(store, cfg=None, top_moves=None, phase=None):
    """Return the status projection as a JSON-serializable dict.

    ``top_moves`` is an iterable of :class:`~fieldkit.kb.Opportunity`-shaped
    objects (or None to omit). ``phase`` is the ``(name, hint)`` tuple produced
    by ``_current_phase`` in the CLI (or None). Both are passed in rather than
    computed here so this stays a pure projection and the caller decides
    whether to run the analyze predicates.
    """
    cfg = cfg or config_mod.load(store)
    counts = store.counts()
    row = store.require_engagement()

    scope = {"allow": [], "deny": []}
    for r in store.scope_rules():
        scope.setdefault(r["kind"], []).append(r["cidr"])

    os_breakdown = {(r["os"] or "unknown"): r["n"] for r in store.host_os_breakdown()}
    cred_types = {r["secret_type"]: r["n"] for r in store.credential_type_breakdown()}

    admin_hosts = [
        {"ip": h["ip"], "hostname": h["hostname"], "is_dc": bool(h["is_dc"])}
        for h in store.admin_hosts()[:32]
    ]

    top_moves_out = []
    if top_moves is not None:
        for m in list(top_moves)[:10]:
            top_moves_out.append({
                "key": getattr(m, "key", ""),
                "title": getattr(m, "title", ""),
                "host": getattr(m, "host", None),
                "axes": getattr(m, "axes", ""),
                "score": getattr(m, "score", 0),
                "exploitability": getattr(m, "exploitability", ""),
                "safety": getattr(m, "safety", ""),
                "detection": getattr(m, "detection", ""),
                "next_step": getattr(m, "next_step", ""),
                "detail": getattr(m, "detail", ""),
                "evidence": getattr(m, "evidence", ""),
                "manual": bool(getattr(m, "manual", False)),
            })

    pf_missing = [{"tool": rec[0], "reason": rec[1]}
                  for rec in preflight_mod.missing_required(preflight_mod.check())]

    # Only surface keys the operator actually set (or that have a default) —
    # skip Nones so the JSON stays honest about what's configured.
    config_out = {}
    for key in config_mod.KEYS:
        val = cfg.get(key)
        if val is not None and val != "":
            config_out[key] = val

    phase_name, phase_hint = (phase or (None, None))

    return {
        "_projection": PROJECTION_VERSION,
        "engagement": {
            "name": row["name"],
            "created": row["created"],
            "db_path": store.path,
        },
        "config": config_out,
        "scope": scope,
        "phase": {"name": phase_name, "hint": phase_hint} if phase_name else None,
        "counts": {
            "hosts": counts["hosts"],
            "services": counts["services"],
            "credentials": counts["credentials"],
            "access": counts["access"],
            "admin_access": counts["admin_access"],
            "admin_hosts": counts["admin_hosts"],
            "findings": counts["findings"],
            "proven_findings": counts["proven_findings"],
            "loot": counts["loot"],
        },
        "os_breakdown": os_breakdown,
        "credential_types": cred_types,
        "pwned_hosts": admin_hosts,
        "top_moves": top_moves_out,
        "preflight_missing": pf_missing,
    }
