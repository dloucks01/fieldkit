"""Cross-engagement correlation — walk multiple engagement DBs and
surface credentials, usernames, hosts, and hashes that recur across
them. The point: a credential cracked on engagement A likely reaches
engagement B's AD if both target the same org; a username that shows
up in both an AD compromise and a cloud IAM dump proves cross-domain
reach. fieldkit's single-engagement core couldn't tell you that.

The projection is a merge across read-only Store opens — no DB is
modified. The output is a list of :class:`Match` records, one per
value that appears in more than one engagement, with the list of
engagement names where it was seen.

Pure read side. The caller provides the paths; the module reads them
and emits the merged view."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Match:
    """One value seen in multiple engagements.

    ``kind`` is a short tag: ``credential`` for a password/hash,
    ``username`` for a bare account, ``host`` for an IP or hostname,
    ``email`` for an email address.
    ``value`` is the matched string (secret-type credentials are keyed
    by (username, secret) so the operator sees both halves).
    ``engagements`` is the sorted list of engagement names it appeared in.
    """
    kind: str
    value: str
    engagements: tuple


def _row_get(row, key, default=None):
    if hasattr(row, "keys"):
        try:
            return row[key]
        except (KeyError, IndexError):
            return default
    return getattr(row, key, default)


def _collect_from(store, name):
    """Return a dict ``{(kind, value): engagement_name}`` for every
    correlatable datum in ``store``. Walks credentials + hosts +
    findings; emails that are extracted from captured steps are
    gathered by the enrich extractor so the correlator doesn't
    re-implement that layer."""
    out = {}
    try:
        creds = store.credentials()
    except AttributeError:
        creds = []
    for row in creds:
        user = (_row_get(row, "username") or "").strip()
        secret = (_row_get(row, "secret") or "").strip()
        if user:
            out[("username", user.lower())] = name
        if user and secret:
            # Key on both so (alice, Spring2024!) in two engagements
            # is a stronger signal than just (alice) alone.
            out[("credential", f"{user.lower()}:{secret}")] = name
        if secret:
            out[("secret", secret)] = name
    try:
        hosts = store.conn.execute(
            "SELECT ip, hostname FROM host").fetchall()
    except Exception:
        hosts = []
    for h in hosts:
        ip = _row_get(h, "ip") or ""
        hostname = _row_get(h, "hostname") or ""
        if ip:
            out[("host", ip)] = name
        if hostname:
            out[("host", hostname.lower())] = name
    return out


def correlate(stores_by_name):
    """``stores_by_name`` is a dict ``{engagement_name: Store}`` of
    already-opened stores. Returns a list of :class:`Match` for every
    (kind, value) that appears in two or more engagements, sorted by
    (kind, value).

    The caller is responsible for opening + closing the stores — the
    correlator never writes, so a read-only open suffices (and is
    strongly recommended for shared engagement archives)."""
    # kind-value → set of engagement names
    index = {}
    for name, store in stores_by_name.items():
        for key in _collect_from(store, name):
            index.setdefault(key, set()).add(name)
    matches = [
        Match(kind=kind, value=value, engagements=tuple(sorted(engs)))
        for (kind, value), engs in index.items()
        if len(engs) >= 2
    ]
    matches.sort(key=lambda m: (m.kind, m.value))
    return matches
