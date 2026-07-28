"""The opportunity knowledge base — detect predicates + three-axis ranking.

``analyze`` does not guess; it reads what the loop *proved* and names the next move.
Each entry here is a **detect predicate**: a function that queries state and yields
:class:`Opportunity` rows only when its precondition is actually met. So the list
``analyze`` prints is grounded — every line has a host or credential behind it.

Every opportunity carries the three ranking axes from the design:

  * **exploitability** — how directly it advances the engagement (a DC we own vs a
    foothold that still needs a local exploit);
  * **safety** — ``read-only`` (reusing a proven credential) up to ``crash-risk``;
  * **detection** — ``quiet`` (native, already-valid auth) to ``loud`` (DCSync).

The score floats the *quiet, safe, high-impact, precondition-met* path to the top,
which is the path an operator should take first. Each also carries a ``safe_proof``:
how to demonstrate the finding for the report without detonating it.

The predicate set is intentionally the Phase-1 subset — everything derivable from
spray/loot state. Token-privilege and ADCS predicates that need a shell + enum land
with those phases; adding one is appending a function to :data:`PREDICATES`.
"""
from dataclasses import dataclass

_EXPLOIT = {"high": 3, "medium": 2, "low": 1}
_SAFETY = {"read-only": 3, "config-change": 2, "crash-risk": 1}
_DETECTION = {"quiet": 3, "moderate": 2, "loud": 1}


@dataclass(frozen=True)
class Opportunity:
    """One ranked next move, with the evidence and the command behind it."""

    key: str
    title: str
    exploitability: str
    safety: str
    detection: str
    next_step: str
    host: str = None
    detail: str = ""
    evidence: str = ""
    safe_proof: str = None

    @property
    def score(self):
        # Exploitability dominates (a met precondition that ends the engagement beats a
        # quieter half-step); safety breaks ties ahead of detection, per the design.
        return (_EXPLOIT[self.exploitability] * 100
                + _SAFETY[self.safety] * 10
                + _DETECTION[self.detection])

    @property
    def axes(self):
        return f"{self.exploitability}/{self.safety}/{self.detection}"


# --------------------------------------------------------------------- predicates

def _dc_takeover(store):
    for r in store.admin_on_dcs():
        who = f"{r['domain']}\\{r['username']}" if r["domain"] else r["username"]
        yield Opportunity(
            key="dc-takeover",
            title=f"Domain takeover — admin on DC {r['hostname'] or r['ip']}",
            exploitability="high", safety="read-only", detection="loud",
            host=r["ip"],
            detail=f"{who} is admin on a domain controller — DCSync/NTDS yields every hash.",
            evidence=f"admin access on {r['ip']} (is_dc) via {who}",
            next_step=f"nxc smb {r['ip']} -u {r['username']} ... --ntds   "
                      f"(or secretsdump.py -just-dc)",
            safe_proof="DCSync a single throwaway account (e.g. krbtgt) to prove the "
                       "primitive without pulling the whole directory.")


def _password_reuse(store):
    for r in store.creds_valid_on_multiple():
        who = f"{r['domain']}\\{r['username']}" if r["domain"] else r["username"]
        scope = "local" if r["local_auth"] else "domain"
        admin = r["admin_hits"] or 0
        yield Opportunity(
            key="password-reuse",
            title=f"Password reuse — {who} valid on {r['hosts']} hosts",
            exploitability="high" if admin else "medium",
            safety="read-only", detection="quiet",
            detail=f"a single {scope} credential authenticates on {r['hosts']} hosts"
                   + (f" ({admin} as admin)" if admin else "")
                   + " — lateral movement is already proven.",
            evidence=f"{who} has access rows on {r['hosts']} distinct hosts",
            next_step="fieldkit status --creds; move laterally to the admin hosts "
                      "(evil-winrm / wmiexec) with this credential.",
            safe_proof="reuse is proven by the existing access rows; no new packet needed "
                       "to evidence the finding.")


def _pth_local_admin(store):
    for c in store.local_hash_credentials():
        who = f".\\{c['username']}"
        yield Opportunity(
            key="pth-local-admin",
            title=f"Pass-the-hash — local hash for {who}",
            exploitability="high", safety="read-only", detection="moderate",
            detail="a local-account NT hash sweeps a fleet that shares its local admin "
                   "(no LAPS) — the classic one-hash-owns-everything.",
            evidence=f"credential #{c['id']} is a local {c['secret_type']} hash",
            next_step="fieldkit spray smb   (reuses this hash across the scope, "
                      "lockout-safe), or nxc smb <scope> -u "
                      f"{c['username']} -H <hash> --local-auth",
            safe_proof="a --local-auth login check proves reuse without writing anything "
                       "to the target.")


def _loot_admin_host(store):
    for h in store.admin_hosts_without_loot():
        yield Opportunity(
            key="loot-admin-host",
            title=f"Unlooted admin — {h['hostname'] or h['ip']} owned but not dumped",
            exploitability="high", safety="read-only", detection="moderate",
            host=h["ip"],
            detail="admin is held here but no secrets have been read — SAM/LSA hand you "
                   "the next round's credentials for free.",
            evidence=f"admin access on {h['ip']} with no loot rows",
            next_step=f"fieldkit spray smb   (loots owned hosts), or "
                      f"nxc smb {h['ip']} -u <admin> ... --sam --lsa",
            safe_proof="SAM/LSA reads are read-only; no persistence is written.")


def _foothold_enum(store):
    for r in store.footholds_without_admin():
        who = f"{r['domain']}\\{r['username']}" if r["domain"] else r["username"]
        osname = r["os"] or "unknown-OS"
        module = "winpriv" if r["os"] == "windows" else ("linpriv" if r["os"] == "linux" else "winpriv/linpriv")
        yield Opportunity(
            key="foothold-enum",
            title=f"Foothold — {who} valid on {r['hostname'] or r['ip']} (not admin)",
            exploitability="medium", safety="read-only", detection="quiet",
            host=r["ip"],
            detail=f"a non-admin foothold on a {osname} host — local privilege "
                   "escalation is the next step.",
            evidence=f"valid non-admin access on {r['ip']}",
            next_step=f"get a shell, then run the {module} enum (it names the route).",
            safe_proof="the foothold is already proven by the valid auth; enum is "
                       "read-only.")


#: The registry. Append a predicate to extend the KB; order here does not matter —
#: output is sorted by score.
PREDICATES = (
    _dc_takeover,
    _password_reuse,
    _pth_local_admin,
    _loot_admin_host,
    _foothold_enum,
)


def analyze(store):
    """Run every predicate over ``store`` and return opportunities, best-ranked first."""
    found = []
    for predicate in PREDICATES:
        found.extend(predicate(store))
    found.sort(key=lambda o: (-o.score, o.key, o.host or ""))
    return found
