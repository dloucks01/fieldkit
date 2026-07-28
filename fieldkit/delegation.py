"""Kerberos delegation — find the accounts that can impersonate their way to DA.

Three misconfigurations, all of which turn control of one account (or a coercion) into
domain-wide impersonation:

  * **unconstrained** — the account caches the TGT of anyone who authenticates to it;
    coerce a DC to it and capture Domain Admin;
  * **constrained** — S4U lets the account impersonate any user to its allowed service;
  * **resource-based (RBCD)** — write access to a computer's
    ``msDS-AllowedToActOnBehalfOfOtherIdentity`` lets an attacker account impersonate
    anyone to that host.

fieldkit drives nxc's ``--find-delegation`` and records each account as a finding so
``analyze`` ranks it and ``report`` writes it up. Detection is the deliverable here;
the abuse chains (Rubeus/impacket getST, PetitPotam) are operator-driven and surfaced
as the finding's next step. Pure parse + injected-runner driver.
"""
import re
from dataclasses import dataclass

from .creds import Credential

#: nxc's DelegationType strings -> the reportkb vector_type.
_TYPE = {
    "unconstrained": "unconstrained_delegation",
    "constrained": "constrained_delegation",
    "resource-based": "rbcd",
    "rbcd": "rbcd",
}

# a --find-delegation row: AccountName AccountType DelegationType [DelegationRightsTo]
_ROW = re.compile(
    r"(?P<account>\S+)\s+(?P<atype>User|Computer)\s+"
    r"(?P<dtype>Unconstrained|Constrained|Resource-Based(?:\s+Constrained)?|RBCD)\b"
    r"\s*(?P<rights>.*?)\s*$", re.I)


@dataclass(frozen=True)
class Delegation:
    account: str
    account_type: str
    kind: str            # reportkb vector_type
    dtype: str           # the raw DelegationType label
    rights_to: str


def _vector_type(dtype):
    key = dtype.strip().lower().split()[0]
    if key.startswith("resource"):
        return "rbcd"
    return _TYPE.get(key, "constrained_delegation")


def parse_delegation(text):
    """Parse nxc ``--find-delegation`` output into :class:`Delegation` rows."""
    out, seen = [], set()
    for raw in (text or "").splitlines():
        body = raw
        # strip the nxc PROTO/IP/PORT/HOST prefix if present
        if "]" in body and body.lstrip().startswith(("LDAP", "SMB")):
            body = body.split("  ", 4)[-1]
        m = _ROW.search(body)
        if not m:
            continue
        account = m.group("account")
        if account.lower() in ("accountname", "account"):
            continue  # header row
        vt = _vector_type(m.group("dtype"))
        rights = m.group("rights").strip()
        rights = "" if rights.upper() in ("N/A", "") else rights
        if account in seen:
            continue
        seen.add(account)
        out.append(Delegation(account, m.group("atype"), vt, m.group("dtype").strip(),
                              rights))
    return out


def _argv(cred, dc_ip):
    from .creds import render_nxc
    return render_nxc(cred, "ldap", target=dc_ip, extra=["--find-delegation"])


@dataclass
class DelegationReport:
    dc: str = None
    found: int = 0
    delegations: list = None
    aborted: str = None

    def __post_init__(self):
        if self.delegations is None:
            self.delegations = []


def run_find(store, dc_host, cred, *, run=None, on_event=None):
    """Enumerate delegation via nxc and record each account as a finding."""
    from . import runner as runner_mod
    run = run or (lambda argv, env=None: runner_mod.run(argv, env_add=env))
    cred = cred if isinstance(cred, Credential) else Credential.from_row(cred)
    report = DelegationReport(dc=dc_host["ip"])
    rendered = _argv(cred, dc_host["ip"])
    result = run(rendered.argv, rendered.env)
    if not result.ok:
        report.aborted = result.error
        return report
    with store.transaction():
        for d in parse_delegation(result.output):
            title = f"{d.dtype} delegation on {d.account}"
            evidence = f"{d.account} ({d.account_type}) — {d.dtype}" + (
                f" -> {d.rights_to}" if d.rights_to else "")
            _, created = store.add_finding(d.kind, title, host_id=dc_host["id"],
                                           evidence=evidence, risk="reversible")
            report.delegations.append(d)
            if created:
                report.found += 1
                if on_event:
                    on_event(f"  {d.dtype}: {d.account}"
                             + (f" -> {d.rights_to}" if d.rights_to else ""))
    return report
