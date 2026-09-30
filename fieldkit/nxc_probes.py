"""NXC probes — the built-in flags and ``-M`` modules fieldkit drives beyond target-side
exec.

The Windows ``enum`` runs command-shell checks (``whoami /priv`` etc.) via nxc's exec
transport. But nxc itself carries a large module ecosystem (``--shares``,
``--loggedon-users``, ``--sessions``, ``-M laps``, ``-M gpp_password`` …) that reveals
facts the exec-transport can't reach: readable shares, active sessions on remote
hosts, LAPS passwords the caller is allowed to fetch, GPP cpasswords in SYSVOL. Each
probe is a short nxc invocation with a specific flag/module, a parser for its output,
and a record of what it found — folded into engagement state as steps, findings, or
promoted credentials.

A probe is intentionally tiny — one flag or module per probe — so a single one that
misbehaves (nxc version drift, a module that crashes on a specific target) doesn't
kill the whole enum. Each probe records its captured output as a step; findings and
credentials are promoted through the same store paths the rest of fieldkit uses, so
``report --check`` and ``retest`` see them just like any other proven work.
"""
import re
import shlex
from dataclasses import dataclass, field

from . import runner as runner_mod
from .creds import Credential, render_nxc


@dataclass(frozen=True)
class Probe:
    """One nxc probe. ``extra`` is the argv fragment appended after user/password
    (``["--shares"]`` or ``["-M", "laps"]``); ``parse`` turns nxc output into a
    :class:`ProbeResult`. ``requires_admin`` guards probes that are only useful with
    admin — LAPS read, LSA-through-modules — so a non-admin foothold skips them."""

    key: str
    label: str
    proto: str
    extra: tuple
    requires_admin: bool = False


@dataclass
class ProbeFinding:
    """One fact extracted from a probe: a shape the engagement store can render."""
    kind: str                # vector_type in the store: "smb_share", "laps_password", ...
    title: str
    evidence: str = ""       # verbatim slice of nxc output
    severity: str = "Info"
    admin: bool = False      # promote to admin_access if the probe revealed one


@dataclass
class PromotedCredential:
    """A credential a probe recovered — passes to store.add_credential."""
    username: str
    secret: str
    secret_type: str = "password"
    domain: str = ""
    source: str = "nxc-probe"


@dataclass
class ProbeResult:
    ok: bool = False
    findings: list = field(default_factory=list)   # ProbeFinding
    credentials: list = field(default_factory=list)  # PromotedCredential
    error: str = None                              # tool error / parse error
    raw_output: str = ""


# ------------------------------------------------------------- parsers

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def _strip_ansi(text):
    return _ANSI.sub("", text or "")


#: A permissions token in ``nxc --shares`` output: READ, WRITE, or their comma pair.
#: Nothing else in a share row matches — used to distinguish "no perms" (IPC$ shown
#: without a permissions column) from a real permissions cell.
_PERMS_RE = re.compile(r"^(READ|WRITE|READ,WRITE|WRITE,READ)$", re.IGNORECASE)


def parse_shares(text):
    """``nxc smb ... --shares`` output → one finding per readable+writable share.

    nxc prints a table after the ``Enumerated shares`` marker::

        SMB   10.0.0.1  445  DC01  Share       Permissions  Remark
        SMB   10.0.0.1  445  DC01  -----       -----------  ------
        SMB   10.0.0.1  445  DC01  sysvol      READ,WRITE
    """
    findings = []
    text = _strip_ansi(text)
    seen_header = False
    for raw in text.splitlines():
        # skip until we've passed the "---" separator row.
        if "-----" in raw and "---" in raw:
            seen_header = True
            continue
        if not seen_header:
            continue
        # tokens after the nxc PROTO/IP/PORT/HOST prefix are the table row. Split on
        # runs of 2+ spaces so a multi-word remark doesn't shard.
        toks = raw.split()
        if len(toks) < 5:
            continue
        after = raw.split(toks[3], 1)[-1]
        parts = [p.strip() for p in re.split(r"\s{2,}", after.strip()) if p.strip()]
        if not parts:
            continue
        share = parts[0]
        # perms is only present when the second column is one of the permission tokens.
        # IPC$ often appears with an empty permissions column, so parts[1] is the remark
        # ("IPC Service ..."), not the perms — skip it.
        perms = parts[1] if len(parts) > 1 and _PERMS_RE.match(parts[1]) else ""
        remark = parts[2] if len(parts) > 2 else ""
        if not perms:
            continue
        title = f"SMB share {share!r} — {perms}" + (f" ({remark})" if remark else "")
        sev = "Medium" if "WRITE" in perms.upper() else "Info"
        findings.append(ProbeFinding(
            kind="smb_share", title=title, evidence=raw.strip(), severity=sev))
    return findings


def parse_loggedon_users(text):
    """``nxc smb ... --loggedon-users`` — one finding per active user session."""
    findings = []
    for raw in _strip_ansi(text).splitlines():
        # Rows look like: SMB IP 445 HOST domain\user   type: interactive/service
        if "\\" not in raw:
            continue
        after = raw.split("]", 1)[-1].strip() if "]" in raw else ""
        m = re.search(r"([A-Za-z0-9._-]+\\[A-Za-z0-9._-]+)", after or raw)
        if not m:
            continue
        principal = m.group(1)
        findings.append(ProbeFinding(
            kind="loggedon_user", title=f"active session: {principal}",
            evidence=raw.strip()))
    return findings


def parse_sessions(text):
    """``nxc smb ... --sessions`` — active SMB sessions (source IP + username)."""
    findings = []
    for raw in _strip_ansi(text).splitlines():
        after = raw.split("]", 1)[-1].strip() if "]" in raw else ""
        # Rows: "user     source_ip     hidden/authenticated"
        m = re.search(r"([A-Za-z0-9._$-]+)\s+(\d+\.\d+\.\d+\.\d+)", after)
        if not m:
            continue
        user, src = m.group(1), m.group(2)
        if user in ("Username", "-------"):
            continue
        findings.append(ProbeFinding(
            kind="smb_session", title=f"SMB session: {user} from {src}",
            evidence=raw.strip()))
    return findings


def parse_laps(text):
    """``nxc smb ... -M laps`` — retrieved LAPS passwords are credentials."""
    result = ProbeResult(ok=True, raw_output=text)
    for raw in _strip_ansi(text).splitlines():
        body = raw.split("]", 1)[-1] if "]" in raw else raw
        # nxc laps output: "Computer:ACCOUNT Password: <plaintext>"
        # or JSON-ish depending on version. Match the classic form.
        m = re.search(
            r"(?:Computer|Host)[:=]\s*([A-Za-z0-9._$-]+).*Password[:=]\s*(\S+)",
            body)
        if m:
            host, pw = m.group(1), m.group(2)
            result.findings.append(ProbeFinding(
                kind="laps_password", title=f"LAPS: {host}", severity="High",
                evidence=raw.strip()))
            result.credentials.append(PromotedCredential(
                username=".\\Administrator", secret=pw, secret_type="password",
                source="nxc-probe:laps"))
    return result


def parse_gpp(text):
    """``nxc smb ... -M gpp_password`` — cleartext creds from SYSVOL GPP XML."""
    result = ProbeResult(ok=True, raw_output=text)
    # Match ``username: <u>  password: <p>`` anywhere in the line — some nxc versions
    # prefix each result with ``[+]`` and the module tag; others just print the pair
    # directly under the SMB banner. ``search`` (vs ``match``) tolerates both.
    pair_re = re.compile(
        r"username\s*[:=]\s*(\S+)\s+password\s*[:=]\s*(\S+)",
        re.IGNORECASE)
    for raw in _strip_ansi(text).splitlines():
        m = pair_re.search(raw)
        if m:
            user, pw = m.group(1), m.group(2)
            result.findings.append(ProbeFinding(
                kind="gpp_cpassword", title=f"GPP cpassword: {user}",
                severity="High", evidence=raw.strip()))
            result.credentials.append(PromotedCredential(
                username=user, secret=pw, secret_type="password",
                source="nxc-probe:gpp_password"))
    return result


# ------------------------------------------------------------- registry

PROBES = (
    Probe("shares", "readable/writable SMB shares",
          "smb", ("--shares",)),
    Probe("loggedon_users", "active logon sessions",
          "smb", ("--loggedon-users",), requires_admin=True),
    Probe("sessions", "SMB session table",
          "smb", ("--sessions",)),
    Probe("laps", "LAPS passwords (if authorised to read)",
          "smb", ("-M", "laps"), requires_admin=True),
    Probe("gpp_password", "GPP cpassword in SYSVOL",
          "smb", ("-M", "gpp_password")),
)


PARSERS = {
    "shares": lambda t: ProbeResult(ok=True, findings=parse_shares(t), raw_output=t),
    "loggedon_users": lambda t: ProbeResult(
        ok=True, findings=parse_loggedon_users(t), raw_output=t),
    "sessions": lambda t: ProbeResult(
        ok=True, findings=parse_sessions(t), raw_output=t),
    "laps": parse_laps,
    "gpp_password": parse_gpp,
}


# ------------------------------------------------------------- driver

@dataclass
class ProbeRunReport:
    ran: list = field(default_factory=list)          # [(probe_key, ProbeResult)]
    skipped: list = field(default_factory=list)      # [(probe_key, reason)]


def run_probes(store, host, cred_row, *, is_admin=False, run=None, on_event=None,
               probes=PROBES, timeout=120):
    """Run each ``PROBES`` entry against ``host`` as ``cred_row``, capturing output as
    a step + folding recognized facts into findings/credentials.

    Skips admin-only probes when ``is_admin`` is False so a low-priv foothold doesn't
    hammer LAPS/logged-on-users pointlessly. Runs read-only.
    """
    run = run or (lambda argv, env=None:
                  runner_mod.run(argv, env_add=env, timeout=timeout))
    cred = Credential.from_row(cred_row)
    report = ProbeRunReport()
    for probe in probes:
        if probe.requires_admin and not is_admin:
            report.skipped.append((probe.key, "requires admin"))
            continue
        rendered = render_nxc(cred, probe.proto, target=host["ip"],
                              extra=list(probe.extra))
        res = run(rendered.argv, rendered.env)
        if on_event:
            on_event(f"  [nxc:{probe.key}] {host['ip']}: "
                     f"{shlex.join(list(probe.extra))}")
        if not res.ok:
            report.skipped.append((probe.key, res.error or "tool run failed"))
            continue
        text = res.output or ""
        parser = PARSERS.get(probe.key, lambda t: ProbeResult(ok=True, raw_output=t))
        parsed = parser(text)
        with store.transaction():
            step_id = store.add_step(
                cmd=f"nxc {probe.proto} {host['ip']} {' '.join(probe.extra)}",
                output=text, exit_code=res.exit_code, host_id=host["id"],
                transport=f"nxc-probe:{probe.key}")
            for f in parsed.findings:
                store.add_finding(host_id=host["id"], vector_type=f.kind,
                                  title=f.title, evidence=f.evidence,
                                  severity=f.severity, proven=True)
            for c in parsed.credentials:
                cred_obj = Credential(username=c.username, secret=c.secret,
                                      secret_type=c.secret_type, domain=c.domain)
                store.add_credential(cred_obj, source=c.source)
        report.ran.append((probe.key, parsed))
    return report
