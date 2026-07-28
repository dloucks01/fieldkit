"""Parse netexec (nxc) output — the ``(Pwn3d!)`` oracle, turned into facts.

netexec is the protocol engine fieldkit drives; fieldkit owns no protocol code, it
reads what nxc printed. nxc's output is line-oriented and stable across its protocol
modules::

    SMB   10.0.0.5   445   DC01   [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)
    SMB   10.0.0.6   445   WS01   [+] corp.local\\Administrator:Winter2025! (Pwn3d!)
    SMB   10.0.0.7   445   WS02   [-] corp.local\\jdoe:Winter2025! STATUS_LOGON_FAILURE

This module turns those lines into two kinds of fact the credential loop runs on:

  * :class:`HostInfo` — the ``[*]`` banner: OS, hostname, domain, SMB signing. It
    fingerprints scope for free every time a spray touches a host.
  * :class:`AuthResult` — a ``[+]``/``[-]`` line: *is this credential valid on this
    host*, and does ``(Pwn3d!)`` mean *it is admin there*.

It is pure text→dataclass — no state, no subprocess — so the loop is testable
without a single packet. **Secret extraction is best-effort** (a password can contain
the spaces and status-shaped words nxc appends); the loop already knows the exact
credential it sprayed and keys on that, using the parser for the verdict, not to
re-learn the secret.
"""
import re
from dataclasses import dataclass, field

#: nxc colourizes when stdout is a tty; captured through a pipe it usually does not,
#: but strip SGR escapes unconditionally so a forced-colour capture still parses.
_ANSI = re.compile(r"\x1b\[[0-9;]*m")

#: PROTO  IP  PORT  HOSTNAME  BODY — the fixed four-column prefix every nxc line has.
#: HOSTNAME is a single token (netbios/computer name, or the literal ``None``); the
#: body is everything after it. IP is matched loosely to admit IPv6.
_LINE = re.compile(
    r"^(?P<proto>[A-Za-z][A-Za-z0-9]*)\s+"
    r"(?P<ip>[0-9A-Fa-f:.]+)\s+"
    r"(?P<port>\d+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<body>.*\S)\s*$")

#: The status result markers nxc prints at the head of a line body.
_MARKERS = ("[*]", "[+]", "[-]", "[!]")

#: nxc marks admin with a literal ``(Pwn3d!)``; on some modules it is preceded by a
#: reason (``Pwn3d!`` for admin, or e.g. ``(Guest)``). We treat the token as boolean.
_PWNED = "(Pwn3d!)"

#: A trailing failure reason nxc appends after ``[-] dom\\user:secret`` —
#: STATUS_LOGON_FAILURE, KDC_ERR_PREAUTH_FAILED, LOGON_FAILURE, and friends. Matched
#: only at end-of-line so a password that merely *contains* underscores is untouched.
_STATUS = re.compile(r"\s+(?P<status>(?:STATUS_|KDC_ERR_|SEC_E_)?[A-Z][A-Z0-9_]{3,})$")

#: ``(key:value)`` pairs in a host banner: (name:DC01) (domain:corp.local) (signing:True).
_KV = re.compile(r"\(([A-Za-z0-9_]+):([^)]*)\)")


@dataclass(frozen=True)
class HostInfo:
    """A parsed ``[*]`` host banner. Fields nxc did not print stay ``None``."""

    proto: str
    ip: str
    port: int
    hostname: str = None
    os: str = None          # the banner text before the first (key:value), e.g. "Windows Server 2019 Build 17763 x64"
    domain: str = None
    signing: bool = None
    smbv1: bool = None
    fields: dict = field(default_factory=dict)  # every (key:value) pair, verbatim

    @property
    def is_dc(self):
        """A signing-required SMB host that names a domain is, in practice, a DC.

        nxc does not print a DC flag, but domain controllers require SMB signing by
        default while member servers do not, so ``signing:True`` + a domain is the
        cheap heuristic the loop uses to pick where to read the password policy.
        """
        return bool(self.domain) and self.signing is True


@dataclass(frozen=True)
class AuthResult:
    """A parsed ``[+]``/``[-]`` authentication line."""

    proto: str
    ip: str
    port: int
    hostname: str = None
    domain: str = ""
    username: str = ""
    secret: str = ""        # as nxc echoed it (password or hash); best-effort — see module docstring
    success: bool = False
    admin: bool = False     # (Pwn3d!)
    status: str = None      # the failure reason on a [-] line, else None

    @property
    def principal(self):
        return f"{self.domain}\\{self.username}" if self.domain else self.username


@dataclass
class ParsedOutput:
    """Everything one nxc invocation told us, split by kind."""

    hosts: list = field(default_factory=list)   # HostInfo
    auth: list = field(default_factory=list)     # AuthResult

    @property
    def valid(self):
        return [r for r in self.auth if r.success]

    @property
    def pwned(self):
        return [r for r in self.auth if r.admin]


# --------------------------------------------------------------------------- lines

def _to_bool(text):
    t = text.strip().lower()
    if t in ("true", "yes", "1"):
        return True
    if t in ("false", "no", "0"):
        return False
    return None


def _split_marker(body):
    """Return ``(marker, message)`` for the first result marker in ``body``.

    nxc sometimes prefixes a module tag before the marker; we scan for the earliest
    of the known markers rather than assuming it leads the body.
    """
    best = None
    for mark in _MARKERS:
        idx = body.find(mark)
        if idx != -1 and (best is None or idx < best[0]):
            best = (idx, mark)
    if best is None:
        return None, body
    idx, mark = best
    return mark, body[idx + len(mark):].strip()


def _parse_host_info(proto, ip, port, host, message):
    pairs = {k.lower(): v for k, v in _KV.findall(message)}
    if not pairs:
        return None  # a generic [*] module line, not a host banner — nothing to record
    os_text = message.split("(", 1)[0].strip() or None
    signing = _to_bool(pairs["signing"]) if "signing" in pairs else None
    smbv1 = _to_bool(pairs["smbv1"]) if "smbv1" in pairs else None
    return HostInfo(
        proto=proto, ip=ip, port=port,
        hostname=pairs.get("name") or _clean_host(host),
        os=os_text, domain=pairs.get("domain") or None,
        signing=signing, smbv1=smbv1, fields=pairs)


def _parse_auth(proto, ip, port, host, mark, message):
    admin = _PWNED in message
    if admin:
        message = message.replace(_PWNED, "").strip()
    status = None
    if mark == "[-]":
        m = _STATUS.search(message)
        if m:
            status = m.group("status")
            message = message[: m.start()].rstrip()
    domain, username, secret = _split_credential(message)
    return AuthResult(
        proto=proto, ip=ip, port=port, hostname=_clean_host(host),
        domain=domain, username=username, secret=secret,
        success=(mark == "[+]"), admin=admin, status=status)


def _split_credential(text):
    """``DOMAIN\\user:secret`` → ``(domain, user, secret)``; missing parts empty.

    Splits on the first ``:`` (the principal never contains one; the secret may) and
    the last ``\\`` before it (a domain never contains one; a username may in odd
    cases, so favour the domain side being clean).
    """
    principal, sep, secret = text.partition(":")
    domain, _, username = principal.rpartition("\\")
    return domain, username or principal, secret if sep else ""


def _clean_host(token):
    return None if token in ("None", "") else token


def strip_prefix(line):
    """Return the message body of an nxc line (everything after PROTO/IP/PORT/HOST).

    A raw secretsdump paste with no nxc prefix is returned unchanged, so ``dump``
    parses tool output whether it came through nxc or straight from impacket.
    """
    clean = _ANSI.sub("", line).rstrip()
    m = _LINE.match(clean)
    return m.group("body") if m else clean.strip()


def parse_line(line):
    """Parse one nxc output line into a :class:`HostInfo`, :class:`AuthResult`, or
    ``None`` when the line is not one nxc auth/banner line we model."""
    m = _LINE.match(_ANSI.sub("", line).rstrip())
    if not m:
        return None
    proto = m.group("proto").upper()
    ip, port, host = m.group("ip"), int(m.group("port")), m.group("host")
    mark, message = _split_marker(m.group("body"))
    if mark in ("[+]", "[-]"):
        return _parse_auth(proto, ip, port, host, mark, message)
    if mark == "[*]":
        return _parse_host_info(proto, ip, port, host, message)
    return None  # [!] errors and unmarked module chatter carry no fact for the loop


def parse_output(text):
    """Parse a whole nxc capture into a :class:`ParsedOutput` (hosts + auth results)."""
    out = ParsedOutput()
    for line in text.splitlines():
        rec = parse_line(line)
        if isinstance(rec, HostInfo):
            out.hosts.append(rec)
        elif isinstance(rec, AuthResult):
            out.auth.append(rec)
    return out


# ---------------------------------------------------------------------- pass policy

@dataclass(frozen=True)
class PassPolicy:
    """The domain password policy — the lockout-safety input read before any spray.

    ``threshold`` is the bad-password count that locks an account (0 = lockout
    disabled). ``reset_minutes`` is the observation window after which the bad-count
    resets. Spraying stays lockout-safe by firing at most ``safe_attempts`` guesses
    per account inside one ``reset_minutes`` window.
    """

    domain: str = ""
    min_length: int = None
    threshold: int = None       # None = not seen, 0 = lockout disabled
    reset_minutes: int = None
    lockout_minutes: int = None

    @property
    def has_lockout(self):
        return bool(self.threshold)

    @property
    def safe_attempts(self):
        """Guesses per account per window that cannot trip the lockout.

        One below the threshold — the last allowed attempt before AD locks the
        account. ``None`` when lockout is disabled (spray freely) or the policy was
        not read (spray refuses without a policy)."""
        if self.threshold is None:
            return None
        if self.threshold == 0:
            return None
        return max(1, self.threshold - 1)


def _duration_minutes(text):
    """Sum a ``"1 day 4 minutes"`` / ``"30 minutes"`` duration to whole minutes.

    nxc renders lockout windows in mixed units; ``"None"``/``"Not Set"`` → ``None``."""
    text = text.strip()
    if not text or text.lower() in ("none", "not set"):
        return None
    total, seen = 0, False
    for value, unit in re.findall(r"(\d+)\s*(day|hour|minute|second)s?", text, re.I):
        seen = True
        n = int(value)
        unit = unit.lower()
        total += n * {"day": 1440, "hour": 60, "minute": 1, "second": 0}[unit]
    return total if seen else None


def _policy_int(text):
    text = text.strip()
    if text.lower() in ("none", "not set", ""):
        return 0 if text.lower() == "none" else None
    m = re.match(r"\d+", text)
    return int(m.group()) if m else None


def parse_pass_policy(text):
    """Parse ``nxc smb <dc> --pass-pol`` output into a :class:`PassPolicy`.

    Returns ``None`` when the capture contains no recognizable policy — the caller
    treats a missing policy as *refuse to spray*, never as *no lockout*.
    """
    domain = min_len = threshold = reset = lockout = None
    seen = False
    for raw in text.splitlines():
        line = _ANSI.sub("", raw)
        _, _, body = line.partition("]")  # drop the PROTO/IP/PORT/HOST prefix if present
        body = (body or line).strip()

        m = re.search(r"Dumping password info for domain:\s*(\S+)", body, re.I)
        if m:
            domain, seen = m.group(1), True
        m = re.search(r"Minimum password length:\s*(.+)", body, re.I)
        if m:
            min_len, seen = _policy_int(m.group(1)), True
        m = re.search(r"Account Lockout Threshold:\s*(.+)", body, re.I)
        if m:
            threshold, seen = _policy_int(m.group(1)), True
        m = re.search(r"Reset Account Lockout Counter:\s*(.+)", body, re.I)
        if m:
            reset, seen = _duration_minutes(m.group(1)), True
        m = re.search(r"Locked Account Duration:\s*(.+)", body, re.I)
        if m:
            lockout, seen = _duration_minutes(m.group(1)), True
    if not seen:
        return None
    return PassPolicy(domain=domain or "", min_length=min_len, threshold=threshold,
                      reset_minutes=reset, lockout_minutes=lockout)
