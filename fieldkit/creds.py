"""The canonical credential model, one liberal parser, and per-tool renderers.

Every tool in the kit takes credentials differently, and getting the format wrong 40
hosts into a spray was a real failure. fieldkit removes that class of problem by
owning **one** model and translating outward:

    messy operator paste  ->  parse_credential()  ->  Credential  ->  render_*()

Ingest is deliberately liberal — it accepts the shapes operators actually paste
(``DOMAIN\\user:pass``, ``user@corp.local``, ``corp/user:pass``, pwdump
``user:LM:NT``, ``:NT``, a secretsdump line, an AES key, a ccache path, an SSH key).
Output is strict: renderers return **argv lists**, never shell strings, so a password
containing ``'``, ``"``, ``\\`` or a space is passed through verbatim by
``subprocess`` instead of being mangled by hand-rolled quoting (the v1 bug class).

Anything the parser had to *assume* is returned as a note so the CLI can echo its
interpretation back before a single packet is sent.
"""
import os
import re
from dataclasses import dataclass, field

from .errors import FieldkitError

#: The canonical secret kinds. ``lm:nt`` keeps a non-empty LM half (some tools want
#: the full pair); everything else stores a single value.
SECRET_TYPES = ("password", "nt", "lm:nt", "aes256", "aes128", "ccache", "ssh_key")

#: The "no LM hash" sentinel every modern dump emits; carrying it around is noise.
EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"

HEX32 = r"[0-9a-fA-F]{32}"
HEX64 = r"[0-9a-fA-F]{64}"

_RE_HEX32 = re.compile(rf"^{HEX32}$")
_RE_HEX64 = re.compile(rf"^{HEX64}$")
# secretsdump / pwdump:  user:RID:LM:NT:::   (trailing colons optional)
_RE_PWDUMP = re.compile(rf"^(?P<user>[^:]*):(?P<rid>\d+):(?P<lm>{HEX32}):(?P<nt>{HEX32}):*.*$")
# hash pair without the RID:  user:LM:NT
_RE_LMNT = re.compile(rf"^(?P<user>[^:]*):(?P<lm>{HEX32}):(?P<nt>{HEX32})$")
# secretsdump kerberos key line:  user:aes256-cts-hmac-sha1-96:<hex>
_RE_KRBKEY = re.compile(
    r"^(?P<user>[^:]*):(?P<kind>aes256-cts-hmac-sha1-96|aes128-cts-hmac-sha1-96):"
    r"(?P<key>[0-9a-fA-F]+)$")
# user::NT  or  user:NT   (NT-only, the shape `nxc -H` wants)
_RE_NTONLY = re.compile(rf"^(?P<user>[^:]*)::?(?P<nt>{HEX32})$")

_CCACHE_SUFFIXES = (".ccache", ".kirbi", ".tgt")
_KEY_SUFFIXES = (".pem", ".key", ".priv")
_KEY_NAMES = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")


class CredentialError(FieldkitError, ValueError):
    """A credential could not be understood — reported to the operator verbatim."""


@dataclass(frozen=True)
class Credential:
    """One credential, normalized. This is what state stores and tools render from."""

    username: str
    secret: str
    secret_type: str = "password"
    domain: str = ""
    local_auth: bool = False

    def __post_init__(self):
        if not self.username:
            raise CredentialError("a credential needs a username (use --user)")
        if not self.secret:
            raise CredentialError("a credential needs a secret (password/hash/key)")
        if self.secret_type not in SECRET_TYPES:
            raise CredentialError(
                f"unknown secret type {self.secret_type!r} — one of {', '.join(SECRET_TYPES)}")

    # -- derived views ------------------------------------------------------

    @property
    def is_hash(self):
        return self.secret_type in ("nt", "lm:nt")

    @property
    def nt(self):
        """The NT half, for tools that only take one hash."""
        if self.secret_type == "nt":
            return self.secret
        if self.secret_type == "lm:nt":
            return self.secret.split(":", 1)[1]
        return None

    @property
    def principal(self):
        """``DOMAIN\\user`` when domain-joined, ``.\\user`` for an explicit local account."""
        if self.local_auth and not self.domain:
            return f".\\{self.username}"
        return f"{self.domain}\\{self.username}" if self.domain else self.username

    @classmethod
    def from_row(cls, row):
        """Rebuild the model from a ``credential`` row, so stored creds render too.

        Everything downstream (spray, exec, loot, report) works from a credential it
        read back out of state — this is the inverse of ``Store.add_credential`` and
        the only supported way to get there.
        """
        return cls(username=row["username"], secret=row["secret"],
                   secret_type=row["secret_type"], domain=row["domain"] or "",
                   local_auth=bool(row["local_auth"]))


@dataclass
class Parsed:
    """A parse result plus every assumption made getting there."""

    credential: Credential
    notes: list = field(default_factory=list)


# ------------------------------------------------------------------------ helpers

def _strip_wrapping_quotes(spec):
    """Operators paste quotes in from a terminal more often than you'd think."""
    if len(spec) >= 2 and spec[0] == spec[-1] and spec[0] in "'\"":
        inner = spec[1:-1]
        if spec[0] not in inner:
            return inner, True
    return spec, False


def _classify_path(value):
    """``'ccache'``, ``'ssh_key'`` or ``None`` — a ticket/key path is not a principal.

    Classified once per parse and passed down, so the filesystem is probed at most
    once. Bulk ingest of ``corp/user:pass`` lines must not stat a file per line, so
    the on-disk check only runs for something actually shaped like a path.
    """
    lowered = value.lower()
    if lowered.endswith(_CCACHE_SUFFIXES):
        return "ccache"
    if os.path.basename(lowered) in _KEY_NAMES or lowered.endswith(_KEY_SUFFIXES):
        return "ssh_key"
    path_shaped = ":" not in value and (
        value.startswith(("/", "./", "~", "..")) or os.sep in value)
    if path_shaped and os.path.isfile(value) and _file_has_key_header(value):
        return "ssh_key"
    return None


def _file_has_key_header(path):
    try:
        with open(path, "r", errors="replace") as fh:
            return "PRIVATE KEY" in fh.read(200)
    except OSError:
        return False


def _normalize_hash_pair(lm, nt, notes):
    """Drop the empty-LM sentinel; keep a real LM half as ``lm:nt``."""
    lm, nt = lm.lower(), nt.lower()
    if lm in (EMPTY_LM, "0" * 32, ""):
        return "nt", nt
    notes.append("LM half is non-empty and was kept (secret_type=lm:nt)")
    return "lm:nt", f"{lm}:{nt}"


def _split_principal(spec):
    """Peel ``DOMAIN\\``, ``corp/`` or ``.\\`` off the front. Returns (domain, local, rest)."""
    first_colon = spec.find(":")

    def _before_colon(idx):
        return idx != -1 and (first_colon == -1 or idx < first_colon)

    if spec.startswith(".\\") or spec.startswith("./"):
        return "", True, spec[2:]

    backslash = spec.find("\\")
    if _before_colon(backslash):
        domain, spec = spec[:backslash], spec[backslash + 1:]
        if domain == ".":
            return "", True, spec
        return domain, False, spec

    slash = spec.find("/")
    # A leading slash is a filesystem path (ccache/key), not corp/user.
    if _before_colon(slash) and slash > 0:
        return spec[:slash], False, spec[slash + 1:]

    return "", False, spec


def _split_upn(user):
    """``jdoe@corp.local`` carries its own domain. Returns (user, domain)."""
    user = user.strip()
    if "@" in user:
        name, _, suffix = user.rpartition("@")
        if name and suffix:
            return name, suffix
    return user, ""


# -------------------------------------------------------------------------- parse

def parse_credential(spec=None, *, domain=None, username=None, password=None,
                     nt_hash=None, aes_key=None, ccache=None, ssh_key=None,
                     local_auth=None):
    """Normalize whatever the operator has into one :class:`Credential`.

    ``spec`` is the free-form paste; the keyword arguments are the explicit CLI
    flags, which always win over anything inferred from ``spec``. Returns a
    :class:`Parsed` (credential + the assumptions made), or raises
    :class:`CredentialError` with a message aimed at the operator.
    """
    notes = []
    explicit = [("password", password), ("nt", nt_hash), ("aes", aes_key),
                ("ccache", ccache), ("ssh_key", ssh_key)]
    given = [(k, v) for k, v in explicit if v]
    if len(given) > 1:
        raise CredentialError(
            "give exactly one secret: " + ", ".join(k for k, _ in given) + " were all supplied")

    spec = (spec or "").strip()
    if spec:
        spec, stripped = _strip_wrapping_quotes(spec)
        if stripped:
            notes.append("stripped the surrounding quotes you pasted")

    sec_type, secret, spec_domain, spec_user, spec_local = None, None, "", "", False

    path_kind = _classify_path(spec) if spec else None
    if path_kind:
        # A bare ticket/key path: never split it on '/' as if it were corp/user.
        sec_type, secret, spec_user, upn_domain = path_kind, _resolve_path(spec), "", ""
    elif spec:
        spec_domain, spec_local, rest = _split_principal(spec)
        sec_type, secret, spec_user, upn_domain = _parse_rest(rest, notes)
        if upn_domain and not spec_domain:
            spec_domain = upn_domain
        elif upn_domain and spec_domain and upn_domain.lower() != spec_domain.lower():
            notes.append(
                f"two domains in the input ({spec_domain} and {upn_domain}); kept {spec_domain}")

    # Explicit flags override anything sniffed out of the spec.
    if given:
        kind, value = given[0]
        if secret is not None:
            notes.append(f"--{kind.replace('_', '-')} overrode the secret in the input")
        sec_type, secret = _secret_from_flag(kind, value, notes)

    user = username or spec_user
    if user:
        user, upn_domain = _split_upn(user)
        if upn_domain and not (domain or spec_domain):
            spec_domain = upn_domain

    if sec_type == "ccache" and not user:
        user = _user_from_ccache_path(secret)
        if user:
            notes.append(f"took the username ({user}) from the ccache filename")

    dom = domain if domain is not None else spec_domain
    dom = (dom or "").strip().rstrip("\\/")
    is_local = spec_local if local_auth is None else bool(local_auth)

    if not user:
        raise CredentialError(f"could not find a username in {spec!r} — pass --user")
    if secret is None:
        raise CredentialError(
            f"could not find a secret in {spec!r} — pass --password/--hash/--aes/--ccache/--ssh-key")

    if is_local and dom:
        notes.append(
            f"local auth requested: domain {dom} is recorded but tools will be told --local-auth")

    cred = Credential(username=user, secret=secret, secret_type=sec_type or "password",
                      domain=dom, local_auth=is_local)
    return Parsed(cred, notes)


def _secret_from_flag(kind, value, notes):
    value = value.strip()
    if kind == "password":
        return "password", value
    if kind == "nt":
        return _hash_from_flag(value, notes)
    if kind == "aes":
        if _RE_HEX64.match(value):
            return "aes256", value.lower()
        if _RE_HEX32.match(value):
            return "aes128", value.lower()
        raise CredentialError(
            f"--aes wants a 32 (AES128) or 64 (AES256) character hex key, got {len(value)} chars")
    if kind == "ccache":
        return "ccache", _resolve_path(value)
    if kind == "ssh_key":
        return "ssh_key", _resolve_path(value)
    raise CredentialError(f"unknown secret kind {kind!r}")  # pragma: no cover - guarded above


def _hash_from_flag(value, notes):
    """--hash takes ``NT``, ``:NT`` or ``LM:NT``."""
    value = value.strip().lstrip(":")
    if _RE_HEX32.match(value):
        return "nt", value.lower()
    parts = value.split(":")
    if len(parts) == 2 and all(_RE_HEX32.match(p) for p in parts):
        return _normalize_hash_pair(parts[0], parts[1], notes)
    raise CredentialError(
        f"--hash wants an NT hash (32 hex chars), ':NT' or 'LM:NT' — got {value!r}")


def _resolve_path(value):
    path = os.path.expanduser(value)
    return os.path.abspath(path) if os.path.exists(path) else path


def _user_from_ccache_path(path):
    """impacket names tickets ``user@DOMAIN.ccache`` / ``user.ccache``."""
    stem = os.path.basename(path)
    for suffix in _CCACHE_SUFFIXES:
        if stem.lower().endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    stem = stem.split("@", 1)[0]
    return stem if re.fullmatch(r"[\w.$-]+", stem or "") else ""


def _parse_rest(rest, notes):
    """Parse ``user[:secret]`` after the domain prefix is gone.

    Returns ``(secret_type, secret, username, upn_domain)``; ``secret`` is ``None``
    when the input carried a principal only (the flags must supply the secret).
    """
    rest = rest.strip()

    # A key path can still show up after a principal prefix was stripped.
    path_kind = _classify_path(rest)
    if path_kind:
        return path_kind, _resolve_path(rest), "", ""

    m = _RE_PWDUMP.match(rest)
    if m:
        notes.append("read as a secretsdump/pwdump line")
        sec_type, secret = _normalize_hash_pair(m.group("lm"), m.group("nt"), notes)
        return (sec_type, secret) + _split_upn(m.group("user"))

    m = _RE_KRBKEY.match(rest)
    if m:
        key = m.group("key").lower()
        kind = "aes256" if m.group("kind").startswith("aes256") else "aes128"
        want = 64 if kind == "aes256" else 32
        if len(key) != want:
            raise CredentialError(
                f"{m.group('kind')} key should be {want} hex chars, got {len(key)}")
        notes.append(f"read as a Kerberos {kind} key")
        return (kind, key) + _split_upn(m.group("user"))

    m = _RE_LMNT.match(rest)
    if m:
        sec_type, secret = _normalize_hash_pair(m.group("lm"), m.group("nt"), notes)
        return (sec_type, secret) + _split_upn(m.group("user"))

    m = _RE_NTONLY.match(rest)
    if m:
        # `user:<32 hex>` is overwhelmingly a hash, but a password *can* look like
        # one — say so instead of guessing silently. `user::<hash>` is unambiguous.
        if "::" not in rest:
            notes.append("secret read as an NT hash (32 hex chars) — "
                         "use --password if it is really a password")
        return ("nt", m.group("nt").lower()) + _split_upn(m.group("user"))

    if ":" in rest:
        # Split on the FIRST colon only: passwords contain colons.
        user, _, secret = rest.partition(":")
        if not secret:
            notes.append("input ended with ':' — no secret found there")
            return (None, None) + _split_upn(user)
        if ":" in secret:
            notes.append("password contains ':' — kept everything after the first colon")
        return ("password", secret) + _split_upn(user)

    return (None, None) + _split_upn(rest)


def parse_credential_lines(text, **kwargs):
    """Parse a credential file (one per line; ``#`` comments and blanks skipped).

    Returns ``(parsed, errors)`` where ``errors`` is a list of
    ``(line_number, line, message)`` — a bad line never aborts the good ones.
    """
    parsed, errors = [], []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            parsed.append(parse_credential(line, **kwargs))
        except CredentialError as exc:
            errors.append((lineno, line, str(exc)))
    return parsed, errors


# --------------------------------------------------------------------- confirm-back

def secret_display(cred):
    """How the secret is shown to the operator.

    Passwords are shown in full and quoted (a mis-split password is exactly what the
    confirm-back exists to catch, and trailing spaces must be visible); hashes and
    keys are fingerprinted, since their value is long and their *type* is the thing
    worth checking.
    """
    t = cred.secret_type
    if t == "password":
        return f"'{cred.secret}' (password)"
    if t in ("nt", "lm:nt"):
        return f"<{t.upper()} hash {_fingerprint(cred.secret)}>"
    if t in ("aes256", "aes128"):
        return f"<{t.upper()} key {_fingerprint(cred.secret)}>"
    if t == "ccache":
        return f"<kerberos ccache {cred.secret}>"
    if t == "ssh_key":
        return f"<ssh key {cred.secret}>"
    return f"<{t}>"  # pragma: no cover - SECRET_TYPES is closed


def _fingerprint(value):
    return value if len(value) <= 20 else f"{value[:8]}…{value[-8:]}"


def describe(cred):
    """The one-line confirm-back echoed before anything runs."""
    return (f"parsed as → domain={cred.domain or '(none)'}  user={cred.username}  "
            f"secret={secret_display(cred)}  "
            f"local_auth={'yes' if cred.local_auth else 'no'}")


# ------------------------------------------------------------------------ renderers

@dataclass
class Rendered:
    """A ready-to-run command: argv (never a shell string), env additions, caveats."""

    argv: list
    env: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)


def _auth_scope_nxc(cred):
    if cred.local_auth:
        return ["--local-auth"]
    return ["-d", cred.domain] if cred.domain else []


def render_nxc(cred, proto=None, target=None, extra=()):
    """netexec: ``-u user`` + ``-p pass`` | ``-H hash``, and the domain/local scope."""
    argv = ["nxc"]
    if proto:
        argv.append(proto)
    if target:
        argv.append(target)
    argv += ["-u", cred.username]
    env, notes = {}, []

    t = cred.secret_type
    if t == "password":
        argv += ["-p", cred.secret]
    elif t in ("nt", "lm:nt"):
        argv += ["-H", cred.secret]
    elif t in ("aes256", "aes128"):
        argv += ["--aesKey", cred.secret, "-k"]
    elif t == "ccache":
        argv += ["-k", "--use-kcache"]
        env["KRB5CCNAME"] = cred.secret
    elif t == "ssh_key":
        argv += ["--key-file", cred.secret]
        notes.append("key auth is the ssh protocol only")
    argv += _auth_scope_nxc(cred)
    argv += list(extra)
    return Rendered(argv, env, notes)


def render_impacket(cred, host, tool="wmiexec.py", extra=(), port=None):
    """impacket: ``domain/user:pass@host`` | ``-hashes :NT`` | ``-k -no-pass``.

    impacket's own target parser stops a password at ``@``; when that would corrupt
    the credential the password is left out and the tool prompts for it instead.
    """
    argv, env, notes = [tool], {}, []
    prefix = f"{cred.domain}/" if cred.domain else ""
    t = cred.secret_type
    inline_secret = ""

    if t == "password":
        if "@" in cred.secret:
            notes.append("password contains '@' — impacket's target parser splits on it, "
                         "so the password is omitted and impacket will prompt for it")
        else:
            inline_secret = f":{cred.secret}"
    target = f"{prefix}{cred.username}{inline_secret}@{host}"
    argv.append(target)

    if t in ("nt", "lm:nt"):
        argv += ["-hashes", cred.secret if t == "lm:nt" else f":{cred.secret}"]
    elif t in ("aes256", "aes128"):
        argv += ["-aesKey", cred.secret, "-k", "-no-pass"]
    elif t == "ccache":
        argv += ["-k", "-no-pass"]
        env["KRB5CCNAME"] = cred.secret
    elif t == "ssh_key":
        notes.append("impacket has no SSH key auth — use ssh/nxc ssh for this credential")

    if cred.local_auth and cred.domain:
        notes.append("local account: impacket authenticates locally when the domain is the host")
    if port:
        argv += ["-port", str(port)]
    argv += list(extra)
    return Rendered(argv, env, notes)


def render_evil_winrm(cred, host, port=None, extra=()):
    """evil-winrm: ``-u user`` + ``-p pass`` | ``-H NT``; ``-r domain`` for Kerberos."""
    argv = ["evil-winrm", "-i", host, "-u", cred.username]
    env, notes = {}, []
    t = cred.secret_type
    if t == "password":
        argv += ["-p", cred.secret]
    elif t in ("nt", "lm:nt"):
        # evil-winrm takes the NT half only.
        argv += ["-H", cred.nt]
        if t == "lm:nt":
            notes.append("evil-winrm takes the NT half only; the LM half was dropped")
    elif t == "ccache":
        argv += ["-r", cred.domain or "<realm>"]
        env["KRB5CCNAME"] = cred.secret
        if not cred.domain:
            notes.append("kerberos auth needs the realm — set the domain on this credential")
    else:
        notes.append(f"evil-winrm cannot use a {t} secret")
    if cred.domain and t not in ("ccache",) and not cred.local_auth:
        argv += ["-r", cred.domain]
    if port:
        argv += ["-P", str(port)]
    argv += list(extra)
    return Rendered(argv, env, notes)


def render_mssqlclient(cred, host, port=None, extra=()):
    """mssqlclient.py, with the ``-windows-auth`` rule.

    Windows auth is required whenever the login is a domain account *or* we are
    passing a hash — including for a local Windows account, which is the case the v1
    kit got wrong.
    """
    rendered = render_impacket(cred, host, tool="mssqlclient.py", port=port)
    if cred.domain or cred.is_hash or cred.local_auth:
        rendered.argv.append("-windows-auth")
    rendered.argv += list(extra)
    return rendered
