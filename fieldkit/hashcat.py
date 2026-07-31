"""Hashcat potfile ingest — cracked ``hash:plaintext`` → promoted credentials.

Hashes usually enter the store as :func:`dump.parse_dump` loot rows (SAM/NTDS/
LSA output from a spray). When the tester cracks them offline with hashcat,
the potfile has ``<hash>:<plaintext>`` per line — this module reads that,
matches each cracked hash against loot to recover the principal it belongs to,
and promotes the plaintext to a :class:`~fieldkit.creds.Credential`.

Two ends the same tester hits:

  * cracked hash that HAS a loot match — attributed to the right user, promoted
    as a full ``DOMAIN\\user:password`` credential ready to spray;
  * cracked hash with no loot match yet — recorded as its own loot row
    (``kind='cracked_hash'``) so the pair survives until the missing dump is
    ingested later.

Split the same way :mod:`ingest` is: :func:`parse_potfile` is pure, :func:`apply`
writes.
"""
import re
from dataclasses import dataclass, field

from .creds import Credential, CredentialError


# ------------------------------------------------------------------- hash shapes

_NT_HASH = re.compile(r"^[0-9a-fA-F]{32}$")
_LM_NT = re.compile(r"^([0-9a-fA-F]{32}):([0-9a-fA-F]{32})$")


def _detect_hash_type(h):
    """Best-effort hash-type detection from the shape alone.

    Returns one of: 'nt' | 'lm:nt' | 'ntlmv2' | 'dcc2' | 'krb5tgs' | 'unknown'.
    """
    if _LM_NT.match(h):
        return "lm:nt"
    if _NT_HASH.match(h):
        return "nt"
    if h.startswith("$DCC2$"):
        return "dcc2"
    if h.startswith("$krb5tgs$"):
        return "krb5tgs"
    if h.startswith("$krb5asrep$"):
        return "krb5asrep"
    # netntlmv2 has 5 colon-separated fields ending in a hex blob
    if h.count("::") >= 1 and "::" in h:
        return "ntlmv2"
    return "unknown"


# ------------------------------------------------------------------- parse

@dataclass
class CrackedEntry:
    """One cracked line from a hashcat potfile: the raw hash + the plaintext."""

    hash: str
    plaintext: str
    hash_type: str = "unknown"


_NT_LINE = re.compile(r"^([0-9a-fA-F]{32}):(.+)$")
_LM_NT_LINE = re.compile(r"^([0-9a-fA-F]{32}:[0-9a-fA-F]{32}):(.+)$")


def parse_potfile(text):
    """Yield every ``hash:plaintext`` line as a :class:`CrackedEntry`.

    Splitting hash from plaintext is ambiguous in the general potfile format
    (both sides may contain colons). We detect the two common well-known
    prefixes — NT (32 hex chars) and LM:NT (32:32 hex chars) — and split on the
    first colon AFTER the recognized hash, so plaintexts with colons survive.
    For unknown hash shapes (DCC2, krb5*, custom formats) we fall back to
    ``rpartition(":")`` — the plaintext is the last colon-separated field.
    Skips blank lines and lines starting with ``#``.
    """
    out = []
    for raw in (text or "").splitlines():
        line = raw.rstrip("\r\n")
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        # Try well-known prefixes first so plaintexts with colons are preserved.
        m = _LM_NT_LINE.match(line)
        if m:
            h, plain = m.group(1), m.group(2)
        else:
            m = _NT_LINE.match(line)
            if m:
                h, plain = m.group(1), m.group(2)
            else:
                # Unknown hash shape (DCC2 / krb5* / custom) — best-effort split
                # on the last colon. Plaintexts with colons in these modes are
                # genuinely ambiguous.
                h, _, plain = line.rpartition(":")
        out.append(CrackedEntry(hash=h, plaintext=plain,
                                 hash_type=_detect_hash_type(h)))
    return out


# ------------------------------------------------------------------- attribution

# SAM/NTDS dump line: `[DOMAIN\]user:RID:LM:NT:::` — the NT hash is the 4th field.
_DUMP_LINE = re.compile(
    r"^(?:(?P<domain>[^:\\]+)\\)?(?P<user>[^:\\]+):\d+:"
    r"(?P<lm>[0-9a-fA-F]{32}):(?P<nt>[0-9a-fA-F]{32}):"
)


def _principal_from_loot(loot_value, hash_type, hash_str):
    """Given a loot row and a cracked (hash_type, hash), return
    ``(domain, user)`` if the loot line matches — else ``None``."""
    if not loot_value:
        return None
    m = _DUMP_LINE.match(loot_value.strip())
    if not m:
        return None
    # For an NT crack, match on the NT field (case-insensitive).
    if hash_type == "nt" and m.group("nt").lower() == hash_str.lower():
        return (m.group("domain") or "", m.group("user"))
    # For an LM:NT crack, both must match.
    if hash_type == "lm:nt":
        want = _LM_NT.match(hash_str)
        if want and (m.group("lm").lower() == want.group(1).lower()
                     and m.group("nt").lower() == want.group(2).lower()):
            return (m.group("domain") or "", m.group("user"))
    return None


# ------------------------------------------------------------------- apply

@dataclass
class HashcatReport:
    entries: int = 0                     # total cracked lines read
    matched: int = 0                     # cracked lines that found a loot row
    creds_promoted: int = 0              # new credentials that landed in the store
    unmatched_stored: int = 0            # cracked lines with no loot match, kept as loot
    matches: list = field(default_factory=list)   # (principal, plaintext, host_id)


def apply(store, entries, source="hashcat"):
    """Fold cracked entries into the store in one transaction.

    Every matched entry becomes a :class:`Credential` (source tagged with
    ``hashcat``). Unmatched entries — hashes we didn't dump ourselves — are
    stored as loot with ``kind='cracked_hash'`` so the pair survives; a later
    dump can retroactively attribute them by re-running this ingest.
    """
    rep = HashcatReport()
    with store.transaction():
        loot_rows = store.loot()          # snapshot: matching is O(loot × entries)
        for entry in entries:
            rep.entries += 1
            matched_any = False
            for loot in loot_rows:
                principal = _principal_from_loot(
                    loot["value"], entry.hash_type, entry.hash)
                if principal is None:
                    continue
                domain, user = principal
                try:
                    cred = Credential(username=user, secret=entry.plaintext,
                                      secret_type="password", domain=domain)
                except CredentialError:
                    continue
                _, created = store.add_credential(cred, source=source)
                rep.creds_promoted += 1 if created else 0
                rep.matches.append((principal, entry.plaintext, loot["host_id"]))
                matched_any = True
            if matched_any:
                rep.matched += 1
            else:
                # Keep the pair; a later dump can attribute it. Value is
                # deterministic (hash:plain) so re-ingest doesn't duplicate.
                store.add_loot(host_id=None, kind="cracked_hash",
                               value=f"{entry.hash}:{entry.plaintext}")
                rep.unmatched_stored += 1
    return rep
