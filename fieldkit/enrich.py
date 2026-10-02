"""Analysis-depth enrichment — extract structured entities from captured
tool output, suggest hashcat crack modes, and surface what a step actually
*found* beyond its exit code.

The anti-fabrication rule from the rest of fieldkit still holds: enrich
only reads what fieldkit already captured. It never speculates or
guesses — if an entity isn't in the text, it doesn't surface.

Two layers:

  * :func:`extract_entities` — stateless pattern-matched extractor over an
    arbitrary string. Returns an :class:`Entity` per hit. Entities carry
    their ``kind`` (``ipv4``, ``email``, ``nt_hash``, ``aws_access_key``,
    ``github_pat`` …), the matched ``value`` verbatim, and a short
    ``context`` line (the line the match was on, trimmed).

  * :func:`suggest_hashcat_mode` — hash-shape → hashcat ``-m`` number.
    Covers the hashes that fieldkit actually promotes (NT, NetNTLMv2,
    Kerberos TGS/AS-REP, sha512crypt, bcrypt, md5crypt). Returns
    ``None`` for shapes we can't disambiguate — never a guess.

The CLI (``fieldkit enrich <engagement>``) walks the engagement's steps,
runs the extractor over each captured output, deduplicates, and prints
the entity table — the "what did we actually find?" view that Nemesis
auto-produces but fieldkit was previously missing.
"""
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Entity:
    """One structured datum extracted from captured output.

    ``context`` is the trimmed line the match was on, so a reader can
    judge whether the match is a real find or a noisy pattern collision
    (``10.0.0.1`` in a textbook example, say) without re-reading the
    source."""
    kind: str
    value: str
    context: str = ""


# --------------------------------------------------------------- entity patterns
#
# Each entry is (kind, compiled_pattern, post_filter). post_filter is called with
# the match string and returns True to keep, False to drop — used to reject known
# false positives (``127.0.0.1``, ``0.0.0.0``, documentation ranges) that pattern
# matching alone can't exclude.


def _keep_ipv4(s):
    """Reject loopback, link-local, IANA documentation (``192.0.2.*`` /
    ``198.51.100.*`` / ``203.0.113.*``), and leading-zero oddities that the
    pattern happily matches."""
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    if any(not 0 <= o <= 255 for o in octets):
        return False
    if any(len(p) > 1 and p[0] == "0" for p in parts):
        return False
    # loopback + any-address
    if octets[0] == 127 or octets == [0, 0, 0, 0]:
        return False
    # IANA TEST-NET-1/2/3 — safe to drop in operator output
    if octets[0:2] == [192, 0] and octets[2] == 2:
        return False
    if octets[0:3] == [198, 51, 100]:
        return False
    if octets[0:3] == [203, 0, 113]:
        return False
    return True


def _keep_hash_hex(s, want_len):
    """Reject obvious non-hashes: digits-only runs (phone numbers), the
    well-known NT ``aad3b435b51404eeaad3b435b51404ee`` (that's the empty
    LM hash — surface it under its own kind elsewhere), repeats like
    ``aaaaaaaa...``."""
    if len(s) != want_len:
        return False
    if not re.fullmatch(r"[0-9a-fA-F]+", s):
        return False
    if len(set(s.lower())) == 1:
        return False
    return True


_EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"


_PATTERNS = (
    # (kind, pattern, filter_fn or None)
    ("ipv4",
     re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
     _keep_ipv4),
    ("ipv6",
     # Loose shape — a conservative pattern matches 8 colon-separated
     # 1-4 hex groups OR a double-colon compressed form with at least 2
     # groups on each side. Deliberately misses extreme corner cases
     # (zone IDs, scope selectors) — those are rare in tool output.
     re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
                r"|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b"),
     None),
    ("email",
     # Internet-mail: local-part@domain. Rejects anchoring to a leading
     # path separator so we don't eat `root@/etc/passwd` style noise.
     re.compile(r"(?<![\w./])"
                r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
                r"(?![\w./])"),
     None),
    ("url",
     re.compile(r"\bhttps?://[^\s<>\"']+"),
     None),
    ("aws_access_key",
     re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b"),
     None),
    ("aws_secret_key",
     # 40-char base64-ish strings are also GitHub tokens / random strings,
     # so we only match when prefixed by an aws-keyish label on the same
     # line — the extractor passes the context in, we check inside filter.
     re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
     None),
    ("github_pat",
     re.compile(r"\b(?:gh[opsu]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{20,})\b"),
     None),
    ("gitlab_pat",
     re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
     None),
    ("slack_bot_token",
     re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
     None),
    ("stripe_secret",
     re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b"),
     None),
    # Hash shapes — order matters: NetNTLMv2 must come before "sha-ish 32-hex"
    # so the longer composite shape wins. We extract the full hash row.
    ("netntlmv2",
     # "user::DOMAIN:challenge:hash1:hash2" — standard responder format.
     re.compile(r"[^\s:]+::[^\s:]+:[0-9a-fA-F]{16}:[0-9a-fA-F]{32}:[0-9a-fA-F]+"),
     None),
    ("netntlmv1",
     re.compile(r"[^\s:]+::[^\s:]+:[0-9a-fA-F]{48}:[0-9a-fA-F]{48}:[0-9a-fA-F]{16}"),
     None),
    ("kerberos_tgsrep",
     # krb5tgs$23$* — Kerberoastable service ticket.
     re.compile(r"\$krb5tgs\$\d+\$[^\s]+"),
     None),
    ("kerberos_asrep",
     re.compile(r"\$krb5asrep\$\d+\$[^\s]+"),
     None),
    ("bcrypt_hash",
     re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}"),
     None),
    ("sha512crypt",
     re.compile(r"\$6\$[^\s$]+\$[./A-Za-z0-9]{86}"),
     None),
    ("sha256crypt",
     re.compile(r"\$5\$[^\s$]+\$[./A-Za-z0-9]{43}"),
     None),
    ("md5crypt",
     re.compile(r"\$1\$[^\s$]+\$[./A-Za-z0-9]{22}"),
     None),
    # NT / LM — exactly 32 hex, not the empty LM, no single-char repeat.
    ("nt_hash",
     re.compile(r"\b[0-9a-fA-F]{32}\b"),
     lambda s: _keep_hash_hex(s, 32) and s.lower() != _EMPTY_LM),
)


def extract_entities(text):
    """Walk ``text`` and return a list of :class:`Entity` for every pattern
    hit. Order of return is pattern-definition order (so the longer-shape
    hashes surface first); within one pattern the matches are in textual
    order.

    Duplicates are NOT deduplicated here — the caller decides whether a
    second ``10.0.0.5`` from the same output is noise or evidence of
    repeat observation. The ``fieldkit enrich`` CLI de-dupes at the
    engagement level."""
    if not text:
        return []
    seen_spans = []  # [(start, end)] — reject overlaps between kinds
    out = []
    for kind, pat, flt in _PATTERNS:
        for m in pat.finditer(text):
            value = m.group(0)
            if flt is not None and not flt(value):
                continue
            s, e = m.start(), m.end()
            # Reject overlap with an already-matched longer-kind span
            if any(ss <= s < ee or ss < e <= ee for ss, ee in seen_spans):
                continue
            # Context: the physical line the match is on, trimmed to 160 chars.
            line_start = text.rfind("\n", 0, s) + 1
            line_end = text.find("\n", e)
            if line_end == -1:
                line_end = len(text)
            ctx = text[line_start:line_end].strip()
            if len(ctx) > 160:
                ctx = ctx[:160] + "…"
            out.append(Entity(kind=kind, value=value, context=ctx))
            seen_spans.append((s, e))
    return out


# --------------------------------------------------------------- hashcat modes
#
# Shape → hashcat -m. Only shapes fieldkit actually promotes to credentials
# or finds in enum / probe output. Returning None means "we can't tell from
# shape alone" — the operator decides.


_HASHCAT_MODES = {
    "nt_hash":          (1000, "NTLM"),
    "lm_hash":          (3000, "LM"),
    "netntlmv1":        (5500, "NetNTLMv1"),
    "netntlmv2":        (5600, "NetNTLMv2"),
    "kerberos_tgsrep":  (13100, "Kerberos 5 TGS-REP etype 23"),
    "kerberos_asrep":   (18200, "Kerberos 5 AS-REP etype 23"),
    "md5crypt":         (500,  "md5crypt / MD5(Unix)"),
    "sha256crypt":      (7400, "sha256crypt / SHA-256(Unix)"),
    "sha512crypt":      (1800, "sha512crypt / SHA-512(Unix)"),
    "bcrypt_hash":      (3200, "bcrypt"),
}


def suggest_hashcat_mode(hash_text):
    """Return ``(mode_num, mode_name)`` for a hash string whose shape maps
    unambiguously to a hashcat mode, or ``None`` if we can't tell.

    This is a pure shape classifier — it does NOT run against hashcat and
    does not need network access. It matches on the same patterns the
    extractor uses so the two layers never disagree."""
    for ent in extract_entities(hash_text):
        if ent.kind in _HASHCAT_MODES:
            return _HASHCAT_MODES[ent.kind]
    # One extra: the special-case LM hash form embedded in NT:LM pairs
    # (``aad3b435b51404eeaad3b435b51404ee:aad3b435...``) isn't matched
    # by nt_hash because of our empty-LM filter; recognize the pair.
    if re.fullmatch(r"[0-9a-fA-F]{32}:[0-9a-fA-F]{32}", hash_text.strip() or ""):
        return _HASHCAT_MODES["nt_hash"]
    return None


# --------------------------------------------------------------- summary helper


def extract_from_steps(step_rows):
    """Walk a list of step rows ``[{output: str, ...}, ...]`` and return a
    deduplicated list of (kind, value, first_context) tuples.

    Only one entry per (kind, value) survives — the FIRST context the
    extractor saw. Operator view: "here's every structured datum fieldkit
    captured across the run, each with proof of where it came from." """
    seen = {}
    for row in step_rows:
        text = row.get("output") if isinstance(row, dict) else row
        if not text:
            continue
        for ent in extract_entities(text):
            key = (ent.kind, ent.value)
            if key not in seen:
                seen[key] = ent.context
    return [(k[0], k[1], ctx) for k, ctx in seen.items()]
