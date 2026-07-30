"""Wordlist mutation — seeds + rules → a password list ready for ``spray --wordlist``.

Building the right password list is the hardest part of a real spray. What actually
works on a domain engagement is small: the company name, product names, seasons,
years, common suffixes. This module takes seeds and expands them through a
transparent, inspectable ruleset — the same three-axis "small enough to reason
about, big enough to be useful" philosophy the rest of fieldkit uses.

Every rule is a pure ``(str) -> Iterable[str]``. The ruleset itself is exposed in
:data:`RULES` and shows up in `fieldkit wordlist rules`, so the operator knows
exactly what shapes fieldkit will produce (and won't fabricate anything else).

Bounded by construction — default output for one seed is under 500 words, for a
typical 4-seed engagement under 3000. There is no combinatorial explosion of
seed×seed×suffix×prefix×case unless the operator explicitly opts in.
"""
import re
from dataclasses import dataclass, field


# ------------------------------------------------------------------- rule set

def _cases(word):
    """Common capitalization variants — original, First, UPPER. No camelCase or
    weird alternating-case (those don't hit; they inflate the wordlist)."""
    yield word
    if word.lower() != word:
        yield word.lower()
    if word[:1].islower():
        yield word[:1].upper() + word[1:]
    if word.upper() != word and word.isascii():
        yield word.upper()


#: Single-char leet substitutions that actually appear in real passwords.
#: Deliberately narrow: alternating-case + full leet produces meaningless lists.
LEET_MAP = {"o": "0", "e": "3", "i": "1", "a": "@", "s": "$", "l": "1", "t": "7"}


def _leet_variants(word, subs=None):
    """One-substitution-per-position leet variants. Multi-substitution is off by
    default — a 5-substitution word would produce 32 lines almost none of which
    a user ever set. Yields the original AND each single-swap variant."""
    subs = subs if subs is not None else LEET_MAP
    yield word
    for i, ch in enumerate(word):
        rep = subs.get(ch.lower())
        if rep and rep != ch:
            yield word[:i] + rep + word[i + 1:]


#: The suffix set that lands on real corporate passwords. Order = generation
#: order, so the most common shapes come first (matters when we truncate to a
#: `max_output` ceiling).
BASE_SUFFIXES = ("", "!", "1", "123", "1!", "!1", "!!", "@", "#", "$",
                 "2024", "2025", "2023", "2024!", "2025!", "2023!",
                 "!2024", "!2025", "@2024", "@2025",
                 "01", "02", "007", "1234", "12345")

#: Seasons + months. Common enough to auto-add when the operator passes
#: ``--seasons`` (off by default so 3 seeds don't silently become 300).
SEASONS = ("Winter", "Spring", "Summer", "Fall", "Autumn")
MONTHS = ("January", "February", "March", "April", "May", "June", "July",
          "August", "September", "October", "November", "December")


@dataclass(frozen=True)
class Rule:
    """One mutation rule. Pure, inspectable — shows up in `fieldkit wordlist rules`."""
    name: str
    description: str


RULES = (
    Rule("cases", "capitalization variants: original, lower, First, UPPER"),
    Rule("leet", "single-char leet: o→0 e→3 i→1 a→@ s→$ l→1 t→7"),
    Rule("suffix", "append a corporate suffix ('!', '123', '2024', '2025', '2024!', etc.)"),
    Rule("prefix", "prepend a chosen prefix (off by default — corporate patterns are almost all suffix-heavy)"),
    Rule("combine", "concat two seeds (off by default; combinatorial. Opt-in with --combine)"),
    Rule("season", "add every season/month to the seed pool (opt-in with --seasons)"),
    Rule("walks", "keyboard walks (qwerty/qazwsx/1qaz2wsx families, incl. shift-mix). Opt-in with --walks"),
    Rule("wrapped", "wrap seed with symbols+numbers before/after: !Password2024!, #Winter@, 2024Password!"),
)


# ------------------------------------------------------------- keyboard walks

#: Curated keyboard walks. These are STANDALONE passwords, not seeds — a walk
#: like ``1qaz@WSX3edc`` is itself the credential someone chose. Modern policies
#: force ≥12 chars, and walks are the top-3 way users cope. Grouped by shape so
#: the operator can filter with --min-len/--max-len.
KEYBOARD_WALKS = (
    # horizontal, single row (US-QWERTY)
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn", "zxcvbnm",
    "1234567890", "0987654321",
    "QWERTY", "QWERTYUIOP", "ASDFGH", "ASDFGHJKL",
    # shift-of-numeric-row
    "!@#$%^", "!@#$%^&*", "!@#$%^&*()",
    # diagonal, top-left → bottom-right (the classic "1qaz" family)
    "qaz", "qazwsx", "qazwsxedc", "qazwsxedcrfv", "qazwsxedcrfvtgb",
    "1qaz2wsx", "1qaz2wsx3edc", "1qaz2wsx3edc4rfv", "1qaz2wsx3edc4rfv5tgb",
    "1qaz@WSX", "1qaz@WSX3edc", "1qaz@WSX3edc$RFV",
    "!QAZ@wsx", "!QAZ2wsx", "!QAZ2wsx#EDC",
    # diagonal, top-right → bottom-left (rarer but real)
    "poi", "poiuyt", "poiuytre", "poiuytrewq",
    "0okm", "0okm9ijn", "0okm9ijn8uhb",
    # column pairs
    "qazxsw", "qazxsw2", "1qazxsw2", "1qazxsw2!QAZXSW@",
    # numeric-row + row-below hybrid
    "1q2w3e", "1q2w3e4r", "1q2w3e4r5t", "1q2w3e4r5t6y",
    "1Q2W3E", "1Q2W3E4R", "1Q2W3E4R5T",
    # popular non-walks that behave like walks (very common)
    "password", "Password", "Password1", "Password!", "Passw0rd",
    "Passw0rd!", "P@ssw0rd", "P@ssw0rd!",
    "welcome", "Welcome", "Welcome1", "Welcome!", "Welcome@123",
    "letmein", "Letmein1", "Letmein!",
    "changeme", "Changeme1", "Changeme!",
    "admin", "admin123", "Admin@123",
    # add-year variants of the two most common
    "Password2024", "Password2024!", "Password2025", "Password2025!",
    "Welcome2024", "Welcome2024!", "Welcome2025", "Welcome2025!",
)


# ------------------------------------------------------------- wrapper phrases

#: Wrapper elements. Small, curated — the point is not "every character" but
#: the shapes users actually pick. Order = most common first.
_WRAP_SYMBOLS = ("!", "@", "#", "$", "*", "?", "!!", "@@", "##", "!@#", "!@#$")
_WRAP_NUMBERS = ("1", "12", "123", "1234", "12345", "007", "01", "02",
                 "2024", "2025", "2023", "2022")


def _wrap_seed(seed, years=(), max_variants_per_seed=30):
    """Emit wrapper-shaped variants of one seed. Shapes covered (in order):

        <sym><seed><num>          !Password2024
        <sym><seed><num><sym>     !Password2024!
        <num><seed><sym>          2024Password!
        <sym><seed><sym>          !Password!
        <sym><sym><seed><num>     !!Password2024
        <seed><sym><num><sym>     Password!2024!

    Bounded to `max_variants_per_seed` to keep single-seed output reasonable.
    """
    # Prepend the operator's chosen years to the number pool so they dominate.
    numbers = [str(y) for y in years] + [n for n in _WRAP_NUMBERS
                                          if n not in {str(y) for y in years}]
    out = []
    for sym in _WRAP_SYMBOLS:
        for num in numbers:
            for shape in (
                f"{sym}{seed}{num}",
                f"{sym}{seed}{num}{sym}",
                f"{num}{seed}{sym}",
                f"{sym}{seed}{sym}",
                f"{seed}{sym}{num}{sym}",
            ):
                out.append(shape)
                if len(out) >= max_variants_per_seed:
                    return out
    return out


# ------------------------------------------------------------------ generator

@dataclass
class WordlistReport:
    """What a mutation run produced — for the CLI summary and tests."""
    seeds: tuple = ()
    total: int = 0
    truncated: int = 0             # how many candidates fell off the max_output cap
    rules: tuple = ()               # rule names actually applied
    words: list = field(default_factory=list)


DEFAULT_MAX_OUTPUT = 5000           # generous but not runaway; ~15 min at 3 attempts/sec


def generate(seeds, *, years=(), extra_suffixes=(), extra_prefixes=(),
             cases=True, leet=True, suffixes=True, prefixes=False, combine=False,
             seasons=False, walks=False, wrapped=False,
             min_len=6, max_len=32, max_output=DEFAULT_MAX_OUTPUT):
    """Expand ``seeds`` into a wordlist by applying the enabled rules.

    Every combination is filtered by ``min_len``/``max_len`` (default 6–32, which
    covers most corporate password policies without emitting single-char noise or
    128-char experimental strings). Duplicates are collapsed. Order is preserved
    from ``seeds`` × the rule order, so more-likely hits land earlier — matters
    when the operator caps the output.

    ``walks=True`` — include :data:`KEYBOARD_WALKS` (standalone passwords, not
    mutations); ``wrapped=True`` — apply the wrapper pattern (``!Password2024!``,
    ``#Winter@``, ``2024Password!``, etc). Both are OFF by default because they
    push output length toward the 12–16 range and duplicate work when the seed
    set is short-corporate-style; toggle them on for modern ≥12-char policies.

    Returns a :class:`WordlistReport`.
    """
    if not seeds and not walks:
        return WordlistReport(seeds=(), total=0)
    seed_pool = list(seeds)
    if seasons:
        seed_pool = list(seed_pool) + list(SEASONS) + list(MONTHS)
    all_suffixes = list(BASE_SUFFIXES) + list(extra_suffixes or ())
    # Auto-add year suffixes when the operator names years (e.g. --years 2024 2025):
    # generate both the year alone and year+symbol variants.
    for y in years or ():
        y = str(y)
        for extra in ("", "!", "!!", "@", "#"):
            candidate = f"{y}{extra}"
            if candidate not in all_suffixes:
                all_suffixes.append(candidate)
    applied = ["cases"] if cases else []
    if leet:
        applied.append("leet")
    if suffixes:
        applied.append("suffix")
    if prefixes or extra_prefixes:
        applied.append("prefix")
    if combine and len(seed_pool) > 1:
        applied.append("combine")
    if seasons:
        applied.append("season")
    if walks:
        applied.append("walks")
    if wrapped:
        applied.append("wrapped")

    seen = set()
    ordered = []                    # preserve insertion order (dedupe with set)

    def add(word):
        if word in seen:
            return False
        if not (min_len <= len(word) <= max_len):
            return False
        seen.add(word)
        ordered.append(word)
        return True

    def case_variants(w):
        return list(_cases(w)) if cases else [w]

    def leet_variants(w):
        return list(_leet_variants(w)) if leet else [w]

    # Rule order matters for the truncation cap: cheap high-value shapes first
    # (raw seed + suffix), then case × suffix, then leet, then prefixes, then combos.
    seed_variants = []
    for raw in seed_pool:
        for w in case_variants(raw):
            if w not in seed_variants:
                seed_variants.append(w)

    # Pass 1: seed × suffix (the classic Winter2025 shape)
    if suffixes:
        for w in seed_variants:
            for suf in all_suffixes:
                if len(ordered) >= max_output:
                    break
                add(w + suf)
    else:
        for w in seed_variants:
            add(w)

    # Pass 2: leet variants of the seed × common suffixes
    if leet and len(ordered) < max_output:
        for w in seed_variants:
            for leeted in leet_variants(w):
                if leeted == w:
                    continue
                if suffixes:
                    for suf in all_suffixes[:8]:   # only the very common suffixes
                        if len(ordered) >= max_output:
                            break
                        add(leeted + suf)
                else:
                    add(leeted)

    # Pass 3: prefixes (opt-in)
    if (prefixes or extra_prefixes) and len(ordered) < max_output:
        prefix_pool = list(extra_prefixes) if extra_prefixes else \
            (list(years) if years else [])
        for pfx in prefix_pool:
            pfx = str(pfx)
            for w in seed_variants:
                if len(ordered) >= max_output:
                    break
                add(pfx + w)

    # Pass 4: combined seeds (opt-in; combinatorial)
    if combine and len(seed_pool) > 1 and len(ordered) < max_output:
        for i, a in enumerate(seed_variants):
            for b in seed_variants[i + 1:]:
                if len(ordered) >= max_output:
                    break
                if suffixes:
                    for suf in all_suffixes[:6]:
                        if len(ordered) >= max_output:
                            break
                        add(a + b + suf)
                        add(b + a + suf)
                else:
                    add(a + b)
                    add(b + a)

    # Pass 5: keyboard walks (opt-in). Standalone passwords, not mutations —
    # a walk like 1qaz@WSX3edc is itself the credential a user picked.
    if walks and len(ordered) < max_output:
        for w in KEYBOARD_WALKS:
            if len(ordered) >= max_output:
                break
            add(w)

    # Pass 6: wrapper phrases (opt-in). The shape modern ≥12-char policies
    # push users toward: !Password2024!, #Winter@, 2024Password!, etc.
    if wrapped and len(ordered) < max_output:
        for w in seed_variants:
            for shape in _wrap_seed(w, years=years):
                if len(ordered) >= max_output:
                    break
                add(shape)

    total_generated = len(ordered)
    truncated = 0
    if total_generated >= max_output:
        # we hit the cap; the counter is best-effort informational
        truncated = 1
    return WordlistReport(seeds=tuple(seeds), total=total_generated,
                          truncated=truncated, rules=tuple(applied),
                          words=ordered)


# ---------------------------------------------------------------- seed helpers

_WORD = re.compile(r"[A-Za-z][A-Za-z0-9]{2,}")


def seeds_from_text(text):
    """Extract likely seed words from a blob of text (CeWL-style, tiny).

    Deduplicates, preserves first-seen order, filters trivial short words. The
    operator's own list still beats this — use it to bootstrap from a client's
    website copy or an About page.
    """
    seen, out = set(), []
    for m in _WORD.finditer(text or ""):
        w = m.group(0)
        lo = w.lower()
        if lo in seen or len(w) < 3:
            continue
        seen.add(lo)
        out.append(w)
    return out


# --------------------------------------------------------------- username sets

def usernames(first_names, last_names, *, patterns=None):
    """Common username patterns from a first/last name pair.

    Default patterns cover: first, last, first.last, firstlast, flast, first_last,
    lastf, last.first. The pattern list is exposed so the operator can trim or
    extend it to whatever the client's schema is (banks tend to use ``flast``,
    schools ``first.last``, etc.).
    """
    patterns = tuple(patterns) if patterns else (
        "{first}", "{last}",
        "{first}.{last}", "{first}{last}", "{first}_{last}",
        "{f}{last}", "{last}{f}", "{f}.{last}",
        "{last}.{first}",
    )
    seen, out = set(), []
    for first in first_names:
        for last in last_names:
            for tmpl in patterns:
                u = tmpl.format(first=first, last=last,
                                f=first[:1] if first else "",
                                l=last[:1] if last else "").lower()
                if u and u not in seen:
                    seen.add(u)
                    out.append(u)
    return out
