"""TTP schema — the field-by-field contract for a fieldkit-TTP YAML file.

Every YAML file in ``fieldkit/ttps/*.yaml`` loads into one :class:`TTP` object
with validated fields. The loader raises :class:`~fieldkit.ttps.loader.LoaderError`
with a clear message when a file doesn't conform, so a bad TTP file fails at
startup rather than silently at run time.

The schema deliberately keeps the SAME three-axis ranking + safety tier + proof-
command shape that :mod:`fieldkit.privesc`'s inlined drivers use, so porting an
existing driver to YAML is a mechanical translation, not a rewrite.

Schema version 1 fields (all required unless marked optional):

  technique   — MITRE T-code with optional sub-technique (e.g. "T1548.003")
  name        — human-readable title shown in Analyze / TOP MOVES
  tactic      — list of ATT&CK tactics this technique enables
  platform    — list, one or more of "windows" | "linux" | "mac"
  ranking     — { exploitability, safety, detection } — same enums as kb.score
  detect      — precondition dict; the loader passes it to a matcher
                (Phase B1 accepts a bare `always: true` — real predicates land B2+)
  execute     — { command: <target-side string>, transport: [<name>, …] (optional) }
  verify      — { success: <regex/substring the command output must contain>,
                  proof:   <alt proof-only command, optional> }
  cleanup     — { command: <reversal command, optional> }
  report      — { vector_type, description, remediation, refs (optional) }

Extra keys are ignored (forward-compat: adding a field to the schema doesn't
break older engines that haven't learned to read it).
"""
from dataclasses import dataclass, field

#: Bump when a schema change is BREAKING (a required field is added or a value
#: enum shrinks). Files declare their target schema via `schema: N` — files at
#: the wrong version fail with a clear error rather than half-parse.
SCHEMA_VERSION = 1

VALID_PLATFORMS = frozenset({"windows", "linux", "mac"})
VALID_EXPLOITABILITY = frozenset({"high", "medium", "low"})
VALID_SAFETY = frozenset({"read-only", "config-change", "crash-risk"})
VALID_DETECTION = frozenset({"quiet", "moderate", "loud"})


@dataclass(frozen=True)
class Ranking:
    """The three-axis ranking mirrored from :mod:`fieldkit.kb`. Values are
    enum strings, not ints — the score computation happens in kb.score."""
    exploitability: str
    safety: str
    detection: str


@dataclass(frozen=True)
class Detect:
    """Precondition spec. Phase B1 supports:
       - always: True   → the TTP is always applicable
       - sudo_allows: <binary>   → applicable when hostenum shows sudo NOPASSWD on <binary>
       - suid: <binary>          → applicable when hostenum shows <binary> is SUID root
       - capability: <name>      → applicable when hostenum shows a capability
       - facts_match: <dict>     → generic HostFacts predicate (attribute equality)
    Phase B2 will add richer predicates (version windows, group membership, …)."""
    kind: str        # "always" | "sudo_allows" | "suid" | "capability" | "facts_match"
    value: object    # per-kind payload


@dataclass(frozen=True)
class Execute:
    """The target-side proof command.

    ``transport`` (optional) constrains which transports the executor may
    pick. ``shell`` overrides the platform default (cmd/sh) — Windows TTPs
    that need PowerShell set ``shell: powershell``.

    ``stages`` is a tuple of ``(name, remote_path)`` pairs. The escalate
    loop auto-pushes each named arsenal artifact to the given remote path
    before firing the command. Used by Potato-style TTPs that need a binary
    dropped on the target first.

    ``serves`` is a tuple of arsenal-artifact names to expose over HTTP
    for the duration of the command run. The command references them via
    the ``{url}{served}`` placeholders (resolved by provision.py at run time),
    so the target loads them into memory — nothing lands on disk.
    """
    command: str
    transport: tuple = ()
    shell: str = ""
    stages: tuple = ()
    serves: tuple = ()


@dataclass(frozen=True)
class Verify:
    """How to confirm the command actually worked. ``success`` is a substring
    the executor greps in the captured output. ``proof`` (optional) is an
    alternate command to run for the proof-only demonstration (safe_proof)."""
    success: str
    proof: str = ""


@dataclass(frozen=True)
class Cleanup:
    """Reversal spec. ``command`` (optional) runs to undo state mutation.
    Empty means the technique made no target-side change worth reversing
    (a read-only enum, a Kerberos ticket request)."""
    command: str = ""


@dataclass(frozen=True)
class Report:
    """How the report renders findings from this technique. ``vector_type`` is
    the same key the engine uses for finding-table dedup. ``refs`` are the
    CVEs / T-codes to link to.

    ``evidence`` (optional) is a template rendered into the Vector.evidence
    string, replacing ``{{field}}``, ``{{version}}``, ``{{lo}}``, ``{{hi}}``
    (from version_range predicates) and ``{{binary}}`` (from
    suid/capability/sudo_allows predicates). When empty, the adapter falls
    back to a generic ``"detected via TTP T… (kind)"`` string. Kernel-CVE
    ports use ``"{{field}} {{version}} in {{lo}}–{{hi}}"`` so the inlined
    driver's evidence format is preserved (``"kernel 5.15.0 in 5.8–5.16.11"``).
    """
    vector_type: str
    description: str = ""
    remediation: str = ""
    refs: tuple = ()
    evidence: str = ""


@dataclass(frozen=True)
class Playbook:
    """Operator steps for a TTP that fieldkit prepares but can't safely one-shot.

    Mirrors :class:`fieldkit.privesc.Playbook` — kernel-CVE routes against a
    client host are ranked and explained but never blind-fired, so they carry
    a playbook the operator follows.

    Template substitution is the same shape as ``execute.command``:
    ``{{stage}}`` becomes ctx.stage_lin (linux) or ctx.stage_win (windows),
    ``{{binary}}`` the matched-payload binary, ``{{artifact}}`` the arsenal
    artifact name (from the first `execute.stages` entry).
    """
    summary: str
    place: str
    steps: tuple
    restore: str = ""


@dataclass(frozen=True)
class TTP:
    """One loaded technique, ready for the engine to consume."""
    technique: str          # e.g. "T1548.003"
    name: str
    tactic: tuple           # e.g. ("privilege-escalation",)
    platform: tuple         # e.g. ("linux",)
    ranking: Ranking
    detect: Detect
    execute: Execute
    verify: Verify
    cleanup: Cleanup
    report: Report
    #: Optional dedup key override. When set, this is the Vector.key value
    #: (used by `vectors_for`'s seen-set dedup). Only set when the natural
    #: key from `_key_for` doesn't match the inlined driver's key — e.g.
    #: SeDebug uses key `sedebug` but reports as vector_type `lsass`. Most
    #: TTPs omit this; the adapter's default naming rules match cleanly.
    key: str = field(default="")
    #: Evasion-loop family — vectors sharing a family are delivery alternates
    #: for the same objective (e.g. all Potato variants share `seimpersonate`).
    #: The escalate loop climbs to another family member on a caught delivery.
    family: str = field(default="")
    #: The :mod:`fieldkit.evasion` technique key this vector's delivery
    #: presents. Marking a caught technique red keeps the loop from re-burning
    #: it. Empty means "no specific delivery technique" (a plain nxc command).
    delivery: str = field(default="")
    #: Operator playbook for prepare-only routes (kernel CVEs against a client
    #: host). When set, the emitted Vector carries a `playbook` and reports as
    #: `manual` — the escalate loop won't auto-fire it; `fieldkit prep` renders
    #: the steps. Most TTPs omit this (they auto-fire cleanly).
    playbook: object = field(default=None)
    #: Source path of the YAML file — populated by the loader, used in error
    #: messages when a TTP misbehaves at runtime.
    source_path: str = field(default="")
