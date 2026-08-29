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


@dataclass(frozen=True)
class Step:
    """One atomic move in a coerce chain.

    ``action`` receives ``(chain, ctx)`` and returns an :class:`Outcome`.
    ``ctx`` is opaque here — every profile hands its own context object
    (Store, target IP, credential, arsenal paths). The chain module never
    inspects ``ctx`` — it just threads it through.

    ``detection_cost`` is a 0-10 integer estimating the noise this step
    generates on a mature SOC's timeline. D6 aggregates these into a
    chain-total score surfaced in the report; D1 stores them without
    doing anything with them yet.
    """
    name: str
    kind: str
    action: Callable
    detection_cost: int = 0

    def __post_init__(self):
        if self.kind not in STEP_KINDS:
            raise ValueError(f"Step.kind must be one of {sorted(STEP_KINDS)}, got {self.kind!r}")
        if not (0 <= self.detection_cost <= 10):
            raise ValueError(
                f"Step.detection_cost must be 0-10, got {self.detection_cost}")


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
        """Sum of detection_cost across every step actually walked
        (skipped/failed steps count once — the cost lands as soon as
        the step runs). D6 uses this as the primary chain score."""
        walked = self.steps[:len(self.outcomes)]
        return sum(s.detection_cost for s in walked)


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

def walk(chain, ctx, on_step=None):
    """Run every remaining step of ``chain``, in order. Returns the
    chain object mutated in-place (caller reads ``chain.status`` +
    ``chain.outcomes`` for the result).

    Halts at the first step returning ``fail`` or ``skip`` (D1 has no
    fallback logic — D5 adds profile-chaining). ``manual`` outcomes DO
    NOT halt; the walker advances so the whole plan is walkable and
    the trail records what the operator needs to finish.

    ``on_step(chain, step, outcome)`` (optional) is called after each
    step for CLI progress rendering.
    """
    if chain.started_at is None:
        chain.started_at = utcnow()
    while chain.current < len(chain.steps):
        step = chain.steps[chain.current]
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
    detection_cost=0)


def _stub_action(msg):
    """Factory that returns a Step action which always yields ``manual``
    with the given message. Used for the D1 esc8 profile — the whole
    plan is walkable, but the non-preflight steps hand off to the
    operator until their landing slice ships (D2 through D4)."""
    def _action(chain, ctx):
        _ = chain, ctx
        return Outcome(kind="manual", evidence=msg)
    return _action


# ---------------------------------------------------------------- esc8 profile

@register("esc8")
def esc8_chain(target_dc, ca_endpoint=None, cred=None):
    """The canonical fieldkit coerce chain: coerce a DC → HTTP-relay
    to the enterprise CA → obtain a certificate for the DC account →
    PKINIT → DCSync.

    D1 lands the shape with reachability as the only live primitive;
    every subsequent step is a manual-outcome stub with an inline
    ETA pointing at its landing slice (D2 → petitpotam, D3 → relay
    server, D4 → post-relay actions).
    """
    _ = ca_endpoint, cred        # will be threaded into steps in D3/D4
    return Chain(
        profile="esc8",
        target=target_dc,
        steps=(
            REACHABILITY_STEP,
            Step("coerce:petitpotam",
                 "target-side",
                 _stub_action("coerce primitive lands in D2 (PetitPotam MS-EFSR)"),
                 detection_cost=3),
            Step("relay:listen",
                 "attacker-side",
                 _stub_action("ntlmrelayx subprocess wrap lands in D3"),
                 detection_cost=1),
            Step("relay:capture",
                 "attacker-side",
                 _stub_action("relay outcome parser lands in D3"),
                 detection_cost=2),
            Step("post:cert-request",
                 "attacker-side",
                 _stub_action("ADCS certificate retrieval lands in D4"),
                 detection_cost=1),
            Step("post:pkinit-tgt",
                 "attacker-side",
                 _stub_action("PKINIT → TGT (existing kerberos.py) lands in D4"),
                 detection_cost=0),
            Step("post:dcsync",
                 "attacker-side",
                 _stub_action("DCSync via nxc lands in D4"),
                 detection_cost=3),
        ))
