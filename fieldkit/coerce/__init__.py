"""Coerce primitives — force a target to authenticate outbound.

fieldkit's chain module (:mod:`fieldkit.chain`) composes these into
multi-step flows. Each primitive is an independent module:

  * :mod:`fieldkit.coerce.petitpotam` — MS-EFSR EfsRpcOpenFileRaw
    (D2 — first primitive)
  * :mod:`fieldkit.coerce.printerbug`  — MS-RPRN RpcRemoteFindFirstPrinterChangeNotification
    (D4)
  * :mod:`fieldkit.coerce.dfscoerce`   — MS-DFSNM NetrDfsRemoveStdRoot
    (D4)

Each module exposes a ``fire(target, listener_uri, cred=None,
tool_bin=None, tool_timeout=…) -> CoerceResult`` API. The common
:class:`CoerceResult` shape lets chain-time code branch on outcome
without needing per-primitive knowledge.
"""
from dataclasses import dataclass, field
from typing import Optional


#: Ordered by preference for chain-time branching:
#:   ``ok`` — the coerce trigger call was accepted by the target;
#:            an outbound auth attempt is now in flight to
#:            ``listener_uri``.
#:   ``no-tool`` — no viable PetitPotam-family tool was found and
#:            fieldkit can't fall back to a from-scratch implementation
#:            (D2 lands with fallback-only behavior when impacket lacks
#:            the examples/PetitPotam.py file — common on newer
#:            impacket builds). The chain step reports ``manual`` and
#:            hands the operator the exact command to run.
#:   ``patched`` — the target responded with ERROR_ACCESS_DENIED /
#:            RPC_S_ACCESS_DENIED on the trigger call. The DC has the
#:            MS-EFSR patch or the RPC filter is blocking the interface.
#:            The chain treats this as ``skip`` so the profile can try
#:            the next coerce fallback (PrinterBug / DFSCoerce in D4).
#:   ``unreachable`` — the RPC endpoint couldn't be reached (SMB port
#:            filtered, DCERPC endpoint mapper down). Different from a
#:            patched target — the primitive itself never got to send.
#:   ``auth-error`` — target required auth we don't have. Rare on
#:            modern DCs since MS-EFSR was gated to auth users, but
#:            still happens on hardened builds.
#:   ``fail`` — tool ran but produced an unexpected/parseable-as-error
#:            output; caller reads .detail for diagnostics.
COERCE_RESULT_KINDS = frozenset({
    "ok", "no-tool", "patched", "unreachable", "auth-error", "fail",
})


@dataclass(frozen=True)
class CoerceResult:
    """Result of running one coerce primitive against one target.

    :attr:`kind` — one of :data:`COERCE_RESULT_KINDS`.
    :attr:`evidence` — human-readable summary the chain step logs.
    :attr:`detail` — verbatim tool output (or the reason no tool was
        found). Empty by default; populated for diagnostics.
    :attr:`command_hint` — for ``no-tool`` results, the exact command
        string the operator should run manually. Empty otherwise.
    :attr:`listener_uri` — the URI passed to the target as the auth
        destination. Recorded for the chain artifacts dict so
        downstream steps (relay-capture) know what to expect.
    """
    kind: str
    evidence: str
    detail: str = ""
    command_hint: str = ""
    listener_uri: str = ""

    def __post_init__(self):
        if self.kind not in COERCE_RESULT_KINDS:
            raise ValueError(
                f"CoerceResult.kind must be one of {sorted(COERCE_RESULT_KINDS)}, "
                f"got {self.kind!r}")
