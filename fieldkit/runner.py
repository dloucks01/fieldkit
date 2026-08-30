"""Run an external tool and capture everything it said.

fieldkit orchestrates; the tools (netexec, impacket) do the protocol work. This is
the one place a child process is spawned. It captures stdout, stderr and the exit
code verbatim — the design's "everything that runs is captured" rule — and turns the
failures an operator actually hits (the binary is not installed, the tool hung) into
a :class:`RunResult` rather than a traceback.

It is deliberately small and does **not** decide whether a command is *safe* to run —
that gate lands in Phase 2 with the general executor. Spraying is a read-only auth
check, so Phase 1 needs capture, not a gate.
"""
import os
import subprocess
import time
from dataclasses import dataclass


@dataclass
class RunResult:
    """The verbatim result of one child process."""

    argv: list
    exit_code: int = None       # None when the process never ran or was killed
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    timed_out: bool = False
    error: str = None           # set when the tool could not be executed at all
    stdout_bytes: bytes = None  # set when binary output was requested (openssl decrypt)

    @property
    def ok(self):
        """The tool ran to completion (exit code is not itself a fieldkit failure —
        nxc exits 0 even when every credential was rejected)."""
        return self.error is None and not self.timed_out

    @property
    def output(self):
        """stdout + stderr — netexec prints results to whichever the environment picks."""
        return self.stdout + (("\n" + self.stderr) if self.stderr else "")


def spawn(argv, env_add=None):
    """Launch a long-running child process for the caller to poll + kill.

    Returns a :class:`subprocess.Popen` handle. The caller owns the
    lifecycle: reading stdout via ``proc.stdout``, deciding when to
    ``send_signal`` / ``kill``, joining any reader threads it starts.
    Used by :mod:`fieldkit.relay` for the ntlmrelayx listener — a
    blocking :func:`run` doesn't fit a process the operator watches
    tail-of-log style then stops on demand.

    This is one of the child-process entry points in fieldkit outside
    :func:`run` (see also :func:`spawn_detached`); the "runner is the
    only child-process spawn" architecture invariant covers all three
    (see tests/test_report.py::test_runner_is_the_only_child_process_spawn).
    Never call subprocess.Popen from anywhere else — pass through
    here so a future test harness can inject a fake.
    """
    env = None
    if env_add:
        env = {**os.environ, **env_add}
    return subprocess.Popen(
        list(argv),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, env=env, start_new_session=True)


def spawn_detached(argv, env_add=None, cwd=None):
    """Launch a child process fully detached from the caller: no
    stdio pipes, its own session so a Ctrl-C on the parent (or a
    TUI closing) doesn't propagate. Fire-and-forget shape.

    Used by the TUI's escalate confirm screen — the escalate loop
    can run for minutes and blocking the Textual event loop would
    freeze every screen; the caller only cares that the process
    started, not its output (which lands in the shared engagement
    DB where Watch picks it up).

    Returns the caller-side :class:`subprocess.Popen` handle so a
    caller that wants to (rarely) check ``proc.pid`` for logging
    can. The stdio handles are DEVNULL — reading them yields EOF.
    """
    env = None
    if env_add:
        env = {**os.environ, **env_add}
    return subprocess.Popen(
        list(argv),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        env=env, cwd=cwd)


def run(argv, env_add=None, timeout=600, input_text=None, input_bytes=None):
    """Execute ``argv``, capturing output. Never raises for an operator-caused failure.

    ``env_add`` is merged onto the current environment (renderers use it for
    ``KRB5CCNAME``). ``timeout`` guards against a tool that hangs on an unreachable
    host. A missing binary comes back as ``error``, not an exception, so the loop can
    tell the operator to install it and move on.

    ``input_bytes`` switches to binary I/O — used by the GPP cpassword decrypter, which
    pipes AES ciphertext into openssl. Text and bytes are mutually exclusive; when
    binary, output lands in ``stdout_bytes`` and ``stdout`` gets a latin-1 shadow of it.
    """
    argv = list(argv)
    env = None
    if env_add:
        env = {**os.environ, **env_add}
    start = time.monotonic()
    binary = input_bytes is not None
    try:
        if binary:
            proc = subprocess.run(
                argv, capture_output=True, env=env, input=input_bytes,
                timeout=timeout)
        else:
            proc = subprocess.run(
                argv, capture_output=True, text=True, env=env, input=input_text,
                timeout=timeout, errors="replace")
    except FileNotFoundError:
        return RunResult(argv, error=f"{argv[0]}: not found — is it installed and on PATH?")
    except PermissionError as exc:
        return RunResult(argv, error=f"{argv[0]}: {exc}")
    except subprocess.TimeoutExpired as exc:
        return RunResult(
            argv, stdout=(exc.stdout.decode("latin-1") if binary and exc.stdout
                          else (exc.stdout or "")) or "",
            stderr=(exc.stderr.decode("latin-1") if binary and exc.stderr
                    else (exc.stderr or "")) or "",
            duration=time.monotonic() - start, timed_out=True,
            error=f"timed out after {timeout}s")
    if binary:
        return RunResult(
            argv, exit_code=proc.returncode,
            stdout=proc.stdout.decode("latin-1"),
            stderr=proc.stderr.decode("latin-1"),
            stdout_bytes=proc.stdout,
            duration=time.monotonic() - start)
    return RunResult(
        argv, exit_code=proc.returncode, stdout=proc.stdout, stderr=proc.stderr,
        duration=time.monotonic() - start)
