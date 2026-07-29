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
