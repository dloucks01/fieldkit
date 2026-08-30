"""Session recording + replay — every fieldkit invocation captured
to a JSONL log for reproducible playback.

Enable recording by exporting ``FIELDKIT_SESSION_LOG=<path>`` in
the shell; every subsequent ``fieldkit`` invocation appends one
JSON object to that file (argv, cwd, start timestamp, exit code,
duration). ``fieldkit session log --enable`` prints the export
line for eval. ``fieldkit session show`` pretty-prints a log;
``fieldkit session replay`` re-runs each entry in order.

Design rules:
  * append-only writes with a per-line JSON object (JSONL) — safe
    to tail, safe to grep, safe to lose the last write on crash;
  * never records when the env-var is unset (opt-in, on purpose —
    session recording is for reproducibility exercises, not
    default operational overhead);
  * captures argv AS-INVOKED, so a replay reproduces the same
    argument parsing (positional vs flag, order, defaults);
  * skips itself: a ``session record`` / ``session show`` /
    ``session replay`` invocation is NOT written to the log
    (avoids replay loops).

Not recorded:
  * environment variables (except for the log path itself),
  * stdin content,
  * output produced by the invocation.

Replay uses the same ``main()`` entry point that records did,
in-process — so a replayed invocation exercises the same argparse
+ handler paths a live invocation does.
"""
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone


ENV_VAR = "FIELDKIT_SESSION_LOG"


#: Argv tokens that identify a session-management subcommand.
#: The recorder skips these to prevent loops (replaying a replay
#: entry would re-fire the whole log inside itself).
_SKIP_SUBCOMMANDS = frozenset({"session"})


@dataclass
class Entry:
    """One recorded invocation."""
    timestamp: str
    cwd: str
    argv: list
    exit_code: int
    duration_ms: int

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "cwd": self.cwd,
            "argv": self.argv,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
        }

    @classmethod
    def from_dict(cls, d):
        return cls(
            timestamp=d["timestamp"],
            cwd=d["cwd"],
            argv=list(d["argv"]),
            exit_code=int(d["exit_code"]),
            duration_ms=int(d["duration_ms"]),
        )


def is_recording_enabled():
    """True when the env var is set + non-empty."""
    return bool(os.environ.get(ENV_VAR, "").strip())


def log_path():
    """Current log file path, or None if recording disabled."""
    p = os.environ.get(ENV_VAR, "").strip()
    return p or None


def should_record(argv):
    """Skip session-management subcommands so a replay doesn't
    loop. Also skip empty argv (bare ``fieldkit``)."""
    if not argv:
        return False
    for tok in argv:
        if tok in _SKIP_SUBCOMMANDS:
            return False
    return True


def record(argv, exit_code, duration_ms, cwd=None, path=None):
    """Append one Entry to the log at ``path`` (or the env-var
    location). No-op if no path is configured, or if the argv
    matches a skip rule."""
    path = path or log_path()
    if not path:
        return None
    if not should_record(argv):
        return None
    entry = Entry(
        timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        cwd=cwd or os.getcwd(),
        argv=list(argv),
        exit_code=int(exit_code),
        duration_ms=int(duration_ms),
    )
    # Best-effort append; a failed write shouldn't break the
    # invocation the operator just ran.
    try:
        with open(path, "a") as fh:
            fh.write(json.dumps(entry.to_dict()) + "\n")
    except OSError:
        return None
    return entry


def read(path):
    """Read every Entry from ``path``. Malformed lines are skipped
    silently — the log format is JSONL, one bad line shouldn't
    corrupt the whole read."""
    entries = []
    try:
        with open(path, "r") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(Entry.from_dict(json.loads(line)))
                except (json.JSONDecodeError, KeyError, ValueError):
                    continue
    except OSError:
        return []
    return entries


def replay(path, *, main_fn=None, on_entry=None, dry_run=False):
    """Re-execute every entry in ``path`` in order.

    ``main_fn`` is the entry point to call (defaults to
    :func:`fieldkit.cli.main`) — swappable for testing.
    ``on_entry(entry, exit_code)`` fires after each replay; used
    by the CLI to print progress.

    ``dry_run=True`` prints what would run without actually calling
    main. Returns the list of ``(entry, exit_code)`` tuples — for
    a dry-run every exit_code is ``None``.
    """
    if main_fn is None:
        from . import cli as cli_mod
        main_fn = cli_mod.main
    results = []
    for entry in read(path):
        if dry_run:
            if on_entry:
                on_entry(entry, None)
            results.append((entry, None))
            continue
        # Re-invoke with the recorded argv. sys.argv is what
        # argparse reads by default; save + restore so we don't
        # trample the caller's environment.
        saved_argv = sys.argv[:]
        try:
            sys.argv = ["fieldkit"] + list(entry.argv)
            rc = main_fn(entry.argv)
        finally:
            sys.argv = saved_argv
        if on_entry:
            on_entry(entry, rc)
        results.append((entry, rc))
    return results
