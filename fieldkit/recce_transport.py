"""Recce-session execution transport — POST to recce's task endpoint, capture output.

The ``recce-session`` transport rides on recce's webui ``POST /api/sessions/{id}/task``
route: a JSON body carrying a target-side command + timeout goes over HTTP; recce runs
:meth:`Session.run_and_capture` on the caught shell and returns the captured bytes
base64-encoded. Fieldkit wraps the response as a :class:`~fieldkit.runner.RunResult`
so the executor's step-capture, safety-gate, and ``report --check`` invariants all hold
unchanged — the anti-fabrication guarantee is preserved because the executor writes the
same ``step`` row shape either way.

Stdlib-only (``http.client``) so the airgap clone-and-run property is preserved.
The HTTP call is injectable (``http_call=`` kwarg) so tests drive it against a fake
handler without opening a real socket.

Config lives on the engagement, not per-invocation: ``recce_url`` (webui URL) and
``recce_tester`` (attribution string sent as the ``X-Tester`` header, matching recce's
own soft-auth convention). Per-host session binding is CLI-time (``--via-recce=<id>``)
until we have data on whether persistent binding would help.
"""
import base64
import http.client
import json
import time
from dataclasses import dataclass
from urllib.parse import urlparse

from .runner import RunResult

#: Default task timeout when the caller doesn't specify one. Kept modest so a hung
#: session doesn't wedge the escalate loop for minutes.
DEFAULT_TIMEOUT = 30.0

#: How much longer the HTTP socket waits than the task itself, so recce has time to
#: return a response even after a task hit its own timeout.
_HTTP_MARGIN = 15.0


@dataclass
class TaskConfig:
    """Resolved recce endpoint config."""

    url: str                        # e.g. http://localhost:8000 (no trailing /api)
    tester: str = "fieldkit"        # X-Tester attribution


class _HTTPCallError(Exception):
    """Raised by _http_call when the socket-layer request fails; caught in task_session."""


def _http_call(method, url, headers, body, socket_timeout):
    """Real stdlib HTTP call. Injectable via ``http_call=`` for tests.

    Returns ``(status_int, response_bytes)``. Raises :class:`_HTTPCallError` on
    connection/timeout failures so the caller can surface a clean operator error
    without a stack trace.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise _HTTPCallError(f"unsupported URL scheme: {parsed.scheme}")
    conn_cls = (http.client.HTTPSConnection if parsed.scheme == "https"
                else http.client.HTTPConnection)
    default_port = 443 if parsed.scheme == "https" else 80
    conn = conn_cls(parsed.hostname, parsed.port or default_port,
                    timeout=socket_timeout)
    try:
        path = parsed.path or "/"
        if parsed.query:
            path = path + "?" + parsed.query
        try:
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            return resp.status, resp.read()
        except (OSError, http.client.HTTPException, TimeoutError) as exc:
            raise _HTTPCallError(str(exc)) from exc
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001 — close errors are diagnostics, not failures
            pass


def _config_from_store(store):
    """Read the engagement config for recce endpoint + tester, with sane defaults.

    Returns ``TaskConfig(url="", ...)`` when not configured — the caller distinguishes
    unconfigured from unreachable so the operator sees the right error.
    """
    cfg_json = store.get_config()
    return TaskConfig(
        url=str(cfg_json.get("recce_url") or ""),
        tester=str(cfg_json.get("recce_tester") or "fieldkit"),
    )


def task_session(config, session_id, command, timeout=DEFAULT_TIMEOUT, *,
                 http_call=None):
    """POST ``command`` to recce's session-task endpoint. Returns a
    :class:`RunResult` shaped like the subprocess path, so the executor's downstream
    step-write is identical.

    Errors surface as ``RunResult.error`` (matching the subprocess-not-found pattern),
    never exceptions — the executor caller expects this contract.

    ``argv`` on the returned RunResult carries ``["POST <url>", command]`` so the step
    table's captured evidence names both the transport wire fact (which webui was hit)
    and the target-side command that ran, which is what ``report --check`` renders.
    """
    if not config.url:
        return RunResult(
            [command],
            error=("recce_url not configured — set with "
                   "`fieldkit config set recce_url=http://recce-host:port`"))
    http_call = http_call or _http_call
    url = config.url.rstrip("/") + f"/api/sessions/{session_id}/task"
    body = json.dumps({"command": command, "timeout": float(timeout)}).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "X-Tester": config.tester or "fieldkit",
    }
    argv = [f"POST {url}", command]
    start = time.monotonic()
    try:
        status, resp_bytes = http_call("POST", url, headers, body,
                                       timeout + _HTTP_MARGIN)
    except _HTTPCallError as exc:
        return RunResult(argv, error=f"recce webui unreachable: {exc}",
                         duration=time.monotonic() - start)
    duration = time.monotonic() - start

    if status == 404:
        return RunResult(
            argv, exit_code=404, duration=duration,
            error=f"recce says: no such session {session_id!r} (has it dropped?)")
    if status == 409:
        return RunResult(
            argv, exit_code=409, duration=duration,
            error=f"recce says: session {session_id!r} is not currently connected")
    if status == 400:
        return RunResult(
            argv, exit_code=400, duration=duration,
            error=f"recce rejected the task: "
                  f"{resp_bytes[:200].decode('latin-1', errors='replace')}")
    if status != 200:
        return RunResult(
            argv, exit_code=status, duration=duration,
            error=f"recce returned status {status}: "
                  f"{resp_bytes[:200].decode('latin-1', errors='replace')}")

    try:
        payload = json.loads(resp_bytes)
    except json.JSONDecodeError as exc:
        return RunResult(argv, duration=duration,
                         error=f"recce sent unparseable JSON: {exc}")
    try:
        out_bytes = base64.b64decode(payload.get("output_b64") or "")
    except (ValueError, TypeError) as exc:
        return RunResult(argv, duration=duration,
                         error=f"recce sent unparseable output_b64: {exc}")

    return RunResult(argv, exit_code=0, duration=duration,
                     stdout=out_bytes.decode("utf-8", errors="replace"))
