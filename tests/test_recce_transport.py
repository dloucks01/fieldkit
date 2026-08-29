#!/usr/bin/env python3
"""Recce-session execution transport — POSTs commands through recce's task endpoint.

Pinned:

  * ``task_session`` returns a :class:`RunResult` — never raises for network / HTTP
    failure; the executor's contract is that operator-caused failures surface as
    ``result.error``, not exceptions.
  * The full ``executor.execute`` flow via a recce-session transport writes a step
    row with cmd + output + exit_code + transport — the anti-fabrication invariant
    that ``report --check`` depends on holds by construction (same shape as the
    subprocess path).
  * Missing ``recce_url`` fails clean with a clear operator error.
  * ``upload=`` on a recce-session action is blocked with an explicit error, since
    a session's tasking channel can't push files.
  * ``recce_session_id`` is required on the action; missing it is blocked.
  * Safety gate still applies to recce-session actions — a ``config-change`` action
    without ``--allow config-change`` is refused before any HTTP call.
"""
import json
import os
import sys
import tempfile
import unittest
from base64 import b64encode

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import executor, recce_transport, runner, transport  # noqa: E402
from fieldkit.state import Store  # noqa: E402


class _FakeHTTP:
    """Injectable HTTP handler. Records calls, returns canned responses.

    Signature matches recce_transport._http_call: (method, url, headers, body, timeout).
    """

    def __init__(self, status=200, body=None, raise_error=None):
        self.status = status
        self.body = body if body is not None else _ok_body()
        self.raise_error = raise_error
        self.calls = []

    def __call__(self, method, url, headers, body, socket_timeout):
        self.calls.append({"method": method, "url": url, "headers": headers,
                           "body": body, "socket_timeout": socket_timeout})
        if self.raise_error is not None:
            raise recce_transport._HTTPCallError(self.raise_error)
        return self.status, self.body


def _ok_body(output=b"fieldkit-alice\n", captured_ms=42):
    return json.dumps({
        "id": "sess1234abcd",
        "host_ip": "10.0.0.7",
        "output_b64": b64encode(output).decode(),
        "captured_ms": captured_ms,
    }).encode()


class TaskSessionTest(unittest.TestCase):
    def test_happy_path_returns_captured_output_as_runresult(self):
        cfg = recce_transport.TaskConfig(url="http://recce:8000", tester="alice")
        http = _FakeHTTP(status=200, body=_ok_body(b"root\n", captured_ms=17))
        result = recce_transport.task_session(cfg, "sess1234abcd", "id", timeout=5.0,
                                              http_call=http)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout, "root\n")
        self.assertTrue(result.ok)
        # the request went to the right URL with the right headers/body
        call = http.calls[0]
        self.assertEqual(call["url"], "http://recce:8000/api/sessions/sess1234abcd/task")
        self.assertEqual(call["method"], "POST")
        self.assertEqual(call["headers"]["X-Tester"], "alice")
        payload = json.loads(call["body"])
        self.assertEqual(payload["command"], "id")
        self.assertEqual(payload["timeout"], 5.0)
        # argv on the RunResult names the wire fact + the target command
        self.assertEqual(result.argv,
                         ["POST http://recce:8000/api/sessions/sess1234abcd/task", "id"])

    def test_missing_url_fails_clean(self):
        cfg = recce_transport.TaskConfig(url="", tester="alice")
        result = recce_transport.task_session(cfg, "sess", "id",
                                              http_call=_FakeHTTP())
        self.assertIn("recce_url not configured", result.error)
        self.assertFalse(result.ok)

    def test_network_failure_surfaces_as_error_not_exception(self):
        cfg = recce_transport.TaskConfig(url="http://nope:9", tester="x")
        http = _FakeHTTP(raise_error="Connection refused")
        result = recce_transport.task_session(cfg, "sess", "id", http_call=http)
        self.assertIn("recce webui unreachable", result.error)
        self.assertIn("Connection refused", result.error)

    def test_404_maps_to_session_dropped_message(self):
        cfg = recce_transport.TaskConfig(url="http://r:8000")
        result = recce_transport.task_session(
            cfg, "gone", "id", http_call=_FakeHTTP(status=404, body=b"not found"))
        self.assertEqual(result.exit_code, 404)
        self.assertIn("no such session", result.error)

    def test_409_maps_to_session_disconnected_message(self):
        cfg = recce_transport.TaskConfig(url="http://r:8000")
        result = recce_transport.task_session(
            cfg, "sess", "id",
            http_call=_FakeHTTP(status=409, body=b"shell not connected"))
        self.assertEqual(result.exit_code, 409)
        self.assertIn("not currently connected", result.error)

    def test_unparseable_response_yields_clean_error(self):
        cfg = recce_transport.TaskConfig(url="http://r:8000")
        result = recce_transport.task_session(
            cfg, "sess", "id", http_call=_FakeHTTP(status=200, body=b"<html>lol</html>"))
        self.assertIn("unparseable JSON", result.error)

    def test_url_trailing_slash_is_trimmed(self):
        cfg = recce_transport.TaskConfig(url="http://recce:8000/")
        http = _FakeHTTP()
        recce_transport.task_session(cfg, "sess", "id", http_call=http)
        self.assertEqual(http.calls[0]["url"],
                         "http://recce:8000/api/sessions/sess/task")


class ExecutorRecceBranchTest(unittest.TestCase):
    """The executor.execute() flow over a recce-session transport — the invariant
    is that ``report --check`` sees the same step shape as the subprocess path."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME")
        # recce endpoint configured for the transport
        self.store.set_config({"recce_url": "http://recce:8000",
                               "recce_tester": "alice"})
        # a host to run against
        self.host_id, _ = self.store.add_host("10.0.0.7", hostname="WS02",
                                              os_name="windows")
        self.host = self.store.host_by_id(self.host_id)

    def _action(self, command="whoami", session_id="sess1234abcd",
                safety="read-only", upload=None):
        return executor.Action(
            host=self.host, cred=None, command=command, label="vector:test",
            safety=safety, transport="recce-session-win",
            recce_session_id=session_id, upload=upload)

    def test_full_flow_writes_step_with_output_and_transport_label(self):
        http = _FakeHTTP(status=200, body=_ok_body(b"NT AUTHORITY\\SYSTEM\n", captured_ms=12))
        result = executor.execute(self.store, self._action(),
                                  allow="read-only", recce_http=http)
        self.assertTrue(result.ok)
        self.assertEqual(result.transport, "recce-session:sess1234abcd")
        # step row lands with the RIGHT shape — the report --check invariant
        steps = self.store.steps(host_id=self.host_id)
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0]["cmd"], "whoami")
        self.assertIn("NT AUTHORITY\\SYSTEM", steps[0]["output"])
        self.assertEqual(steps[0]["exit_code"], 0)
        self.assertEqual(steps[0]["transport"], "recce-session:sess1234abcd")

    def test_missing_session_id_is_blocked_before_any_http_call(self):
        http = _FakeHTTP()
        action = self._action(session_id=None)
        result = executor.execute(self.store, action, recce_http=http)
        self.assertIn("--via-recce", result.blocked)
        self.assertEqual(http.calls, [])
        # nothing hit the store either
        self.assertEqual(self.store.steps(host_id=self.host_id), [])

    def test_safety_gate_still_applies(self):
        # a config-change action without --allow config-change is refused even on recce
        http = _FakeHTTP()
        result = executor.execute(self.store, self._action(safety="config-change"),
                                  allow="read-only", recce_http=http)
        self.assertIn("safety gate", result.blocked)
        self.assertEqual(http.calls, [])           # no HTTP; step never written
        self.assertEqual(self.store.steps(host_id=self.host_id), [])

    def test_upload_via_recce_session_is_blocked_with_operator_error(self):
        http = _FakeHTTP()
        action = executor.Action(
            host=self.host, cred=None, command="", label="stage",
            safety="config-change", transport="recce-session-win",
            recce_session_id="sess1234abcd", upload=("/tmp/x", "/tmp/x-remote"))
        result = executor.execute(self.store, action, allow="config-change",
                                  recce_http=http)
        self.assertIn("can't push files", result.blocked)
        self.assertEqual(http.calls, [])

    def test_recce_404_surfaces_as_failed_step_with_evidence_intact(self):
        # a dropped session still captures evidence — the operator sees exactly what
        # was attempted and why it failed, which is the anti-fabrication guarantee.
        http = _FakeHTTP(status=404, body=b"not found")
        result = executor.execute(self.store, self._action(),
                                  allow="read-only", recce_http=http)
        self.assertFalse(result.ok)                # the tool did not run to completion
        # BUT a step row still lands with the command + the transport label —
        # nothing about the attempt is silently lost.
        steps = self.store.steps(host_id=self.host_id)
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0]["cmd"], "whoami")
        self.assertEqual(steps[0]["transport"], "recce-session:sess1234abcd")
        self.assertEqual(steps[0]["exit_code"], 404)


class TransportRegistryTest(unittest.TestCase):
    """The recce-session transports are wired into the transport registry."""

    def test_two_recce_transports_are_registered(self):
        self.assertIsNotNone(transport.by_name("recce-session-win"))
        self.assertIsNotNone(transport.by_name("recce-session-linux"))

    def test_recce_transports_use_shared_proto_string(self):
        # the executor keys off transport.proto == "recce-session" — both win and
        # linux entries must share it, else one path silently bypasses the branch
        self.assertEqual(transport.by_name("recce-session-win").proto, "recce-session")
        self.assertEqual(transport.by_name("recce-session-linux").proto, "recce-session")


class RunResultShapeTest(unittest.TestCase):
    """Sanity: the shape task_session returns matches what runner.RunResult produces
    for the subprocess path — the executor's downstream step-write depends on it."""

    def test_runresult_from_task_session_has_output_property(self):
        cfg = recce_transport.TaskConfig(url="http://r:8000")
        result = recce_transport.task_session(
            cfg, "sess", "id",
            http_call=_FakeHTTP(status=200, body=_ok_body(b"OK\n")))
        # `RunResult.output` returns stdout + stderr; recce path has no stderr
        self.assertEqual(result.output, "OK\n")
        self.assertIsInstance(result, runner.RunResult)


if __name__ == "__main__":
    unittest.main()
