#!/usr/bin/env python3
"""The executor — safety gate, transport selection, and evidence capture.

Pinned:

  * a read-only action runs and its command+output+exit land in `step` verbatim;
  * the safety gate refuses a config-change / crash-risk action unless the operator
    widened `allow`, and nothing runs when it is refused;
  * exec uses only a transport the acting credential has *proven*, and records
    cleanup artifacts for anything a vector changes.

Run:  python3 -m unittest discover -s tests
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit.creds import Credential  # noqa: E402
from fieldkit.executor import Action, execute, gate  # noqa: E402
from fieldkit.runner import RunResult  # noqa: E402
from fieldkit.state import Store  # noqa: E402


def canned(output, exit_code=0):
    return lambda argv, env=None: RunResult(argv, exit_code=exit_code, stdout=output)


class ExecutorTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME")
        self.hid, _ = self.store.add_host("10.0.0.8", os_name="linux")
        self.cid, _ = self.store.add_credential(Credential("svc", "s3cret", domain="corp"))
        self.store.add_access(self.hid, self.cid, "ssh", admin=False)
        self.host = self.store.host_by_ip("10.0.0.8")
        self.cred = self.store.credential_by_id(self.cid)

    def action(self, **kw):
        base = dict(host=self.host, cred=self.cred, command="id", label="enum:id")
        base.update(kw)
        return Action(**base)


class GateTest(unittest.TestCase):
    def test_read_only_always_allowed(self):
        self.assertTrue(gate("read-only", "read-only"))

    def test_prefix_semantics(self):
        self.assertTrue(gate("config-change", "config-change"))
        self.assertFalse(gate("crash-risk", "config-change"))
        self.assertTrue(gate("crash-risk", "crash-risk"))

    def test_explicit_set(self):
        self.assertTrue(gate("crash-risk", {"read-only", "crash-risk"}))
        self.assertFalse(gate("config-change", {"read-only", "crash-risk"}))


class ExecuteTest(ExecutorTestCase):
    def test_read_only_runs_and_captures(self):
        res = execute(self.store, self.action(), run=canned("uid=1000(svc)"))
        self.assertTrue(res.ok)
        self.assertEqual(res.transport, "ssh")
        steps = self.store.steps(host_id=self.hid)
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0]["cmd"], "id")
        self.assertIn("uid=1000", steps[0]["output"])
        self.assertEqual(steps[0]["transport"], "ssh")

    def test_gate_blocks_config_change_by_default(self):
        res = execute(self.store, self.action(command="echo x >> /etc/passwd",
                                              safety="config-change"),
                      run=canned("should not run"))
        self.assertFalse(res.ok)
        self.assertIn("safety gate", res.blocked)
        self.assertEqual(self.store.steps(host_id=self.hid), [])  # nothing ran

    def test_gate_allows_when_widened(self):
        res = execute(self.store, self.action(safety="config-change"),
                      run=canned("ok"), allow="config-change")
        self.assertTrue(res.ok)

    def test_crash_risk_needs_explicit_allow(self):
        blocked = execute(self.store, self.action(safety="crash-risk"),
                          run=canned("x"), allow="config-change")
        self.assertFalse(blocked.ok)
        ok = execute(self.store, self.action(safety="crash-risk"),
                     run=canned("x"), allow="crash-risk")
        self.assertTrue(ok.ok)

    def test_no_proven_path_is_blocked(self):
        # a windows host we hold no access on: no transport, nothing runs.
        wid, _ = self.store.add_host("10.0.0.9", os_name="windows")
        win = self.store.host_by_ip("10.0.0.9")
        res = execute(self.store, self.action(host=win), run=canned("x"))
        self.assertFalse(res.ok)
        self.assertIn("no proven way", res.blocked)

    def test_creates_recorded_as_cleanup_artifacts(self):
        res = execute(
            self.store,
            self.action(command="cp /bin/bash /tmp/.rb; chmod 4755 /tmp/.rb",
                        safety="config-change",
                        creates=[("SUID bash at /tmp/.rb", "rm -f /tmp/.rb")]),
            run=canned("done"), allow="config-change")
        self.assertTrue(res.ok)
        arts = self.store.artifacts()
        self.assertEqual(len(arts), 1)
        self.assertEqual(arts[0]["cleanup_cmd"], "rm -f /tmp/.rb")
        self.assertEqual(arts[0]["host_id"], self.hid)

    def test_forced_transport(self):
        res = execute(self.store, self.action(transport="winrm"), run=canned("x"))
        # winrm forced, but the host proved only ssh — nxc still gets rendered; the
        # point is the name is honored.
        self.assertEqual(res.transport, "winrm")

    def test_evidence_ties_to_a_finding_when_given(self):
        fid, _ = self.store.add_finding("gtfobins", "sudo find", host_id=self.hid)
        execute(self.store, self.action(finding_id=fid, label="vector:find"),
                run=canned("# root"))
        self.assertEqual(len(self.store.steps(finding_id=fid)), 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
