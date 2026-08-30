#!/usr/bin/env python3
"""fieldkit dpapi — DPAPI secret decryption via impacket-dpapi.

C18 gap-slice B. Wraps dpapi.py masterkey / credential
subcommands; monkey-patches shutil.which + runner.run for
test isolation.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class FindToolTest(unittest.TestCase):

    def test_find_tool_when_dpapi_present(self):
        from fieldkit import dpapi
        import shutil as _shutil
        orig = _shutil.which
        _shutil.which = lambda name: "/usr/bin/dpapi.py" if name == "dpapi.py" else None
        self.addCleanup(lambda: setattr(_shutil, "which", orig))
        self.assertEqual(dpapi.find_tool(), "/usr/bin/dpapi.py")

    def test_find_tool_when_neither_present(self):
        from fieldkit import dpapi
        import shutil as _shutil
        orig = _shutil.which
        _shutil.which = lambda _: None
        self.addCleanup(lambda: setattr(_shutil, "which", orig))
        self.assertIsNone(dpapi.find_tool())


class MasterKeyTest(unittest.TestCase):

    def _patch_tools(self, canned_result):
        import shutil as _shutil
        from fieldkit import runner as runner_mod
        orig_which = _shutil.which
        orig_run = runner_mod.run
        _shutil.which = lambda name: f"/fake/{name}"
        runner_mod.run = lambda argv, timeout=None: canned_result
        self.addCleanup(lambda: setattr(_shutil, "which", orig_which))
        self.addCleanup(lambda: setattr(runner_mod, "run", orig_run))

    def _fake_run(self, stdout="", stderr="", exit_code=0,
                    timed_out=False, error=None):
        class _R:
            pass
        r = _R()
        r.stdout = stdout
        r.stderr = stderr
        r.exit_code = exit_code
        r.timed_out = timed_out
        r.error = error
        return r

    def test_missing_masterkey_file_returns_fail(self):
        from fieldkit import dpapi
        result = dpapi.decrypt_masterkey(
            "/nonexistent/mk", "S-1-5-21-x", password="p")
        self.assertEqual(result.kind, "fail")
        self.assertIn("no such file", result.output)

    def test_no_tool_returns_no_tool(self):
        from fieldkit import dpapi
        import shutil as _shutil
        orig = _shutil.which
        _shutil.which = lambda _: None
        self.addCleanup(lambda: setattr(_shutil, "which", orig))
        # Create a real file so we don't short-circuit on file check
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        mk = os.path.join(tmp.name, "mk")
        open(mk, "w").close()
        result = dpapi.decrypt_masterkey(mk, "S-1", password="p")
        self.assertEqual(result.kind, "no-tool")

    def test_successful_decrypt_extracts_key(self):
        from fieldkit import dpapi
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        mk = os.path.join(tmp.name, "mk")
        open(mk, "w").close()
        self._patch_tools(self._fake_run(
            stdout="Impacket dpapi.py\nDecrypted key: abcdef1234"))
        result = dpapi.decrypt_masterkey(mk, "S-1-5", password="pw")
        self.assertEqual(result.kind, "ok")
        self.assertEqual(result.artifact, "abcdef1234")

    def test_fail_output_classifies_as_fail(self):
        from fieldkit import dpapi
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        mk = os.path.join(tmp.name, "mk")
        open(mk, "w").close()
        self._patch_tools(self._fake_run(
            stdout="", stderr="[-] Invalid password"))
        result = dpapi.decrypt_masterkey(mk, "S-1", password="wrong")
        self.assertEqual(result.kind, "fail")

    def test_requires_password_or_hash(self):
        from fieldkit import dpapi
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        mk = os.path.join(tmp.name, "mk")
        open(mk, "w").close()
        # Force tool present so we hit the "need creds" branch
        import shutil as _shutil
        orig = _shutil.which
        _shutil.which = lambda _: "/fake/dpapi.py"
        self.addCleanup(lambda: setattr(_shutil, "which", orig))
        result = dpapi.decrypt_masterkey(mk, "S-1")
        self.assertEqual(result.kind, "fail")
        self.assertIn("need --password", result.output)


class CredentialTest(unittest.TestCase):

    def test_missing_blob_returns_fail(self):
        from fieldkit import dpapi
        result = dpapi.decrypt_credential("/nonexistent/blob", "abcdef")
        self.assertEqual(result.kind, "fail")

    def test_extracts_credential_fields(self):
        from fieldkit import dpapi
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        blob = os.path.join(tmp.name, "blob")
        open(blob, "w").close()
        # Patch shutil + runner
        import shutil as _shutil
        from fieldkit import runner as runner_mod
        orig_which = _shutil.which
        orig_run = runner_mod.run
        _shutil.which = lambda _: "/fake/dpapi.py"
        class _R: pass
        r = _R()
        r.stdout = "Username: CORP\\jdoe\nPassword: Winter2025!"
        r.stderr = ""
        r.exit_code = 0
        r.timed_out = False
        r.error = None
        runner_mod.run = lambda argv, timeout=None: r
        self.addCleanup(lambda: setattr(_shutil, "which", orig_which))
        self.addCleanup(lambda: setattr(runner_mod, "run", orig_run))
        result = dpapi.decrypt_credential(blob, "deadbeef")
        self.assertEqual(result.kind, "ok")
        self.assertIn("CORP\\jdoe", result.artifact)
        self.assertIn("Winter2025", result.artifact)


class CLITest(unittest.TestCase):

    def test_dpapi_subparser_registered(self):
        from fieldkit.cli import build_parser
        parser = build_parser()
        args = parser.parse_args([
            "dpapi", "masterkey", "--file", "/tmp/x", "--sid", "S-1",
            "--password", "p"])
        self.assertEqual(args.dpapi_command, "masterkey")

    def test_credential_subparser_registered(self):
        from fieldkit.cli import build_parser
        parser = build_parser()
        args = parser.parse_args([
            "dpapi", "credential", "--file", "/tmp/x",
            "--masterkey", "abc"])
        self.assertEqual(args.dpapi_command, "credential")


if __name__ == "__main__":
    unittest.main()
