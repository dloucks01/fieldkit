#!/usr/bin/env python3
"""chain register --from-yaml — user-defined chain profiles.

C16 gaps slice 4. Auto-load from ~/.fieldkit/chains/*.yaml on
fieldkit.chain import; install/uninstall via CLI.
"""
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


VALID_YAML = """\
name: test-yaml-chain
description: A test chain.
steps:
  - name: preflight:reachability
    kind: preflight
    detection_cost: 0
    action: builtin:reachability
    signals:
      - kind: smb-conn
        identifier: tcp-syn/445
  - name: manual:coerce
    kind: target-side
    detection_cost: 3
    action: manual
    manual_message: "run mytool -t <target>"
    signals:
      - kind: rpc-call
        identifier: MS-EFSR/EfsRpcOpenFileRaw
"""


def _snap_registry(test_case):
    """Save + restore chain._PROFILES around a test that touches it."""
    from fieldkit import chain as chain_mod
    snap = dict(chain_mod._PROFILES)
    test_case.addCleanup(
        lambda: (chain_mod._PROFILES.clear(),
                  chain_mod._PROFILES.update(snap)))


def _write(tmp, name, body):
    path = os.path.join(tmp, name)
    with open(path, "w") as fh:
        fh.write(body)
    return path


class BuildProfileTest(unittest.TestCase):

    def test_valid_yaml_builds_factory(self):
        from fieldkit import chain_yaml
        import yaml as _yaml
        doc = _yaml.safe_load(VALID_YAML)
        name, factory = chain_yaml.build_profile_from_doc(doc)
        self.assertEqual(name, "test-yaml-chain")
        ch = factory("10.0.0.5")
        self.assertEqual(ch.profile, "test-yaml-chain")
        self.assertEqual(len(ch.steps), 2)
        self.assertEqual(ch.steps[0].name, "preflight:reachability")

    def test_missing_name_raises(self):
        from fieldkit import chain_yaml
        with self.assertRaises(chain_yaml.ChainYamlError):
            chain_yaml.build_profile_from_doc({"steps": []})

    def test_empty_steps_raises(self):
        from fieldkit import chain_yaml
        with self.assertRaises(chain_yaml.ChainYamlError):
            chain_yaml.build_profile_from_doc({"name": "x", "steps": []})

    def test_missing_action_raises(self):
        from fieldkit import chain_yaml
        doc = {"name": "x", "steps": [{"name": "s", "kind": "preflight"}]}
        with self.assertRaises(chain_yaml.ChainYamlError):
            chain_yaml.build_profile_from_doc(doc)

    def test_unknown_builtin_action_raises(self):
        from fieldkit import chain_yaml
        doc = {"name": "x", "steps": [
            {"name": "s", "kind": "preflight",
             "action": "builtin:nonexistent"}]}
        with self.assertRaises(chain_yaml.ChainYamlError):
            chain_yaml.build_profile_from_doc(doc)

    def test_manual_without_message_raises(self):
        from fieldkit import chain_yaml
        doc = {"name": "x", "steps": [
            {"name": "s", "kind": "target-side", "action": "manual"}]}
        with self.assertRaises(chain_yaml.ChainYamlError):
            chain_yaml.build_profile_from_doc(doc)

    def test_bad_signal_kind_raises(self):
        from fieldkit import chain_yaml
        doc = {"name": "x", "steps": [{
            "name": "s", "kind": "preflight",
            "action": "manual", "manual_message": "hi",
            "signals": [{"kind": "not-a-real-kind",
                          "identifier": "x"}]}]}
        with self.assertRaises(chain_yaml.ChainYamlError):
            chain_yaml.build_profile_from_doc(doc)


class RegisterFromFileTest(unittest.TestCase):

    def test_register_adds_to_registry(self):
        from fieldkit import chain_yaml, chain as chain_mod
        _snap_registry(self)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        p = _write(tmp.name, "test.yaml", VALID_YAML)
        name = chain_yaml.register_from_file(p)
        self.assertEqual(name, "test-yaml-chain")
        self.assertIn("test-yaml-chain", chain_mod.known_profiles())


class InstallUninstallTest(unittest.TestCase):

    def _isolated_user_dir(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        from fieldkit import chain_yaml
        orig = chain_yaml.USER_CHAINS_DIR
        chain_yaml.USER_CHAINS_DIR = tmp.name
        self.addCleanup(
            lambda: setattr(chain_yaml, "USER_CHAINS_DIR", orig))
        return tmp.name

    def test_install_yaml_copies_to_user_dir(self):
        from fieldkit import chain_yaml
        _snap_registry(self)
        user_dir = self._isolated_user_dir()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        src = _write(tmp.name, "candidate.yaml", VALID_YAML)
        dest = chain_yaml.install_yaml(src)
        self.assertEqual(os.path.dirname(dest), user_dir)
        # Copied as <profile-name>.yaml
        self.assertTrue(dest.endswith("test-yaml-chain.yaml"))

    def test_install_bad_yaml_raises_and_doesnt_copy(self):
        from fieldkit import chain_yaml
        user_dir = self._isolated_user_dir()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        bad = _write(tmp.name, "bad.yaml", "name: x\nsteps: []")
        with self.assertRaises(chain_yaml.ChainYamlError):
            chain_yaml.install_yaml(bad)
        # Nothing lands in the user dir
        # (dir may not exist yet; if it does it's empty)
        if os.path.isdir(user_dir):
            self.assertEqual(os.listdir(user_dir), [])

    def test_uninstall_removes_file(self):
        from fieldkit import chain_yaml
        _snap_registry(self)
        user_dir = self._isolated_user_dir()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        src = _write(tmp.name, "candidate.yaml", VALID_YAML)
        chain_yaml.install_yaml(src)
        # Load into registry so uninstall clears both
        chain_yaml.register_from_file(
            os.path.join(user_dir, "test-yaml-chain.yaml"))
        removed = chain_yaml.uninstall("test-yaml-chain")
        self.assertTrue(removed)
        from fieldkit import chain as chain_mod
        self.assertNotIn("test-yaml-chain",
                          chain_mod.known_profiles())


class CLIRegisterTest(unittest.TestCase):

    def _run(self, argv):
        from fieldkit.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(argv)
        buf = io.StringIO()
        errbuf = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(errbuf):
            code = args.func(args)
        return code, buf.getvalue(), errbuf.getvalue()

    def _isolated_user_dir(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        from fieldkit import chain_yaml
        orig = chain_yaml.USER_CHAINS_DIR
        chain_yaml.USER_CHAINS_DIR = tmp.name
        self.addCleanup(
            lambda: setattr(chain_yaml, "USER_CHAINS_DIR", orig))
        return tmp.name

    def test_cli_register_installs_yaml(self):
        _snap_registry(self)
        self._isolated_user_dir()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        p = _write(tmp.name, "candidate.yaml", VALID_YAML)
        code, out, _ = self._run(
            ["chain", "register", "--from-yaml", p])
        self.assertEqual(code, 0)
        self.assertIn("installed", out)

    def test_cli_register_bad_yaml_exits_2(self):
        _snap_registry(self)
        self._isolated_user_dir()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        p = _write(tmp.name, "bad.yaml", "not valid yaml at all: :: :")
        code, _, err = self._run(
            ["chain", "register", "--from-yaml", p])
        self.assertEqual(code, 2)

    def test_cli_unregister_refuses_shipped(self):
        code, _, err = self._run(["chain", "unregister", "esc8"])
        self.assertEqual(code, 2)
        self.assertIn("shipped", err)

    def test_cli_list_profiles_shows_origin_column(self):
        code, out, _ = self._run(["chain", "list-profiles"])
        self.assertEqual(code, 0)
        self.assertIn("origin", out)
        self.assertIn("shipped", out)
        # 5 shipped profiles by name
        for p in ("esc8", "rbcd", "smb-relay-exec", "esc1", "nopac"):
            self.assertIn(p, out)


if __name__ == "__main__":
    unittest.main()
