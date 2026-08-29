#!/usr/bin/env python3
"""AIE port + execute.builds schema — B5h.

Phase B5h: `_d_win_aie` retires from DRIVERS[WINDOWS], and
AlwaysInstallElevated now flows through
T1548.002-alwaysinstallelevated.yaml. The load-bearing surface change
is the new `execute.builds` schema field — a tuple of
`(format, remote_path, build_command)` triples that tells the escalate
loop to *build* a per-target payload (rather than push a static
arsenal artifact via `stages`).

AIE uses `builds: [{format: msi, as: {{stage}}\\evil.msi}]` — same
shape the inlined driver emitted:
`builds=(("msi", "C:\\Windows\\Temp\\evil.msi", None),)`.

The 4 remaining Windows service drivers (unquoted / weak / writable /
dllhijack) ALSO need `builds`, but they additionally need per-fact
iteration (one Vector per service in `facts.reconfigurable_services`
etc.). That adapter extension lands in the next slice. `builds` alone
is generally-useful and worth shipping now.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class DriverRetirementTest(unittest.TestCase):

    def test_d_win_aie_not_in_drivers_windows(self):
        from fieldkit.privesc import DRIVERS, WINDOWS, _d_win_aie
        self.assertNotIn(_d_win_aie, DRIVERS[WINDOWS])

    def test_iterable_service_drivers_stay_inlined_for_now(self):
        # These four still need per-item iteration in the adapter — they
        # emit ONE Vector per service in facts.<attr>, and the current
        # predicate model fires ONCE per host. Next slice lands the
        # iteration surface and closes DRIVERS[WINDOWS] to (_d_ttp_yaml,).
        from fieldkit.privesc import (
            DRIVERS, WINDOWS,
            _d_win_unquoted, _d_win_weak_service,
            _d_win_writable_service, _d_win_dll_hijack,
        )
        for d in (_d_win_unquoted, _d_win_weak_service,
                   _d_win_writable_service, _d_win_dll_hijack):
            self.assertIn(d, DRIVERS[WINDOWS])


class AIETTPTest(unittest.TestCase):

    def _fire(self, **kw):
        from fieldkit.hostenum import HostFacts, WINDOWS
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        base = dict(os=WINDOWS, user="alice", uid=1000)
        base.update(kw)
        return vectors_for(HostFacts(**base), "10.0.0.7",
                            stage_win="C:\\stage")

    def test_fires_when_both_keys_set(self):
        vs = self._fire(always_install_elevated=True)
        aie = [v for v in vs if v.key == "aie"]
        self.assertEqual(len(aie), 1)

    def test_does_not_fire_when_flag_off(self):
        vs = self._fire(always_install_elevated=False)
        self.assertEqual([v for v in vs if v.key == "aie"], [])

    def test_command_matches_inlined_shape(self):
        vs = self._fire(always_install_elevated=True)
        v = [x for x in vs if x.key == "aie"][0]
        self.assertIn("msiexec", v.command)
        self.assertIn("/i C:\\stage\\evil.msi", v.command)

    def test_builds_field_populated_with_msi_triple(self):
        # Matches the inlined driver's builds=(("msi", staged, None),).
        vs = self._fire(always_install_elevated=True)
        v = [x for x in vs if x.key == "aie"][0]
        self.assertEqual(v.builds, (("msi", "C:\\stage\\evil.msi", None),))

    def test_stage_substitution_flows_through_to_builds(self):
        # {{stage}} in the YAML `as:` slot is filled from ctx.stage_win.
        # A test that passes a non-default stage_win exercises the
        # substitution path (not just the C:\Windows\Temp fallback).
        from fieldkit.hostenum import HostFacts, WINDOWS
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=WINDOWS, user="alice", uid=1000,
                       always_install_elevated=True),
            "10.0.0.7", stage_win="D:\\ops")
        v = [x for x in vs if x.key == "aie"][0]
        self.assertEqual(v.builds, (("msi", "D:\\ops\\evil.msi", None),))
        self.assertIn("D:\\ops\\evil.msi", v.command)

    def test_report_type_alwaysinstallelevated(self):
        vs = self._fire(always_install_elevated=True)
        v = [x for x in vs if x.key == "aie"][0]
        self.assertEqual(v.report_type, "alwaysinstallelevated")
        self.assertIn("AlwaysInstallElevated", v.evidence)

    def test_cleanup_removes_staged_msi(self):
        vs = self._fire(always_install_elevated=True)
        v = [x for x in vs if x.key == "aie"][0]
        self.assertIn("del", v.cleanup)
        self.assertIn("evil.msi", v.cleanup)


class ExecuteBuildsSchemaTest(unittest.TestCase):
    """Load + parse the new schema field in isolation, so a future TTP
    author gets clear errors on malformed builds blocks."""

    def _load_from_string(self, yaml_text):
        import tempfile
        from fieldkit.ttps.loader import load_file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml",
                                          delete=False) as fh:
            fh.write(yaml_text)
            path = fh.name
        try:
            return load_file(path)
        finally:
            os.unlink(path)

    #: YAML template composed by string concatenation — avoids the
    #: escaping headaches of embedded backslashes across Python string,
    #: YAML string, and .replace() layers.
    _HEADER = (
        "technique: T1548.002\n"
        "name: test\n"
        "tactic: [privilege-escalation]\n"
        "platform: [windows]\n"
        "key: 'test:builds'\n"
        "ranking:\n"
        "  exploitability: high\n"
        "  safety: read-only\n"
        "  detection: quiet\n"
        "detect:\n"
        "  always: true\n"
        "execute:\n"
        "  command: 'echo ok'\n"
    )
    _FOOTER = (
        "verify:\n"
        "  success: 'ok'\n"
        "cleanup:\n"
        "  command: ''\n"
        "report:\n"
        "  vector_type: test\n"
    )

    def test_builds_parses_msi_triple(self):
        y = (self._HEADER
             + "  builds:\n"
             + "    - format: msi\n"
             + "      as: '/tmp/evil.msi'\n"
             + self._FOOTER)
        ttp = self._load_from_string(y)
        self.assertEqual(len(ttp.execute.builds), 1)
        fmt, remote, run = ttp.execute.builds[0]
        self.assertEqual(fmt, "msi")
        self.assertEqual(remote, "/tmp/evil.msi")
        self.assertIsNone(run)

    def test_builds_parses_run_when_present(self):
        y = (self._HEADER
             + "  builds:\n"
             + "    - format: msi\n"
             + "      as: '/tmp/evil.msi'\n"
             + "      run: 'cmd /c whoami'\n"
             + self._FOOTER)
        ttp = self._load_from_string(y)
        _, _, run = ttp.execute.builds[0]
        self.assertEqual(run, "cmd /c whoami")

    def test_missing_format_key_raises_loader_error(self):
        from fieldkit.ttps.loader import LoaderError
        y = (self._HEADER
             + "  builds:\n"
             + "    - as: '/tmp/evil.msi'\n"
             + self._FOOTER)
        with self.assertRaises(LoaderError):
            self._load_from_string(y)

    def test_missing_as_key_raises_loader_error(self):
        from fieldkit.ttps.loader import LoaderError
        y = (self._HEADER
             + "  builds:\n"
             + "    - format: msi\n"
             + self._FOOTER)
        with self.assertRaises(LoaderError):
            self._load_from_string(y)

    def test_omitted_builds_defaults_to_empty_tuple(self):
        y = self._HEADER + self._FOOTER
        ttp = self._load_from_string(y)
        self.assertEqual(ttp.execute.builds, ())


class BuildsAdapterSubstitutionTest(unittest.TestCase):
    """Adapter emits Vector.builds with {{stage}} + {{binary}} filled in."""

    def test_stage_and_run_are_substituted_together(self):
        # A TTP with `run: '{{stage}}\\proof.txt'` gets the stage dir
        # applied to both the remote path and the run command.
        import tempfile
        from fieldkit.hostenum import HostFacts, WINDOWS
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        y = """
technique: T1548.002
name: test-run-subst
tactic: [privilege-escalation]
platform: [windows]
key: test:runsubst
ranking:
  exploitability: high
  safety: read-only
  detection: quiet
detect:
  always: true
execute:
  command: 'echo ok'
  builds:
    - format: exe
      as: '{{stage}}\\p.exe'
      run: 'cmd /c whoami > {{stage}}\\proof.txt'
verify:
  success: "ok"
cleanup:
  command: ''
report:
  vector_type: test
"""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "t.yaml")
            with open(path, "w") as fh:
                fh.write(y)
            # Load directly through the whole adapter chain by pointing
            # the built-in dir at this tmp.
            import fieldkit.ttps.loader as loader
            from fieldkit.ttps.loader import load_all
            _reset_ttp_cache_for_tests()
            ttps = load_all(tmp)
            ttp = [t for t in ttps if t.key == "test:runsubst"][0]
            from fieldkit.ttps.adapter import ttp_to_vector
            from fieldkit.privesc import _Ctx
            v = ttp_to_vector(ttp,
                                HostFacts(os=WINDOWS, user="alice", uid=1000),
                                _Ctx(host="10.0.0.7", stage_win="D:\\stg"))
            self.assertEqual(v.builds, (("exe", "D:\\stg\\p.exe",
                                          "cmd /c whoami > D:\\stg\\proof.txt"),))
            _ = loader   # keep the import; used above


if __name__ == "__main__":
    unittest.main()
