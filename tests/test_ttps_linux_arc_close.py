#!/usr/bin/env python3
"""Linux privesc port arc — closed at B5g.

Phase B5g retires the LAST three inlined Linux drivers:

  * `_d_sudo_all`     — sudo -l says (ALL : ALL) ALL → root
  * `_d_docker_group` — member of docker group → host mount → root
  * `_d_sudo_env`     — sudoers preserves LD_PRELOAD → linker hijack → root

Two new adapter predicates land alongside:

  * `linux_group`        — value is a group name; matches when it's in
    `facts.groups` AND the operator is not already root (mirrors the
    inlined driver's `not facts.is_root` gate; without it every
    root shell would falsely report `group:docker` as an escalation);

  * `sudo_env_keep_any`  — value is a list of env-var names; matches
    when ANY intersects `facts.sudo_env_keep`. Payload is the matched
    var name(s) as a comma-joined string, rendered into the evidence
    template's `{{binary}}` slot ("sudo -l: env_keep+=LD_PRELOAD").

After this slice, `DRIVERS[LINUX]` is `(_d_ttp_yaml,)` — every Linux
privesc vector comes from a YAML TTP. The three retired driver
functions stay defined (module-level exports for tests + operator
introspection) but no longer wired into the vector-emission path.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class DriverRetirementTest(unittest.TestCase):

    def test_drivers_linux_is_ttp_only(self):
        from fieldkit.privesc import DRIVERS, LINUX, _d_ttp_yaml
        self.assertEqual(DRIVERS[LINUX], (_d_ttp_yaml,))

    def test_retired_drivers_not_in_drivers_linux(self):
        from fieldkit.privesc import (
            DRIVERS, LINUX, _d_sudo_all, _d_docker_group, _d_sudo_env,
        )
        for d in (_d_sudo_all, _d_docker_group, _d_sudo_env):
            self.assertNotIn(d, DRIVERS[LINUX])


class SudoAllTTPTest(unittest.TestCase):

    def _fire(self, **kw):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        base = dict(os=LINUX, user="alice", uid=1000)
        base.update(kw)
        return vectors_for(HostFacts(**base), "10.0.0.7")

    def test_sudo_all_fires_when_flag_set(self):
        vs = self._fire(sudo_all=True)
        keys = {v.key for v in vs}
        self.assertIn("sudo:ALL", keys)

    def test_sudo_all_does_not_fire_without_flag(self):
        vs = self._fire(sudo_all=False)
        keys = {v.key for v in vs}
        self.assertNotIn("sudo:ALL", keys)

    def test_sudo_all_suppresses_per_binary_sudo_ttps(self):
        # `_p_sudo_allows` short-circuits when sudo_all is True — the
        # per-binary sudo:<X> TTPs must NOT fire alongside sudo:ALL.
        vs = self._fire(sudo_all=True, sudo_binaries={"find", "bash"})
        keys = {v.key for v in vs}
        self.assertIn("sudo:ALL", keys)
        self.assertNotIn("sudo:find", keys)
        self.assertNotIn("sudo:bash", keys)

    def test_sudo_all_report_type_sudo_misconfig(self):
        vs = self._fire(sudo_all=True)
        v = [x for x in vs if x.key == "sudo:ALL"][0]
        self.assertEqual(v.report_type, "sudo_misconfig")
        self.assertIn("(ALL : ALL)", v.evidence)


class DockerGroupTTPTest(unittest.TestCase):

    def _fire(self, **kw):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        base = dict(os=LINUX, user="alice", uid=1000)
        base.update(kw)
        return vectors_for(HostFacts(**base), "10.0.0.7")

    def test_docker_group_fires_for_non_root(self):
        vs = self._fire(groups={"docker", "users"})
        keys = {v.key for v in vs}
        self.assertIn("group:docker", keys)

    def test_docker_group_suppressed_for_root(self):
        vs = self._fire(uid=0, user="root", groups={"root", "docker"})
        keys = {v.key for v in vs}
        self.assertNotIn("group:docker", keys)

    def test_docker_group_does_not_fire_without_membership(self):
        vs = self._fire(groups={"users", "audio"})
        keys = {v.key for v in vs}
        self.assertNotIn("group:docker", keys)

    def test_docker_group_report_type(self):
        vs = self._fire(groups={"docker"})
        v = [x for x in vs if x.key == "group:docker"][0]
        self.assertEqual(v.report_type, "docker_group")
        self.assertIn("docker run -v /:/mnt", v.command)


class SudoEnvPreloadTTPTest(unittest.TestCase):

    def _fire(self, **kw):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        base = dict(os=LINUX, user="alice", uid=1000)
        base.update(kw)
        return vectors_for(HostFacts(**base), "10.0.0.7")

    def test_ld_preload_fires(self):
        vs = self._fire(sudo_env_keep={"LD_PRELOAD"})
        keys = {v.key for v in vs}
        self.assertIn("sudo:env-preload", keys)

    def test_ld_library_path_fires(self):
        vs = self._fire(sudo_env_keep={"LD_LIBRARY_PATH"})
        keys = {v.key for v in vs}
        self.assertIn("sudo:env-preload", keys)

    def test_both_env_vars_render_in_evidence(self):
        vs = self._fire(sudo_env_keep={"LD_PRELOAD", "LD_LIBRARY_PATH"})
        v = [x for x in vs if x.key == "sudo:env-preload"][0]
        # Comma-joined sorted string in the payload → {{binary}} slot.
        self.assertIn("LD_LIBRARY_PATH", v.evidence)
        self.assertIn("LD_PRELOAD", v.evidence)

    def test_unrelated_env_keep_does_not_fire(self):
        # PATH is a common env_keep entry but doesn't enable linker
        # hijacking; the predicate must ignore it.
        vs = self._fire(sudo_env_keep={"PATH", "HOME"})
        keys = {v.key for v in vs}
        self.assertNotIn("sudo:env-preload", keys)

    def test_is_prepare_only(self):
        # Playbook-driven — never blind-fired at a client host (dropping
        # a .so is `config-change`).
        vs = self._fire(sudo_env_keep={"LD_PRELOAD"})
        v = [x for x in vs if x.key == "sudo:env-preload"][0]
        self.assertTrue(v.manual)
        self.assertIsNotNone(v.playbook)
        self.assertEqual(v.report_type, "ld_preload")


class LinuxGroupPredicateTest(unittest.TestCase):

    def _facts(self, **kw):
        from fieldkit.hostenum import HostFacts, LINUX
        base = dict(os=LINUX, user="alice", uid=1000)
        base.update(kw)
        return HostFacts(**base)

    def test_match_when_group_present_and_not_root(self):
        from fieldkit.ttps.adapter import _p_linux_group
        matched, payload = _p_linux_group(
            self._facts(groups={"docker"}), "docker")
        self.assertTrue(matched)
        self.assertEqual(payload, "docker")

    def test_no_match_when_root(self):
        from fieldkit.ttps.adapter import _p_linux_group
        matched, _ = _p_linux_group(
            self._facts(uid=0, user="root", groups={"docker"}), "docker")
        self.assertFalse(matched)

    def test_no_match_when_group_absent(self):
        from fieldkit.ttps.adapter import _p_linux_group
        matched, _ = _p_linux_group(
            self._facts(groups={"users"}), "docker")
        self.assertFalse(matched)


class SudoEnvKeepAnyPredicateTest(unittest.TestCase):

    def _facts(self, **kw):
        from fieldkit.hostenum import HostFacts, LINUX
        base = dict(os=LINUX, user="alice", uid=1000)
        base.update(kw)
        return HostFacts(**base)

    def test_match_when_any_intersects(self):
        from fieldkit.ttps.adapter import _p_sudo_env_keep_any
        matched, payload = _p_sudo_env_keep_any(
            self._facts(sudo_env_keep={"LD_PRELOAD", "PATH"}),
            ["LD_PRELOAD", "LD_LIBRARY_PATH"])
        self.assertTrue(matched)
        self.assertEqual(payload, "LD_PRELOAD")

    def test_payload_joins_multiple_matches_sorted(self):
        from fieldkit.ttps.adapter import _p_sudo_env_keep_any
        matched, payload = _p_sudo_env_keep_any(
            self._facts(sudo_env_keep={"LD_PRELOAD", "LD_LIBRARY_PATH"}),
            ["LD_PRELOAD", "LD_LIBRARY_PATH"])
        self.assertTrue(matched)
        # sorted() alphabetically
        self.assertEqual(payload, "LD_LIBRARY_PATH, LD_PRELOAD")

    def test_no_match_on_disjoint_sets(self):
        from fieldkit.ttps.adapter import _p_sudo_env_keep_any
        matched, _ = _p_sudo_env_keep_any(
            self._facts(sudo_env_keep={"PATH", "HOME"}),
            ["LD_PRELOAD", "LD_LIBRARY_PATH"])
        self.assertFalse(matched)

    def test_no_match_on_empty_env_keep(self):
        from fieldkit.ttps.adapter import _p_sudo_env_keep_any
        matched, _ = _p_sudo_env_keep_any(
            self._facts(sudo_env_keep=set()),
            ["LD_PRELOAD"])
        self.assertFalse(matched)


if __name__ == "__main__":
    unittest.main()
