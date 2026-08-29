#!/usr/bin/env python3
"""B5b — T1611 container escape TTPs + the HostFacts.container_context
extension they gate on.

Pinned:

  * hostenum's `container` enum-check output → in_container / has_docker_sock /
    has_k8s_token flags via sentinel strings (deterministic, no false-positives);
  * bare-metal hosts (no container context) produce zero container-escape vectors;
  * a compromised container with docker.sock + k8s token produces exactly the
    three shipped escape vectors, no more, no less;
  * facts_match's AND semantics correctly gate the sys_admin TTP on both
    in_container=True AND has_docker_sock=True.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class ContainerParserTest(unittest.TestCase):
    """The `_p_container` parser in hostenum turns the enum-check's
    sentinel-tagged output into typed HostFacts fields."""

    def test_all_sentinels_present_sets_all_flags(self):
        from fieldkit.hostenum import HostFacts, LINUX, _p_container
        facts = HostFacts(os=LINUX)
        _p_container(facts,
                      "FK-DOCKERENV\nFK-DOCKER-SOCK\nFK-K8S-TOKEN\n")
        self.assertTrue(facts.in_container)
        self.assertTrue(facts.has_docker_sock)
        self.assertTrue(facts.has_k8s_token)

    def test_containerenv_alone_sets_in_container(self):
        from fieldkit.hostenum import HostFacts, LINUX, _p_container
        facts = HostFacts(os=LINUX)
        _p_container(facts, "FK-CONTAINERENV\n")
        self.assertTrue(facts.in_container)
        self.assertFalse(facts.has_docker_sock)

    def test_cgroup_containerized_sets_in_container(self):
        from fieldkit.hostenum import HostFacts, LINUX, _p_container
        facts = HostFacts(os=LINUX)
        _p_container(facts, "FK-CGROUP-CONTAINER\n")
        self.assertTrue(facts.in_container)

    def test_k8s_token_implies_in_container(self):
        # k8s tokens only exist inside pods — the parser sets in_container
        # even if no explicit container sentinel fired.
        from fieldkit.hostenum import HostFacts, LINUX, _p_container
        facts = HostFacts(os=LINUX)
        _p_container(facts, "FK-K8S-TOKEN\n")
        self.assertTrue(facts.in_container)
        self.assertTrue(facts.has_k8s_token)

    def test_empty_output_leaves_flags_false(self):
        # A bare-metal host with the check running produces empty output;
        # the parser must leave every flag False.
        from fieldkit.hostenum import HostFacts, LINUX, _p_container
        facts = HostFacts(os=LINUX)
        _p_container(facts, "")
        self.assertFalse(facts.in_container)
        self.assertFalse(facts.has_docker_sock)
        self.assertFalse(facts.has_k8s_token)

    def test_incidental_words_dont_false_positive(self):
        # A container-shaped word appearing in unrelated output shouldn't
        # trip the flags — the sentinels are the load-bearing signal.
        from fieldkit.hostenum import HostFacts, LINUX, _p_container
        facts = HostFacts(os=LINUX)
        _p_container(facts, "the docker daemon is installed\ncontainer image list:\n")
        self.assertFalse(facts.in_container)

    def test_cgroup_v1_sentinel_sets_flag(self):
        from fieldkit.hostenum import HostFacts, LINUX, _p_container
        facts = HostFacts(os=LINUX)
        _p_container(facts, "FK-DOCKERENV\nFK-CGROUP-V1\n")
        self.assertTrue(facts.cgroup_v1)

    def test_hostpid_sentinel_sets_flag(self):
        from fieldkit.hostenum import HostFacts, LINUX, _p_container
        facts = HostFacts(os=LINUX)
        _p_container(facts, "FK-DOCKERENV\nFK-HOSTPID\n")
        self.assertTrue(facts.hostpid_visible)

    def test_hostnetwork_sentinel_sets_flag(self):
        from fieldkit.hostenum import HostFacts, LINUX, _p_container
        facts = HostFacts(os=LINUX)
        _p_container(facts, "FK-DOCKERENV\nFK-HOSTNETWORK\n")
        self.assertTrue(facts.has_hostnetwork)


class ContainerEscapeVectorTest(unittest.TestCase):
    """End-to-end: `vectors_for` on a container-context HostFacts emits the
    shipped T1611 vectors; on bare metal it emits none."""

    def test_container_with_docker_sock_and_k8s_yields_three_escapes(self):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=LINUX, user="www-data", uid=33,
                      in_container=True, has_docker_sock=True,
                      has_k8s_token=True),
            "10.0.0.7")
        escapes = {v.key for v in vs
                   if v.report_type.startswith("container_escape")}
        self.assertEqual(escapes, {
            "container_escape:docker_sock",
            "container_escape:sys_admin",
            "container_escape:k8s_sa",
        })

    def test_bare_metal_with_docker_installed_yields_no_escapes(self):
        # A bare-metal host that happens to have /var/run/docker.sock (root
        # membership of docker group is a separate `_d_docker_group` TTP,
        # not a container escape) must NOT emit container-escape vectors.
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=LINUX, user="alice", uid=1000,
                      in_container=False, has_docker_sock=True),
            "10.0.0.7")
        escapes = [v for v in vs if v.report_type.startswith("container_escape")]
        self.assertEqual(escapes, [])

    def test_container_without_privileged_context_only_yields_k8s(self):
        # A pod with just an SA token but no docker.sock/sys_admin only
        # gets the K8s escape — proves each TTP's detect predicate is
        # independent, not a shared always-on set.
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=LINUX, in_container=True, has_k8s_token=True),
            "10.0.0.7")
        escapes = {v.key for v in vs
                   if v.report_type.startswith("container_escape")}
        self.assertEqual(escapes, {"container_escape:k8s_sa"})


class NsenterHostpidTest(unittest.TestCase):
    """T1611 nsenter escape gates on root + in_container + hostpid_visible."""

    def _facts(self, **overrides):
        from fieldkit.hostenum import HostFacts, LINUX
        base = dict(os=LINUX, user="root", uid=0,
                     in_container=True, hostpid_visible=True)
        base.update(overrides)
        return HostFacts(**base)

    def _has_nsenter(self, facts):
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(facts, "10.0.0.7")
        return any(v.key == "container_escape:nsenter_hostpid" for v in vs)

    def test_fires_when_root_in_container_with_hostpid(self):
        self.assertTrue(self._has_nsenter(self._facts()))

    def test_does_not_fire_for_non_root(self):
        self.assertFalse(self._has_nsenter(self._facts(user="www-data", uid=33)))

    def test_does_not_fire_without_hostpid_visible(self):
        self.assertFalse(self._has_nsenter(self._facts(hostpid_visible=False)))

    def test_does_not_fire_outside_container(self):
        self.assertFalse(self._has_nsenter(self._facts(in_container=False)))


class CgroupV1ReleaseAgentTest(unittest.TestCase):
    """T1611 release_agent escape gates on root + in_container + cgroup_v1."""

    def _has_v1(self, **overrides):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        base = dict(os=LINUX, user="root", uid=0,
                     in_container=True, cgroup_v1=True)
        base.update(overrides)
        _reset_ttp_cache_for_tests()
        vs = vectors_for(HostFacts(**base), "10.0.0.7")
        return any(v.key == "container_escape:cgroup_v1_release_agent" for v in vs)

    def test_fires_when_root_v1_container(self):
        self.assertTrue(self._has_v1())

    def test_does_not_fire_on_cgroup_v2(self):
        self.assertFalse(self._has_v1(cgroup_v1=False))


class HostpathRootSshTest(unittest.TestCase):
    def test_fires_when_root_in_container(self):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(HostFacts(os=LINUX, user="root", uid=0, in_container=True),
                          "10.0.0.7")
        keys = {v.key for v in vs}
        self.assertIn("container_escape:hostpath_root_ssh", keys)

    def test_does_not_fire_for_non_root_container(self):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(HostFacts(os=LINUX, user="www-data", uid=33,
                                     in_container=True), "10.0.0.7")
        keys = {v.key for v in vs}
        self.assertNotIn("container_escape:hostpath_root_ssh", keys)


class HostNetworkTest(unittest.TestCase):
    def test_fires_when_container_has_hostnetwork(self):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(HostFacts(os=LINUX, user="www-data", uid=33,
                                     in_container=True, has_hostnetwork=True),
                          "10.0.0.7")
        keys = {v.key for v in vs}
        self.assertIn("container_escape:hostnetwork", keys)

    def test_does_not_fire_without_hostnetwork(self):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(HostFacts(os=LINUX, user="www-data", uid=33,
                                     in_container=True, has_hostnetwork=False),
                          "10.0.0.7")
        keys = {v.key for v in vs}
        self.assertNotIn("container_escape:hostnetwork", keys)

    def test_fires_for_non_root_hostnetwork_pod(self):
        # hostNetwork by itself is a network surface; doesn't require root.
        # This distinguishes it from the hostpath / nsenter / release_agent
        # escapes which all gate on uid=0.
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(HostFacts(os=LINUX, user="nobody", uid=65534,
                                     in_container=True, has_hostnetwork=True),
                          "10.0.0.7")
        keys = {v.key for v in vs}
        self.assertIn("container_escape:hostnetwork", keys)


class HostpathShadowTest(unittest.TestCase):
    def test_fires_when_root_in_container(self):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(HostFacts(os=LINUX, user="root", uid=0, in_container=True),
                          "10.0.0.7")
        keys = {v.key for v in vs}
        self.assertIn("container_escape:hostpath_shadow", keys)

    def test_does_not_fire_on_bare_metal_root(self):
        # Bare-metal root has legitimate /etc/shadow access; that's the
        # host's normal state, not an escape.
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(HostFacts(os=LINUX, user="root", uid=0, in_container=False),
                          "10.0.0.7")
        keys = {v.key for v in vs}
        self.assertNotIn("container_escape:hostpath_shadow", keys)


if __name__ == "__main__":
    unittest.main()
