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


if __name__ == "__main__":
    unittest.main()
