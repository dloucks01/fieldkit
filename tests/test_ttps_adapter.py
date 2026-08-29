#!/usr/bin/env python3
"""fieldkit.ttps.adapter — TTP → Vector, and its integration with
fieldkit.privesc.vectors_for.

Pinned:

  * platform filter fires first — a Linux TTP never matches Windows facts;
  * each supported predicate matches the right HostFacts attribute;
  * `sudo_allows` bows out on `facts.sudo_all` so `_d_sudo_all` produces
    the single `sudo:ALL` vector instead of N noisy per-binary duplicates;
  * TTP-generated Vector keys match the inlined-driver naming convention
    (`sudo:find`, `cap:python`) so dedup at `vectors_for` collapses cleanly;
  * TTP vectors WIN the dedup contest against inlined drivers, so as
    entries port to YAML the inlined driver stops firing for those.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _ctx(host="10.0.0.7"):
    from fieldkit.privesc import _Ctx
    return _Ctx(host=host, stage_win="C:\\Windows\\Temp", stage_lin="/tmp")


def _mk_ttp(kind, value, technique="T1548.003", platform=("linux",),
             safety="read-only", cmd="id", success="uid=0"):
    from fieldkit.ttps.schema import (
        Cleanup, Detect, Execute, Ranking, Report, TTP, Verify,
    )
    return TTP(
        technique=technique, name="Test TTP", tactic=("privilege-escalation",),
        platform=platform,
        ranking=Ranking(exploitability="high", safety=safety, detection="quiet"),
        detect=Detect(kind=kind, value=value),
        execute=Execute(command=cmd),
        verify=Verify(success=success),
        cleanup=Cleanup(),
        report=Report(vector_type="gtfobins_sudo"),
    )


def _facts(**kw):
    from fieldkit.hostenum import HostFacts, LINUX
    defaults = dict(os=LINUX, user="alice", uid=1000, groups=set(),
                    sudo_all=False, sudo_nopasswd=False,
                    sudo_binaries=set(), suid=set(), caps={})
    defaults.update(kw)
    return HostFacts(**defaults)


class PredicateTest(unittest.TestCase):
    def test_platform_mismatch_returns_none(self):
        from fieldkit.ttps.adapter import ttp_to_vector
        ttp = _mk_ttp("always", True, platform=("windows",))
        self.assertIsNone(ttp_to_vector(ttp, _facts(), _ctx()))

    def test_always_matches(self):
        from fieldkit.ttps.adapter import ttp_to_vector
        ttp = _mk_ttp("always", True)
        v = ttp_to_vector(ttp, _facts(), _ctx())
        self.assertIsNotNone(v)

    def test_sudo_allows_matches_on_binary_in_set(self):
        from fieldkit.ttps.adapter import ttp_to_vector
        ttp = _mk_ttp("sudo_allows", "find")
        v = ttp_to_vector(ttp, _facts(sudo_binaries={"find"}), _ctx())
        self.assertIsNotNone(v)
        self.assertEqual(v.key, "sudo:find")

    def test_sudo_allows_bows_out_on_sudo_all(self):
        # When `sudo -l` grants ALL, per-binary vectors are noise; we let
        # the inlined `_d_sudo_all` produce the single `sudo:ALL` vector.
        from fieldkit.ttps.adapter import ttp_to_vector
        ttp = _mk_ttp("sudo_allows", "find")
        self.assertIsNone(
            ttp_to_vector(ttp, _facts(sudo_all=True, sudo_binaries={"find"}), _ctx()))

    def test_sudo_allows_no_match_when_binary_absent(self):
        from fieldkit.ttps.adapter import ttp_to_vector
        ttp = _mk_ttp("sudo_allows", "find")
        self.assertIsNone(ttp_to_vector(ttp, _facts(sudo_binaries={"vim"}), _ctx()))

    def test_suid_matches_binary_in_set(self):
        from fieldkit.ttps.adapter import ttp_to_vector
        ttp = _mk_ttp("suid", "python")
        v = ttp_to_vector(ttp, _facts(suid={"python"}), _ctx())
        self.assertIsNotNone(v)
        self.assertEqual(v.key, "suid:python")

    def test_capability_matches_when_any_binary_has_cap(self):
        from fieldkit.ttps.adapter import ttp_to_vector
        ttp = _mk_ttp("capability", "cap_setuid")
        v = ttp_to_vector(ttp, _facts(caps={"python3": "cap_setuid"}), _ctx())
        self.assertIsNotNone(v)
        # Vector key names the actual binary that carries the cap.
        self.assertEqual(v.key, "cap:python3")

    def test_facts_match_dict_all_keys_must_equal(self):
        from fieldkit.ttps.adapter import ttp_to_vector
        ttp = _mk_ttp("facts_match", {"uid": 0})
        self.assertIsNone(ttp_to_vector(ttp, _facts(uid=1000), _ctx()))
        v = ttp_to_vector(ttp, _facts(uid=0), _ctx())
        self.assertIsNotNone(v)


class VectorFieldTest(unittest.TestCase):
    def test_generated_vector_preserves_ttp_fields(self):
        from fieldkit.ttps.adapter import ttp_to_vector
        ttp = _mk_ttp("sudo_allows", "find", cmd="sudo find . -exec id \\; -quit",
                       success="uid=0")
        v = ttp_to_vector(ttp, _facts(sudo_binaries={"find"}), _ctx())
        self.assertEqual(v.command, "sudo find . -exec id \\; -quit")
        self.assertEqual(v.exploitability, "high")
        self.assertEqual(v.safety, "read-only")
        self.assertEqual(v.detection, "quiet")
        self.assertEqual(v.shell, "sh")               # linux → sh
        self.assertEqual(v.report_type, "gtfobins_sudo")
        self.assertIn("via TTP T1548.003", v.evidence)


class DedupTest(unittest.TestCase):
    """When both a TTP and the inlined driver produce a vector for the same
    key, the TTP wins because `_d_ttp_yaml` runs before `_d_sudo_gtfo`."""

    def test_ttp_supersedes_inlined_gtfo_for_same_binary(self):
        # `find` is ported → TTP produces `sudo:find`. The inlined driver
        # would also produce `sudo:find` from GTFO. Dedup keeps only one,
        # and it's the TTP's (evidence names TTP T1548.003).
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=LINUX, user="alice", uid=1000, sudo_nopasswd=True,
                      sudo_binaries={"find"}),
            "10.0.0.7")
        matching = [v for v in vs if v.key == "sudo:find"]
        self.assertEqual(len(matching), 1, "duplicate sudo:find vectors")
        self.assertIn("via TTP T1548.003", matching[0].evidence,
                       "TTP should win dedup, not inlined driver")

    def test_suid_still_served_by_inlined_driver(self):
        # SUID mode is not yet ported to YAML — the inlined `_d_suid_gtfo`
        # still handles it. This asserts the transition: sudo is TTP-served,
        # SUID stays inlined until Phase B3.
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=LINUX, user="alice", uid=1000, suid={"find"}),
            "10.0.0.7")
        matching = [v for v in vs if v.key == "suid:find"]
        self.assertEqual(len(matching), 1)
        self.assertNotIn("via TTP", matching[0].evidence)


class TemplateSubstitutionTest(unittest.TestCase):
    """`{{binary}}` in the command is filled from the predicate's matched
    payload — so one YAML covers N binaries carrying the same capability."""

    def test_binary_template_substituted_from_capability_match(self):
        from fieldkit.ttps.adapter import ttp_to_vector
        ttp = _mk_ttp("capability", "cap_dac_read_search",
                       cmd="{{binary}} /etc/shadow 2>/dev/null | head")
        v = ttp_to_vector(ttp,
                           _facts(caps={"openssl": "cap_dac_read_search"}),
                           _ctx())
        self.assertIsNotNone(v)
        self.assertIn("openssl /etc/shadow", v.command)
        self.assertNotIn("{{binary}}", v.command)

    def test_binary_template_untouched_when_no_placeholder(self):
        # A YAML without {{binary}} passes through verbatim regardless of
        # what payload the predicate matched.
        from fieldkit.ttps.adapter import ttp_to_vector
        ttp = _mk_ttp("capability", "cap_dac_override",
                       cmd="echo 'fk::0:0:fk:/root:/bin/bash' >> /etc/passwd")
        v = ttp_to_vector(ttp, _facts(caps={"cp": "cap_dac_override"}), _ctx())
        self.assertEqual(v.command, "echo 'fk::0:0:fk:/root:/bin/bash' >> /etc/passwd")


class CapabilityPortTest(unittest.TestCase):
    """The two shipped cap TTPs (B3) supersede the inlined _cap_vector via
    dedup for the caps they cover; the interpreter+cap_setuid case (not
    ported) still falls through to the inlined driver."""

    def test_dac_read_search_wins_dedup_over_inlined_cap_vector(self):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=LINUX, user="alice", uid=1000,
                      caps={"openssl": "cap_dac_read_search"}),
            "10.0.0.7")
        cap_vecs = [v for v in vs if v.key == "cap:openssl"]
        self.assertEqual(len(cap_vecs), 1)
        self.assertTrue(cap_vecs[0].evidence.startswith("detected via TTP"))

    def test_dac_override_wins_dedup_over_inlined_cap_vector(self):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=LINUX, user="alice", uid=1000,
                      caps={"cp": "cap_dac_override"}),
            "10.0.0.7")
        cap_vecs = [v for v in vs if v.key == "cap:cp"]
        self.assertEqual(len(cap_vecs), 1)
        self.assertTrue(cap_vecs[0].evidence.startswith("detected via TTP"))

    def test_cap_setuid_on_interpreter_still_inlined(self):
        # Not ported to YAML yet (needs per-interpreter templating); the
        # inlined _cap_vector still handles it.
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=LINUX, user="alice", uid=1000,
                      caps={"python": "cap_setuid"}),
            "10.0.0.7")
        cap_vecs = [v for v in vs if v.key == "cap:python"]
        self.assertEqual(len(cap_vecs), 1)
        self.assertNotIn("via TTP", cap_vecs[0].evidence)


class WindowsPredicateTest(unittest.TestCase):
    """Windows-specific predicates + templating for the Phase B4 port."""

    def test_privilege_predicate_matches_priv_in_set(self):
        from fieldkit.ttps.adapter import ttp_to_vector
        ttp = _mk_ttp("privilege", "SeBackupPrivilege", platform=("windows",))
        v = ttp_to_vector(ttp,
                           _facts(os="windows", privs={"SeBackupPrivilege"}),
                           _ctx())
        self.assertIsNotNone(v)

    def test_privilege_predicate_no_match_when_priv_absent(self):
        from fieldkit.ttps.adapter import ttp_to_vector
        ttp = _mk_ttp("privilege", "SeBackupPrivilege", platform=("windows",))
        self.assertIsNone(
            ttp_to_vector(ttp, _facts(os="windows", privs=set()), _ctx()))

    def test_group_member_predicate_matches_group(self):
        from fieldkit.ttps.adapter import ttp_to_vector
        ttp = _mk_ttp("group_member", "Backup Operators", platform=("windows",))
        v = ttp_to_vector(ttp,
                           _facts(os="windows", win_groups={"Backup Operators"}),
                           _ctx())
        self.assertIsNotNone(v)

    def test_stage_template_substituted_from_ctx(self):
        # {{stage}} is filled from ctx.stage_win on windows.
        from fieldkit.ttps.adapter import ttp_to_vector
        ttp = _mk_ttp("privilege", "SeBackupPrivilege", platform=("windows",),
                       cmd="reg save HKLM\\SAM {{stage}}\\sam")
        v = ttp_to_vector(ttp,
                           _facts(os="windows", privs={"SeBackupPrivilege"}),
                           _ctx())
        self.assertIn("C:\\Windows\\Temp\\sam", v.command)
        self.assertNotIn("{{stage}}", v.command)

    def test_shell_field_from_yaml_overrides_platform_default(self):
        # A Windows TTP with `execute.shell: powershell` sets Vector.shell.
        from fieldkit.ttps.adapter import ttp_to_vector
        from fieldkit.ttps.schema import (
            Cleanup, Detect, Execute, Ranking, Report, TTP, Verify,
        )
        ttp = TTP(
            technique="T1003.001", name="test",
            tactic=("credential-access",), platform=("windows",),
            ranking=Ranking(exploitability="high", safety="config-change",
                             detection="loud"),
            detect=Detect(kind="privilege", value="SeDebugPrivilege"),
            execute=Execute(command="dump lsass", shell="powershell"),
            verify=Verify(success="ok"),
            cleanup=Cleanup(),
            report=Report(vector_type="lsass"),
        )
        v = ttp_to_vector(ttp,
                           _facts(os="windows", privs={"SeDebugPrivilege"}),
                           _ctx())
        self.assertEqual(v.shell, "powershell")

    def test_explicit_key_field_overrides_default_naming(self):
        # SeDebug pattern: dedup key differs from report vector_type.
        from fieldkit.ttps.adapter import ttp_to_vector
        from fieldkit.ttps.schema import (
            Cleanup, Detect, Execute, Ranking, Report, TTP, Verify,
        )
        ttp = TTP(
            technique="T1003.001", name="test",
            tactic=("credential-access",), platform=("windows",),
            ranking=Ranking(exploitability="high", safety="config-change",
                             detection="loud"),
            detect=Detect(kind="privilege", value="SeDebugPrivilege"),
            execute=Execute(command="dump"),
            verify=Verify(success="ok"),
            cleanup=Cleanup(),
            report=Report(vector_type="lsass"),
            key="sedebug",
        )
        v = ttp_to_vector(ttp,
                           _facts(os="windows", privs={"SeDebugPrivilege"}),
                           _ctx())
        self.assertEqual(v.key, "sedebug")
        self.assertEqual(v.report_type, "lsass")

    def test_sebackup_and_backup_operators_dedup_to_one_vector(self):
        # Different fact source (priv vs group) but same vector_type → same key
        # → dedup collapses them to one entry in Analyze.
        from fieldkit.hostenum import HostFacts, WINDOWS
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        vs = vectors_for(
            HostFacts(os=WINDOWS, privs={"SeBackupPrivilege"},
                      win_groups={"Backup Operators"}),
            "10.0.0.7", stage_win="C:\\Windows\\Temp")
        sebackup = [v for v in vs if v.key == "sebackup"]
        self.assertEqual(len(sebackup), 1,
                         f"sebackup priv + group should dedup to one, got {len(sebackup)}")


class ShippedTTPsTest(unittest.TestCase):
    """The shipped ~7 sudo TTPs each match their intended binary."""

    def test_all_ported_binaries_produce_a_vector(self):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        ported = {"find", "python", "perl", "awk", "tar", "docker", "bash"}
        vs = vectors_for(
            HostFacts(os=LINUX, user="alice", uid=1000, sudo_nopasswd=True,
                      sudo_binaries=ported),
            "10.0.0.7")
        got = {v.key for v in vs if v.evidence.startswith("detected via TTP")}
        expected = {f"sudo:{b}" for b in ported}
        self.assertEqual(got, expected)


if __name__ == "__main__":
    unittest.main()
