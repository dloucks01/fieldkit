#!/usr/bin/env python3
"""Privesc drivers — detect from facts, emit a runnable, ranked, self-cleaning vector.

Pinned:

  * each driver fires only on its precondition and fills the concrete binary/service
    into the command, which runs `id`/`whoami` as the elevated context (survives
    one-shot capture, proves the win without leaving a shell);
  * safety is honest — a shell escape is read-only, a /etc/passwd write is
    config-change and carries a cleanup;
  * find_vector/vectors_from_state round-trip through captured enum steps.

Run:  python3 -m unittest discover -s tests
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit.hostenum import HostFacts  # noqa: E402
from fieldkit.privesc import (  # noqa: E402
    Vector, find_vector, vectors_for, vectors_from_state,
)
from fieldkit.state import Store  # noqa: E402


class LinuxDriverTest(unittest.TestCase):
    def facts(self, **kw):
        base = dict(os="linux", uid=1000, user="svc")
        base.update(kw)
        return HostFacts(**base)

    def keys(self, facts):
        return {v.key for v in vectors_for(facts, "10.0.0.8")}

    def test_sudo_all(self):
        v = [x for x in vectors_for(self.facts(sudo_all=True), "10.0.0.8")
             if x.key == "sudo:ALL"][0]
        self.assertEqual(v.safety, "read-only")
        self.assertIn("sudo -n id", v.command)

    def test_sudo_gtfobins_fills_binary_and_proof(self):
        v = [x for x in vectors_for(self.facts(sudo_binaries={"find"}), "10.0.0.8")
             if x.key == "sudo:find"][0]
        self.assertIn("sudo find", v.command)
        self.assertIn("id", v.command)         # proof, not an interactive shell
        self.assertEqual(v.safety, "read-only")

    def test_suid_matches_versioned_binary(self):
        keys = self.keys(self.facts(suid={"python3.8", "passwd"}))
        self.assertIn("suid:python3.8", keys)   # python3.8 -> python table
        self.assertNotIn("suid:passwd", keys)   # passwd is not a GTFO primitive

    def test_cap_setuid_interpreter(self):
        v = [x for x in vectors_for(self.facts(caps={"python3.8": "cap_setuid"}), "10.0.0.8")
             if x.key == "cap:python3.8"][0]
        self.assertIn("os.setuid(0)", v.command)
        self.assertIn("python3.8 -c", v.command)  # the real capped binary, not generic python
        self.assertEqual(v.safety, "read-only")

    def test_cap_dac_override_is_config_change_with_cleanup(self):
        v = [x for x in vectors_for(self.facts(caps={"tar": "cap_dac_override"}), "10.0.0.8")
             if x.key == "cap:tar"][0]
        self.assertEqual(v.safety, "config-change")
        self.assertIsNotNone(v.cleanup)

    def test_docker_group(self):
        self.assertIn("group:docker", self.keys(self.facts(groups={"svc", "docker"})))

    def test_docker_group_skipped_when_root(self):
        self.assertNotIn("group:docker",
                         self.keys(self.facts(uid=0, groups={"root", "docker"})))

    def test_sudo_env_preload(self):
        self.assertIn("sudo:env-preload",
                      self.keys(self.facts(sudo_env_keep={"LD_PRELOAD"})))

    def test_ld_preload_builds_so_and_fires_concrete_command(self):
        # with an allowed sudo binary, the vector builds a root .so and preloads it.
        f = self.facts(sudo_env_keep={"LD_PRELOAD"}, sudo_binaries={"apache2ctl"})
        v = [x for x in vectors_for(f, "10.0.0.8", stage_lin="/dev/shm")
             if x.key == "sudo:env-preload"][0]
        self.assertEqual(v.builds, (("so", "/dev/shm/p.so", "id"),))
        self.assertIn("sudo LD_PRELOAD=/dev/shm/p.so apache2ctl", v.command)
        self.assertEqual(v.report_type, "ld_preload")

    def test_ld_preload_without_allowed_binary_stays_guidance(self):
        f = self.facts(sudo_env_keep={"LD_PRELOAD"})   # no sudo_binaries
        v = [x for x in vectors_for(f, "10.0.0.8") if x.key == "sudo:env-preload"][0]
        self.assertEqual(v.builds, ())                 # nothing to trigger -> no auto-build

    def test_sudo_all_suppresses_individual_sudo_gtfo(self):
        keys = self.keys(self.facts(sudo_all=True, sudo_binaries={"find"}))
        self.assertIn("sudo:ALL", keys)
        self.assertNotIn("sudo:find", keys)  # ALL already means root


class WindowsDriverTest(unittest.TestCase):
    def test_seimpersonate_potato(self):
        f = HostFacts(os="windows", privs={"SeImpersonatePrivilege"})
        v = [x for x in vectors_for(f, "10.0.0.7") if x.key == "seimpersonate:native"][0]
        self.assertIn("GodPotato", v.command)
        self.assertIn("whoami", v.command)
        self.assertEqual(v.safety, "config-change")
        self.assertEqual(v.family, "seimpersonate")
        self.assertEqual(v.delivery, "native-exe")

    def test_seimpersonate_is_a_delivery_ladder(self):
        # one objective, several delivery methods the loop can climb in posture order.
        f = HostFacts(os="windows", privs={"SeImpersonatePrivilege"})
        vs = [x for x in vectors_for(f, "10.0.0.7") if x.family == "seimpersonate"]
        self.assertEqual({v.delivery for v in vs},
                         {"native-exe", "inmem-fileless", "ps-amsi-revshell"})
        # all record under the one finding type, so proof dedupes regardless of delivery
        self.assertEqual({v.report_type for v in vs}, {"seimpersonate"})

    def test_assign_primary_token_maps_to_same_ladder(self):
        f = HostFacts(os="windows", privs={"SeAssignPrimaryTokenPrivilege"})
        vs = [x for x in vectors_for(f, "10.0.0.7") if x.family == "seimpersonate"]
        self.assertEqual(len(vs), 3)

    def test_stage_dir_is_substituted(self):
        f = HostFacts(os="windows", privs={"SeImpersonatePrivilege"})
        v = [x for x in vectors_for(f, "10.0.0.7", stage_win="C:\\stage")
             if x.key == "seimpersonate:native"][0]
        self.assertIn("C:\\stage\\GodPotato.exe", v.command)

    def test_native_alternate_declares_a_stageable_artifact(self):
        # the loop reads Vector.stages to auto-stage a missing tool (Phase 8).
        f = HostFacts(os="windows", privs={"SeImpersonatePrivilege"})
        v = [x for x in vectors_for(f, "10.0.0.7", stage_win="C:\\stage")
             if x.key == "seimpersonate:native"][0]
        self.assertEqual(v.stages, (("GodPotato", "C:\\stage\\GodPotato.exe"),))
        # the in-memory / script alternates are built, not staged
        inmem = [x for x in vectors_for(f, "10.0.0.7") if x.key == "seimpersonate:inmem"][0]
        self.assertEqual(inmem.stages, ())

    def test_backup_operators_group_route(self):
        f = HostFacts(os="windows", win_groups={"Backup Operators"})
        self.assertIn("sebackup", {v.key for v in vectors_for(f, "10.0.0.7")})

    def test_priv_and_group_dedupe_to_one_sebackup(self):
        f = HostFacts(os="windows", privs={"SeBackupPrivilege"},
                      win_groups={"Backup Operators"})
        keys = [v.key for v in vectors_for(f, "10.0.0.7")]
        self.assertEqual(keys.count("sebackup"), 1)

    def test_always_install_elevated(self):
        f = HostFacts(os="windows", always_install_elevated=True)
        v = [x for x in vectors_for(f, "10.0.0.7") if x.key == "aie"][0]
        self.assertIn("msiexec", v.command)

    def test_aie_declares_a_buildable_msi(self):
        # the loop reads Vector.builds to auto-build a missing artifact (Phase 9).
        f = HostFacts(os="windows", always_install_elevated=True)
        v = [x for x in vectors_for(f, "10.0.0.7", stage_win="C:\\stage")
             if x.key == "aie"][0]
        self.assertEqual(v.builds, (("msi", "C:\\stage\\evil.msi", None),))
        self.assertEqual(v.report_type, "alwaysinstallelevated")  # a real reportkb key

    def test_unquoted_service_builds_and_plants_a_payload(self):
        f = HostFacts(os="windows",
                      unquoted_services=[("AppMgmt", "C:\\Program Files\\My App\\svc.exe")])
        v = [x for x in vectors_for(f, "10.0.0.7", stage_win="C:\\stg")
             if x.key.startswith("unquoted:")][0]
        # builds a payload exe planted at the first space-truncated candidate
        self.assertEqual(v.builds[0][0], "exe")
        self.assertEqual(v.builds[0][1], "C:\\Program.exe")
        self.assertIn("whoami", v.builds[0][2])                 # writes its identity
        self.assertIn("sc start AppMgmt", v.command)            # restarts by name
        self.assertIn("type", v.command)                       # reads the proof back
        self.assertEqual(v.report_type, "unquoted_service")

    def test_unquoted_without_a_name_stays_guidance(self):
        f = HostFacts(os="windows", unquoted_services=[(None, "C:\\a b\\s.exe")])
        v = [x for x in vectors_for(f, "10.0.0.7") if x.key.startswith("unquoted:")][0]
        self.assertEqual(v.builds, ())                          # can't restart -> no auto-build

    def test_weak_service_perms_reconfigures_binpath_natively(self):
        f = HostFacts(os="windows",
                      reconfigurable_services={"AppMgmt": "C:\\Program Files\\App\\svc.exe -k net"})
        v = [x for x in vectors_for(f, "10.0.0.7", stage_win="C:\\stg")
             if x.key == "weakservice:AppMgmt"][0]
        self.assertIn('sc config AppMgmt binPath= "cmd /c whoami', v.command)
        self.assertIn("sc start AppMgmt", v.command)
        self.assertIn("type", v.command)                       # reads the SYSTEM proof back
        self.assertEqual(v.builds, ())                         # native — nothing to build/stage
        self.assertIn("binPath= C:\\Program Files\\App\\svc.exe -k net", v.cleanup)  # restored
        self.assertEqual(v.report_type, "weak_service_perms")

    def test_writable_service_binary_is_a_manual_build_route(self):
        f = HostFacts(os="windows",
                      writable_service_bins={"AppMgmt": "C:\\Apps\\svc.exe"})
        v = [x for x in vectors_for(f, "10.0.0.7", stage_win="C:\\stg")
             if x.key == "writablesvc:AppMgmt"][0]
        self.assertTrue(v.manual)                          # not auto-fired
        self.assertEqual(v.builds[0][0], "exe")            # fieldkit builds the payload
        self.assertIsNotNone(v.playbook)
        self.assertEqual(v.playbook.place, "C:\\Apps\\svc.exe")
        self.assertTrue(any("sc stop AppMgmt" in s for s in v.playbook.steps))
        self.assertEqual(v.report_type, "writable_service_binary")

    def test_dll_hijack_is_manual_and_yields_to_writable_binary(self):
        # a writable dir alone → a DLL-hijack manual route...
        f = HostFacts(os="windows", writable_service_dirs={"AppMgmt": "C:\\Apps"})
        v = [x for x in vectors_for(f, "10.0.0.7") if x.key == "dllhijack:AppMgmt"][0]
        self.assertTrue(v.manual)
        self.assertEqual(v.builds[0][0], "dll")
        self.assertTrue(any("Procmon" in s for s in v.playbook.steps))
        # ...but if the binary is ALSO writable, don't offer the weaker dll route
        f2 = HostFacts(os="windows", writable_service_dirs={"AppMgmt": "C:\\Apps"},
                       writable_service_bins={"AppMgmt": "C:\\Apps\\svc.exe"})
        self.assertNotIn("dllhijack:AppMgmt",
                         {x.key for x in vectors_for(f2, "10.0.0.7")})

    def test_unquoted_service(self):
        f = HostFacts(os="windows",
                      unquoted_services=[(None, "C:\\Program Files\\My App\\svc.exe")])
        v = [x for x in vectors_for(f, "10.0.0.7") if x.key.startswith("unquoted:")][0]
        self.assertIn("C:\\Program", v.command)

    def test_seloaddriver_is_crash_risk(self):
        f = HostFacts(os="windows", privs={"SeLoadDriverPrivilege"})
        v = [x for x in vectors_for(f, "10.0.0.7") if x.key == "seloaddriver"][0]
        self.assertEqual(v.safety, "crash-risk")


class RankingTest(unittest.TestCase):
    def test_read_only_root_outranks_config_change(self):
        f = HostFacts(os="linux", uid=1000, sudo_all=True,
                      caps={"tar": "cap_dac_override"})
        vs = vectors_for(f, "10.0.0.8")
        self.assertEqual(vs[0].key, "sudo:ALL")  # high/read-only/quiet tops


class StateRoundTripTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME")
        self.hid, _ = self.store.add_host("10.0.0.8", os_name="linux")
        self.store.add_step(cmd="id", output="uid=1000(svc) gid=1000(svc) groups=1000(svc)",
                            host_id=self.hid, label="enum:id")
        self.store.add_step(cmd="find ...", output="/usr/bin/find\n",
                            host_id=self.hid, label="enum:suid")

    def test_vectors_from_state_reads_enum_steps(self):
        keys = {v.key for v in vectors_from_state(self.store)}
        self.assertIn("suid:find", keys)

    def test_find_vector_by_key(self):
        v = find_vector(self.store, "10.0.0.8", "suid:find")
        self.assertIsInstance(v, Vector)
        self.assertEqual(v.host, "10.0.0.8")

    def test_find_vector_missing(self):
        self.assertIsNone(find_vector(self.store, "10.0.0.8", "sudo:nope"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
