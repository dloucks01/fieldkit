#!/usr/bin/env python3
"""Windows privesc port arc — closed at B5i.

Phase B5i retires the LAST four inlined Windows drivers:

  * `_d_win_unquoted`         → T1574.010-unquoted-service-path{,-unnamed}.yaml
  * `_d_win_weak_service`     → T1574.011-weak-service-perms.yaml
  * `_d_win_writable_service` → T1574.011-writable-service-binary.yaml
  * `_d_win_dll_hijack`       → T1574.001-service-dll-hijack.yaml

All four drivers iterate a fact list/dict (`facts.unquoted_services`,
`facts.reconfigurable_services`, etc.) and emit ONE Vector per entry —
a shape the classic one-fire-per-host predicate model can't express.
This slice adds per-item iteration to the adapter so a single YAML
covers N services.

New adapter surface:

  * `ttp_to_vectors(ttp, facts, ctx) -> [Vector]` — plural counterpart
    to `ttp_to_vector`. Predicates that return a LIST of payloads
    trigger per-item emission; classic single-payload predicates still
    return one Vector (or none). `_d_ttp_yaml` calls the plural form.

  * `ttp_to_vector` becomes a legacy convenience wrapper returning the
    first Vector or None — every test in test_ttps_adapter.py keeps
    working unchanged.

  * `_substitute` extended to fill any `{{key}}` from a dict payload
    (not just `{{binary}}`). Per-item TTPs use `{{name}}` / `{{path}}` /
    `{{exe}}` / `{{binpath}}` / `{{candidate}}` / `{{proof}}` / `{{slug}}`
    / `{{dir}}` in commands, cleanups, playbooks.

  * `_render_evidence` and `_key_for` picked up the same generalization
    so `key: 'unquoted:{{path}}'` and
    `evidence: "unquoted service path: {{path}}"` render per-payload.

  * Four new iterable predicates:
      - `unquoted_services` (optional `has_name` filter — powers the
        named/unnamed split);
      - `reconfigurable_services`;
      - `writable_service_bins`;
      - `writable_service_dirs` (DEDUPS against writable-bin services —
        matches the inlined driver's `if name in
        facts.writable_service_bins: continue` gate).

With this slice landing, both `DRIVERS[LINUX]` and `DRIVERS[WINDOWS]`
reduce to ``(_d_ttp_yaml,)`` — every privesc vector fieldkit emits
flows through the YAML + adapter path. B-phase port arc closes.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class ArcCloseTest(unittest.TestCase):

    def test_drivers_windows_is_ttp_only(self):
        from fieldkit.privesc import DRIVERS, WINDOWS, _d_ttp_yaml
        self.assertEqual(DRIVERS[WINDOWS], (_d_ttp_yaml,))

    def test_drivers_linux_stays_ttp_only(self):
        # Verify B5g's Linux close didn't regress under the B5i changes.
        from fieldkit.privesc import DRIVERS, LINUX, _d_ttp_yaml
        self.assertEqual(DRIVERS[LINUX], (_d_ttp_yaml,))

    def test_every_retired_driver_is_absent_from_drivers(self):
        # Sanity: none of the retired drivers are wired in on either
        # platform. Catches an accidental re-add during a merge.
        from fieldkit import privesc
        retired = [
            privesc._d_sudo_gtfo, privesc._d_kernel_lpe,
            privesc._d_suid_gtfo, privesc._d_caps,
            privesc._d_sudo_all, privesc._d_docker_group,
            privesc._d_sudo_env,
            privesc._d_win_privs, privesc._d_win_lpe,
            privesc._d_win_aie,
            privesc._d_win_unquoted, privesc._d_win_weak_service,
            privesc._d_win_writable_service, privesc._d_win_dll_hijack,
        ]
        wired = set(privesc.DRIVERS[privesc.LINUX]
                    + privesc.DRIVERS[privesc.WINDOWS])
        for d in retired:
            with self.subTest(driver=d.__name__):
                self.assertNotIn(d, wired)


class UnquotedServiceTTPTest(unittest.TestCase):

    def _fire(self, unquoted_services, **kw):
        from fieldkit.hostenum import HostFacts, WINDOWS
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        base = dict(os=WINDOWS, user="alice", uid=1000,
                    unquoted_services=unquoted_services)
        base.update(kw)
        return [v for v in vectors_for(HostFacts(**base), "10.0.0.7",
                                        stage_win="C:\\stg")
                if v.key.startswith("unquoted:")]

    def test_named_service_auto_fires_with_builds(self):
        vs = self._fire([("AppMgmt", "C:\\Program Files\\My App\\svc.exe")])
        self.assertEqual(len(vs), 1)
        v = vs[0]
        self.assertEqual(v.builds[0][0], "exe")
        self.assertEqual(v.builds[0][1], "C:\\Program.exe")
        self.assertIn("whoami", v.builds[0][2])
        self.assertIn("sc start AppMgmt", v.command)
        self.assertIn("type", v.command)
        self.assertEqual(v.report_type, "unquoted_service")

    def test_unnamed_service_stays_guidance_no_builds(self):
        vs = self._fire([(None, "C:\\a b\\s.exe")])
        self.assertEqual(len(vs), 1)
        v = vs[0]
        self.assertEqual(v.builds, ())      # nothing to auto-build
        self.assertIn("plant a payload", v.command.lower())

    def test_per_item_emission_yields_one_vector_per_service(self):
        vs = self._fire([
            ("SvcA", "C:\\Program Files\\A\\a.exe"),
            ("SvcB", "D:\\Long Path\\B\\b.exe"),
        ])
        keys = {v.key for v in vs}
        self.assertEqual(len(keys), 2)      # distinct-per-path keys
        # Each vector references its own service by name in the command.
        by_key = {v.key: v for v in vs}
        self.assertIn("sc start SvcA", by_key["unquoted:C:\\Program Files\\A\\a.exe"].command)
        self.assertIn("sc start SvcB", by_key["unquoted:D:\\Long Path\\B\\b.exe"].command)

    def test_mixed_named_and_unnamed_emit_from_two_ttps(self):
        # A host with both a named AND an unnamed unquoted service
        # produces two vectors — one via each YAML variant.
        vs = self._fire([
            ("SvcA", "C:\\Program Files\\A\\a.exe"),
            (None,   "D:\\b c\\d.exe"),
        ])
        self.assertEqual(len(vs), 2)


class WeakServiceTTPTest(unittest.TestCase):

    def _fire(self, reconfigurable_services, **kw):
        from fieldkit.hostenum import HostFacts, WINDOWS
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        base = dict(os=WINDOWS, user="alice", uid=1000,
                    reconfigurable_services=reconfigurable_services)
        base.update(kw)
        return [v for v in vectors_for(HostFacts(**base), "10.0.0.7",
                                        stage_win="C:\\stg")
                if v.key.startswith("weakservice:")]

    def test_reconfigures_binpath_natively(self):
        vs = self._fire({"AppMgmt": "C:\\Program Files\\App\\svc.exe -k net"})
        self.assertEqual(len(vs), 1)
        v = vs[0]
        self.assertIn('sc config AppMgmt binPath= "cmd /c whoami', v.command)
        self.assertIn("sc start AppMgmt", v.command)
        self.assertIn("type", v.command)
        self.assertEqual(v.builds, ())      # native — no payload
        self.assertIn("binPath= C:\\Program Files\\App\\svc.exe -k net",
                       v.cleanup)
        self.assertEqual(v.report_type, "weak_service_perms")

    def test_per_service_emission(self):
        vs = self._fire({"A": "C:\\a.exe", "B": "C:\\b.exe", "C": "C:\\c.exe"})
        self.assertEqual({v.key for v in vs},
                         {"weakservice:A", "weakservice:B", "weakservice:C"})

    def test_no_reconfigurable_services_no_vector(self):
        vs = self._fire({})
        self.assertEqual(vs, [])


class WritableServiceBinTTPTest(unittest.TestCase):

    def _fire(self, writable_service_bins, **kw):
        from fieldkit.hostenum import HostFacts, WINDOWS
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        base = dict(os=WINDOWS, user="alice", uid=1000,
                    writable_service_bins=writable_service_bins)
        base.update(kw)
        return [v for v in vectors_for(HostFacts(**base), "10.0.0.7",
                                        stage_win="C:\\stg")
                if v.key.startswith("writablesvc:")]

    def test_is_prepare_only_with_playbook_and_builds(self):
        vs = self._fire({"AppMgmt": "C:\\Apps\\svc.exe"})
        self.assertEqual(len(vs), 1)
        v = vs[0]
        self.assertTrue(v.manual)                       # playbook-driven
        self.assertEqual(v.builds[0][0], "exe")
        self.assertIsNotNone(v.playbook)
        self.assertEqual(v.playbook.place, "C:\\Apps\\svc.exe")
        self.assertTrue(any("sc stop AppMgmt" in s for s in v.playbook.steps))
        self.assertEqual(v.report_type, "writable_service_binary")


class DLLHijackTTPTest(unittest.TestCase):

    def _fire(self, **kw):
        from fieldkit.hostenum import HostFacts, WINDOWS
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        base = dict(os=WINDOWS, user="alice", uid=1000)
        base.update(kw)
        return [v for v in vectors_for(HostFacts(**base), "10.0.0.7",
                                        stage_win="C:\\stg")
                if v.key.startswith("dllhijack:")]

    def test_fires_per_writable_dir_service(self):
        vs = self._fire(writable_service_dirs={"AppMgmt": "C:\\Apps"})
        self.assertEqual(len(vs), 1)
        v = vs[0]
        self.assertTrue(v.manual)
        self.assertIsNotNone(v.playbook)
        self.assertEqual(v.playbook.place, "C:\\Apps")
        self.assertEqual(v.builds[0][0], "dll")

    def test_dedups_against_writable_bin_service(self):
        # A service with BOTH a writable binary AND a writable load dir
        # produces exactly ONE vector — the writable-bin route
        # (simpler + more reliable). Mirrors the inlined driver's dedup.
        vs = self._fire(
            writable_service_bins={"AppMgmt": "C:\\Apps\\svc.exe"},
            writable_service_dirs={"AppMgmt": "C:\\Apps"})
        self.assertEqual(vs, [])            # dllhijack suppressed for AppMgmt

    def test_mixed_services_only_suppresses_the_overlap(self):
        # AppMgmt has both → dllhijack suppressed;
        # BarSvc only has a writable dir → dllhijack fires for it.
        vs = self._fire(
            writable_service_bins={"AppMgmt": "C:\\Apps\\svc.exe"},
            writable_service_dirs={"AppMgmt": "C:\\Apps",
                                    "BarSvc": "C:\\Bar"})
        self.assertEqual({v.key for v in vs}, {"dllhijack:BarSvc"})


class AdapterIterationTest(unittest.TestCase):
    """Direct tests on the adapter's per-item iteration surface."""

    def test_ttp_to_vectors_returns_list(self):
        # Even for a classic single-payload predicate, ttp_to_vectors
        # returns a list — a 1-element list when it fires.
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _Ctx
        from fieldkit.ttps.adapter import ttp_to_vectors
        from fieldkit.ttps.loader import load_all
        ttps = load_all()
        find_ttp = [t for t in ttps
                    if t.detect.kind == "suid" and t.detect.value == "find"][0]
        vs = ttp_to_vectors(find_ttp,
                             HostFacts(os=LINUX, user="alice", uid=1000,
                                        suid={"find"}),
                             _Ctx(host="10.0.0.7"))
        self.assertEqual(len(vs), 1)

    def test_ttp_to_vectors_returns_empty_on_no_match(self):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _Ctx
        from fieldkit.ttps.adapter import ttp_to_vectors
        from fieldkit.ttps.loader import load_all
        ttps = load_all()
        find_ttp = [t for t in ttps
                    if t.detect.kind == "suid" and t.detect.value == "find"][0]
        vs = ttp_to_vectors(find_ttp,
                             HostFacts(os=LINUX, user="alice", uid=1000,
                                        suid=set()),
                             _Ctx(host="10.0.0.7"))
        self.assertEqual(vs, [])

    def test_ttp_to_vector_legacy_wrapper_still_works(self):
        # Every existing test in test_ttps_adapter.py calls
        # ttp_to_vector (singular). The wrapper must still return
        # the first Vector (or None), so old tests don't regress.
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _Ctx
        from fieldkit.ttps.adapter import ttp_to_vector
        from fieldkit.ttps.loader import load_all
        ttps = load_all()
        find_ttp = [t for t in ttps
                    if t.detect.kind == "suid" and t.detect.value == "find"][0]
        v = ttp_to_vector(find_ttp,
                          HostFacts(os=LINUX, user="alice", uid=1000,
                                     suid={"find"}),
                          _Ctx(host="10.0.0.7"))
        self.assertIsNotNone(v)
        self.assertEqual(v.key, "suid:find")


class IterablePredicateTest(unittest.TestCase):
    """Direct tests on the four new iterable predicates."""

    def _facts(self, **kw):
        from fieldkit.hostenum import HostFacts, WINDOWS
        base = dict(os=WINDOWS, user="alice", uid=1000)
        base.update(kw)
        return HostFacts(**base)

    def test_unquoted_services_filter_named_only(self):
        from fieldkit.ttps.adapter import _p_unquoted_services
        facts = self._facts(unquoted_services=[
            ("SvcA", "C:\\a b\\a.exe"),
            (None,   "D:\\c d\\d.exe"),
        ])
        matched, payloads = _p_unquoted_services(facts, {"has_name": True})
        self.assertTrue(matched)
        self.assertEqual(len(payloads), 1)
        self.assertEqual(payloads[0]["name"], "SvcA")

    def test_unquoted_services_filter_unnamed_only(self):
        from fieldkit.ttps.adapter import _p_unquoted_services
        facts = self._facts(unquoted_services=[
            ("SvcA", "C:\\a b\\a.exe"),
            (None,   "D:\\c d\\d.exe"),
        ])
        matched, payloads = _p_unquoted_services(facts, {"has_name": False})
        self.assertTrue(matched)
        self.assertEqual(len(payloads), 1)
        self.assertEqual(payloads[0]["path"], "D:\\c d\\d.exe")

    def test_reconfigurable_services_sorted(self):
        # Deterministic output — matches the inlined driver's
        # `sorted(facts.reconfigurable_services.items())`.
        from fieldkit.ttps.adapter import _p_reconfigurable_services
        facts = self._facts(reconfigurable_services={
            "Zeta": "C:\\z.exe", "Alpha": "C:\\a.exe"})
        _, payloads = _p_reconfigurable_services(facts, True)
        self.assertEqual([p["name"] for p in payloads], ["Alpha", "Zeta"])

    def test_writable_service_dirs_dedup_matches_inlined_driver(self):
        from fieldkit.ttps.adapter import _p_writable_service_dirs
        facts = self._facts(
            writable_service_bins={"Overlap": "C:\\o.exe"},
            writable_service_dirs={"Overlap": "C:\\o",
                                    "Only": "C:\\only"})
        _, payloads = _p_writable_service_dirs(facts, True)
        names = [p["name"] for p in payloads]
        self.assertEqual(names, ["Only"])   # Overlap deduped out


if __name__ == "__main__":
    unittest.main()
