#!/usr/bin/env python3
"""Persistence-discovery TTPs — C5 slice.

Six TTPs land here, three per platform, all always-fire (persistence
surfaces are enumeration-driven — the FIND is the finding; the plant
is the operator's next config-change step):

Linux:
  * persist:writable-cron          T1053.003 — cron dirs + per-user crontabs
  * persist:writable-systemd       T1543.002 — .service / .timer / .conf files
  * persist:writable-motd          T1546.003 — update-motd.d + profile.d + bashrc

Windows:
  * persist:win-run-keys           T1547.001 — HKCU + HKLM Run/RunOnce
  * persist:win-schtasks           T1053.005 — non-Microsoft scheduled tasks
  * persist:win-startup-folders    T1547.001 — per-user + all-users Startup

All ranked medium/read-only/quiet (score 233) so they sort below
deterministic escalation vectors and above nothing — matching the
loot-hunt pattern from C2/C3. Fills the biggest coverage gap
identified before the C-arc: fieldkit had zero persistence TTPs
before this slice.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

LINUX_PERSIST = {
    "persist:writable-cron",
    "persist:writable-systemd",
    "persist:writable-motd",
}
WIN_PERSIST = {
    "persist:win-run-keys",
    "persist:win-schtasks",
    "persist:win-startup-folders",
}


class PersistTTPCoverageTest(unittest.TestCase):

    def _load(self):
        from fieldkit.ttps.loader import load_all
        return [t for t in load_all() if t.key.startswith("persist:")]

    def test_six_persistence_ttps_shipped(self):
        keys = {t.key for t in self._load()}
        self.assertEqual(keys, LINUX_PERSIST | WIN_PERSIST)

    def test_all_use_always_predicate(self):
        # Persistence discovery is grep/find/reg-query — the command
        # IS the check. `always: true` matches that "the shell one-
        # liner is the enum" pattern.
        for t in self._load():
            with self.subTest(key=t.key):
                self.assertEqual(t.detect.kind, "always")

    def test_all_are_medium_read_only_quiet(self):
        # Load-bearing: persistence hunts must NOT outrank real
        # escalation (sudo:ALL, seimpersonate, cve:*). Pinning to
        # medium/read-only/quiet keeps loot-family + persist-family
        # both at score 233 — a coherent "operator-value tier"
        # below deterministic root paths.
        for t in self._load():
            with self.subTest(key=t.key):
                self.assertEqual(t.ranking.exploitability, "medium")
                self.assertEqual(t.ranking.safety, "read-only")
                self.assertEqual(t.ranking.detection, "quiet")

    def test_reuses_existing_reportkb_categories(self):
        # No new reportkb entries added by this slice — every
        # persist TTP maps to one of the 4 existing categories:
        # writable_cron / writable_systemd / writable_motd (Linux)
        # + writable_run_key / schtask_abuse (Windows).
        allowed_vector_types = {
            "writable_cron", "writable_systemd", "writable_motd",
            "writable_run_key", "schtask_abuse",
        }
        for t in self._load():
            with self.subTest(key=t.key):
                self.assertIn(t.report.vector_type, allowed_vector_types)


class PersistPlatformIsolationTest(unittest.TestCase):
    """Windows TTPs don't fire on Linux and vice-versa. Load-bearing
    for report cleanliness — a Linux foothold should never surface
    'writable Run keys' as a route."""

    def _fire(self, os_name, **kw):
        from fieldkit.hostenum import HostFacts
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        base = dict(os=os_name, user="alice", uid=1000)
        base.update(kw)
        return vectors_for(HostFacts(**base), "10.0.0.7")

    def test_linux_persist_ttps_fire_on_linux(self):
        vs = self._fire("linux")
        keys = {v.key for v in vs if v.key.startswith("persist:")}
        self.assertEqual(keys, LINUX_PERSIST)

    def test_windows_persist_ttps_fire_on_windows(self):
        vs = self._fire("windows")
        keys = {v.key for v in vs if v.key.startswith("persist:")}
        self.assertEqual(keys, WIN_PERSIST)

    def test_windows_persist_never_fires_on_linux(self):
        vs = self._fire("linux")
        win_keys = {v.key for v in vs if v.key.startswith("persist:win-")}
        self.assertEqual(win_keys, set())

    def test_linux_persist_never_fires_on_windows(self):
        vs = self._fire("windows")
        lin_keys = {v.key for v in vs
                    if v.key.startswith("persist:") and not v.key.startswith("persist:win-")}
        self.assertEqual(lin_keys, set())


class PersistRankingTest(unittest.TestCase):
    """Persistence hunts sit below deterministic escalation."""

    def _fire(self, os_name, **kw):
        from fieldkit.hostenum import HostFacts
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        base = dict(os=os_name, user="alice", uid=1000)
        base.update(kw)
        return vectors_for(HostFacts(**base), "10.0.0.7")

    def test_sudo_all_ranks_above_all_linux_persist(self):
        vs = self._fire("linux", sudo_all=True)
        # sudo:ALL is high/read-only/quiet = 333; persist is 233.
        self.assertEqual(vs[0].key, "sudo:ALL")
        persist = [v for v in vs if v.key.startswith("persist:")]
        for v in persist:
            self.assertEqual(v.score, 233)

    def test_seimpersonate_ranks_above_all_win_persist(self):
        vs = self._fire("windows", privs={"SeImpersonatePrivilege"})
        # seimpersonate:* is high/config-change/moderate = 322 > 233
        persist_scores = {v.score for v in vs
                          if v.key.startswith("persist:")}
        self.assertEqual(persist_scores, {233})
        # first entry is a seimpersonate route
        self.assertTrue(vs[0].key.startswith("seimpersonate:"))

    def test_all_six_fire_on_bare_host(self):
        # Empty-facts host still shows something actionable — every
        # persist TTP surfaces, giving the operator a starting point.
        linux_vs = self._fire("linux")
        self.assertEqual(len(
            [v for v in linux_vs if v.key.startswith("persist:")]),
            3)
        win_vs = self._fire("windows")
        self.assertEqual(len(
            [v for v in win_vs if v.key.startswith("persist:")]),
            3)


class PersistCommandShapeTest(unittest.TestCase):
    """Each command contains the specific enum surface it advertises —
    regression guard against a copy-paste swapping one path for
    another."""

    def _load_by_key(self, key):
        from fieldkit.ttps.loader import load_all
        return [t for t in load_all() if t.key == key][0]

    def test_cron_hunt_covers_system_dirs_and_user_crontabs(self):
        t = self._load_by_key("persist:writable-cron")
        for token in ("/etc/crontab", "/etc/cron.d", "/etc/cron.daily",
                       "/etc/cron.hourly", "/etc/cron.weekly",
                       "/etc/cron.monthly", "/var/spool/cron",
                       "-writable"):
            with self.subTest(token=token):
                self.assertIn(token, t.execute.command)

    def test_systemd_hunt_covers_service_timer_dropins(self):
        t = self._load_by_key("persist:writable-systemd")
        for token in ("/etc/systemd/system", ".service", ".timer",
                       ".conf", "-writable"):
            with self.subTest(token=token):
                self.assertIn(token, t.execute.command)

    def test_motd_hunt_covers_updatemotd_profile_bashrc(self):
        t = self._load_by_key("persist:writable-motd")
        for token in ("/etc/update-motd.d", "/etc/profile.d",
                       "/etc/bash.bashrc"):
            with self.subTest(token=token):
                self.assertIn(token, t.execute.command)

    def test_run_keys_hunt_covers_hkcu_hklm_wow64(self):
        t = self._load_by_key("persist:win-run-keys")
        # HKCU + HKLM + Wow6432Node, both Run + RunOnce
        for token in ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                       "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                       "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                       "Wow6432Node"):
            with self.subTest(token=token):
                self.assertIn(token, t.execute.command)

    def test_schtask_enum_uses_query_verbose_list(self):
        t = self._load_by_key("persist:win-schtasks")
        self.assertIn("schtasks /query", t.execute.command)
        self.assertIn("/fo LIST /v", t.execute.command)
        # Filters out Microsoft\Windows\* auto-tasks
        self.assertIn("\\\\Windows\\\\", t.execute.command)

    def test_startup_folder_hunt_covers_appdata_and_allusers(self):
        t = self._load_by_key("persist:win-startup-folders")
        for token in ("%APPDATA%", "%ALLUSERSPROFILE%",
                       "Start Menu\\Programs\\Startup"):
            with self.subTest(token=token):
                self.assertIn(token, t.execute.command)


if __name__ == "__main__":
    unittest.main()
