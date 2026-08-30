#!/usr/bin/env python3
"""Windows credential-loot TTPs — C3 slice, mirror of C2.

Five new-coverage Windows TTPs land here — the Windows analog of
the C2 Linux loot slice. All `always: true` (grep/query-driven,
same "the command IS the check" pattern), all ranked
medium/read-only/quiet so they sort below deterministic privesc
routes:

  * loot:win-registry-password-search    T1552.002 — `reg query /f password`
  * loot:win-browser-credentials         T1555.003 — Chrome/Edge/Firefox stores
  * loot:win-ssh-putty-keys              T1552.004 — %USERPROFILE%\\.ssh + PuTTY
  * loot:win-credential-manager          T1555.004 — cmdkey /list + vaultcmd
  * loot:win-unattend-sysprep            T1552.001 — unattend.xml / sysprep.xml

All Windows-only (platform filter keeps them off Linux hosts). All
report under existing `exposed_secret` KB — no new report_type.

Together with the C2 Linux slice this brings the loot-hunt family
to 10 TTPs (5 per platform) covering the biggest per-foothold
credential-access surfaces on each OS.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

WIN_LOOT_KEYS = {
    "loot:win-registry-password-search",
    "loot:win-browser-credentials",
    "loot:win-ssh-putty-keys",
    "loot:win-credential-manager",
    "loot:win-unattend-sysprep",
}


class WinLootTTPCoverageTest(unittest.TestCase):

    def _load_win_loot(self):
        from fieldkit.ttps.loader import load_all
        return [t for t in load_all() if t.key.startswith("loot:win-")]

    def test_five_win_loot_ttps_shipped(self):
        keys = {t.key for t in self._load_win_loot()}
        self.assertEqual(keys, WIN_LOOT_KEYS)

    def test_all_report_under_exposed_secret(self):
        for t in self._load_win_loot():
            with self.subTest(key=t.key):
                self.assertEqual(t.report.vector_type, "exposed_secret")

    def test_all_are_medium_read_only_quiet(self):
        # Same pin as the Linux slice — protects against a future
        # "bump to high" edit that would crowd out real privesc
        # (seimpersonate, wincve:*, priv:* etc.) in TOP MOVES.
        for t in self._load_win_loot():
            with self.subTest(key=t.key):
                self.assertEqual(t.ranking.exploitability, "medium")
                self.assertEqual(t.ranking.safety, "read-only")
                self.assertEqual(t.ranking.detection, "quiet")

    def test_all_target_windows_only(self):
        for t in self._load_win_loot():
            with self.subTest(key=t.key):
                self.assertEqual(t.platform, ("windows",))

    def test_all_use_always_predicate(self):
        for t in self._load_win_loot():
            with self.subTest(key=t.key):
                self.assertEqual(t.detect.kind, "always")


class WinLootPlatformIsolationTest(unittest.TestCase):
    """The Windows loot TTPs must never fire on a Linux host, and
    vice-versa. Platform gate is the load-bearing bit."""

    def _fire(self, os_name, **kw):
        from fieldkit.hostenum import HostFacts
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        base = dict(os=os_name, user="alice", uid=1000)
        base.update(kw)
        return vectors_for(HostFacts(**base), "10.0.0.7")

    def test_win_loot_does_not_fire_on_linux(self):
        vs = self._fire("linux")
        win_keys = {v.key for v in vs if v.key.startswith("loot:win-")}
        self.assertEqual(win_keys, set())

    def test_linux_loot_does_not_fire_on_windows(self):
        vs = self._fire("windows")
        lin_keys = {v.key for v in vs
                    if v.key.startswith("loot:") and not v.key.startswith("loot:win-")}
        self.assertEqual(lin_keys, set())

    def test_all_five_win_loot_fire_on_bare_windows(self):
        vs = self._fire("windows")
        win_keys = {v.key for v in vs if v.key.startswith("loot:win-")}
        self.assertEqual(win_keys, WIN_LOOT_KEYS)


class WinLootRankingTest(unittest.TestCase):
    """Loot must never outrank a real Windows privesc."""

    def _fire(self, **kw):
        from fieldkit.hostenum import HostFacts, WINDOWS
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        base = dict(os=WINDOWS, user="alice", uid=1000)
        base.update(kw)
        return vectors_for(HostFacts(**base), "10.0.0.7")

    def test_seimpersonate_ranks_above_all_win_loot(self):
        vs = self._fire(privs={"SeImpersonatePrivilege"})
        # SeImpersonate potatoes: high/config-change/moderate = 322
        # Loot: medium/read-only/quiet = 233
        top_key = vs[0].key
        self.assertTrue(top_key.startswith("seimpersonate:"))
        # Every loot vector ranks strictly below every real
        # (deterministic-escalation) vector. C5's persist:* family
        # sits at the same 233 as loot — an "operator value" tier,
        # both below deterministic escalation but visible on hosts
        # where nothing else applies — so exclude both from
        # `real_scores`.
        loot_scores = {v.score for v in vs if v.key.startswith("loot:")}
        real_scores = {v.score for v in vs
                       if not v.key.startswith("loot:")
                       and not v.key.startswith("persist:")}
        for ls in loot_scores:
            for rs in real_scores:
                self.assertGreater(rs, ls)

    def test_aie_ranks_above_all_win_loot(self):
        vs = self._fire(always_install_elevated=True)
        # aie: high/config-change/moderate = 322 vs loot 233
        self.assertEqual(vs[0].key, "aie")


class WinLootCommandShapeTest(unittest.TestCase):
    """Each Windows loot command contains the specific reg path /
    binary / dir the description promises — copy-paste regression
    guard."""

    def _load_by_key(self, key):
        from fieldkit.ttps.loader import load_all
        return [t for t in load_all() if t.key == key][0]

    def test_registry_search_covers_hklm_and_hkcu(self):
        t = self._load_by_key("loot:win-registry-password-search")
        self.assertIn("reg query HKLM", t.execute.command)
        self.assertIn("reg query HKCU", t.execute.command)
        self.assertIn('/f "password"', t.execute.command)

    def test_browser_credentials_covers_chromium_and_firefox(self):
        t = self._load_by_key("loot:win-browser-credentials")
        self.assertIn("Google\\Chrome", t.execute.command)
        self.assertIn("Microsoft\\Edge", t.execute.command)
        self.assertIn("Login Data", t.execute.command)
        self.assertIn("key4.db", t.execute.command)

    def test_ssh_putty_covers_id_files_registry_and_ppk(self):
        t = self._load_by_key("loot:win-ssh-putty-keys")
        self.assertIn(".ssh\\id_*", t.execute.command)
        self.assertIn("SimonTatham\\PuTTY\\Sessions", t.execute.command)
        self.assertIn("*.ppk", t.execute.command)

    def test_credential_manager_uses_cmdkey_and_vaultcmd(self):
        t = self._load_by_key("loot:win-credential-manager")
        self.assertIn("cmdkey /list", t.execute.command)
        self.assertIn("vaultcmd", t.execute.command)

    def test_unattend_covers_panther_sysprep_and_root(self):
        t = self._load_by_key("loot:win-unattend-sysprep")
        for path_token in ("Windows\\Panther", "Sysprep", "unattend"):
            with self.subTest(token=path_token):
                self.assertIn(path_token, t.execute.command)


if __name__ == "__main__":
    unittest.main()
