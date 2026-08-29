#!/usr/bin/env python3
"""T1552 credential-access loot-hunt TTPs — C2 slice.

Five new-coverage TTPs land here, all Linux, all `always: true`
(they're grep/find-driven so the command IS the check):

  * shell-history-creds       — bash/zsh/fish history for
    curl -u / password= / api-key patterns
  * cloud-credentials         — aws/gcp/azure/kube/doctl SDK caches
  * git-credentials           — ~/.git-credentials + gh CLI hosts.yml
  * webapp-config-secrets     — .env / wp-config.php / database.yml
    under common webroots
  * private-key-loot          — id_rsa / *.pem / *.key files
    outside their intended ~/.ssh scope

All ranked `medium/read-only/quiet` (score 233) so they sit BELOW
deterministic escalation vectors (sudo:ALL is 333, cve:pwnkit is
323) but surface above nothing on hosts without a proven privesc
route — matching the operator instinct "no root path yet, so
sweep for credentials that lateral-move me to another box."

Genuinely new coverage — the CLI has no equivalent loot subcommand
today (`fieldkit roast` covers Kerberos-side, not on-host).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

LOOT_KEYS = {
    "loot:shell-history-creds",
    "loot:cloud-credentials",
    "loot:git-credentials",
    "loot:webapp-config-secrets",
    "loot:private-key-loot",
}


class LootTTPCoverageTest(unittest.TestCase):

    def _load_loot(self):
        from fieldkit.ttps.loader import load_all
        return [t for t in load_all() if t.key.startswith("loot:") and not t.key.startswith("loot:win-")]

    def test_five_loot_ttps_shipped(self):
        loot = self._load_loot()
        keys = {t.key for t in loot}
        self.assertEqual(keys, LOOT_KEYS)

    def test_all_report_under_exposed_secret(self):
        for t in self._load_loot():
            with self.subTest(key=t.key):
                self.assertEqual(t.report.vector_type, "exposed_secret")

    def test_all_are_medium_read_only_quiet(self):
        # The whole point of the medium ranking is that loot hunts
        # sit BELOW deterministic escalation vectors — verifying the
        # ranking is a pin against a well-meaning "bump this to high"
        # future edit that would crowd out real privesc.
        for t in self._load_loot():
            with self.subTest(key=t.key):
                self.assertEqual(t.ranking.exploitability, "medium")
                self.assertEqual(t.ranking.safety, "read-only")
                self.assertEqual(t.ranking.detection, "quiet")

    def test_all_target_linux_only(self):
        for t in self._load_loot():
            with self.subTest(key=t.key):
                self.assertEqual(t.platform, ("linux",))

    def test_all_use_always_predicate(self):
        # `always: true` matches the "the command IS the check" pattern
        # — the vector fires on every linux foothold and lets the
        # operator (or a later `escalate --allow read-only`) sweep for
        # loot without needing per-file HostFacts enum.
        for t in self._load_loot():
            with self.subTest(key=t.key):
                self.assertEqual(t.detect.kind, "always")


class LootRankingTest(unittest.TestCase):
    """The load-bearing behavior: loot never outranks a real privesc."""

    def _fire(self, **kw):
        from fieldkit.hostenum import HostFacts, LINUX
        from fieldkit.privesc import _reset_ttp_cache_for_tests, vectors_for
        _reset_ttp_cache_for_tests()
        base = dict(os=LINUX, user="alice", uid=1000)
        base.update(kw)
        return vectors_for(HostFacts(**base), "10.0.0.7")

    def test_all_five_fire_on_bare_linux_foothold(self):
        # Empty facts host — no privesc route enumerated, no loot
        # HostFacts field. All 5 loot TTPs still fire (`always: true`)
        # so the operator has SOMETHING actionable to run.
        vs = self._fire()
        loot_keys = {v.key for v in vs if v.key.startswith("loot:")}
        self.assertEqual(loot_keys, LOOT_KEYS)

    def test_sudo_all_ranks_above_all_loot(self):
        # A host with sudo -l (ALL:ALL) is root — the loot hunts are
        # still worth running but they're strictly less valuable than
        # the direct root path. sudo:ALL must sort first.
        vs = self._fire(sudo_all=True)
        self.assertEqual(vs[0].key, "sudo:ALL")

    def test_suid_gtfo_ranks_above_all_loot(self):
        # SUID find is deterministic root — outranks loot.
        vs = self._fire(suid={"find"})
        self.assertEqual(vs[0].key, "suid:find")

    def test_kernel_cve_ranks_above_all_loot(self):
        # Even a matched kernel CVE (crash-risk) beats the loot hunts
        # on exploitability points — high vs medium is a 100-point gap.
        vs = self._fire(kernel="5.15.0")
        # cve:dirtypipe is high/config-change/moderate = 322
        dirtypipe = [v for v in vs if v.key == "cve:dirtypipe"]
        self.assertTrue(dirtypipe)
        loot = [v for v in vs if v.key.startswith("loot:")]
        self.assertTrue(loot)
        # every loot ranks below every kernel-cve
        for lv in loot:
            for cve in dirtypipe:
                self.assertGreater(cve.score, lv.score)

    def test_loot_ranks_above_nothing_on_bare_host(self):
        # Bare host: loot is what's on offer. Score should be
        # 233 (medium/read-only/quiet).
        vs = self._fire()
        for v in vs:
            with self.subTest(key=v.key):
                self.assertEqual(v.score, 233)


class LootCommandShapeTest(unittest.TestCase):
    """The commands are grep/find-driven — verify each one actually
    contains the expected shape (not a copy-paste bug where a TTP
    body accidentally references the wrong paths)."""

    def _load_by_key(self, key):
        from fieldkit.ttps.loader import load_all
        return [t for t in load_all() if t.key == key][0]

    def test_shell_history_greps_password_pattern(self):
        t = self._load_by_key("loot:shell-history-creds")
        self.assertIn(".bash_history", t.execute.command)
        self.assertIn("password", t.execute.command.lower())

    def test_cloud_credentials_covers_aws_gcp_azure_kube(self):
        t = self._load_by_key("loot:cloud-credentials")
        for token in (".aws/credentials", "gcloud", ".azure/", ".kube/config"):
            with self.subTest(token=token):
                self.assertIn(token, t.execute.command)

    def test_git_credentials_covers_both_helper_and_gh(self):
        t = self._load_by_key("loot:git-credentials")
        self.assertIn(".git-credentials", t.execute.command)
        self.assertIn("gh/hosts.yml", t.execute.command)

    def test_webapp_config_covers_common_frameworks(self):
        t = self._load_by_key("loot:webapp-config-secrets")
        for token in ("wp-config.php", "database.yml", "settings.py",
                       ".env", "config.php"):
            with self.subTest(token=token):
                self.assertIn(token, t.execute.command)

    def test_private_key_loot_greps_pem_headers(self):
        t = self._load_by_key("loot:private-key-loot")
        # find over id_rsa/.pem AND filters to actual PEM/OpenSSH
        # headers — matches the "not every .pem is a private key"
        # reality (some are certs).
        self.assertIn("id_rsa", t.execute.command)
        self.assertIn("*.pem", t.execute.command)
        self.assertIn("BEGIN", t.execute.command)


if __name__ == "__main__":
    unittest.main()
