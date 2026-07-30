#!/usr/bin/env python3
"""The credential loop, end to end, against a fake nxc.

The whole spine is exercised without a packet: the runner is a stub that maps an
nxc argv to canned output. What is pinned:

  * a spray records validity and (Pwn3d!) admin, and enriches scope from banners;
  * an owned host is looted and its recovered secret is promoted to a credential;
  * the next round sprays *only* that new credential, pivots with it, and the loop
    stops when a round adds nothing new;
  * the domain password policy is read before the first spray;
  * a missing nxc binary aborts cleanly instead of crashing.

Run:  python3 -m unittest discover -s tests
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import spray as spray_mod  # noqa: E402
from fieldkit.config import load as load_config  # noqa: E402
from fieldkit.creds import Credential  # noqa: E402
from fieldkit.runner import RunResult  # noqa: E402
from fieldkit.spray import spray_loop  # noqa: E402
from fieldkit.state import Store  # noqa: E402

NT = "31d6cfe0d16ae931b73c59d7e0c089c0"

POLICY = """\
SMB   10.0.0.6   445   DC01   [+] Dumping password info for domain: CORP
SMB   10.0.0.6   445   DC01   Minimum password length: 7
SMB   10.0.0.6   445   DC01   Reset Account Lockout Counter: 30 minutes
SMB   10.0.0.6   445   DC01   Account Lockout Threshold: 5
"""

# username -> {ip: (valid, admin)}
SPRAY = {
    "jdoe": {"10.0.0.6": (True, False), "10.0.0.7": (True, True)},
    "svc_adm": {"10.0.0.6": (True, True), "10.0.0.7": (True, True)},
}

# host ip -> --sam/--lsa dump output
DUMPS = {
    "10.0.0.7": ("SMB   10.0.0.7   445   WS02   [+] Dumping LSA secrets\n"
                 "SMB   10.0.0.7   445   WS02   CORP\\svc_adm:Sup3rS3cret!\n"),
    # The DC dump yields only a cached blob — nothing new to promote (loop must converge).
    "10.0.0.6": ("SMB   10.0.0.6   445   DC01   [+] Dumping LSA secrets\n"
                 "SMB   10.0.0.6   445   DC01   CORP\\Administrator:$DCC2$10240#Administrator#deadbeef\n"),
}


def _banner(ip, host):
    return (f"SMB   {ip}   445   {host}   [*] Windows 10 Build 19041 x64 "
            f"(name:{host}) (domain:corp.local) (signing:False) (SMBv1:False)")


def fake_nxc(argv, env=None):
    if "--pass-pol" in argv:
        return RunResult(argv, exit_code=0, stdout=POLICY)
    if "--sam" in argv:
        return RunResult(argv, exit_code=0, stdout=DUMPS.get(argv[2], ""))
    # a spray: user after -u, targets are the IPs between the proto and -u. nxc echoes
    # back the exact domain it was handed (-d <dom>), which is what fieldkit reingests.
    user = argv[argv.index("-u") + 1]
    secret = argv[argv.index("-p") + 1] if "-p" in argv else argv[argv.index("-H") + 1]
    dom = argv[argv.index("-d") + 1] if "-d" in argv else ""
    principal = f"{dom}\\{user}" if dom else user
    targets = argv[2:argv.index("-u")]
    lines = []
    for ip in targets:
        valid, admin = SPRAY.get(user, {}).get(ip, (False, False))
        host = {"10.0.0.6": "DC01", "10.0.0.7": "WS02"}.get(ip, "HOST")
        lines.append(_banner(ip, host))
        if valid:
            pwn = " (Pwn3d!)" if admin else ""
            lines.append(f"SMB   {ip}   445   {host}   [+] {principal}:{secret}{pwn}")
        else:
            lines.append(f"SMB   {ip}   445   {host}   [-] {principal}:{secret} STATUS_LOGON_FAILURE")
    return RunResult(argv, exit_code=0, stdout="\n".join(lines))


class LoopTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME")
        self.store.add_host("10.0.0.6", hostname="DC01", is_dc=True)
        self.store.add_host("10.0.0.7", hostname="WS02")
        self.store.add_credential(
            Credential(username="jdoe", secret="Winter2025!", domain="corp.local"))
        self.cfg = load_config(self.store)

    def run_loop(self, **kw):
        return spray_loop(self.store, self.cfg, run=fake_nxc, **kw)


class CredentialLoopTest(LoopTestCase):
    def test_full_loop_pivots_and_converges(self):
        rep = self.run_loop()
        self.assertIsNone(rep.aborted)
        self.assertEqual(rep.rounds, 2)               # round 3 has nothing new to spray
        self.assertEqual(rep.creds_recovered, 1)      # svc_adm from WS02's LSA
        # jdoe owns WS02, svc_adm then owns the DC.
        self.assertEqual(self.store.counts()["admin_hosts"], 2)
        self.assertEqual(self.store.counts()["credentials"], 2)

    def test_recovered_cred_is_stored_from_the_right_source(self):
        self.run_loop()
        svc = [c for c in self.store.credentials() if c["username"] == "svc_adm"][0]
        self.assertEqual(svc["source"], "lsa")
        self.assertEqual(svc["secret"], "Sup3rS3cret!")

    def test_policy_is_read_first(self):
        rep = self.run_loop()
        self.assertIsNotNone(rep.policy)
        self.assertEqual(rep.policy.threshold, 5)
        self.assertEqual(rep.policy.safe_attempts, 4)

    def test_banner_enriches_scope_during_spray(self):
        self.run_loop()
        ws = self.store.host_by_ip("10.0.0.7")
        self.assertEqual(ws["os"], "windows")
        self.assertEqual(ws["hostname"], "WS02")

    def test_loot_disabled_stops_after_first_round(self):
        rep = self.run_loop(loot=False)
        self.assertEqual(rep.rounds, 1)
        self.assertEqual(rep.creds_recovered, 0)
        self.assertEqual(self.store.counts()["admin_hosts"], 1)  # only WS02, no pivot

    def test_dcc2_from_dc_is_not_promoted(self):
        self.run_loop()
        # The DC's LSA held only a $DCC2$ blob; it must not become a credential.
        self.assertFalse(any(c["secret"].startswith("$DCC2$")
                             for c in self.store.credentials()))
        self.assertTrue(any(l["kind"] == "lsa_secret" for l in self.store.loot()))

    def test_subnet_filter_limits_targets(self):
        # Both hosts are in 10.0.0.0/24; a foreign subnet yields no targets.
        rep = self.run_loop(subnet="10.9.9.0/24")
        self.assertEqual(rep.aborted, "no hosts in scope for 10.9.9.0/24")


class RunnerFailureTest(LoopTestCase):
    def test_missing_nxc_aborts_cleanly(self):
        def missing(argv, env=None):
            if "--pass-pol" in argv:
                return RunResult(argv, exit_code=0, stdout=POLICY)
            return RunResult(argv, error="nxc: not found — is it installed and on PATH?")
        rep = spray_loop(self.store, self.cfg, run=missing)
        self.assertIn("not found", rep.aborted)
        self.assertEqual(self.store.counts()["access"], 0)

    def test_missing_nxc_at_policy_read_aborts_before_the_round_header(self):
        # If nxc isn't on PATH at all, the policy call is the first thing to fail.
        # spray_loop MUST abort right there — not print a "round 1: spraying..."
        # header and then error out on the first credential (which produced the
        # same message N+1 times and looked like the loop was still running).
        events = []

        def totally_missing(argv, env=None):
            return RunResult(argv, error="nxc: not found — is it installed and on PATH?")
        rep = spray_loop(self.store, self.cfg, run=totally_missing,
                          on_event=events.append)
        self.assertIn("not found", rep.aborted)
        self.assertEqual(rep.creds_sprayed, 0)               # nothing was attempted
        # No round header emitted — the tester should see one clean error,
        # not a spraying-in-progress message before the failure.
        self.assertFalse(any("round" in e.lower() for e in events),
                          f"unexpected 'round' emit: {events}")


class WordlistSprayTest(LoopTestCase):
    """Wordlist × password spray via nxc -u FILE -p FILE."""

    def _write_wordlists(self, users=("jdoe", "admin"),
                          passwords=("Winter2025!", "Summer2024!")):
        u = os.path.join(self.tmp.name, "users.txt")
        p = os.path.join(self.tmp.name, "passwords.txt")
        open(u, "w").write("\n".join(users) + "\n")
        open(p, "w").write("\n".join(passwords) + "\n")
        return u, p

    def _fake_wordlist_nxc(self, hits=(("10.0.0.7", "admin", "Winter2025!", True),)):
        """Fake nxc: reads the wordlist files, emits Pwn3d! for the hits given."""
        def run(argv, env=None):
            if "--pass-pol" in argv:
                return RunResult(argv, exit_code=0, stdout=POLICY)
            lines = ["SMB   10.0.0.6   445   DC01   [*] Windows Server 2019",
                     "SMB   10.0.0.7   445   WS02   [*] Windows 10"]
            for ip, user, pw, admin in hits:
                pwn = " (Pwn3d!)" if admin else ""
                lines.append(f"SMB   {ip}   445   host   [+] {user}:{pw}{pwn}")
            return RunResult(argv, exit_code=0, stdout="\n".join(lines))
        return run

    def test_wordlist_finds_and_stores_only_valid_creds(self):
        u, p = self._write_wordlists()
        rep = spray_mod.wordlist_spray(
            self.store, self.cfg, userlist=u, passlist=p,
            run=self._fake_wordlist_nxc())
        self.assertIsNone(rep.aborted)
        self.assertEqual(rep.valid, 1)
        self.assertEqual(rep.admin, 1)
        # only the hit was stored; the whole wordlist did NOT pollute state
        # (initial cred + 1 recovered = 2)
        self.assertEqual(self.store.counts()["credentials"], 2)

    def test_missing_wordlist_files_are_reported(self):
        rep = spray_mod.wordlist_spray(
            self.store, self.cfg, userlist="/no/such.txt", passlist="/no/other.txt",
            run=self._fake_wordlist_nxc())
        self.assertIn("not found", rep.aborted)

    def test_lockout_policy_blocks_run_unless_operator_opts_in(self):
        # POLICY (fixture) has a lockout threshold that safe_attempts derives from;
        # write a passlist with more entries than safe_attempts to force the block.
        u = os.path.join(self.tmp.name, "u.txt")
        p = os.path.join(self.tmp.name, "p.txt")
        open(u, "w").write("jdoe\n")
        open(p, "w").write("\n".join(f"pw{i}" for i in range(50)) + "\n")

        rep = spray_mod.wordlist_spray(
            self.store, self.cfg, userlist=u, passlist=p,
            run=self._fake_wordlist_nxc())
        self.assertIn("lockout policy", rep.aborted)
        self.assertIn("safe attempts", rep.aborted)
        # opting in with allow_lockout_risk skips the guard
        rep2 = spray_mod.wordlist_spray(
            self.store, self.cfg, userlist=u, passlist=p,
            run=self._fake_wordlist_nxc(), allow_lockout_risk=True)
        self.assertIsNone(rep2.aborted)

    def test_nxc_invocation_includes_the_wordlist_flags(self):
        u, p = self._write_wordlists()
        seen = []

        def capture(argv, env=None):
            seen.append(argv)
            if "--pass-pol" in argv:
                return RunResult(argv, exit_code=0, stdout=POLICY)
            return RunResult(argv, exit_code=0, stdout="")
        spray_mod.wordlist_spray(self.store, self.cfg,
                                  userlist=u, passlist=p, run=capture)
        # find the wordlist call (not the policy call)
        cmd = [a for a in seen if "-u" in a and "--pass-pol" not in a][0]
        self.assertIn("-u", cmd)
        self.assertIn(u, cmd)
        self.assertIn("-p", cmd)
        self.assertIn(p, cmd)
        self.assertIn("--continue-on-success", cmd)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
