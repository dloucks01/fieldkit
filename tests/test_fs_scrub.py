#!/usr/bin/env python3
"""On-box filesystem scrub — same scrubbers as sharespider, driven over exec.

Pinned:

  * ``parse_stream`` is pure — canned output → (path, body) chunks;
  * ``scrub_stream`` runs every scrubber over every chunk (reuse, not fork);
  * ``fs_scrub`` refuses on a Windows host (recommends `spider` instead);
  * blocked exec (no proven access) aborts cleanly, not raises;
  * every hit becomes a step + loot; a credential hit is promoted (source =
    ``fs-scrub:<kind>``, so the audit trail is honest);
  * the runner is injected — no child process spawns.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import fs_scrub  # noqa: E402
from fieldkit.creds import Credential  # noqa: E402
from fieldkit.runner import RunResult  # noqa: E402
from fieldkit.state import Store  # noqa: E402


def stream(chunks):
    """Build a FK-FS delimited stream from ``[(path, body), ...]``."""
    return "\n".join(f"==FK-FS=={p}==\n{b}\n==FK-FS/END==" for p, b in chunks) + "\n"


class ParseTest(unittest.TestCase):
    def test_delimited_chunks_are_split(self):
        raw = stream([("/etc/app/x.yaml", "k: v"),
                      ("/home/svc/.env", "DB_PASSWORD='X'")])
        got = list(fs_scrub.parse_stream(raw))
        self.assertEqual([p for p, _ in got],
                         ["/etc/app/x.yaml", "/home/svc/.env"])
        self.assertEqual(got[1][1], "DB_PASSWORD='X'")

    def test_broken_chunk_at_the_tail_is_skipped_not_raised(self):
        # a target that disconnected mid-write leaves the last chunk without a tail;
        # the operator wants what did come through
        raw = ("==FK-FS==/ok==\nk: v\n==FK-FS/END==\n"
               "==FK-FS==/truncated==\npartial…")
        got = list(fs_scrub.parse_stream(raw))
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0][0], "/ok")


class ScrubStreamTest(unittest.TestCase):
    def test_recognizes_kv_and_promotes_credential(self):
        raw = stream([("/etc/app/config.yaml",
                       "username: 'appadmin'\npassword: 'Winter2025!'")])
        hits = list(fs_scrub.scrub_stream(raw))
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].kind, "kv-secret")
        self.assertEqual(
            (hits[0].credential.username, hits[0].credential.secret),
            ("appadmin", "Winter2025!"))

    def test_filename_only_hits_do_not_need_body(self):
        raw = stream([("/home/svc/.git-credentials", "")])
        kinds = [h.kind for h in fs_scrub.scrub_stream(raw)]
        self.assertIn("vcs-creds", kinds)

    def test_ssh_key_by_filename(self):
        raw = stream([("/root/.ssh/id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----")])
        kinds = [h.kind for h in fs_scrub.scrub_stream(raw)]
        self.assertIn("ssh-key", kinds)


class DriverTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME")
        self.hid, _ = self.store.add_host("10.0.0.9", hostname="app01", os_name="linux")
        self.cid, _ = self.store.add_credential(
            Credential("svc", "s3cret", domain="corp"))
        self.store.add_access(self.hid, self.cid, "ssh", admin=False)
        self.host = self.store.host_by_ip("10.0.0.9")

    def _fake_ssh(self, stream_output):
        """A fake nxc/ssh runner that returns canned FK-FS stream when the
        fs-scrub command runs; a policy/no-op for anything else."""
        def run(argv, env=None):
            # the find|cat pipeline lands in -x for nxc / equivalent — its
            # presence in argv is unique enough for the fake to route.
            if any("FK-FS" in a for a in argv):
                return RunResult(argv, exit_code=0, stdout=stream_output)
            return RunResult(argv, exit_code=0, stdout="")
        return run

    def test_end_to_end_scrub_and_promote(self):
        raw = stream([
            ("/etc/app/config.yaml", "username: 'appadmin'\npassword: 'Winter2025!'"),
            ("/root/.ssh/id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----"),
            ("/home/svc/.git-credentials", "https://svc:GitPass@github/"),
        ])
        rep = fs_scrub.fs_scrub(self.store, self.host,
                                self.store.credential_by_id(self.cid),
                                run=self._fake_ssh(raw))
        self.assertIsNone(rep.aborted)
        self.assertGreaterEqual(rep.files_scrubbed, 3)
        self.assertIn("kv-secret", {h.kind for h in rep.hits})
        self.assertIn("ssh-key", {h.kind for h in rep.hits})
        # kv-secret hit promoted a real credential
        self.assertEqual(rep.creds_promoted, 1)
        promoted = [c for c in self.store.credentials()
                    if c["username"] == "appadmin"]
        self.assertEqual(len(promoted), 1)
        self.assertTrue(promoted[0]["source"].startswith("fs-scrub:"))

    def test_command_shape_uses_the_default_paths_and_delimiters(self):
        seen = []

        def capture(argv, env=None):
            seen.append(argv)
            return RunResult(argv, exit_code=0, stdout="")
        fs_scrub.fs_scrub(self.store, self.host,
                          self.store.credential_by_id(self.cid), run=capture)
        # find the actual command that was run
        cmd_str = " ".join(a for argv in seen for a in argv)
        self.assertIn("/etc", cmd_str)
        self.assertIn("/opt", cmd_str)
        self.assertIn("==FK-FS==", cmd_str)      # sentinel
        self.assertIn("head -c", cmd_str)         # per-file cap

    def test_windows_host_uses_powershell_pipeline(self):
        # Windows scrub is supported now — Get-ChildItem PowerShell pipeline,
        # same FK-FS delimiters so the parser is reused unchanged.
        self.store.add_host("10.0.0.7", os_name="windows")
        wcid, _ = self.store.add_credential(Credential("jdoe", "pw", domain="corp"))
        self.store.add_access(self.store.host_by_ip("10.0.0.7")["id"],
                              wcid, "smb", admin=True)
        # also need a winrm/smb transport the executor recognizes for PowerShell —
        # smb+admin gives us cmd/powershell access. Verify the command shape by
        # spying on argv.
        seen = []

        def capture(argv, env=None):
            seen.append(argv)
            # Return canned output so apply() completes without crashing
            return RunResult(argv, exit_code=0, stdout="")
        rep = fs_scrub.fs_scrub(
            self.store, self.store.host_by_ip("10.0.0.7"),
            self.store.credential_by_id(wcid), run=capture)
        self.assertIsNone(rep.aborted)
        cmd_str = " ".join(a for argv in seen for a in argv)
        # PowerShell shape — Get-ChildItem + FK-FS sentinels
        self.assertIn("Get-ChildItem", cmd_str)
        self.assertIn("==FK-FS==", cmd_str)
        # default Windows paths appear
        self.assertIn("C:\\ProgramData", cmd_str)
        # NOT the Linux find pipeline
        self.assertNotIn("head -c", cmd_str)

    def test_unsupported_os_is_refused_with_helpful_message(self):
        # BSD / macOS / anything not linux+windows should refuse cleanly
        self.store.add_host("10.0.0.99", os_name="freebsd")
        fcid, _ = self.store.add_credential(Credential("root", "pw"))
        self.store.add_access(self.store.host_by_ip("10.0.0.99")["id"],
                              fcid, "ssh")
        rep = fs_scrub.fs_scrub(
            self.store, self.store.host_by_ip("10.0.0.99"),
            self.store.credential_by_id(fcid), run=self._fake_ssh(""))
        self.assertIn("freebsd", rep.aborted)
        self.assertIn("linux + windows", rep.aborted)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
