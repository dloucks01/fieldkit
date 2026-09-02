"""Integration: esc8 chain walk against a real vulnerable DC.

Uses the synced_engagement fixture (already has hosts / creds
folded from recce's bridge). Walks esc8; asserts terminal
status matches operator's pinned expectation.
"""
import pytest


@pytest.mark.integration
class TestEsc8Chain:

    def test_esc8_walks_to_proven_against_lab_dc(
            self, synced_engagement, lab_dc, lab_low_priv_cred,
            lab_expectations):
        from fieldkit import chain as chain_mod

        # Cred should already be in the store from the sync,
        # but seed it defensively so this test doesn't depend
        # on the bridge shape.
        from fieldkit.creds import Credential
        cred = Credential(
            username=lab_low_priv_cred["user"],
            secret=lab_low_priv_cred["password"],
            domain=lab_low_priv_cred.get("domain", ""))
        synced_engagement.add_credential(cred, source="integration-fixture")

        class _Ctx:
            probe_port = 445
            probe_timeout = 5
            listener_ip = lab_dc.get("listener_ip", "")
            ca_endpoint = lab_dc.get("ca_hostname", "")
            template = "DomainController"
            relay_port_smb = 445
            relay_port_http = 80
            relay_wait_capture = 60
            domain = lab_dc["domain"]
            cred = {"domain": cred.domain,
                    "username": cred.username,
                    "password": cred.secret}
            relay_mode = "adcs-cert"
            relay_target = lab_dc.get("ca_hostname", "")
            impersonate = "Administrator"
            dc_ip = lab_dc["ip"]
            listener_uri = None
            store = synced_engagement

        ch = chain_mod.esc8_chain(lab_dc["ip"])
        chain_mod.walk(ch, _Ctx())

        expected = lab_expectations.get("chain_run_esc8", "proven")
        assert ch.status == expected, (
            f"expected esc8 chain status={expected}, got {ch.status}. "
            f"Aborted reason: {ch.aborted_reason or '(none)'}. "
            f"Outcomes: {[o.kind for o in ch.outcomes]}")
