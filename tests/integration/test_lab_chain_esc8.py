"""Integration: esc8 chain walk against a real vulnerable DC.

Every step of the esc8 chain (reachability → PetitPotam →
ntlmrelayx → ADCS cert-request → PKINIT → DCSync) fires for
real. Catches: impacket arg drift, ntlmrelayx output-parsing
regressions, real KDC / ADCS response strings vs marker
patterns.
"""
import pytest


@pytest.mark.integration
class TestEsc8Chain:

    def test_esc8_walks_to_proven_against_lab_dc(
            self, lab_dc, lab_low_priv_cred, lab_expectations,
            fresh_engagement_db):
        """Walk esc8 against the lab DC + assert the terminal
        status matches the operator-pinned expectation
        (usually 'proven' for a known-vulnerable lab)."""
        from fieldkit import chain as chain_mod
        from fieldkit.creds import Credential

        # Add the low-priv cred to the engagement so
        # coerce/relay steps can auth
        cred = Credential(
            username=lab_low_priv_cred["user"],
            secret=lab_low_priv_cred["password"],
            domain=lab_low_priv_cred.get("domain", ""))
        fresh_engagement_db.add_credential(cred, source="lab-fixture")

        # Build + walk the chain with the ctx the CLI's
        # cmd_chain_run would assemble
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
            store = fresh_engagement_db

        ch = chain_mod.esc8_chain(lab_dc["ip"])
        chain_mod.walk(ch, _Ctx())

        expected = lab_expectations.get("chain_run_esc8", "proven")
        assert ch.status == expected, (
            f"expected esc8 chain status={expected}, got {ch.status}. "
            f"Aborted reason: {ch.aborted_reason or '(none)'}. "
            f"Outcomes: {[o.kind for o in ch.outcomes]}")
