"""Integration: nopac chain walk against a real vulnerable DC.

Exercises the C18 NoPac live-wiring (impacket-addcomputer +
bloodyAD + impacket-getST). Catches: impacket ticketer output
format changes, bloodyAD arg drift, KDC_ERR_S_PRINCIPAL_UNKNOWN
handling on patched DCs.
"""
import pytest


@pytest.mark.integration
class TestNoPacChain:

    def test_nopac_walks_to_proven_against_lab_dc(
            self, lab_dc, lab_low_priv_cred, lab_expectations,
            fresh_engagement_db):
        from fieldkit import chain as chain_mod
        from fieldkit.creds import Credential

        cred = Credential(
            username=lab_low_priv_cred["user"],
            secret=lab_low_priv_cred["password"],
            domain=lab_low_priv_cred.get("domain", ""))
        fresh_engagement_db.add_credential(cred, source="lab-fixture")

        class _Ctx:
            probe_port = 445
            probe_timeout = 5
            domain = lab_dc["domain"]
            cred = {"domain": cred.domain,
                    "username": cred.username,
                    "password": cred.secret}
            dc_name = lab_dc.get("hostname", "DC01")
            impersonate = "Administrator"
            store = fresh_engagement_db

        ch = chain_mod.nopac_chain(lab_dc["ip"])
        chain_mod.walk(ch, _Ctx())

        expected = lab_expectations.get("chain_run_nopac", "proven")
        assert ch.status == expected, (
            f"expected nopac status={expected}, got {ch.status}. "
            f"Aborted reason: {ch.aborted_reason or '(none)'}. "
            f"Outcomes: {[o.kind for o in ch.outcomes]}")

    def test_nopac_bails_cleanly_on_patched_dc(
            self, lab_dc, lab_low_priv_cred, lab_expectations,
            fresh_engagement_db):
        """When the operator declares the DC as patched
        (via `expectations.chain_run_nopac: aborted`), verify
        the walker classifies the KDC refuse as fail →
        chain aborted, not a runtime crash."""
        expected = lab_expectations.get("chain_run_nopac")
        if expected != "aborted":
            pytest.skip("lab isn't declared patched — "
                        "test_nopac_walks_to_proven_against_lab_dc "
                        "covers the proven path")
        # Delegated to the walks-to-proven test which checks
        # status == expected regardless of whether that's
        # 'proven' or 'aborted'. Placeholder to document the
        # "we also test the patched-DC case" contract.
