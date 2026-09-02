"""Integration: nopac chain walk against a real vulnerable DC."""
import pytest


@pytest.mark.integration
class TestNoPacChain:

    def test_nopac_walks_to_expected_status(
            self, synced_engagement, lab_dc, lab_low_priv_cred,
            lab_expectations):
        from fieldkit import chain as chain_mod
        from fieldkit.creds import Credential

        cred = Credential(
            username=lab_low_priv_cred["user"],
            secret=lab_low_priv_cred["password"],
            domain=lab_low_priv_cred.get("domain", ""))
        synced_engagement.add_credential(cred, source="integration-fixture")

        class _Ctx:
            probe_port = 445
            probe_timeout = 5
            domain = lab_dc["domain"]
            cred = {"domain": cred.domain,
                    "username": cred.username,
                    "password": cred.secret}
            dc_name = lab_dc.get("hostname", "DC01")
            impersonate = "Administrator"
            store = synced_engagement

        ch = chain_mod.nopac_chain(lab_dc["ip"])
        chain_mod.walk(ch, _Ctx())

        # Expected can be "proven" (vulnerable DC) or "aborted"
        # (patched — KDC_ERR_S_PRINCIPAL_UNKNOWN classifies fail).
        # Operator declares which in lab.yaml.
        expected = lab_expectations.get("chain_run_nopac", "proven")
        assert ch.status == expected, (
            f"expected nopac status={expected}, got {ch.status}. "
            f"Aborted reason: {ch.aborted_reason or '(none)'}. "
            f"Outcomes: {[o.kind for o in ch.outcomes]}")
