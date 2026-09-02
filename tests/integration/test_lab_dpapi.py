"""Integration: DPAPI decrypt against staged artifacts in the lab folder.

Recce (or the operator) stages a real master key file +
credential blob from a Windows host into <lab-folder>/dpapi/.
Fixture locates them by glob (mkey-* / cred-*); test decrypts
via fieldkit.dpapi.
"""
import pytest


@pytest.mark.integration
class TestDpapiDecrypt:

    def test_masterkey_decrypt_produces_key_hex(
            self, lab_dpapi_artifacts):
        from fieldkit import dpapi

        result = dpapi.decrypt_masterkey(
            masterkey_file=lab_dpapi_artifacts["mkey_path"],
            sid=lab_dpapi_artifacts["sid"],
            password=lab_dpapi_artifacts["password"])
        assert result.kind == "ok", (
            f"dpapi masterkey failed: {result.output}")
        assert len(result.artifact) >= 32, (
            f"decrypted key too short: {result.artifact!r}")

    def test_credential_decrypt_surfaces_fields(
            self, lab_dpapi_artifacts):
        from fieldkit import dpapi

        mk = dpapi.decrypt_masterkey(
            masterkey_file=lab_dpapi_artifacts["mkey_path"],
            sid=lab_dpapi_artifacts["sid"],
            password=lab_dpapi_artifacts["password"])
        if mk.kind != "ok":
            pytest.skip(f"masterkey didn't unlock: {mk.output}")

        cr = dpapi.decrypt_credential(
            cred_blob_file=lab_dpapi_artifacts["cred_blob_path"],
            masterkey_hex=mk.artifact)
        assert cr.kind == "ok", (
            f"dpapi credential failed: {cr.output}")
        assert ("Username:" in cr.artifact or
                "URL:" in cr.artifact), (
            f"credential parse looks empty: {cr.artifact[:200]}")
