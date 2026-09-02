"""Integration: DPAPI decrypt against a staged Windows host.

Verifies fieldkit's dpapi module produces the same output
impacket-dpapi CLI produces against real DPAPI blobs. Catches:
impacket-dpapi arg drift, output-parsing regressions
(Decrypted key: hex format, Username/Password field labels).

The operator stages the master key file + credential blob from
a real Windows box (mimikatz / SharpDPAPI dumps them) into the
lab.yaml's dpapi_host paths.
"""
import os
import pytest


@pytest.mark.integration
class TestDpapiDecrypt:

    def test_masterkey_decrypt_produces_key_hex(
            self, lab_windows_dpapi_host):
        """Decrypt the staged master key file with the user's
        password + SID. On success dpapi returns kind=ok and
        an artifact string that looks like a hex key."""
        from fieldkit import dpapi

        mkey = lab_windows_dpapi_host["mkey_path"]
        if not os.path.isfile(mkey):
            pytest.skip(f"{mkey}: staged master key file missing")

        result = dpapi.decrypt_masterkey(
            masterkey_file=mkey,
            sid=lab_windows_dpapi_host["sid"],
            password=lab_windows_dpapi_host["password"])
        assert result.kind == "ok", (
            f"dpapi masterkey failed: {result.output}")
        # Hex-ish check: expect at least 32 chars
        assert len(result.artifact) >= 32, (
            f"decrypted key looks too short: {result.artifact!r}")

    def test_credential_decrypt_surfaces_username_field(
            self, lab_windows_dpapi_host):
        """After masterkey decrypt, use the key to unlock a
        staged Credential Manager blob. On success dpapi
        parses out at least a Username line."""
        from fieldkit import dpapi

        mkey = lab_windows_dpapi_host["mkey_path"]
        blob = lab_windows_dpapi_host["cred_blob_path"]
        if not (os.path.isfile(mkey) and os.path.isfile(blob)):
            pytest.skip("staged DPAPI artifacts missing")

        mk_result = dpapi.decrypt_masterkey(
            masterkey_file=mkey,
            sid=lab_windows_dpapi_host["sid"],
            password=lab_windows_dpapi_host["password"])
        if mk_result.kind != "ok":
            pytest.skip(f"masterkey didn't unlock: {mk_result.output}")

        cred_result = dpapi.decrypt_credential(
            cred_blob_file=blob,
            masterkey_hex=mk_result.artifact)
        assert cred_result.kind == "ok", (
            f"dpapi credential failed: {cred_result.output}")
        assert "Username:" in cred_result.artifact or \
               "URL:" in cred_result.artifact, (
            f"credential blob parse looks empty: "
            f"{cred_result.artifact[:200]}")
