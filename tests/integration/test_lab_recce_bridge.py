"""Integration: recce → fieldkit bridge round-trip.

Verifies the bridge schema fieldkit assumes matches what recce
actually produces. Regression pin for schema drift: if recce
ships a bridge-shape change, this test fails immediately
rather than surfacing weeks later as an "ingest recce
silently drops hosts" bug in production.
"""
import pytest


@pytest.mark.integration
class TestReceeBridgeRoundTrip:

    def test_recce_bridge_parses_via_fieldkit_recce_module(
            self, lab_recce_bridge):
        """The bridge recce hands us parses cleanly through
        fieldkit.recce.parse — no LoaderError, no missing
        fields, hosts + findings + creds all typed."""
        from fieldkit import recce as recce_mod
        with open(lab_recce_bridge) as fh:
            text = fh.read()
        intent = recce_mod.parse(text)
        # Basic shape: at least one host, no exception
        assert intent.hosts, "recce bridge has no hosts"

    def test_ingest_recce_folds_hosts_into_engagement(
            self, lab_recce_bridge, fresh_engagement_db,
            lab_expectations):
        """`fieldkit ingest recce <path>` populates state.
        Verifies the bridge-to-store apply logic against a
        real bridge, catching any Store schema drift."""
        from fieldkit import recce as recce_mod
        with open(lab_recce_bridge) as fh:
            text = fh.read()
        intent = recce_mod.parse(text)
        recce_mod.apply(fresh_engagement_db, intent)
        counts = fresh_engagement_db.counts()
        # Operator can pin a lower-bound expectation in lab.yaml
        min_hosts = lab_expectations.get(
            "ingest_recce_hosts_min", 1)
        assert counts["hosts"] >= min_hosts, (
            f"expected >={min_hosts} hosts after ingest, got {counts['hosts']}")

    def test_bridge_findings_map_to_known_vector_types(
            self, lab_recce_bridge):
        """Every finding recce emits carries a vector_type
        fieldkit's reportkb recognizes. An unknown vector_type
        renders as generic remediation — usually a schema drift
        signal."""
        from fieldkit import recce as recce_mod, reportkb
        with open(lab_recce_bridge) as fh:
            intent = recce_mod.parse(fh.read())
        unknown = []
        for f in intent.findings:
            vt = getattr(f, "vector_type", None) or ""
            if vt and vt not in reportkb.KB:
                unknown.append(vt)
        assert not unknown, (
            f"recce bridge carries vector_types fieldkit doesn't recognize: "
            f"{sorted(set(unknown))} — either recce added new types or "
            f"our KB needs updating")
