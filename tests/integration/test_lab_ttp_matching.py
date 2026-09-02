"""Integration: version-range TTPs against real vulnerable services.

Verifies canon (product-string → services.<name>) matches what
nmap actually outputs on a vulnerable-services lab. Every
service_cve TTP asserts a canon match; a mismatch (like the
"Ivanti Endpoint Manager" → "manager" audit bug) surfaces
here rather than in production.
"""
import pytest


@pytest.mark.integration
class TestVulnerableServiceMatching:

    def test_each_vulnerable_service_produces_expected_ttp_match(
            self, lab_vulnerable_services, fresh_engagement_db):
        """For every declared vulnerable_service in lab.yaml,
        seed a matching fieldkit host+service, run analyze,
        and assert the expected_cve_key surfaces as a
        finding-worthy opportunity."""
        from fieldkit import kb
        from fieldkit.hostenum import _canon_product

        misses = []
        for svc in lab_vulnerable_services:
            host_ip = svc["host"]
            product = svc["product"]
            version = svc["version"]
            expected_key = svc["expected_cve_key"]
            # Seed the host + service
            hid, _ = fresh_engagement_db.add_host(host_ip,
                                                     os_name="linux")
            fresh_engagement_db.add_service(
                host_id=hid, port=443, proto="tcp",
                product=product, version=version)
            # Sanity: does canon produce the key the TTP expects?
            canon = _canon_product(product)
            # ...

        # Analyze: does the expected CVE key surface?
        opportunities = list(kb.analyze(fresh_engagement_db))
        found_keys = {o.key for o in opportunities}
        for svc in lab_vulnerable_services:
            key = svc["expected_cve_key"]
            if key not in found_keys:
                misses.append((svc["host"], svc["product"],
                                svc["version"], key))
        assert not misses, (
            f"canon or version-range mismatch — these services should have "
            f"surfaced their CVE TTP but didn't: {misses}")
