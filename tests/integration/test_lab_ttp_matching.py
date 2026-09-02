"""Integration: version-range TTPs match against a real synced
vulnerable-services fleet.

After `sync` folds recce's bridge (which carries the real
nmap-derived services + versions), every service the operator
declared vulnerable in lab.yaml.vulnerable_services should
surface its expected CVE key via fieldkit.kb.analyze.

Catches canon mismatches (product string → canon key) + drift
in the version_range predicate.
"""
import pytest


@pytest.mark.integration
class TestVulnerableServiceMatching:

    def test_declared_services_surface_their_expected_cves(
            self, synced_engagement, lab_vulnerable_services):
        """For every declared vulnerable_service in lab.yaml,
        assert its expected_cve_key surfaces via analyze."""
        from fieldkit import kb
        opportunities = list(kb.analyze(synced_engagement))
        found_keys = {getattr(o, "key", "") for o in opportunities}

        misses = []
        for svc in lab_vulnerable_services:
            key = svc["expected_cve_key"]
            if key not in found_keys:
                misses.append({
                    "host": svc["host"],
                    "product": svc["product"],
                    "version": svc["version"],
                    "expected_key": key,
                })
        assert not misses, (
            f"These declared-vulnerable services should have surfaced "
            f"their CVE TTP after sync + analyze but didn't:\n"
            + "\n".join(f"  * {m}" for m in misses)
            + "\n\nLikely causes: canon mismatch (product string → "
            "services.<canon>), version_range gate, or bridge didn't "
            "carry the service+version. Run `fieldkit sync <folder>` "
            "manually + check `fieldkit hosts show <ip>` for service "
            "details.")
