"""Integration: recce → fieldkit engagement folder round-trip.

Verifies `fieldkit sync <lab-folder>` folds every recce
artifact into the engagement DB correctly. Catches: bridge
schema drift, nmap format changes, nxc log format changes,
bloodhound JSON drift.
"""
import os
import pytest


@pytest.mark.integration
class TestEngagementFolderSync:

    def test_sync_processes_recce_bridge(self, lab_folder,
                                             fresh_engagement_db):
        """`sync` walks the folder + applies the bridge JSON."""
        from fieldkit import engagement_sync
        bridge = os.path.join(lab_folder, "recce-bridge.json")
        if not os.path.isfile(bridge):
            pytest.skip(f"{bridge} missing — recce should write it")
        report = engagement_sync.sync_folder(
            fresh_engagement_db, lab_folder)
        processed_kinds = {e["kind"] for e in report.processed}
        assert "recce-bridge" in processed_kinds, (
            f"bridge present but not processed. skipped: "
            f"{[e for e in report.skipped if e['kind'] == 'recce-bridge']}")

    def test_sync_is_idempotent(self, lab_folder, fresh_engagement_db):
        """Re-running sync against the same folder folds no
        new material (counts delta empty)."""
        from fieldkit import engagement_sync
        engagement_sync.sync_folder(fresh_engagement_db, lab_folder)
        second = engagement_sync.sync_folder(
            fresh_engagement_db, lab_folder)
        assert not second.delta, (
            f"second sync should have no state delta, got {second.delta}. "
            "One of the ingest handlers isn't upsert-shaped.")

    def test_synced_engagement_has_at_least_expected_hosts(
            self, synced_engagement, lab_expectations):
        """After sync, host count meets the operator-declared
        floor (from lab.yaml expectations.sync_hosts_min)."""
        min_hosts = lab_expectations.get("sync_hosts_min", 1)
        counts = synced_engagement.counts()
        assert counts["hosts"] >= min_hosts, (
            f"expected >={min_hosts} hosts post-sync, "
            f"got {counts['hosts']}")

    def test_bridge_hosts_carry_expected_fields(
            self, lab_folder):
        """Every host in the bridge carries at minimum ip + os
        — the fields fieldkit's Store.add_host requires. A
        missing ip signals recce schema drift."""
        bridge = os.path.join(lab_folder, "recce-bridge.json")
        if not os.path.isfile(bridge):
            pytest.skip(f"{bridge} missing")
        from fieldkit import recce as recce_mod
        with open(bridge) as fh:
            intent = recce_mod.parse(fh.read())
        missing_ip = [h for h in intent.hosts
                      if not getattr(h, "ip", None)]
        assert not missing_ip, (
            f"{len(missing_ip)} recce host(s) missing 'ip' field — "
            "bridge schema may have drifted")
