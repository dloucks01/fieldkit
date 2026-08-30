#!/usr/bin/env python3
"""NoPac chain profile — CVE-2021-42287 + CVE-2021-42278.

5th shipped chain profile. Manual-outcome steps in this cut
(no impacket dependency in fieldkit vendor tree), so the tests
pin the plan shape + step evidence rather than end-to-end
execution.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class ProfileShapeTest(unittest.TestCase):

    def test_profile_registered(self):
        from fieldkit.chain import known_profiles
        self.assertIn("nopac", known_profiles())

    def test_nopac_has_6_steps_in_expected_order(self):
        from fieldkit.chain import profile
        ch = profile("nopac")("10.0.0.10")
        names = [s.name for s in ch.steps]
        self.assertEqual(names, [
            "preflight:reachability",
            "discover:maq",
            "create:computer-account",
            "modify:sam-spoof",
            "request:s4u2self-tgt",
            "cleanup:restore-sam",
        ])

    def test_first_step_is_preflight(self):
        from fieldkit.chain import profile
        ch = profile("nopac")("10.0.0.10")
        self.assertEqual(ch.steps[0].kind, "preflight")

    def test_every_step_has_a_signals_catalog(self):
        from fieldkit.chain import profile
        ch = profile("nopac")("10.0.0.10")
        for step in ch.steps:
            self.assertGreater(len(step.signals), 0,
                                f"step {step.name} has no signals — "
                                "would trip chain lint's no-signals rule")


class ActionEvidenceTest(unittest.TestCase):

    def _walk_step(self, step_name, ctx):
        from fieldkit.chain import profile, walk, Chain
        ch = profile("nopac")("10.0.0.10")
        by_name = {s.name: s for s in ch.steps}
        step = by_name[step_name]
        one = Chain(profile=ch.profile, target=ch.target,
                     steps=(step,))
        walk(one, ctx)
        return one.outcomes[0]

    def _ctx(self, **kw):
        class C: pass
        base = {"domain": "CORP.LOCAL", "cred": {"username": "jdoe",
                                                    "password": "Winter2025!"},
                "dc_name": "DC01", "impersonate": "Administrator"}
        base.update(kw)
        c = C()
        for k, v in base.items():
            setattr(c, k, v)
        return c

    def test_quota_action_names_maq(self):
        out = self._walk_step("discover:maq", self._ctx())
        self.assertEqual(out.kind, "manual")
        self.assertIn("ms-DS-MachineAccountQuota", out.evidence)
        self.assertIn("CORP.LOCAL", out.evidence)

    def test_quota_action_bails_when_no_domain(self):
        out = self._walk_step("discover:maq", self._ctx(domain=None))
        self.assertEqual(out.kind, "manual")
        self.assertIn("no domain", out.evidence)

    def test_addcomputer_names_impacket_addcomputer(self):
        out = self._walk_step("create:computer-account", self._ctx())
        self.assertIn("impacket-addcomputer", out.evidence)
        self.assertIn("FKPWN$", out.evidence)
        self.assertIn("10.0.0.10", out.evidence)

    def test_addcomputer_bails_when_no_cred(self):
        out = self._walk_step("create:computer-account",
                                self._ctx(cred=None))
        self.assertIn("no cred", out.evidence)

    def test_sam_spoof_uses_dc_name(self):
        out = self._walk_step("modify:sam-spoof", self._ctx())
        self.assertIn("bloodyAD", out.evidence)
        self.assertIn("DC01", out.evidence)

    def test_s4u2self_impersonates_target(self):
        out = self._walk_step("request:s4u2self-tgt", self._ctx())
        self.assertIn("impacket-getST", out.evidence)
        self.assertIn("Administrator", out.evidence)
        self.assertIn("krbtgt/DC01", out.evidence)

    def test_restore_reverts_sam(self):
        out = self._walk_step("cleanup:restore-sam", self._ctx())
        self.assertIn("FKPWN$", out.evidence)


class DnHelperTest(unittest.TestCase):

    def test_dn_from_domain_splits_on_dots(self):
        from fieldkit.chain import _dn_from_domain
        self.assertEqual(_dn_from_domain("CORP.LOCAL"), "DC=CORP,DC=LOCAL")
        self.assertEqual(_dn_from_domain("a.b.c.d"), "DC=a,DC=b,DC=c,DC=d")
        self.assertEqual(_dn_from_domain(""), "DC=corp,DC=local")
        self.assertEqual(_dn_from_domain(None), "DC=corp,DC=local")


class LintPassesTest(unittest.TestCase):
    """The audit + guard rail: nopac must clear chain lint clean."""

    def test_nopac_lints_clean(self):
        from fieldkit import chainlint
        findings = chainlint.audit_profile("nopac")
        self.assertEqual(findings, [],
                          f"nopac has lint findings: {findings}")


if __name__ == "__main__":
    unittest.main()
