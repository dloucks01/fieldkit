#!/usr/bin/env python3
"""The remediation KB — the data every finding renders and bridges through.

`reportkb` is pure data driving the report *and* the recce export, so a malformed or
missing entry is a silent reporting bug rather than a crash: an unknown ``vector_type``
falls back to :data:`reportkb.DEFAULT` and a finding quietly renders as a generic Medium
"Local privilege escalation" with boilerplate remediation.

Pinned:

  * every KB entry is complete and well-formed (severity, CWE, OS, name, desc, remediation);
  * RISK covers exactly the KB, with labels RISK_META can explain;
  * **design rule 9** — every ``vector_type`` a privesc vector can emit resolves to a real
    KB key. This is the regression guard for a bug where `_win_vector` dropped the spec's
    `report_type`, so SeDebug (key "sedebug", type "lsass") fell through to DEFAULT and a
    High credential-theft finding rendered as a generic Medium.

Run:  python3 -m unittest discover -s tests
"""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import privesc, reportkb  # noqa: E402
from fieldkit.hostenum import HostFacts  # noqa: E402

SEVERITIES = {"Critical", "High", "Medium", "Low", "Informational"}
OSES = {"", "win", "lin"}
REQUIRED = ("sev", "cwe", "os", "name", "desc", "rem")


def saturated_facts():
    """Facts that trigger every privesc driver at once, on both OSes."""
    linux = HostFacts(
        os="linux", uid=1000, user="svc", sudo_all=True, sudo_nopasswd=True,
        sudo_binaries={"find", "apache2ctl", "nmap", "tar", "gdb", "make", "docker", "python"},
        sudo_env_keep={"LD_PRELOAD", "LD_LIBRARY_PATH"},
        suid={"bash", "find", "python3.8", "pkexec", "passwd", "nmap", "tar"},
        caps={"python3.8": "cap_setuid", "tar": "cap_dac_override"},
        groups={"svc", "docker", "lxd", "disk", "adm"},
        kernel="5.15.0", sudo_version="1.8.31", pkexec_version="0.105",
        glibc_version="2.35")
    windows = HostFacts(
        os="windows",
        privs=set(privesc.WIN_PRIVS) | {"SeImpersonatePrivilege",
                                        "SeAssignPrimaryTokenPrivilege"},
        win_groups=set(privesc.WIN_GROUPS), always_install_elevated=True,
        unquoted_services=[("Svc", "C:\\Program Files\\a b\\x.exe")],
        reconfigurable_services={"Svc": "C:\\x.exe"},
        writable_service_bins={"Svc": "C:\\Apps\\v.exe"},
        writable_service_dirs={"Svc": "C:\\Apps"})
    return (linux, windows)


def all_vectors():
    out = []
    for facts in saturated_facts():
        out.extend(privesc.vectors_for(facts, "10.0.0.1"))
    return out


class KbShapeTest(unittest.TestCase):
    def test_every_entry_is_complete(self):
        for vt, e in reportkb.KB.items():
            for field in REQUIRED:
                self.assertIn(field, e, f"{vt} is missing {field!r}")
                if field != "os":          # "" is valid — the vector is OS-agnostic
                    self.assertTrue(str(e[field]).strip(), f"{vt}.{field} is empty")

    def test_severity_and_os_are_from_the_known_sets(self):
        for vt, e in reportkb.KB.items():
            self.assertIn(e["sev"], SEVERITIES, f"{vt} has severity {e['sev']!r}")
            self.assertIn(e["os"], OSES, f"{vt} has os {e['os']!r}")

    def test_cwe_is_well_formed(self):
        for vt, e in reportkb.KB.items():
            self.assertTrue(re.fullmatch(r"CWE-(\d+|noinfo)", e["cwe"]),
                            f"{vt} has cwe {e['cwe']!r}")

    def test_remediation_is_actionable_not_a_stub(self):
        # the remediation text is what lands in the client deliverable
        for vt, e in reportkb.KB.items():
            self.assertGreater(len(e["rem"]), 40, f"{vt} remediation is too thin to action")

    def test_default_is_complete_too(self):
        for field in REQUIRED:
            self.assertIn(field, reportkb.DEFAULT)


class RiskTest(unittest.TestCase):
    def test_risk_covers_exactly_the_kb(self):
        self.assertEqual(set(reportkb.RISK), set(reportkb.KB))

    def test_every_risk_label_is_explainable(self):
        for vt, label in reportkb.RISK.items():
            self.assertIn(label, reportkb.RISK_META, f"{vt} has risk {label!r}")

    def test_risk_meta_entries_are_complete(self):
        for label, meta in reportkb.RISK_META.items():
            for field in ("danger", "safe_proof", "cleanup"):
                self.assertTrue(meta.get(field), f"{label}.{field} is empty")

    def test_risk_of_falls_back_safely(self):
        self.assertEqual(reportkb.risk_of("no-such-vector"), "reversible")
        self.assertTrue(reportkb.risk_meta("no-such-vector")["danger"])


class Rule9Test(unittest.TestCase):
    """Design rule 9: a canonical vector_type records -> renders -> bridges, no hand-mapping."""

    def test_every_privesc_vector_resolves_to_a_real_kb_entry(self):
        unresolved = [(v.key, v.report_type) for v in all_vectors()
                      if not v.report_type or v.report_type not in reportkb.KB]
        self.assertEqual(unresolved, [], f"vector_types that would render as DEFAULT: {unresolved}")

    def test_sedebug_reports_as_lsass_not_the_generic_default(self):
        # the regression: _win_vector dropped the spec's report_type, so this High
        # credential-theft finding rendered as a generic Medium with boilerplate remediation.
        facts = HostFacts(os="windows", privs={"SeDebugPrivilege"})
        v = [x for x in privesc.vectors_for(facts, "10.0.0.7") if x.key == "sedebug"][0]
        self.assertEqual(v.report_type, "lsass")
        entry = reportkb.entry(v.report_type)
        self.assertEqual(entry["sev"], "High")
        self.assertNotEqual(entry, reportkb.DEFAULT)

    def test_spec_tables_declare_types_that_exist(self):
        for table in (privesc.WIN_PRIVS, privesc.WIN_GROUPS):
            for trigger, spec in table.items():
                vt = spec.get("report_type", spec["key"])
                self.assertIn(vt, reportkb.KB, f"{trigger} -> {vt!r} is not a KB key")

    def test_kernel_lpe_rules_all_report_under_kernel_cve(self):
        vs = [v for v in all_vectors() if v.key.startswith("cve:")]
        self.assertTrue(vs)
        self.assertEqual({v.report_type for v in vs}, {"kernel_cve"})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
