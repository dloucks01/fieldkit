#!/usr/bin/env python3
"""Engagement archive — package the whole engagement as one tarball.

Pinned:

  * `build_archive` always includes engagement.db + MANIFEST.md
  * when findings exist: report.md, cleanup manifest, recce export, steps.jsonl
    all get generated fresh and bundled
  * when the engagement is empty: only db + manifest land; nothing errors
  * tarball path defaults to <engagement-slug>-<date>.tar.gz
  * every file inside is under a top-level dir named for the archive, so
    extraction doesn't spill into the operator's CWD
  * MANIFEST.md's Contents section self-references (lists every bundled file
    INCLUDING itself)
  * extracted DB is fully usable — `fieldkit --db <extracted> status` works
"""
import os
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import archive  # noqa: E402
from fieldkit.config import load as load_config  # noqa: E402
from fieldkit.creds import Credential  # noqa: E402
from fieldkit.state import Store  # noqa: E402


class ArchiveTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "engagement.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME test")
        self.cfg = load_config(self.store)

    def _seed_proven_finding(self):
        """A minimal proven finding + a captured step + a cleanup artifact +
        a promoted credential — enough to fill every archive slot."""
        hid, _ = self.store.add_host("10.0.0.7", hostname="WS02", os_name="windows")
        cid, _ = self.store.add_credential(
            Credential("svcadmin", "S3cret!", domain="CORP"),
            source="sharespider:gpp-cpassword")
        self.store.add_access(hid, cid, "smb", admin=True)
        fid, _ = self.store.add_finding(
            "seimpersonate", "SeImpersonate → SYSTEM", host_id=hid,
            proven=True, evidence="nt authority\\system")
        self.store.add_step(cmd="GodPotato -cmd \"cmd /c whoami\"",
                            output="nt authority\\system", exit_code=0,
                            host_id=hid, finding_id=fid, transport="winrm")
        self.store.add_artifact("staged GodPotato.exe",
                                cleanup_cmd="del C:\\Windows\\Temp\\GodPotato.exe",
                                host_id=hid, finding_id=fid)


class BuildTest(ArchiveTestCase):
    def _archive(self, **kw):
        out = os.path.join(self.tmp.name, "out.tar.gz")
        return archive.build_archive(self.store, self.cfg,
                                      out_path=out, **kw)

    def _contents(self, path):
        with tarfile.open(path, "r:gz") as tar:
            return sorted(m.name for m in tar.getmembers())

    def test_empty_engagement_bundles_db_and_manifest_only(self):
        # a fresh engagement has no findings, so the report/cleanup/recce/steps
        # generators either skip or produce empty output. db + MANIFEST always land.
        out, bundled, warnings = self._archive(formats=["md"])
        self.assertTrue(os.path.exists(out))
        self.assertEqual(warnings, [])
        self.assertEqual(sorted(bundled), ["MANIFEST.md", "engagement.db"])
        contents = self._contents(out)
        # tarball prefixes each file with a top-level dir named for the archive
        self.assertTrue(all("/" in name for name in contents),
                         "every entry lives under a top-level dir")
        self.assertTrue(any(name.endswith("/engagement.db") for name in contents))
        self.assertTrue(any(name.endswith("/MANIFEST.md") for name in contents))

    def test_proven_engagement_bundles_everything(self):
        self._seed_proven_finding()
        out, bundled, warnings = self._archive(formats=["md"])
        self.assertEqual(warnings, [])
        # every artifact type is present
        for expected in ("engagement.db", "report.md", "report.cleanup.md",
                          "recce_findings.json", "steps.jsonl", "MANIFEST.md"):
            self.assertIn(expected, bundled)

    def test_steps_jsonl_has_one_line_per_captured_step(self):
        self._seed_proven_finding()
        out, _, _ = self._archive(formats=["md"])
        with tarfile.open(out, "r:gz") as tar:
            member = next(m for m in tar.getmembers() if m.name.endswith("/steps.jsonl"))
            content = tar.extractfile(member).read().decode()
        lines = [line for line in content.splitlines() if line.strip()]
        self.assertEqual(len(lines), 1)
        import json
        step = json.loads(lines[0])
        for field in ("id", "ts", "host_id", "cmd", "output", "exit_code"):
            self.assertIn(field, step)
        self.assertIn("GodPotato", step["cmd"])
        self.assertIn("nt authority", step["output"])

    def test_manifest_lists_every_bundled_file_including_itself(self):
        self._seed_proven_finding()
        out, bundled, _ = self._archive(formats=["md"])
        with tarfile.open(out, "r:gz") as tar:
            member = next(m for m in tar.getmembers() if m.name.endswith("/MANIFEST.md"))
            manifest = tar.extractfile(member).read().decode()
        # every bundled filename appears in the manifest's Contents section
        for name in bundled:
            self.assertIn(f"`{name}`", manifest, f"MANIFEST missing {name}")
        # engagement identity + versions surface for a future auditor
        self.assertIn("ACME test", manifest)
        self.assertIn("Schema version:", manifest)
        self.assertIn("fieldkit version:", manifest)

    def test_extracted_db_is_functional(self):
        # a future operator extracting the tarball can `--db <extracted>` and
        # every fieldkit command works against the state.
        self._seed_proven_finding()
        out, _, _ = self._archive(formats=["md"])
        extract_dir = os.path.join(self.tmp.name, "extracted")
        with tarfile.open(out, "r:gz") as tar:
            tar.extractall(extract_dir)
        # find the engagement.db in the extracted tree
        db_path = None
        for root, _, files in os.walk(extract_dir):
            if "engagement.db" in files:
                db_path = os.path.join(root, "engagement.db")
                break
        self.assertIsNotNone(db_path)
        # open it and verify the state survived intact
        with Store.open(db_path) as extracted:
            self.assertEqual(extracted.engagement()["name"], "ACME test")
            self.assertEqual(extracted.counts()["proven_findings"], 1)
            self.assertEqual(extracted.counts()["admin_hosts"], 1)

    def test_default_out_path_slugifies_engagement_name_and_dates_it(self):
        # default filename: <engagement-slug>-<YYYY-MM-DD>.tar.gz in CWD
        cwd = os.getcwd()
        os.chdir(self.tmp.name)
        try:
            out, _, _ = archive.build_archive(self.store, self.cfg,
                                                formats=["md"])
        finally:
            os.chdir(cwd)
        self.assertTrue(out.endswith(".tar.gz"))
        # non-alphanumeric chars in the name → underscore
        self.assertIn("ACME_test", out)
        # date pattern present
        self.assertRegex(out, r"\d{4}-\d{2}-\d{2}\.tar\.gz$")

    def test_regenerates_report_on_each_run(self):
        # running archive twice produces a fresh report each time — no stale
        # state carried over from a prior invocation
        self._seed_proven_finding()
        out1, _, _ = self._archive(formats=["md"])
        # add a second proven finding
        hid, _ = self.store.add_host("10.0.0.8", os_name="linux")
        self.store.add_finding("pwnkit", "PwnKit → root", host_id=hid,
                                proven=True, evidence="uid=0(root)")
        # need a step for check() — anti-fab guard
        self.store.add_step(cmd="./pwnkit", output="uid=0(root)",
                            exit_code=0, host_id=hid,
                            finding_id=self.store.findings()[-1]["id"],
                            transport="ssh")
        out2, _, _ = self._archive(formats=["md"])
        # report.md inside out2 should mention the SECOND finding
        with tarfile.open(out2, "r:gz") as tar:
            member = next(m for m in tar.getmembers() if m.name.endswith("/report.md"))
            report = tar.extractfile(member).read().decode()
        self.assertIn("PwnKit", report)
        self.assertIn("SeImpersonate", report)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
