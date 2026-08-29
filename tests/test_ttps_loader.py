#!/usr/bin/env python3
"""fieldkit.ttps — TTP-as-data schema + loader (Phase B1).

Pinned:

  * loader is strict — bad shape raises LoaderError with the file + field
    named, never silent skip;
  * platform / exploitability / safety / detection values must be from the
    enum sets;
  * detect predicate must be exactly one of the supported kinds;
  * T-code must match the MITRE regex;
  * `load_all` returns TTPs sorted by (technique, source) so engine ordering
    is deterministic;
  * the shipped T1548.003 sample loads without error — it's the pinned example
    the schema is designed against;
  * extra top-level keys are tolerated (forward-compat).
"""
import os
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _write_yaml(dir_, name, body):
    path = os.path.join(dir_, name)
    with open(path, "w") as fh:
        fh.write(textwrap.dedent(body).lstrip("\n"))
    return path


def _valid_body(**overrides):
    """A minimal-but-complete valid TTP body; overrides replace top-level fields."""
    base = {
        "technique": "T1548.003",
        "name": "Sample",
        "tactic": "[privilege-escalation]",
        "platform": "[linux]",
        "ranking": "\n  exploitability: high\n  safety: read-only\n  detection: quiet",
        "detect": "\n  always: true",
        "execute": "\n  command: 'id'",
        "verify": "\n  success: 'uid=0'",
        "report": "\n  vector_type: sample_vector",
    }
    base.update(overrides)
    return "\n".join(f"{k}: {v}" for k, v in base.items())


class LoadFileTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_shipped_sample_loads_without_error(self):
        # The sample TTP is the pinned reference — if it stops loading, the
        # schema silently broke.
        from fieldkit.ttps import load_file
        repo_ttp = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "fieldkit", "ttps", "T1548.003-sudo-find.yaml")
        t = load_file(repo_ttp)
        self.assertEqual(t.technique, "T1548.003")
        self.assertEqual(t.platform, ("linux",))
        self.assertEqual(t.detect.kind, "sudo_allows")
        self.assertEqual(t.detect.value, "find")
        self.assertEqual(t.ranking.exploitability, "high")
        self.assertEqual(t.ranking.safety, "config-change")
        self.assertIn("uid=0", t.verify.success)
        self.assertEqual(t.report.vector_type, "sudo_gtfo_find")

    def test_valid_minimal_body_loads(self):
        from fieldkit.ttps import load_file
        path = _write_yaml(self.tmp.name, "t.yaml", _valid_body())
        t = load_file(path)
        self.assertEqual(t.technique, "T1548.003")
        self.assertEqual(t.detect.kind, "always")
        self.assertEqual(t.cleanup.command, "")   # optional block empty is fine

    def test_missing_required_field_raises_named_error(self):
        # A well-formed YAML that omits `ranking` — must fail with a message
        # that names both the file and the missing field, so the operator can
        # fix without guessing.
        from fieldkit.ttps import LoaderError, load_file
        body = """
        technique: T1548.003
        name: Sample
        tactic: [privilege-escalation]
        platform: [linux]
        detect: {always: true}
        execute: {command: 'id'}
        verify: {success: 'uid=0'}
        report: {vector_type: sample}
        """
        path = _write_yaml(self.tmp.name, "t.yaml", body)
        with self.assertRaises(LoaderError) as cm:
            load_file(path)
        self.assertIn("ranking", str(cm.exception))
        self.assertIn("t.yaml", str(cm.exception))

    def test_invalid_technique_code_rejected(self):
        from fieldkit.ttps import LoaderError, load_file
        path = _write_yaml(self.tmp.name, "t.yaml",
                            _valid_body(technique="not-a-tcode"))
        with self.assertRaises(LoaderError) as cm:
            load_file(path)
        self.assertIn("T-code", str(cm.exception))

    def test_invalid_platform_rejected(self):
        from fieldkit.ttps import LoaderError, load_file
        path = _write_yaml(self.tmp.name, "t.yaml",
                            _valid_body(platform="[freebsd]"))
        with self.assertRaises(LoaderError) as cm:
            load_file(path)
        self.assertIn("windows", str(cm.exception))    # error names the allowed set

    def test_invalid_safety_enum_rejected(self):
        from fieldkit.ttps import LoaderError, load_file
        path = _write_yaml(self.tmp.name, "t.yaml", _valid_body(
            ranking="\n  exploitability: high\n  safety: wild-guess\n  detection: quiet"))
        with self.assertRaises(LoaderError) as cm:
            load_file(path)
        self.assertIn("safety", str(cm.exception))

    def test_detect_requires_exactly_one_predicate(self):
        from fieldkit.ttps import LoaderError, load_file
        # Two predicates — ambiguous
        path = _write_yaml(self.tmp.name, "t.yaml", _valid_body(
            detect="\n  always: true\n  sudo_allows: find"))
        with self.assertRaises(LoaderError) as cm:
            load_file(path)
        self.assertIn("exactly one", str(cm.exception))

    def test_unknown_predicate_kind_rejected(self):
        from fieldkit.ttps import LoaderError, load_file
        path = _write_yaml(self.tmp.name, "t.yaml", _valid_body(
            detect="\n  psychic_powers: true"))
        with self.assertRaises(LoaderError) as cm:
            load_file(path)
        self.assertIn("detect", str(cm.exception))

    def test_extra_keys_are_tolerated_for_forward_compat(self):
        # Adding a field to the schema shouldn't force every existing engine
        # deploy to update at the same time.
        from fieldkit.ttps import load_file
        body = _valid_body() + "\nfuture_field: hello"
        path = _write_yaml(self.tmp.name, "t.yaml", body)
        t = load_file(path)
        self.assertEqual(t.technique, "T1548.003")

    def test_wrong_schema_version_rejected(self):
        from fieldkit.ttps import LoaderError, load_file
        body = _valid_body() + "\nschema: 999"
        path = _write_yaml(self.tmp.name, "t.yaml", body)
        with self.assertRaises(LoaderError) as cm:
            load_file(path)
        self.assertIn("schema", str(cm.exception).lower())
        self.assertIn("999", str(cm.exception))

    def test_malformed_yaml_raises_clean_error(self):
        from fieldkit.ttps import LoaderError, load_file
        path = _write_yaml(self.tmp.name, "t.yaml", "this: is: not: yaml")
        with self.assertRaises(LoaderError):
            load_file(path)


class LoadAllTest(unittest.TestCase):
    def test_load_all_from_shipped_dir(self):
        # The shipped ttps/ has at least the T1548.003 sample; load_all must
        # succeed and return TTPs sorted by technique.
        from fieldkit.ttps import load_all
        ttps = load_all()
        self.assertGreaterEqual(len(ttps), 1)
        techniques = [t.technique for t in ttps]
        self.assertEqual(techniques, sorted(techniques))
        self.assertIn("T1548.003", techniques)

    def test_load_all_from_custom_dir(self):
        from fieldkit.ttps import load_all
        with tempfile.TemporaryDirectory() as tmp:
            _write_yaml(tmp, "a.yaml", _valid_body(technique="T1078.002"))
            _write_yaml(tmp, "b.yaml", _valid_body(technique="T1548.003"))
            # a non-yaml file is ignored
            with open(os.path.join(tmp, "README"), "w") as fh:
                fh.write("not a ttp")
            ttps = load_all(tmp)
            self.assertEqual([t.technique for t in ttps],
                             ["T1078.002", "T1548.003"])

    def test_load_all_fails_loudly_on_first_bad_file(self):
        # No silent skips — a bad TTP file should stop the whole load rather
        # than let the operator run with quietly-missing coverage.
        from fieldkit.ttps import LoaderError, load_all
        with tempfile.TemporaryDirectory() as tmp:
            _write_yaml(tmp, "good.yaml", _valid_body())
            _write_yaml(tmp, "bad.yaml", "technique: not-a-tcode")
            with self.assertRaises(LoaderError):
                load_all(tmp)


if __name__ == "__main__":
    unittest.main()
