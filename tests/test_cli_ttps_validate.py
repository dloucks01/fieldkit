#!/usr/bin/env python3
"""fieldkit ttps validate — schema validator for TTP YAML files.

C16 gaps slice 2. Runs the shipped fieldkit.ttps.loader against
a file or every .yaml in a directory. Useful pre-flight before
landing a new TTP so a schema error surfaces without polluting
the shipped catalog.
"""
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _run(argv):
    from fieldkit.cli import build_parser
    parser = build_parser()
    args = parser.parse_args(argv)
    buf = io.StringIO()
    errbuf = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(errbuf):
        code = args.func(args)
    return code, buf.getvalue(), errbuf.getvalue()


def _write(tmp, name, body):
    path = os.path.join(tmp, name)
    with open(path, "w") as fh:
        fh.write(body)
    return path


VALID_TTP = """\
technique: T1548.001
name: test-valid
tactic: [privilege-escalation]
platform: [linux]
key: test:valid
ranking:
  exploitability: high
  safety: read-only
  detection: quiet
detect:
  version_range:
    services.apache: ">=2.0,<2.5"
execute:
  command: "true"
verify:
  success: "y"
report:
  vector_type: test
  description: t
"""


class ValidateOneFileTest(unittest.TestCase):

    def test_valid_file_exits_0(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        p = _write(tmp.name, "T-good.yaml", VALID_TTP)
        code, out, _ = _run(["ttps", "validate", p])
        self.assertEqual(code, 0)
        self.assertIn("ok", out)
        self.assertIn("1/1 valid", out)

    def test_missing_field_exits_2(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        # No `name` field
        bad = VALID_TTP.replace("name: test-valid\n", "")
        p = _write(tmp.name, "T-bad.yaml", bad)
        code, out, _ = _run(["ttps", "validate", p])
        self.assertEqual(code, 2)
        self.assertIn("ERR", out)
        # The loader's message names the missing field
        self.assertIn("name", out.lower())

    def test_bad_technique_code_exits_2(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        bad = VALID_TTP.replace("T1548.001", "NOT-A-TECH")
        p = _write(tmp.name, "T-bad-tech.yaml", bad)
        code, out, _ = _run(["ttps", "validate", p])
        self.assertEqual(code, 2)
        self.assertIn("T-code", out)

    def test_malformed_yaml_exits_2(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        p = _write(tmp.name, "T-broken.yaml", "not: valid: yaml: syntax:")
        code, out, _ = _run(["ttps", "validate", p])
        self.assertEqual(code, 2)


class ValidateDirTest(unittest.TestCase):

    def test_dir_walks_every_yaml(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        _write(tmp.name, "T-a.yaml", VALID_TTP)
        _write(tmp.name, "T-b.yaml", VALID_TTP.replace("test:valid",
                                                          "test:valid-b"))
        code, out, _ = _run(["ttps", "validate", tmp.name])
        self.assertEqual(code, 0)
        self.assertIn("2/2 valid", out)

    def test_dir_partial_failure_exits_2(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        _write(tmp.name, "T-good.yaml", VALID_TTP)
        _write(tmp.name, "T-bad.yaml", "technique: NOT-A-TECH\nname: b")
        code, out, _ = _run(["ttps", "validate", tmp.name])
        self.assertEqual(code, 2)
        self.assertIn("1/2 valid", out)
        self.assertIn("ok", out)
        self.assertIn("ERR", out)

    def test_dir_no_yaml_exits_2(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        # Non-yaml file
        _write(tmp.name, "notes.txt", "hello")
        code, _, err = _run(["ttps", "validate", tmp.name])
        self.assertEqual(code, 2)
        self.assertIn("no .yaml", err)


class PathErrorsTest(unittest.TestCase):

    def test_nonexistent_path_exits_2(self):
        code, _, err = _run(["ttps", "validate", "/nonexistent/x"])
        self.assertEqual(code, 2)
        self.assertIn("no such", err)


class LiveShippedCatalogTest(unittest.TestCase):
    """Guard rail: every shipped TTP validates via the loader.
    Same check as `load_all()` at import time but via the new
    CLI surface — catches drift if the CLI wrapper ever forks
    validation logic."""

    def test_shipped_catalog_validates_clean(self):
        fk = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        catalog = os.path.join(fk, "fieldkit", "ttps")
        code, out, _ = _run(["ttps", "validate", catalog])
        self.assertEqual(code, 0,
                          f"shipped catalog has invalid TTPs:\n{out}")


if __name__ == "__main__":
    unittest.main()
