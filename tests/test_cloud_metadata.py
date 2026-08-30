#!/usr/bin/env python3
"""cloud metadata IMDS probes.

C18 gap-slice F.
"""
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class ImdsProbeTest(unittest.TestCase):
    """Every probe path — unreachable IMDS returns
    reachable=False + an error string. On a normal test box
    169.254.169.254 doesn't respond, so probes should fail
    gracefully."""

    def test_aws_probe_unreachable_returns_false(self):
        from fieldkit import cloud_metadata as cm
        r = cm.probe_aws(timeout=0.5)
        # Not on AWS — expect unreachable
        self.assertEqual(r.provider, "aws")
        self.assertFalse(r.reachable)
        self.assertTrue(r.error)

    def test_azure_probe_unreachable_returns_false(self):
        from fieldkit import cloud_metadata as cm
        r = cm.probe_azure(timeout=0.5)
        self.assertEqual(r.provider, "azure")
        self.assertFalse(r.reachable)

    def test_gcp_probe_unreachable_returns_false(self):
        from fieldkit import cloud_metadata as cm
        r = cm.probe_gcp(timeout=0.5)
        self.assertEqual(r.provider, "gcp")
        self.assertFalse(r.reachable)

    def test_probe_all_returns_all_three(self):
        from fieldkit import cloud_metadata as cm
        results = cm.probe_all(timeout=0.5)
        self.assertEqual(len(results), 3)
        providers = {r.provider for r in results}
        self.assertEqual(providers, {"aws", "azure", "gcp"})


class CLITest(unittest.TestCase):

    def _run(self, argv):
        from fieldkit.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(argv)
        buf = io.StringIO()
        errbuf = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(errbuf):
            code = args.func(args)
        return code, buf.getvalue(), errbuf.getvalue()

    def test_imds_probe_prints_summary(self):
        code, out, _ = self._run(["cloud", "imds", "--timeout", "0.3"])
        self.assertEqual(code, 0)
        self.assertIn("cloud IMDS probe", out)
        # All 3 providers appear regardless of reachability
        for p in ("aws", "azure", "gcp"):
            self.assertIn(p, out)

    def test_imds_json_output(self):
        code, out, _ = self._run(["cloud", "imds", "--timeout", "0.3",
                                    "--json"])
        self.assertEqual(code, 0)
        doc = json.loads(out)
        self.assertEqual(len(doc), 3)
        providers = {r["provider"] for r in doc}
        self.assertEqual(providers, {"aws", "azure", "gcp"})


if __name__ == "__main__":
    unittest.main()
