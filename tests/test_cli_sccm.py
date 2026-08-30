#!/usr/bin/env python3
"""fieldkit sccm enum + T1552.001 NAA-recovery TTP."""
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _mk_store(test_case):
    tmp = tempfile.TemporaryDirectory()
    test_case.addCleanup(tmp.cleanup)
    from fieldkit.state import Store
    s = Store.create(os.path.join(tmp.name, "e.db"))
    s.init_engagement("test-sccm")
    test_case.addCleanup(s.close)
    return s


def _run(argv, store):
    from fieldkit.cli import build_parser, cmd_sccm_enum
    parser = build_parser()
    args = parser.parse_args(argv)
    buf = io.StringIO()
    errbuf = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(errbuf):
        code = cmd_sccm_enum.__wrapped__(args, store)
    return code, buf.getvalue(), errbuf.getvalue()


class EnumTest(unittest.TestCase):

    def test_enum_prints_attack_paths(self):
        s = _mk_store(self)
        code, out, _ = _run(["sccm", "enum"], s)
        self.assertEqual(code, 0)
        # Every major surface should appear
        for term in ("management points", "Client push",
                      "Network Access Account", "PXEThief",
                      "SharpSCCM", "Site database"):
            self.assertIn(term, out)


class TTPTest(unittest.TestCase):

    def test_naa_recovery_ttp_loads(self):
        from fieldkit.ttps import load_all
        tt = [t for t in load_all() if t.key == "sccm:naa-recovery"]
        self.assertEqual(len(tt), 1)
        self.assertEqual(tt[0].technique, "T1552.001")

    def test_naa_ttp_playbook_present(self):
        from fieldkit.ttps import load_all
        tt = [t for t in load_all() if t.key == "sccm:naa-recovery"][0]
        self.assertGreater(len(tt.playbook.steps), 3)
        self.assertIn("SharpSCCM", " ".join(tt.playbook.steps))


if __name__ == "__main__":
    unittest.main()
