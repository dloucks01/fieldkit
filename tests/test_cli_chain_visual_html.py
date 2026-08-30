#!/usr/bin/env python3
"""fieldkit chain visual --html — HTML kill-chain rendering.

C15 continue slice 3. Emits an inline-styled HTML block for
the chain's step trail — embeddable in a report, shareable as
a standalone page.
"""
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _make_store(test_case):
    tmp = tempfile.TemporaryDirectory()
    test_case.addCleanup(tmp.cleanup)
    from fieldkit.state import Store
    s = Store.create(os.path.join(tmp.name, "e.db"))
    s.init_engagement("test-chain-html")
    test_case.addCleanup(s.close)
    return s, tmp.name


def _persist(store, outcomes, target="10.0.0.5"):
    from fieldkit.chain import esc8_chain, Outcome
    ch = esc8_chain(target)
    for k in outcomes:
        ch.outcomes.append(Outcome(kind=k,
                                     evidence=f"{k}-evidence"))
    ch.current = len(outcomes)
    cid = store.reserve_chain_id(ch)
    store.finalize_chain(cid, ch)
    return cid


def _run(argv, store):
    from fieldkit.cli import build_parser, cmd_chain_visual
    parser = build_parser()
    args = parser.parse_args(argv)
    buf = io.StringIO()
    errbuf = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(errbuf):
        code = cmd_chain_visual.__wrapped__(args, store)
    return code, buf.getvalue(), errbuf.getvalue()


class HTMLRenderingTest(unittest.TestCase):

    def test_html_flag_emits_html_block(self):
        s, _ = _make_store(self)
        cid = _persist(s, ["ok", "ok", "manual"])
        code, out, _ = _run(["chain", "visual", str(cid), "--html"], s)
        self.assertEqual(code, 0)
        # Root container present
        self.assertIn("<div", out)
        # Chain header text
        self.assertIn(f"chain #{cid}", out)
        self.assertIn("esc8", out)
        self.assertIn("10.0.0.5", out)
        # Every step's outcome kind renders inline
        for kind in ("ok", "manual"):
            self.assertIn(f"[{kind}]", out)

    def test_html_escapes_user_supplied_strings(self):
        # If the profile/target ever carried HTML-injection-style
        # content, the render must escape it. Use a target with
        # < and > characters.
        s, _ = _make_store(self)
        cid = _persist(s, ["ok"], target="10.0.0.5<script>")
        code, out, _ = _run(["chain", "visual", str(cid), "--html"], s)
        self.assertEqual(code, 0)
        self.assertNotIn("<script>", out)
        # Escaped form present
        self.assertIn("&lt;script&gt;", out)

    def test_html_includes_running_cost(self):
        s, _ = _make_store(self)
        cid = _persist(s, ["ok", "ok"])
        code, out, _ = _run(["chain", "visual", str(cid), "--html"], s)
        self.assertIn("running=", out)

    def test_out_flag_writes_html_to_file(self):
        s, tmp = _make_store(self)
        cid = _persist(s, ["ok"])
        outp = os.path.join(tmp, "chain.html")
        code, stdout, _ = _run(
            ["chain", "visual", str(cid), "--html", "--out", outp], s)
        self.assertEqual(code, 0)
        self.assertIn("wrote", stdout)
        with open(outp) as fh:
            content = fh.read()
        self.assertIn(f"chain #{cid}", content)
        self.assertIn("<div", content)

    def test_no_html_flag_still_prints_ascii(self):
        # Regression pin: existing ASCII output is default; no HTML
        # tags leak into a bare `chain visual` invocation.
        s, _ = _make_store(self)
        cid = _persist(s, ["ok"])
        code, out, _ = _run(["chain", "visual", str(cid)], s)
        self.assertEqual(code, 0)
        self.assertNotIn("<div", out)
        self.assertNotIn("<style", out)
        # ASCII marker present
        self.assertIn("[+]", out)


class ArgparseTest(unittest.TestCase):

    def test_html_flag_default_false(self):
        from fieldkit.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["chain", "visual", "3"])
        self.assertFalse(getattr(args, "html", False))

    def test_out_flag_default_none(self):
        from fieldkit.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["chain", "visual", "3", "--html"])
        self.assertTrue(args.html)
        self.assertIsNone(args.out)


if __name__ == "__main__":
    unittest.main()
