#!/usr/bin/env python3
"""fieldkit chain export — JSON dump of one chain's trail.

C15 continue slice 5. Read-only export: chain row + step trail
as a structured JSON object matching the report renderer's
chain_history shape.
"""
import io
import json
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
    s.init_engagement("test-chain-export")
    test_case.addCleanup(s.close)
    return s, tmp.name


def _persist_chain(store, outcome_kinds):
    from fieldkit.chain import esc8_chain, Outcome
    ch = esc8_chain("10.0.0.5")
    for k in outcome_kinds:
        ch.outcomes.append(Outcome(kind=k, evidence=f"{k}-evi"))
    ch.current = len(outcome_kinds)
    cid = store.reserve_chain_id(ch)
    store.finalize_chain(cid, ch)
    return cid


def _run(argv, store):
    from fieldkit.cli import build_parser, cmd_chain_export
    parser = build_parser()
    args = parser.parse_args(argv)
    buf = io.StringIO()
    errbuf = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(errbuf):
        code = cmd_chain_export.__wrapped__(args, store)
    return code, buf.getvalue(), errbuf.getvalue()


class ExportShapeTest(unittest.TestCase):

    def test_export_stdout_returns_valid_json(self):
        s, _ = _make_store(self)
        cid = _persist_chain(s, ["ok", "ok", "manual"])
        code, out, _ = _run(["chain", "export", str(cid)], s)
        self.assertEqual(code, 0)
        doc = json.loads(out)
        self.assertEqual(doc["id"], cid)
        self.assertEqual(doc["profile"], "esc8")
        self.assertEqual(doc["target"], "10.0.0.5")
        self.assertEqual(len(doc["steps"]), 3)

    def test_step_fields_populated(self):
        s, _ = _make_store(self)
        cid = _persist_chain(s, ["ok", "ok"])
        code, out, _ = _run(["chain", "export", str(cid)], s)
        doc = json.loads(out)
        step = doc["steps"][0]
        for field in ("idx", "name", "kind", "outcome", "cost",
                      "evidence", "ran_at"):
            self.assertIn(field, step)
        # Partial walk = in_progress (2 of esc8's 7 steps done).
        self.assertEqual(doc["status"], "in_progress")

    def test_finalize_fields_present(self):
        # aborted_reason / started_at / finished_at are always in
        # the payload (empty string when unset) so downstream tools
        # don't have to key-check.
        s, _ = _make_store(self)
        cid = _persist_chain(s, ["ok"])
        code, out, _ = _run(["chain", "export", str(cid)], s)
        doc = json.loads(out)
        for f in ("aborted_reason", "started_at", "finished_at",
                  "detection_debt"):
            self.assertIn(f, doc)

    def test_unknown_id_returns_2(self):
        s, _ = _make_store(self)
        code, _, err = _run(["chain", "export", "9999"], s)
        self.assertEqual(code, 2)
        self.assertIn("no chain", err)


class OutFileTest(unittest.TestCase):

    def test_out_flag_writes_to_file(self):
        s, tmp = _make_store(self)
        cid = _persist_chain(s, ["ok"] * 3)
        outp = os.path.join(tmp, "chain.json")
        code, stdout, _ = _run(
            ["chain", "export", str(cid), "--out", outp], s)
        self.assertEqual(code, 0)
        self.assertIn("wrote", stdout)
        with open(outp) as fh:
            doc = json.loads(fh.read())
        self.assertEqual(doc["id"], cid)


class ArgparseTest(unittest.TestCase):

    def test_chain_export_subparser_registered(self):
        from fieldkit.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["chain", "export", "5"])
        self.assertEqual(args.chain_command, "export")
        self.assertEqual(args.chain_id, 5)


if __name__ == "__main__":
    unittest.main()
