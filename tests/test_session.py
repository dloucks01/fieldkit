#!/usr/bin/env python3
"""Session record + replay — every fieldkit invocation as a
JSONL log for reproducible playback.

Pins:

  * is_recording_enabled reads FIELDKIT_SESSION_LOG;
  * should_record skips session-management subcommands;
  * record appends one JSONL entry;
  * record silently no-ops when env-var unset;
  * read handles malformed lines (skips silently);
  * replay re-runs each entry in order via injected main_fn;
  * replay --dry-run doesn't execute;
  * CLI: session log --enable prints export line;
  * CLI: session show renders entries;
  * CLI: session replay re-runs recorded invocations.
"""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class RecordingEnabledTest(unittest.TestCase):

    def test_env_var_unset_disables(self):
        from fieldkit import session
        os.environ.pop(session.ENV_VAR, None)
        self.assertFalse(session.is_recording_enabled())
        self.assertIsNone(session.log_path())

    def test_env_var_set_enables(self):
        from fieldkit import session
        os.environ[session.ENV_VAR] = "/tmp/x.jsonl"
        self.addCleanup(lambda: os.environ.pop(session.ENV_VAR, None))
        self.assertTrue(session.is_recording_enabled())
        self.assertEqual(session.log_path(), "/tmp/x.jsonl")

    def test_env_var_empty_string_disables(self):
        from fieldkit import session
        os.environ[session.ENV_VAR] = ""
        self.addCleanup(lambda: os.environ.pop(session.ENV_VAR, None))
        self.assertFalse(session.is_recording_enabled())


class ShouldRecordTest(unittest.TestCase):

    def test_bare_command_records(self):
        from fieldkit import session
        self.assertTrue(session.should_record(["analyze"]))

    def test_session_subcommand_skipped(self):
        from fieldkit import session
        # A session-management subcommand doesn't record itself
        # (would cause replay loops).
        self.assertFalse(session.should_record(["session", "show", "log.jsonl"]))
        self.assertFalse(session.should_record(["session", "replay", "log.jsonl"]))

    def test_empty_argv_skipped(self):
        from fieldkit import session
        self.assertFalse(session.should_record([]))


class RecordTest(unittest.TestCase):

    def _tmp_log(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return os.path.join(tmp.name, "s.jsonl")

    def test_record_writes_jsonl_entry(self):
        from fieldkit import session
        path = self._tmp_log()
        entry = session.record(["analyze"], exit_code=0,
                                 duration_ms=42, path=path)
        self.assertIsNotNone(entry)
        with open(path) as fh:
            lines = fh.readlines()
        self.assertEqual(len(lines), 1)
        doc = json.loads(lines[0])
        self.assertEqual(doc["argv"], ["analyze"])
        self.assertEqual(doc["exit_code"], 0)
        self.assertEqual(doc["duration_ms"], 42)
        self.assertIn("timestamp", doc)
        self.assertIn("cwd", doc)

    def test_record_appends_multiple_entries(self):
        from fieldkit import session
        path = self._tmp_log()
        session.record(["analyze"], exit_code=0, duration_ms=10, path=path)
        session.record(["status"], exit_code=0, duration_ms=5, path=path)
        entries = session.read(path)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].argv, ["analyze"])
        self.assertEqual(entries[1].argv, ["status"])

    def test_record_returns_none_when_no_path(self):
        from fieldkit import session
        os.environ.pop(session.ENV_VAR, None)
        self.assertIsNone(session.record(["analyze"], 0, 10))

    def test_record_skips_session_subcommand(self):
        from fieldkit import session
        path = self._tmp_log()
        result = session.record(["session", "show", "x.jsonl"],
                                  0, 10, path=path)
        self.assertIsNone(result)
        self.assertFalse(os.path.exists(path))


class ReadTest(unittest.TestCase):

    def test_read_skips_malformed_lines(self):
        from fieldkit import session
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "s.jsonl")
        with open(path, "w") as fh:
            fh.write('{"timestamp":"t","cwd":"/","argv":["a"],'
                     '"exit_code":0,"duration_ms":1}\n')
            fh.write("garbage line\n")
            fh.write('{"timestamp":"t2","cwd":"/","argv":["b"],'
                     '"exit_code":0,"duration_ms":1}\n')
        entries = session.read(path)
        self.assertEqual(len(entries), 2)   # garbage line skipped
        self.assertEqual([e.argv for e in entries], [["a"], ["b"]])

    def test_read_missing_file_returns_empty(self):
        from fieldkit import session
        self.assertEqual(session.read("/nonexistent/foo.jsonl"), [])


class ReplayTest(unittest.TestCase):

    def _log_with(self, entries):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "s.jsonl")
        with open(path, "w") as fh:
            for e in entries:
                fh.write(json.dumps(e) + "\n")
        return path

    def test_replay_calls_main_for_each_entry(self):
        from fieldkit import session
        path = self._log_with([
            {"timestamp": "t1", "cwd": "/", "argv": ["a"],
             "exit_code": 0, "duration_ms": 1},
            {"timestamp": "t2", "cwd": "/", "argv": ["b", "--flag"],
             "exit_code": 0, "duration_ms": 1},
        ])
        called = []
        def _fake_main(argv):
            called.append(list(argv))
            return 0
        results = session.replay(path, main_fn=_fake_main)
        self.assertEqual(called, [["a"], ["b", "--flag"]])
        self.assertEqual([rc for _, rc in results], [0, 0])

    def test_replay_dry_run_does_not_execute(self):
        from fieldkit import session
        path = self._log_with([
            {"timestamp": "t1", "cwd": "/", "argv": ["a"],
             "exit_code": 0, "duration_ms": 1},
        ])
        called = []
        results = session.replay(path,
                                    main_fn=lambda a: called.append(a) or 0,
                                    dry_run=True)
        self.assertEqual(called, [])
        self.assertEqual([rc for _, rc in results], [None])

    def test_replay_on_entry_fires_per_entry(self):
        from fieldkit import session
        path = self._log_with([
            {"timestamp": "t1", "cwd": "/", "argv": ["a"],
             "exit_code": 0, "duration_ms": 1},
            {"timestamp": "t2", "cwd": "/", "argv": ["b"],
             "exit_code": 0, "duration_ms": 1},
        ])
        events = []
        session.replay(path, main_fn=lambda a: 7,
                        on_entry=lambda e, rc: events.append((e.argv, rc)))
        self.assertEqual(events, [(["a"], 7), (["b"], 7)])


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

    def test_session_log_enable_prints_export(self):
        code, out, _ = self._run([
            "session", "log", "--enable", "--out", "/tmp/x.jsonl"])
        self.assertEqual(code, 0)
        self.assertIn("export FIELDKIT_SESSION_LOG=/tmp/x.jsonl", out)

    def test_session_log_disable_prints_unset(self):
        code, out, _ = self._run(["session", "log", "--disable"])
        self.assertEqual(code, 0)
        self.assertIn("unset FIELDKIT_SESSION_LOG", out)

    def test_session_show_renders_entries(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "s.jsonl")
        with open(path, "w") as fh:
            fh.write('{"timestamp":"2026-01-01T00:00:00","cwd":"/",'
                     '"argv":["analyze"],"exit_code":0,'
                     '"duration_ms":42}\n')
        code, out, _ = self._run(["session", "show", path])
        self.assertEqual(code, 0)
        self.assertIn("analyze", out)
        self.assertIn("42ms", out)

    def test_session_show_empty_returns_1(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "empty.jsonl")
        open(path, "w").close()
        code, _, err = self._run(["session", "show", path])
        self.assertEqual(code, 1)
        self.assertIn("no entries", err)


if __name__ == "__main__":
    unittest.main()
