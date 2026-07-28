#!/usr/bin/env python3
"""Scope parsing: mixed client scope text -> (ip, hostname) pairs."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tempfile  # noqa: E402

from fieldkit.scope import (  # noqa: E402
    ARGV_ORIGIN, ScopeError, parse_entry, parse_scope, read_targets, subnet_of,
)


class EntryTest(unittest.TestCase):

    def test_bare_ip(self):
        self.assertEqual(parse_entry("10.0.0.5"), [("10.0.0.5", None)])

    def test_ip_with_hostname(self):
        self.assertEqual(parse_entry("10.0.0.5  WIN-SQL01"), [("10.0.0.5", "WIN-SQL01")])
        self.assertEqual(parse_entry("10.0.0.5,WIN-SQL01"), [("10.0.0.5", "WIN-SQL01")])

    def test_comments_and_blanks(self):
        self.assertEqual(parse_entry("  # out of scope: 10.0.0.9"), [])
        self.assertEqual(parse_entry("10.0.0.5  # the SQL box"), [("10.0.0.5", None)])

    def test_cidr_expands_to_usable_hosts(self):
        entries = parse_entry("10.0.0.0/29")
        self.assertEqual(len(entries), 6, "network and broadcast are skipped")
        self.assertEqual(entries[0][0], "10.0.0.1")

    def test_single_host_cidr(self):
        self.assertEqual(parse_entry("10.0.0.5/32"), [("10.0.0.5", None)])

    def test_expansion_limit(self):
        with self.assertRaises(ScopeError):
            parse_entry("10.0.0.0/16", max_expand=1024)

    def test_ipv6(self):
        self.assertEqual(parse_entry("dead:beef::1"), [("dead:beef::1", None)])

    def test_hostname_only_is_rejected(self):
        with self.assertRaises(ScopeError):
            parse_entry("dc01.corp.local")


class ScopeFileTest(unittest.TestCase):

    TEXT = """
    # ACME internal scope
    10.0.0.5    WIN-SQL01
    10.0.0.5
    10.0.0.6
    dc01.corp.local
    10.0.1.0/30
    """

    def test_parse(self):
        targets, errors = parse_scope(self.TEXT)
        self.assertEqual([t[0] for t in targets],
                         ["10.0.0.5", "10.0.0.6", "10.0.1.1", "10.0.1.2"])
        self.assertEqual(targets[0][1], "WIN-SQL01", "duplicates collapse, the name survives")
        self.assertEqual(len(errors), 1, "the un-resolvable name is reported")
        self.assertIn("dc01.corp.local", errors[0][1])

    def test_a_later_line_can_add_a_hostname(self):
        targets, _ = parse_scope("10.0.0.5\n10.0.0.5 WIN-SQL01\n")
        self.assertEqual(targets, [("10.0.0.5", "WIN-SQL01")])


class ReadTargetsTest(unittest.TestCase):
    """Literals and scope files, resolved together, with errors that point somewhere."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, name, text):
        path = os.path.join(self.tmp.name, name)
        with open(path, "w") as fh:
            fh.write(text)
        return path

    def test_literals_only(self):
        targets, errors = read_targets(["10.0.0.5", "10.0.0.6"])
        self.assertEqual([t[0] for t in targets], ["10.0.0.5", "10.0.0.6"])
        self.assertEqual(errors, [])

    def test_a_path_may_be_positional_or_behind_the_flag(self):
        a = self.write("a.txt", "10.0.0.5 WIN-SQL01\n")
        b = self.write("b.txt", "10.0.0.6\n")
        targets, _ = read_targets([a], file=b)
        self.assertEqual(sorted(targets), [("10.0.0.5", "WIN-SQL01"), ("10.0.0.6", None)])

    def test_files_and_literals_merge_and_dedupe(self):
        path = self.write("scope.txt", "10.0.0.5\n")
        targets, _ = read_targets([path, "10.0.0.5", "10.0.0.9"])
        self.assertEqual([t[0] for t in targets], ["10.0.0.5", "10.0.0.9"])

    def test_errors_name_their_origin_and_real_line(self):
        path = self.write("scope.txt", "10.0.0.5\ndc01.corp.local\n")
        targets, errors = read_targets([path, "also-not-an-ip"])
        self.assertEqual([t[0] for t in targets], ["10.0.0.5"])
        self.assertEqual([(e[0], e[1]) for e in errors],
                         [(path, 2), (ARGV_ORIGIN, 1)])

    def test_nothing_given(self):
        self.assertEqual(read_targets([]), ([], []))


class SubnetTest(unittest.TestCase):

    def test_ipv4_default_is_a_24(self):
        self.assertEqual(subnet_of("10.0.5.20"), "10.0.5.0/24")

    def test_ipv6_default_is_a_64(self):
        self.assertEqual(subnet_of("dead:beef::1"), "dead:beef::/64")


if __name__ == "__main__":
    unittest.main()
