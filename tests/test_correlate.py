#!/usr/bin/env python3
"""Cross-engagement correlation — walk multiple engagements, surface
every (kind, value) that appears in two or more."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import correlate


class _FakeStore:
    """Minimal store shape — ``correlate._collect_from`` only needs
    ``credentials()`` + a connection with a ``host`` table reachable via
    ``store.conn.execute``."""
    def __init__(self, credentials=None, hosts=None):
        self._creds = credentials or []
        self._hosts = hosts or []

    def credentials(self):
        return self._creds

    class _FakeConn:
        def __init__(self, hosts):
            self._hosts = hosts
        def execute(self, sql, *args):
            # Only the host-select query is used.
            class _Cursor:
                def __init__(self, rows): self._rows = rows
                def fetchall(self): return self._rows
            return _Cursor(self._hosts)

    @property
    def conn(self):
        return self._FakeConn(self._hosts)


class TestCorrelateCredentials(unittest.TestCase):

    def test_shared_username_across_two_engagements(self):
        a = _FakeStore(credentials=[
            {"username": "alice", "secret": "SpringA", "secret_type": "password"}])
        b = _FakeStore(credentials=[
            {"username": "alice", "secret": "SpringB", "secret_type": "password"}])
        matches = correlate.correlate({"engA": a, "engB": b})
        self.assertTrue(any(m.kind == "username" and m.value == "alice"
                             for m in matches))

    def test_shared_credential_tuple_is_a_distinct_match(self):
        """(alice, Spring2024) in both engagements is a STRONGER signal
        than just alice in both — surface it as its own match."""
        a = _FakeStore(credentials=[
            {"username": "alice", "secret": "Spring2024", "secret_type": "password"}])
        b = _FakeStore(credentials=[
            {"username": "alice", "secret": "Spring2024", "secret_type": "password"}])
        matches = correlate.correlate({"engA": a, "engB": b})
        kinds = {m.kind for m in matches}
        self.assertIn("username", kinds)
        self.assertIn("credential", kinds)
        self.assertIn("secret", kinds)

    def test_single_engagement_matches_do_not_fire(self):
        """A credential seen in only one engagement is not a cross-match."""
        a = _FakeStore(credentials=[
            {"username": "alice", "secret": "x", "secret_type": "password"}])
        b = _FakeStore(credentials=[
            {"username": "bob", "secret": "y", "secret_type": "password"}])
        matches = correlate.correlate({"engA": a, "engB": b})
        self.assertEqual(matches, [])

    def test_usernames_match_case_insensitively(self):
        a = _FakeStore(credentials=[
            {"username": "Alice", "secret": "x", "secret_type": "password"}])
        b = _FakeStore(credentials=[
            {"username": "ALICE", "secret": "y", "secret_type": "password"}])
        matches = correlate.correlate({"engA": a, "engB": b})
        users = [m for m in matches if m.kind == "username"]
        self.assertTrue(users)
        self.assertEqual(users[0].value, "alice")


class TestCorrelateHosts(unittest.TestCase):

    def test_shared_ip(self):
        a = _FakeStore(hosts=[{"ip": "10.0.0.5", "hostname": "dc01"}])
        b = _FakeStore(hosts=[{"ip": "10.0.0.5", "hostname": None}])
        matches = correlate.correlate({"engA": a, "engB": b})
        self.assertTrue(any(m.kind == "host" and m.value == "10.0.0.5"
                             for m in matches))

    def test_shared_hostname_case_insensitive(self):
        a = _FakeStore(hosts=[{"ip": "10.0.0.5", "hostname": "DC01"}])
        b = _FakeStore(hosts=[{"ip": "10.0.0.6", "hostname": "dc01"}])
        matches = correlate.correlate({"engA": a, "engB": b})
        hostnames = [m for m in matches if m.kind == "host" and m.value == "dc01"]
        self.assertTrue(hostnames)


class TestCorrelateOutputShape(unittest.TestCase):

    def test_engagements_tuple_is_sorted_and_unique(self):
        a = _FakeStore(credentials=[{"username": "alice", "secret": None}])
        b = _FakeStore(credentials=[{"username": "alice", "secret": None}])
        c = _FakeStore(credentials=[{"username": "alice", "secret": None}])
        matches = correlate.correlate({"engC": c, "engA": a, "engB": b})
        um = [m for m in matches if m.kind == "username"][0]
        self.assertEqual(um.engagements, ("engA", "engB", "engC"))

    def test_results_sorted_by_kind_then_value(self):
        a = _FakeStore(
            credentials=[{"username": "zeta", "secret": None},
                         {"username": "alpha", "secret": None}],
            hosts=[{"ip": "10.0.0.1", "hostname": None}])
        b = _FakeStore(
            credentials=[{"username": "alpha", "secret": None},
                         {"username": "zeta", "secret": None}],
            hosts=[{"ip": "10.0.0.1", "hostname": None}])
        matches = correlate.correlate({"engA": a, "engB": b})
        # alphabetical on (kind, value): host before username; alpha before zeta
        pairs = [(m.kind, m.value) for m in matches]
        self.assertEqual(pairs, sorted(pairs))

    def test_match_is_frozen(self):
        m = correlate.Match(kind="x", value="y", engagements=("e1", "e2"))
        with self.assertRaises(Exception):
            m.kind = "modified"


class TestCorrelateDegenerate(unittest.TestCase):

    def test_empty_stores_dict_returns_nothing(self):
        self.assertEqual(correlate.correlate({}), [])

    def test_single_engagement_returns_nothing(self):
        a = _FakeStore(credentials=[{"username": "alice", "secret": "x"}])
        self.assertEqual(correlate.correlate({"only": a}), [])

    def test_store_without_credentials_method(self):
        class NoCreds:
            class _Conn:
                def execute(self, *a):
                    class C:
                        def fetchall(self): return []
                    return C()
            @property
            def conn(self): return self._Conn()
        self.assertEqual(correlate.correlate({"e1": NoCreds(), "e2": NoCreds()}), [])


if __name__ == "__main__":
    unittest.main()
