#!/usr/bin/env python3
"""Engagement config: validation on write, and per-subnet callback addresses.

v1 sed-edited LHOST into tracked source; the hazard was pointing a payload at the
previous client's redirector. Config now lives in the engagement database, and every
value is checked when it is set — a typo fails at `config set`, not at callback time.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit.config import Config, ConfigError, load, parse_assignment  # noqa: E402
from fieldkit.state import StateError, Store  # noqa: E402


class ConfigTestCase(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store.create(os.path.join(self.tmp.name, "e.db"))
        self.addCleanup(self.store.close)
        self.store.init_engagement("ACME")
        self.cfg = Config(self.store)


class ValidationTest(ConfigTestCase):

    def test_valid_values(self):
        self.assertEqual(self.cfg.set("lhost", "10.10.14.7"), "10.10.14.7")
        self.assertEqual(self.cfg.set("lport", "443"), 443, "ports are stored as ints")
        self.assertEqual(self.cfg.set("domain", "corp.local"), "corp.local")
        self.assertEqual(self.cfg.set("webhost", "http://10.10.14.7:8000/"),
                         "http://10.10.14.7:8000")

    def test_ipv6_lhost(self):
        self.assertEqual(self.cfg.set("lhost", "dead:beef::1"), "dead:beef::1")

    def test_hostname_lhost_is_rejected(self):
        # A payload must not depend on the target resolving our name.
        with self.assertRaises(ConfigError):
            self.cfg.set("lhost", "attacker.example.com")

    def test_bad_port(self):
        for value in ("0", "70000", "https"):
            with self.assertRaises(ConfigError):
                self.cfg.set("lport", value)

    def test_bad_domain(self):
        with self.assertRaises(ConfigError):
            self.cfg.set("domain", "corp local!")

    def test_choice_keys(self):
        self.cfg.set("revtype_lin", "python")
        with self.assertRaises(ConfigError):
            self.cfg.set("revtype_lin", "powershell")  # a Windows delivery
        self.cfg.set("revtype_win", "nc")

    def test_unknown_key(self):
        with self.assertRaises(ConfigError):
            self.cfg.set("lhosts", "10.10.14.7")

    def test_defaults_are_reported_but_not_stored(self):
        self.assertEqual(self.cfg.get("lport"), 443)
        self.assertFalse(self.cfg.is_set("lport"))
        self.assertEqual(self.store.get_config(), {})

    def test_persistence(self):
        self.cfg.set("lhost", "10.10.14.7")
        self.assertEqual(load(self.store).get("lhost"), "10.10.14.7")

    def test_unset(self):
        self.cfg.set("lhost", "10.10.14.7")
        self.cfg.unset("lhost")
        self.assertIsNone(self.cfg.get("lhost"))
        with self.assertRaises(ConfigError):
            self.cfg.unset("lhost")

    def test_config_needs_an_engagement(self):
        store = Store.create(os.path.join(self.tmp.name, "empty.db"))
        self.addCleanup(store.close)
        with self.assertRaises(StateError):
            load(store)


class SubnetOverrideTest(ConfigTestCase):
    """A callback address that routes from one segment may not route from another."""

    def setUp(self):
        super().setUp()
        self.cfg.set("lhost", "10.10.14.7")
        self.cfg.set("lhost", "192.168.56.10", subnet="10.0.5.0/24")

    def test_override_applies_inside_the_subnet(self):
        self.assertEqual(self.cfg.lhost_for("10.0.5.20"), "192.168.56.10")

    def test_global_applies_outside(self):
        self.assertEqual(self.cfg.lhost_for("10.0.9.20"), "10.10.14.7")

    def test_most_specific_wins(self):
        self.cfg.set("lhost", "172.16.0.9", subnet="10.0.5.16/29")
        self.assertEqual(self.cfg.lhost_for("10.0.5.17"), "172.16.0.9")
        self.assertEqual(self.cfg.lhost_for("10.0.5.40"), "192.168.56.10")

    def test_host_address_is_normalized_to_its_network(self):
        self.cfg.set("lhost", "172.16.0.9", subnet="10.9.9.55/24")
        self.assertIn("10.9.9.0/24", self.cfg.overrides())

    def test_only_lhost_can_be_scoped(self):
        with self.assertRaises(ConfigError):
            self.cfg.set("lport", "8443", subnet="10.0.5.0/24")

    def test_bad_cidr(self):
        with self.assertRaises(ConfigError):
            self.cfg.set("lhost", "10.10.14.7", subnet="not-a-network")

    def test_unset_override(self):
        self.cfg.unset("lhost", subnet="10.0.5.0/24")
        self.assertEqual(self.cfg.lhost_for("10.0.5.20"), "10.10.14.7")
        with self.assertRaises(ConfigError):
            self.cfg.unset("lhost", subnet="10.0.5.0/24")

    def test_unresolvable_target_falls_back(self):
        self.assertEqual(self.cfg.lhost_for("not-an-ip"), "10.10.14.7")


class AssignmentTest(unittest.TestCase):

    def test_parse(self):
        self.assertEqual(parse_assignment("lhost=10.10.14.7"), ("lhost", "10.10.14.7"))
        self.assertEqual(parse_assignment("LHOST = 10.10.14.7 "), ("lhost", "10.10.14.7"))

    def test_password_style_values_keep_their_equals_signs(self):
        self.assertEqual(parse_assignment("client=ACME=Corp"), ("client", "ACME=Corp"))

    def test_rejects_bare_words(self):
        for bad in ("lhost", "=10.10.14.7"):
            with self.assertRaises(ConfigError):
                parse_assignment(bad)


if __name__ == "__main__":
    unittest.main()
