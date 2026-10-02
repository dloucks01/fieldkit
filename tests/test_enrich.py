#!/usr/bin/env python3
"""Analysis-depth enrichment — entity extractor + hashcat mode suggestion.

Load-bearing invariants:
  * extractor is PURE: no I/O, no state. A string in, entities out.
  * entity patterns do NOT fire on documentation ranges (TEST-NET),
    loopback IPs, or the empty LM hash — those are shape-collisions
    that would clutter the output;
  * hashcat mode suggestion matches the extractor's kinds (no divergence
    between the two layers);
  * extract_from_steps dedupes by (kind, value) preserving first context.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import enrich


class TestExtractEntitiesIPv4(unittest.TestCase):

    def _kinds(self, text):
        return {(e.kind, e.value) for e in enrich.extract_entities(text)}

    def test_extracts_plain_ipv4(self):
        self.assertIn(("ipv4", "10.0.0.5"),
                      self._kinds("found 10.0.0.5 on wire"))

    def test_rejects_loopback(self):
        self.assertNotIn(("ipv4", "127.0.0.1"), self._kinds("127.0.0.1"))

    def test_rejects_any_address(self):
        self.assertNotIn(("ipv4", "0.0.0.0"), self._kinds("0.0.0.0"))

    def test_rejects_test_net_ranges(self):
        self.assertNotIn(("ipv4", "192.0.2.10"), self._kinds("192.0.2.10"))
        self.assertNotIn(("ipv4", "198.51.100.1"), self._kinds("198.51.100.1"))
        self.assertNotIn(("ipv4", "203.0.113.5"), self._kinds("203.0.113.5"))

    def test_rejects_out_of_range_octets(self):
        self.assertNotIn(("ipv4", "999.999.999.999"),
                         self._kinds("999.999.999.999"))

    def test_rejects_leading_zero_octets(self):
        """``010.0.0.1`` is ambiguous (octal in some parsers) — reject."""
        self.assertNotIn(("ipv4", "010.0.0.1"), self._kinds("010.0.0.1"))

    def test_extracts_multiple_ipv4_in_one_line(self):
        text = "forward from 10.0.0.5 to 192.168.1.10 via 172.16.0.1"
        found = {v for (k, v) in self._kinds(text) if k == "ipv4"}
        self.assertEqual(found, {"10.0.0.5", "192.168.1.10", "172.16.0.1"})


class TestExtractEntitiesHashShapes(unittest.TestCase):

    def _kinds(self, text):
        return [(e.kind, e.value) for e in enrich.extract_entities(text)]

    def test_extracts_nt_hash(self):
        text = "alice:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"
        kinds = self._kinds(text)
        # Empty LM hash should NOT fire as a plain nt_hash
        self.assertNotIn(("nt_hash", "aad3b435b51404eeaad3b435b51404ee"), kinds)
        self.assertIn(("nt_hash", "31d6cfe0d16ae931b73c59d7e0c089c0"), kinds)

    def test_rejects_single_char_repeats_as_hash(self):
        """``aaaaaaaa...`` 32 chars is not a hash in practice — don't fire."""
        self.assertEqual(self._kinds("a" * 32), [])

    def test_extracts_netntlmv2(self):
        responder = "user::DOMAIN:1122334455667788:3B4F4D4F4D4F4D4F4D4F4D4F4D4F4D4F:0101000000000000"
        kinds = self._kinds(responder)
        got = [v for (k, v) in kinds if k == "netntlmv2"]
        self.assertTrue(got)
        self.assertTrue(got[0].startswith("user::DOMAIN:"))

    def test_netntlmv2_wins_over_nested_nt_hash(self):
        """A NetNTLMv2 line contains a 32-hex NT hash substring — the
        longer-shape kind must win so the output doesn't duplicate it as
        both netntlmv2 AND nt_hash."""
        text = "user::DOM:1122334455667788:3B4F4D4F4D4F4D4F4D4F4D4F4D4F4D4F:0101000000000000"
        found_kinds = {k for (k, v) in self._kinds(text)}
        self.assertIn("netntlmv2", found_kinds)
        self.assertNotIn("nt_hash", found_kinds)

    def test_extracts_kerberos_tgs(self):
        text = "service$: $krb5tgs$23$*admin$DOM$svc*$aa$ff...truncated"
        got = [v for (k, v) in self._kinds(text) if k == "kerberos_tgsrep"]
        self.assertTrue(got)

    def test_extracts_kerberos_asrep(self):
        text = "$krb5asrep$23$user@DOMAIN:aa$ff..."
        got = [v for (k, v) in self._kinds(text) if k == "kerberos_asrep"]
        self.assertTrue(got)

    def test_extracts_bcrypt(self):
        bc = "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"
        got = [v for (k, v) in self._kinds(f"root:{bc}:19000:0:99999:7:::")
               if k == "bcrypt_hash"]
        self.assertEqual(got, [bc])

    def test_extracts_sha512crypt(self):
        h = "$6$abcdefgh$" + "." * 86
        self.assertIn(("sha512crypt", h), self._kinds(h))

    def test_extracts_md5crypt(self):
        h = "$1$abc$" + "." * 22
        self.assertIn(("md5crypt", h), self._kinds(h))


class TestExtractEntitiesEmailAndURL(unittest.TestCase):

    def test_email(self):
        got = {e.value for e in enrich.extract_entities(
            "contact alice@example.com for details")}
        self.assertIn("alice@example.com", got)

    def test_url(self):
        got = {(e.kind, e.value) for e in enrich.extract_entities(
            "visit https://corp.local/admin and http://10.0.0.5/api")}
        self.assertIn(("url", "https://corp.local/admin"), got)
        self.assertIn(("url", "http://10.0.0.5/api"), got)

    def test_email_does_not_eat_user_at_file_path(self):
        """``root@/etc/passwd`` is tool output, not a real email."""
        got = {e.value for e in enrich.extract_entities(
            "root@/etc/passwd notation")}
        self.assertNotIn("root@/etc/passwd", got)


class TestExtractEntitiesCloudAndPATs(unittest.TestCase):

    def test_aws_access_key(self):
        got = {e.value for e in enrich.extract_entities(
            "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")}
        self.assertIn("AKIAIOSFODNN7EXAMPLE", got)

    def test_aws_temporary_access_key(self):
        # AWS access keys are exactly 20 chars: 4-char prefix + 16 chars.
        got = {e.value for e in enrich.extract_entities(
            "STS: ASIA" + "X" * 16 + " more")}
        self.assertTrue(any(v.startswith("ASIA") for v in got),
                        f"got: {got}")

    def test_github_pat(self):
        tok = "ghp_" + "A" * 36
        got = {e.value for e in enrich.extract_entities(
            f"GITHUB_TOKEN={tok}")}
        self.assertIn(tok, got)

    def test_github_fine_grained_pat(self):
        tok = "github_pat_" + "A" * 50
        got = {e.value for e in enrich.extract_entities(tok)}
        self.assertIn(tok, got)

    def test_gitlab_pat(self):
        tok = "glpat-" + "A" * 20
        got = {e.value for e in enrich.extract_entities(tok)}
        self.assertIn(tok, got)

    def test_slack_bot_token(self):
        tok = "xoxb-1234567890-abcdef"
        got = {e.value for e in enrich.extract_entities(f"token: {tok}")}
        self.assertIn(tok, got)

    def test_stripe_live_secret(self):
        tok = "sk_live_" + "A" * 24
        got = {e.value for e in enrich.extract_entities(tok)}
        self.assertIn(tok, got)


class TestExtractEntitiesContextAttached(unittest.TestCase):

    def test_entity_carries_its_line_as_context(self):
        text = "line one — no match\nline two: ip is 10.0.0.5 here\nline three"
        ents = [e for e in enrich.extract_entities(text) if e.value == "10.0.0.5"]
        self.assertEqual(len(ents), 1)
        self.assertIn("line two", ents[0].context)

    def test_context_truncates_long_lines(self):
        """Lines over 160 chars get an ellipsis — don't flood the terminal."""
        long = "x" * 200 + " 10.0.0.5 " + "y" * 50
        ents = enrich.extract_entities(long)
        for e in ents:
            self.assertLessEqual(len(e.context), 162)  # 160 + ellipsis


class TestSuggestHashcatMode(unittest.TestCase):

    def test_nt_hash_maps_to_1000(self):
        mode = enrich.suggest_hashcat_mode(
            "31d6cfe0d16ae931b73c59d7e0c089c0")
        self.assertEqual(mode, (1000, "NTLM"))

    def test_netntlmv2_maps_to_5600(self):
        mode = enrich.suggest_hashcat_mode(
            "user::DOM:1122334455667788:3B4F4D4F4D4F4D4F4D4F4D4F4D4F4D4F:0101000000000000")
        self.assertEqual(mode[0], 5600)

    def test_kerberos_tgs_maps_to_13100(self):
        mode = enrich.suggest_hashcat_mode(
            "$krb5tgs$23$*admin$DOM$svc*$aabbcc$ff...")
        self.assertEqual(mode[0], 13100)

    def test_kerberos_asrep_maps_to_18200(self):
        mode = enrich.suggest_hashcat_mode(
            "$krb5asrep$23$user@DOM:aabbcc$ff...")
        self.assertEqual(mode[0], 18200)

    def test_bcrypt_maps_to_3200(self):
        bc = "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"
        self.assertEqual(enrich.suggest_hashcat_mode(bc)[0], 3200)

    def test_sha512crypt_maps_to_1800(self):
        h = "$6$abcdefgh$" + "." * 86
        self.assertEqual(enrich.suggest_hashcat_mode(h)[0], 1800)

    def test_md5crypt_maps_to_500(self):
        h = "$1$abc$" + "." * 22
        self.assertEqual(enrich.suggest_hashcat_mode(h)[0], 500)

    def test_nt_lm_pair_promotes_to_nt(self):
        """A ``LMhash:NThash`` pair (secretsdump shape) resolves to NTLM mode."""
        pair = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        self.assertEqual(enrich.suggest_hashcat_mode(pair)[0], 1000)

    def test_unknown_shape_returns_none(self):
        self.assertIsNone(enrich.suggest_hashcat_mode("not-a-hash"))

    def test_empty_input_returns_none(self):
        self.assertIsNone(enrich.suggest_hashcat_mode(""))


class TestExtractFromSteps(unittest.TestCase):

    def test_dedupes_across_steps(self):
        rows = [
            {"output": "found 10.0.0.5 on wire"},
            {"output": "replay 10.0.0.5 again"},  # dup
            {"output": "new host 10.0.0.9"},
        ]
        ents = enrich.extract_from_steps(rows)
        ips = {v for (k, v, _c) in ents if k == "ipv4"}
        self.assertEqual(ips, {"10.0.0.5", "10.0.0.9"})

    def test_first_context_wins(self):
        rows = [
            {"output": "first match: 10.0.0.5 context one"},
            {"output": "second match: 10.0.0.5 context two"},
        ]
        ents = {(k, v): c for (k, v, c) in enrich.extract_from_steps(rows)}
        self.assertIn("context one", ents[("ipv4", "10.0.0.5")])
        self.assertNotIn("context two", ents[("ipv4", "10.0.0.5")])

    def test_handles_empty_output_rows(self):
        rows = [{"output": None}, {"output": ""}, {"output": "10.0.0.5"}]
        ents = enrich.extract_from_steps(rows)
        self.assertEqual([(k, v) for (k, v, _c) in ents], [("ipv4", "10.0.0.5")])

    def test_accepts_plain_strings_too(self):
        """Simple adapter path for tests + ad-hoc use."""
        ents = enrich.extract_from_steps(["10.0.0.5", "10.0.0.9"])
        self.assertEqual(len({v for (k, v, _c) in ents}), 2)


class TestEntityIsImmutable(unittest.TestCase):
    """The dataclass must be frozen so entities can go into a set / dict key."""

    def test_entity_is_frozen(self):
        e = enrich.Entity(kind="ipv4", value="10.0.0.5", context="x")
        with self.assertRaises(Exception):
            e.kind = "modified"

    def test_entities_are_hashable(self):
        a = enrich.Entity(kind="ipv4", value="10.0.0.5")
        b = enrich.Entity(kind="ipv4", value="10.0.0.5")
        self.assertEqual({a, b}, {a})


if __name__ == "__main__":
    unittest.main()
