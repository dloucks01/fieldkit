#!/usr/bin/env python3
"""Wordlist mutation — seeds + rules → a password list.

Pinned:

  * pure — same input always yields the same output (no timestamps, no random);
  * bounded by construction: `max_output` caps the run and defaults keep single-seed
    output under 200 words, multi-seed under 3000;
  * high-value shapes come first, so truncation cuts the tail (least-common leet
    combos), not the head (Company + year + symbol — the classic real-world hit);
  * min/max length filters out noise (too-short seeds like "IBM" and too-long
    experimental strings);
  * duplicates are collapsed but insertion order is preserved (deterministic).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import wordlist  # noqa: E402


class GenerateTest(unittest.TestCase):
    def test_single_seed_produces_bounded_useful_list(self):
        rep = wordlist.generate(["Acme"], years=[2024, 2025])
        # not too small, not runaway; the classic shapes are early
        self.assertGreater(rep.total, 30)
        self.assertLess(rep.total, 300)
        # the high-value shapes exist and appear early
        first_50 = set(rep.words[:50])
        self.assertIn("Acme2024", first_50)
        self.assertIn("Acme2024!", first_50)
        self.assertIn("Acme2025!", first_50)
        self.assertIn("Acme123", first_50)      # 7 chars; "Acme!" (5) filtered by min_len=6
        # leet is applied but doesn't dominate
        self.assertTrue(any("@" in w for w in rep.words))   # e.g. Acme@2024 or @cme

    def test_length_filter_drops_short_and_long(self):
        rep = wordlist.generate(["IBM"], min_len=6, max_len=32)
        # "IBM" (3) and "IBM!" (4) and "IBM1" (4) are all filtered
        self.assertNotIn("IBM", rep.words)
        self.assertNotIn("IBM!", rep.words)
        # "IBM2024" (7) passes
        self.assertIn("IBM2024", rep.words)

    def test_no_seeds_returns_empty(self):
        rep = wordlist.generate([])
        self.assertEqual(rep.total, 0)
        self.assertEqual(rep.words, [])

    def test_deterministic_order_and_no_duplicates(self):
        rep1 = wordlist.generate(["Acme", "Corp"], years=[2024])
        rep2 = wordlist.generate(["Acme", "Corp"], years=[2024])
        self.assertEqual(rep1.words, rep2.words)                 # deterministic
        self.assertEqual(len(rep1.words), len(set(rep1.words)))  # no dupes

    def test_max_output_truncates(self):
        rep = wordlist.generate(["A", "B", "C", "D", "E"], years=[2024, 2025],
                                 seasons=True, combine=True, max_output=50)
        self.assertLessEqual(len(rep.words), 50)
        self.assertTrue(rep.truncated)

    def test_disabled_rules_dont_appear(self):
        rep = wordlist.generate(["Winter"], cases=False, leet=False, suffixes=True)
        # only cases-off produces one form of each suffix'd seed
        self.assertIn("Winter2024", rep.words)
        self.assertNotIn("winter2024", rep.words)  # lower-case variant off
        self.assertNotIn("Wint3r2024", rep.words)   # leet off

    def test_combine_produces_seed_pairs(self):
        rep = wordlist.generate(["Acme", "Widget"], combine=True, cases=False,
                                 leet=False)
        # both concats appear at least once with a common suffix
        self.assertTrue(any(w.startswith("AcmeWidget") for w in rep.words))
        self.assertTrue(any(w.startswith("WidgetAcme") for w in rep.words))

    def test_seasons_expands_seed_pool(self):
        rep = wordlist.generate(["Acme"], seasons=True, cases=False, leet=False)
        # every season lands in the pool → suffix'd
        self.assertTrue(any(w.startswith("Winter") for w in rep.words))
        self.assertTrue(any(w.startswith("Summer") for w in rep.words))

    def test_extra_suffixes_are_honored(self):
        rep = wordlist.generate(["Acme"], extra_suffixes=["ROCKS"],
                                 cases=False, leet=False)
        self.assertIn("AcmeROCKS", rep.words)

    def test_years_produce_common_variants(self):
        rep = wordlist.generate(["Acme"], years=[2024], cases=False, leet=False)
        for pat in ("Acme2024", "Acme2024!", "Acme2024@", "Acme2024#"):
            self.assertIn(pat, rep.words, f"missing {pat}")


class CaseAndLeetTest(unittest.TestCase):
    def test_cases_covers_first_upper_lower(self):
        variants = set(wordlist._cases("Winter"))
        self.assertEqual(variants, {"Winter", "winter", "WINTER"})

    def test_lowercase_input_gets_first_and_upper(self):
        variants = set(wordlist._cases("acme"))
        self.assertIn("acme", variants)
        self.assertIn("Acme", variants)
        self.assertIn("ACME", variants)

    def test_leet_yields_single_char_substitutions(self):
        variants = set(wordlist._leet_variants("winter"))
        self.assertIn("winter", variants)                       # original
        self.assertIn("w1nter", variants)                       # i→1
        self.assertIn("win7er", variants)                       # t→7
        # multi-substitution not generated (would be "w1n73r" etc.)
        self.assertNotIn("w1n7er", variants)


class SeedsFromTextTest(unittest.TestCase):
    def test_extracts_dedup_preserves_order(self):
        text = "About Acme Corp — Acme is a leading Widget provider."
        seeds = wordlist.seeds_from_text(text)
        self.assertEqual(seeds[:4], ["About", "Acme", "Corp", "leading"])
        self.assertEqual(seeds.count("Acme"), 1)                # dedup

    def test_short_and_pure_number_words_are_dropped(self):
        seeds = wordlist.seeds_from_text("in 1987 IBM built OS/2")
        # "in" (too short), "1987" (numeric-only after strip), "OS" (too short)
        self.assertNotIn("in", seeds)
        self.assertIn("IBM", seeds)


class UsernamesTest(unittest.TestCase):
    def test_default_patterns_cover_common_schemas(self):
        users = wordlist.usernames(["John"], ["Doe"])
        for expected in ("john", "doe", "john.doe", "johndoe", "jdoe",
                          "doej", "j.doe", "doe.john"):
            self.assertIn(expected, users, f"missing {expected}")

    def test_custom_patterns_override_defaults(self):
        users = wordlist.usernames(["John"], ["Doe"], patterns=("{f}{last}",))
        self.assertEqual(users, ["jdoe"])

    def test_dedup_across_first_last_pairs(self):
        # "jdoe" would be produced by both (John, Doe) and (Jane, Doe) via {f}{last}?
        # No — "jdoe" vs "jdoe" — same string, deduped
        users = wordlist.usernames(["John", "Jane"], ["Doe"],
                                    patterns=("{f}{last}",))
        # Jane's is "jdoe" too (same first initial); dedup means one row
        # ...but Jane → j → jdoe same as John → j → jdoe. Confirm.
        self.assertEqual(users, ["jdoe"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
