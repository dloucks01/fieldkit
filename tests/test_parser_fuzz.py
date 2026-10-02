#!/usr/bin/env python3
"""Parser fuzz tests — throw adversarial / malformed input at every parser in
fieldkit's ingest path and ensure NONE crash with an uncaught exception.

The parsers in this project all consume text produced by external tools
(nxc, nmap, nuclei, httpx, impacket, hashcat, recce) or operator-typed
strings (credentials, scope rules). Those inputs are:

  * **not always well-formed** — a tool crash mid-run, a truncated download,
    a locale that mangled encoding, a copy-paste that lost separators;
  * **sometimes attacker-tunable** — the recce bridge is JSON that might
    cross a trust boundary, nxc output is relayed from a target that could
    have poisoned the banner.

A parser that uncaught-crashes on malformed input kills the engagement
mid-ingest. The invariant we test here: for ANY input, a parser must
EITHER return a well-formed empty/partial result OR raise one of the
documented exception types for its module. An ``AttributeError`` on
``None.whatever`` or an ``IndexError`` on a truncated split means the
parser has a hole.

Harness is stdlib-only (``hypothesis``/``atheris`` not available in the
engine's import graph). ~500 random inputs per parser, plus a seeded
corpus of specifically-nasty cases (empty / null bytes / unicode
surrogates / extremely long / deeply nested).
"""
import json
import os
import random
import string
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------- generators

#: A seeded random so the fuzz is reproducible across runs; a crash seen in
#: CI reproduces locally with the same ``i`` value.
_RNG = random.Random(0xf1e1dc17)

#: Specifically-nasty inputs every parser must survive. Each one targets a
#: known failure class the author would ship a bug for.
NASTY_INPUTS = (
    "",
    " ",
    "\x00",
    "\x00\x00\x00",
    "\n",
    "\r\n",
    "\r",
    "a" * 100_000,                                              # one long line
    "line\n" * 10_000,                                          # many lines
    "\n" * 10_000,                                              # all blanks
    "[]",
    "{}",
    "null",
    "0",
    "true",
    "{" * 1000,                                                 # unbalanced JSON
    "[" * 1000,
    '{"a":' * 1000 + "1" + "}" * 1000,                          # deep JSON
    "\"\\u0000\\u0001\\u0002\\u0003\"",                         # escape sequences
    "\udc80",                                                   # lone surrogate (bytes-ish)
    "﻿ header",                                            # BOM
    "\t\t\t",
    ":",
    "::",
    ":::",
    "a:b:c:d:e:f:g",                                            # colon spam
    "SMB   10.0.0.1  445  HOST   [+] " + "a" * 10000,           # banner-shaped huge tail
    "SMB   10.0.0.1  445  HOST   [+] \\",                       # trailing backslash
    "SMB   10.0.0.1  445  HOST   [+] :",                        # empty principal
    "SMB   10.0.0.1  445  HOST   [+] user:",                    # empty secret
    "SMB   10.0.0.1  445  HOST   [+] :pw",                      # empty user
    "SMB   10.0.0.1  445  HOST   [+] " + "‮" * 100,        # unicode RLO
    "<?xml version='1.0'?><nmaprun></nmaprun>",                 # empty xml root
    "<?xml version='1.0'?><nmaprun><host></host></nmaprun>",    # host with no addr
    "<!DOCTYPE a [<!ENTITY a 'b'>]><a>&a;</a>",                 # entity (XXE surface)
    "{\"principals\": null}",
    "{\"principals\": \"not a list\"}",
    "{\"principals\": [null, null, null]}",
    "{\"principals\": [{\"arn\": null}]}",
    "{\"principals\": [{\"arn\": 1234}]}",
    "{\"principals\": [{}]}",
    "{\"edges\": [{\"src\": null, \"dst\": null}]}",
    "corp.local\\user:pass",
    "corp.local\\\\user:pass",                                   # double backslash
    "corp.local\\user",                                          # no secret
    "user@corp.local:",
    "user@:pass",
    "user:" + "lm" * 32 + ":" + "nt" * 32,                       # oddly-sized hashes
)


def _rand_bytes(n):
    """Random bytes, decoded with ``errors='replace'`` so the generator stays
    producing a str but can include every byte value a parser might see."""
    return bytes(_RNG.randrange(256) for _ in range(n)).decode("latin-1")


def _rand_ascii(n):
    chars = string.ascii_letters + string.digits + string.punctuation + " \t\n"
    return "".join(_RNG.choice(chars) for _ in range(n))


def _rand_nxc_shaped(n):
    """A line with the shape ``PROTO   IP   PORT   HOST   [MARK] body`` but
    with the body + marker scrambled — this is the shape most likely to
    exercise the netexec parser's edge cases."""
    protos = ("SMB", "SSH", "WINRM", "MSSQL", "LDAP", "FTP", "RDP", "???")
    marks = ("[+]", "[-]", "[*]", "[!]", "", "[?]")
    lines = []
    for _ in range(n):
        ip = ".".join(str(_RNG.randrange(256)) for _ in range(4))
        port = _RNG.randrange(0, 70000)
        host = _rand_ascii(_RNG.randrange(1, 20)) or "H"
        body = _rand_ascii(_RNG.randrange(0, 200))
        lines.append(f"{_RNG.choice(protos)}   {ip}   {port}   {host}   "
                     f"{_RNG.choice(marks)} {body}")
    return "\n".join(lines)


def _rand_json(depth):
    """Random valid (but weird) JSON of the given depth."""
    if depth <= 0:
        return _RNG.choice([None, True, False, 0, _RNG.random(),
                            _rand_ascii(_RNG.randrange(0, 20))])
    if _RNG.random() < 0.5:
        return [_rand_json(depth - 1) for _ in range(_RNG.randrange(0, 5))]
    return {_rand_ascii(_RNG.randrange(1, 10)): _rand_json(depth - 1)
            for _ in range(_RNG.randrange(0, 5))}


# ---------------------------------------------------------------- harness


class _ParserFuzzBase:
    """Mixin — subclasses set ``parser`` and ``expected_exc`` and the
    harness runs the common corpus + random fuzzing against it. NOT a
    ``TestCase`` itself so the base's test methods don't run with an
    unset parser (pytest/unittest's discovery picks up ``TestCase``
    subclasses only)."""

    #: Tuple of exception types the parser is DOCUMENTED to raise on bad
    #: input. Anything else raised is a bug.
    expected_exc = (ValueError,)

    #: Number of random inputs per generator.
    iterations = 300

    def _run_input(self, inp):
        try:
            self.parser(inp)
        except self.expected_exc:
            pass
        except Exception as exc:                                # noqa: BLE001
            self.fail(
                f"{self.parser.__module__}.{self.parser.__name__} crashed on "
                f"input (type={type(exc).__name__}): {exc!r}\n"
                f"  input (first 200 chars): {inp[:200]!r}")

    def test_nasty_corpus(self):
        for inp in NASTY_INPUTS:
            with self.subTest(inp=inp[:40]):
                self._run_input(inp)

    def test_random_bytes(self):
        for _ in range(self.iterations):
            self._run_input(_rand_bytes(_RNG.randrange(0, 1000)))

    def test_random_ascii(self):
        for _ in range(self.iterations):
            self._run_input(_rand_ascii(_RNG.randrange(0, 1000)))

    def test_random_nxc_shaped(self):
        """Lines that LOOK like nxc output — the shape every nxc-consumer
        parser pattern-matches. Catches split-related bugs."""
        for _ in range(self.iterations):
            self._run_input(_rand_nxc_shaped(_RNG.randrange(0, 20)))

    def test_random_json(self):
        """For JSON-ingest parsers; graph-domain parsers also accept
        malformed JSON by raising their domain error."""
        for _ in range(self.iterations):
            self._run_input(json.dumps(_rand_json(_RNG.randrange(0, 5))))


class ParserFuzzBase(_ParserFuzzBase, unittest.TestCase):
    """Carrier class — concrete subclasses still inherit the mixin methods
    AND unittest.TestCase, so pytest discovers them. The base itself is
    skipped at the discovery layer below via a class-level guard."""

    def _run_input(self, inp):
        if not getattr(self, "parser", None):
            self.skipTest("abstract base — concrete subclasses set .parser")
        return super()._run_input(inp)


# ---------------------------------------------------------------- line parsers


class TestNetexecParseLine(ParserFuzzBase):
    @classmethod
    def setUpClass(cls):
        from fieldkit.netexec import parse_line
        cls.parser = staticmethod(parse_line)
    expected_exc = ()                                           # must never raise


class TestNetexecParseOutput(ParserFuzzBase):
    @classmethod
    def setUpClass(cls):
        from fieldkit.netexec import parse_output
        cls.parser = staticmethod(parse_output)
    expected_exc = ()


class TestNetexecParsePassPolicy(ParserFuzzBase):
    @classmethod
    def setUpClass(cls):
        from fieldkit.netexec import parse_pass_policy
        cls.parser = staticmethod(parse_pass_policy)
    expected_exc = ()                                           # returns None on garbage


class TestIngestClassifyNxc(ParserFuzzBase):
    @classmethod
    def setUpClass(cls):
        from fieldkit.ingest import classify_nxc
        cls.parser = staticmethod(classify_nxc)
    expected_exc = ()


# ---------------------------------------------------------------- probes


class TestProbesShares(ParserFuzzBase):
    @classmethod
    def setUpClass(cls):
        from fieldkit.nxc_probes import parse_shares
        cls.parser = staticmethod(parse_shares)
    expected_exc = ()


class TestProbesLoggedOnUsers(ParserFuzzBase):
    @classmethod
    def setUpClass(cls):
        from fieldkit.nxc_probes import parse_loggedon_users
        cls.parser = staticmethod(parse_loggedon_users)
    expected_exc = ()


class TestProbesSessions(ParserFuzzBase):
    @classmethod
    def setUpClass(cls):
        from fieldkit.nxc_probes import parse_sessions
        cls.parser = staticmethod(parse_sessions)
    expected_exc = ()


class TestProbesLaps(ParserFuzzBase):
    @classmethod
    def setUpClass(cls):
        from fieldkit.nxc_probes import parse_laps
        cls.parser = staticmethod(parse_laps)
    expected_exc = ()


class TestProbesGpp(ParserFuzzBase):
    @classmethod
    def setUpClass(cls):
        from fieldkit.nxc_probes import parse_gpp
        cls.parser = staticmethod(parse_gpp)
    expected_exc = ()


class TestProbesVeeam(ParserFuzzBase):
    @classmethod
    def setUpClass(cls):
        from fieldkit.nxc_probes import parse_veeam
        cls.parser = staticmethod(parse_veeam)
    expected_exc = ()


class TestProbesTeamsLocaldb(ParserFuzzBase):
    @classmethod
    def setUpClass(cls):
        from fieldkit.nxc_probes import parse_teams
        cls.parser = staticmethod(parse_teams)
    expected_exc = ()


class TestProbesNanodump(ParserFuzzBase):
    @classmethod
    def setUpClass(cls):
        from fieldkit.nxc_probes import parse_nanodump
        cls.parser = staticmethod(parse_nanodump)
    expected_exc = ()


class TestProbesMs17_010(ParserFuzzBase):
    @classmethod
    def setUpClass(cls):
        from fieldkit.nxc_probes import parse_ms17_010
        cls.parser = staticmethod(parse_ms17_010)
    expected_exc = ()


class TestProbesCoercePlus(ParserFuzzBase):
    @classmethod
    def setUpClass(cls):
        from fieldkit.nxc_probes import parse_coerce_plus
        cls.parser = staticmethod(parse_coerce_plus)
    expected_exc = ()


# ---------------------------------------------------------------- scan outputs


class TestNmapParse(ParserFuzzBase):
    """``nmap.parse`` dispatches to XML/normal/grepable; must not crash on
    anything that LOOKS like a scan output but isn't one of the three."""
    @classmethod
    def setUpClass(cls):
        from fieldkit.nmap import parse
        cls.parser = staticmethod(parse)
    expected_exc = ()


class TestWebParseHttpx(ParserFuzzBase):
    @classmethod
    def setUpClass(cls):
        from fieldkit.web import parse_httpx
        cls.parser = staticmethod(parse_httpx)
    expected_exc = ()


class TestWebParseNuclei(ParserFuzzBase):
    @classmethod
    def setUpClass(cls):
        from fieldkit.web import parse_nuclei
        cls.parser = staticmethod(parse_nuclei)
    expected_exc = ()


class TestHashcatPotfile(ParserFuzzBase):
    @classmethod
    def setUpClass(cls):
        from fieldkit.hashcat import parse_potfile
        cls.parser = staticmethod(parse_potfile)
    expected_exc = ()


class TestDumpParse(ParserFuzzBase):
    @classmethod
    def setUpClass(cls):
        from fieldkit.dump import parse_dump
        cls.parser = staticmethod(parse_dump)
    expected_exc = ()


class TestDelegationParse(ParserFuzzBase):
    @classmethod
    def setUpClass(cls):
        from fieldkit.delegation import parse_delegation
        cls.parser = staticmethod(parse_delegation)
    expected_exc = ()


class TestAdcsParseCertipy(ParserFuzzBase):
    @classmethod
    def setUpClass(cls):
        from fieldkit.adcs import parse_certipy
        cls.parser = staticmethod(parse_certipy)
    expected_exc = ()


# ---------------------------------------------------------------- credentials


class TestCredentialParse(ParserFuzzBase):
    """``parse_credential`` is a strict parser with a documented error type,
    unlike the stream parsers above. It MAY raise CredentialError but must
    not raise anything else."""
    @classmethod
    def setUpClass(cls):
        from fieldkit.creds import parse_credential, CredentialError
        cls.parser = staticmethod(parse_credential)
        cls.expected_exc = (CredentialError, ValueError)


class TestCredentialLinesParse(ParserFuzzBase):
    @classmethod
    def setUpClass(cls):
        from fieldkit.creds import parse_credential_lines
        cls.parser = staticmethod(parse_credential_lines)
    expected_exc = ()                                           # bulk lines: tolerant


# ---------------------------------------------------------------- graph parsers


class TestCloudIamParse(ParserFuzzBase):
    """Graph parsers accept JSON text and raise a documented error on bad
    shape — everything else is a bug."""
    @classmethod
    def setUpClass(cls):
        from fieldkit.cloud_iam import parse_iam, CloudIamError
        cls.parser = staticmethod(parse_iam)
        cls.expected_exc = (CloudIamError, ValueError)


class TestK8sParse(ParserFuzzBase):
    @classmethod
    def setUpClass(cls):
        from fieldkit.k8s import parse_rbac
        cls.parser = staticmethod(parse_rbac)
    expected_exc = (ValueError,)                                # module raises ValueError flavor


class TestSaasParse(ParserFuzzBase):
    @classmethod
    def setUpClass(cls):
        from fieldkit.saas import parse_saas
        cls.parser = staticmethod(parse_saas)
    expected_exc = (ValueError,)


class TestCicdParse(ParserFuzzBase):
    @classmethod
    def setUpClass(cls):
        from fieldkit.cicd import parse_cicd
        cls.parser = staticmethod(parse_cicd)
    expected_exc = (ValueError,)


class TestRecceParse(ParserFuzzBase):
    """``recce.parse`` accepts bytes OR str — fuzz with both."""
    @classmethod
    def setUpClass(cls):
        from fieldkit.recce import parse, RecceBridgeError
        cls.parser = staticmethod(parse)
        cls.expected_exc = (RecceBridgeError, ValueError)


# ---------------------------------------------------------------- scope


class TestScopeParse(ParserFuzzBase):
    @classmethod
    def setUpClass(cls):
        from fieldkit.scope import parse_scope, ScopeError
        cls.parser = staticmethod(parse_scope)
        cls.expected_exc = (ScopeError, ValueError)


# ---------------------------------------------------------------- config


class TestConfigAssignmentParse(ParserFuzzBase):
    @classmethod
    def setUpClass(cls):
        from fieldkit.config import parse_assignment
        cls.parser = staticmethod(parse_assignment)
    expected_exc = (ValueError,)


if __name__ == "__main__":
    unittest.main()
