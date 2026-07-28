"""Scope parsing — turning what the client gave you into host rows.

Operators receive scope as a text file of mixed shapes: bare IPs, CIDRs, an
``IP hostname`` pair, commented-out exclusions. This module turns that into
``(ip, hostname)`` pairs and nothing else — no I/O, no state, so it is testable on
its own and reusable by ``ingest`` later.
"""
import ipaddress
import os

from .errors import FieldkitError

#: Guard rail: a fat-fingered /8 would insert 16M rows. The operator can raise it.
DEFAULT_MAX_EXPAND = 4096


class ScopeError(FieldkitError, ValueError):
    """An unusable scope entry, phrased for the operator."""


def subnet_of(ip, v4_prefix=24, v6_prefix=64):
    """The segment a host sits on — the grouping key for per-subnet lhost + status."""
    addr = ipaddress.ip_address(ip)
    prefix = v4_prefix if addr.version == 4 else v6_prefix
    return str(ipaddress.ip_network(f"{addr}/{prefix}", strict=False))


def parse_entry(entry, max_expand=DEFAULT_MAX_EXPAND):
    """Parse one scope entry into a list of ``(ip, hostname)``.

    Accepts ``10.0.0.5``, ``10.0.0.5 WIN-SQL01``, ``10.0.0.5,WIN-SQL01``,
    ``10.0.0.0/24``, ``dead:beef::1``. A CIDR expands to its usable hosts (network
    and broadcast addresses are skipped for IPv4 prefixes shorter than /31).
    """
    entry = entry.split("#", 1)[0].strip()
    if not entry:
        return []
    parts = [p for p in entry.replace(",", " ").split() if p]
    target, hostname = parts[0], (parts[1] if len(parts) > 1 else None)

    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError as exc:
            raise ScopeError(f"{target!r}: {exc}") from None
        # Check the size *before* expanding: a fat-fingered /8 is 16M addresses and
        # materializing it to count would hang the command.
        usable = net.num_addresses - (2 if net.version == 4 and net.prefixlen < 31 else 0)
        if usable > max_expand:
            raise ScopeError(
                f"{target} expands to {usable} hosts (limit {max_expand}) — "
                "narrow the range or raise --max-expand")
        return [(str(a), None) for a in (net.hosts() or [net.network_address])]

    try:
        addr = ipaddress.ip_address(target)
    except ValueError:
        raise ScopeError(
            f"{target!r} is not an IP address or CIDR — fieldkit keys hosts on IPs; "
            "put the name in the second column") from None
    return [(str(addr), hostname)]


def parse_scope(text, max_expand=DEFAULT_MAX_EXPAND):
    """Parse a whole scope file. Returns ``(targets, errors)``.

    Duplicates collapse (last hostname wins, so an enriching line can add a name),
    and one bad line never discards the good ones.
    """
    targets, errors = {}, []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        try:
            for ip, hostname in parse_entry(raw, max_expand=max_expand):
                if hostname or ip not in targets:
                    targets[ip] = hostname or targets.get(ip)
        except ScopeError as exc:
            errors.append((lineno, raw.strip(), str(exc)))
    return list(targets.items()), errors


ARGV_ORIGIN = "<command line>"


def read_targets(items=(), file=None, max_expand=DEFAULT_MAX_EXPAND):
    """Resolve what the operator typed into targets: literals, scope files, or both.

    ``items`` may mix literal entries with paths — operators pass a scope file
    positionally as often as behind ``--file``. Errors come back as
    ``(origin, lineno, line, message)`` so a message points at the file and line the
    operator can actually go and fix, not at an offset into a concatenated buffer.
    """
    sources = []
    if file:
        sources.append((file, _read(file)))
    literals = []
    for item in items:
        if os.path.isfile(item):
            sources.append((item, _read(item)))
        else:
            literals.append(item)
    if literals:
        sources.append((ARGV_ORIGIN, "\n".join(literals)))

    targets, errors = {}, []
    for origin, text in sources:
        found, problems = parse_scope(text, max_expand=max_expand)
        for ip, hostname in found:
            if hostname or ip not in targets:
                targets[ip] = hostname or targets.get(ip)
        errors += [(origin, lineno, line, message) for lineno, line, message in problems]
    return list(targets.items()), errors


def _read(path):
    with open(path, "r", errors="replace") as fh:
        return fh.read()
