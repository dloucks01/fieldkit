"""Engagement configuration — in state, never in source.

This replaces v1's ``configure.sh``, which ``sed``-edited LHOST/LPORT into tracked
source files. That was actively dangerous: a dirty tree plus a ``git checkout``
between engagements could point a reverse shell at the *previous client's*
redirector. Config now lives in the engagement row of the database, so it travels
with the engagement and cannot leak into another one.

Every key is validated on write, so a typo is caught at ``config set`` rather than
when a payload fails to call back. Per-subnet ``lhost`` overrides exist because a
routable callback address on one segment is often unreachable from another.
"""
import ipaddress
import re

from .errors import FieldkitError


class ConfigError(FieldkitError, ValueError):
    """A rejected configuration value, phrased for the operator."""


# ------------------------------------------------------------------- validators

def _v_host(key, value):
    """An IP the target can call back to (a hostname is allowed for webhost)."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        raise ConfigError(
            f"{key}: {value!r} is not an IP address — the callback address must be "
            "literal so a payload never depends on the target's DNS") from None
    return value


def _v_port(key, value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ConfigError(f"{key}: {value!r} is not a port number") from None
    if not 1 <= port <= 65535:
        raise ConfigError(f"{key}: {port} is out of range (1-65535)")
    return port


def _v_domain(key, value):
    if not re.fullmatch(r"[A-Za-z0-9._-]+", value or ""):
        raise ConfigError(f"{key}: {value!r} is not a valid AD domain name")
    return value


def _v_url(key, value):
    if not re.match(r"^https?://[^\s]+$", value or ""):
        raise ConfigError(f"{key}: {value!r} should look like http://10.10.14.7[:8000]")
    return value.rstrip("/")


def _v_path(key, value):
    if not value or value != value.strip():
        raise ConfigError(f"{key}: {value!r} is not a usable path")
    return value


def _v_subnet(subnet):
    """A CIDR, normalized to its network address so 10.9.9.55/24 keys as 10.9.9.0/24."""
    try:
        return str(ipaddress.ip_network(subnet, strict=False))
    except ValueError as exc:
        raise ConfigError(f"--subnet {subnet!r}: {exc}") from None


def _choice(*allowed):
    def check(key, value):
        if value not in allowed:
            raise ConfigError(f"{key}: {value!r} is not one of {', '.join(allowed)}")
        return value
    return check


#: key -> (validator, help). These are the engagement-wide knobs the generators used
#: to hardcode; per-host facts (stage dir, Potato tool, revshell type) are inferred by
#: enumeration and stored on the host, not set by hand here.
KEYS = {
    "lhost":    (_v_host, "attacker callback address (revshell catcher / redirector)"),
    "lport":    (_v_port, "attacker callback port"),
    "domain":   (_v_domain, "primary AD domain (blank = local auth / workgroup)"),
    "webhost":  (_v_url, "where targets fetch staged artifacts from, e.g. http://10.10.14.7:8000"),
    "revtype_win": (_choice("powershell", "nc"), "Windows reverse-shell delivery"),
    "revtype_lin": (_choice("bash", "mkfifo", "python", "perl", "nc"),
                    "Linux reverse-shell delivery"),
    "stage_win": (_v_path, "writable staging dir on Windows targets, e.g. C:\\Windows\\Temp"),
    "stage_lin": (_v_path, "writable+exec staging dir on Linux targets, e.g. /dev/shm"),
    "userlist":  (_v_path, "path to the username wordlist (pre-staged for air-gap)"),
    "passlist":  (_v_path, "path to the password wordlist"),
    "client":    (lambda k, v: v, "client name, for the report header"),
}

DEFAULTS = {
    "lport": 443,
    "revtype_win": "powershell",
    "revtype_lin": "bash",
    "stage_win": "C:\\Windows\\Temp",
    "stage_lin": "/dev/shm",
}

#: Nested key holding {cidr: lhost} — a callback address per network segment.
OVERRIDES_KEY = "lhost_overrides"

#: The keys worth showing on one line of the engagement board.
HEADLINE_KEYS = ("lhost", "lport", "domain")


class Config:
    """A validated view over the engagement's ``config_json``."""

    def __init__(self, store):
        self.store = store
        self._data = store.get_config()
        self._nets = None  # parsed override CIDRs, built on first use

    # -- reads --------------------------------------------------------------

    def get(self, key):
        """The set value, else the default, else None."""
        return self._data.get(key, DEFAULTS.get(key))

    def is_set(self, key):
        """True when the operator set this explicitly (as opposed to a default)."""
        return key in self._data

    def as_dict(self):
        """The flat key space only — nested structures have their own accessors."""
        merged = {**DEFAULTS, **self._data}
        merged.pop(OVERRIDES_KEY, None)
        return merged

    def overrides(self):
        return dict(self._data.get(OVERRIDES_KEY, {}))

    def lhost_for(self, ip):
        """The callback address to use for a target — subnet override, else ``lhost``.

        Called once per target on every render path, so the override CIDRs are parsed
        once per Config rather than once per host.
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return self.get("lhost")
        if self._nets is None:
            self._nets = []
            for cidr, lhost in self.overrides().items():
                try:
                    self._nets.append((ipaddress.ip_network(cidr, strict=False), lhost))
                except ValueError:
                    continue  # a hand-edited config blob; ignore the bad entry
        best, best_len = None, -1
        for net, lhost in self._nets:
            # Most specific match wins, so a /29 beats the /16 it sits inside.
            if addr.version == net.version and addr in net and net.prefixlen > best_len:
                best, best_len = lhost, net.prefixlen
        return best or self.get("lhost")

    # -- writes -------------------------------------------------------------

    def set(self, key, value, subnet=None):
        """Validate and store one key. ``subnet`` scopes ``lhost`` to a CIDR."""
        return self.set_many([(key, value)], subnet=subnet)[key]

    def set_many(self, pairs, subnet=None):
        """Validate every assignment first, then apply them in one write.

        All-or-nothing on purpose: a typo in the third key must not leave the first
        two applied, or the operator ends up with a half-configured engagement and no
        signal about which half.
        """
        validated = {}
        for key, value in pairs:
            if key not in KEYS:
                raise ConfigError(
                    f"unknown config key {key!r} — known keys: {', '.join(sorted(KEYS))}")
            if subnet is not None and key != "lhost":
                raise ConfigError("--subnet only scopes 'lhost'")
            validate, _ = KEYS[key]
            validated[key] = validate(key, value)
        if subnet is not None:
            overrides = self.overrides()
            overrides[_v_subnet(subnet)] = validated["lhost"]
            self._data[OVERRIDES_KEY] = overrides
        else:
            self._data.update(validated)
        self.save()
        return validated

    def unset(self, key, subnet=None):
        if subnet is not None:
            overrides = self.overrides()
            net = _v_subnet(subnet)
            if net not in overrides:
                raise ConfigError(f"no lhost override for {net}")
            del overrides[net]
            self._data[OVERRIDES_KEY] = overrides
        elif key in self._data:
            del self._data[key]
        else:
            raise ConfigError(f"{key} is not set")
        self.save()

    def save(self):
        self._nets = None
        self.store.set_config(self._data)


def parse_assignment(arg):
    """``lhost=10.10.14.7`` -> ``('lhost', '10.10.14.7')``."""
    if "=" not in arg:
        raise ConfigError(f"expected key=value, got {arg!r}")
    key, _, value = arg.partition("=")
    key = key.strip().lower()
    if not key:
        raise ConfigError(f"expected key=value, got {arg!r}")
    return key, value.strip()


def load(store):
    """Config for an initialized engagement (Config raises if there isn't one)."""
    return Config(store)


__all__ = ["Config", "ConfigError", "KEYS", "DEFAULTS", "OVERRIDES_KEY",
           "parse_assignment", "load"]
