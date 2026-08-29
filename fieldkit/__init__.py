"""fieldkit — a stateful internal-AD execution engine.

fieldkit is the *brain* of an internal engagement: it holds state (SQLite), owns one
canonical credential model, drives proven external tools (netexec, impacket,
evil-winrm), analyzes privesc opportunities, and reports on what it proved. It does
not reimplement SMB/LDAP/Kerberos.

Nothing in this package prints or performs I/O at import time — every module is
importable and unit-testable. Operator-facing output goes through the CLI layer.

Authorized engagements only.

Vendor shim: this ``__init__`` prepends ``fieldkit/vendor/`` to ``sys.path`` so
optional deps we vendor (Textual + Rich for the TUI, PyYAML for the TTP loader) are
importable without a ``pip install`` on a fresh clone. Non-optional engine code
never imports vendored packages, so system installs of Textual/PyYAML don't affect
the engine — only the specific consumers (fieldkit.tui, fieldkit.ttps) do.
"""
import os as _os
import sys as _sys

__version__ = "2.0.0-dev"

__all__ = ["__version__"]

_VENDOR = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "vendor")
if _os.path.isdir(_VENDOR) and _VENDOR not in _sys.path:
    _sys.path.insert(0, _VENDOR)
