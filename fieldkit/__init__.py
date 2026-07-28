"""fieldkit — a stateful internal-AD execution engine.

fieldkit is the *brain* of an internal engagement: it holds state (SQLite), owns one
canonical credential model, drives proven external tools (netexec, impacket,
evil-winrm), analyzes privesc opportunities, and reports on what it proved. It does
not reimplement SMB/LDAP/Kerberos.

Nothing in this package prints or performs I/O at import time — every module is
importable and unit-testable. Operator-facing output goes through the CLI layer.

Authorized engagements only.
"""

__version__ = "2.0.0-dev"

__all__ = ["__version__"]
