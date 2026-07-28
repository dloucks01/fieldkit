"""One error family for everything the operator can act on.

Each layer keeps its own type (so a caller can still discriminate), but they share a
base the CLI catches once. Anything not derived from :class:`FieldkitError` is a bug
in fieldkit and should reach the operator as a traceback, not as a tidy message.
"""


class FieldkitError(Exception):
    """Base for operator-facing failures: bad input, bad state, refused action."""


class ConfirmationError(FieldkitError):
    """An action needing confirmation could not get one (no tty, no --yes)."""
