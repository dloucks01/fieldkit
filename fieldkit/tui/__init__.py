"""The fieldkit TUI — a Textual-based workbench for one operator.

Importing this package prepends ``fieldkit/vendor/`` to ``sys.path`` so
``import textual`` (etc.) finds the vendored copies without a `pip install`.
Non-TUI code never triggers the shim, so a system-installed different version
of Textual (if the operator has one) does not collide with anything else.

The visual language is the single source of truth in :mod:`fieldkit.tui.theme`;
every widget reads palette + glyphs + text-styles from there, never from color
literals. Design brief: "The Operator View".
"""
import os as _os
import sys as _sys

_VENDOR = _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "vendor")
if _os.path.isdir(_VENDOR) and _VENDOR not in _sys.path:
    _sys.path.insert(0, _VENDOR)
