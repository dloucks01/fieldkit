"""The fieldkit TUI — a Textual-based workbench for one operator.

Importing this package is a no-op beyond marking it importable. The vendor path
shim that makes ``import textual`` resolve to ``fieldkit/vendor/textual/`` lives
in :mod:`fieldkit` — every fieldkit import triggers it, so :mod:`fieldkit.tui`
and :mod:`fieldkit.ttps` both get vendored deps for free.

The visual language is the single source of truth in :mod:`fieldkit.tui.theme`;
every widget reads palette + glyphs + text-styles from there, never from color
literals. Design brief: "The Operator View".
"""
