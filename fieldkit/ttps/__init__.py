"""fieldkit TTPs — techniques as data.

Every technique fieldkit runs is a YAML file in this directory, keyed by MITRE
ATT&CK T-code. Each file declares: what the technique does, what precondition
lets it run, what command proves it, what to check the output for, how to
clean up any mutation, and how the report should render it. The engine reads
the library at startup; extending fieldkit is a PR against ``fieldkit/ttps/``
that touches no Python.

See :mod:`fieldkit.ttps.schema` for the field-by-field spec, and
:mod:`fieldkit.ttps.loader` for the parser. Design source: Phase B of the
strategy plan (``The Operator View`` companion).

Consumers: engine modules (privesc, escalate) call :func:`load_all` at startup
and merge TTPs alongside any remaining inlined drivers. As drivers get ported
to YAML, the inlined tables shrink until the engine is pure orchestration.
"""
from .loader import LoaderError, load_all, load_file
from .schema import TTP

__all__ = ["LoaderError", "load_all", "load_file", "TTP"]
