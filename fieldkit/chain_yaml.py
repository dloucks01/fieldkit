"""YAML-defined chain profiles — user-authored profiles without
touching Python code.

A profile YAML has this shape::

    name: my-custom-chain
    description: |
      One-paragraph what-this-does. Rendered in `chain plan` output.
    steps:
      - name: preflight:reachability
        kind: preflight
        detection_cost: 0
        action: builtin:reachability
        signals:
          - kind: smb-conn
            identifier: tcp-syn/445
      - name: coerce:custom-tool
        kind: target-side
        detection_cost: 3
        action: manual
        manual_message: "run mytool -t <target>; capture the callback"
        signals:
          - kind: rpc-call
            identifier: MS-EFSR/EfsRpcOpenFileRaw
            note: "the tool triggers this DCERPC call"

Two supported action kinds:
  * ``builtin:<key>`` — references a shipped action function
    (currently: ``reachability`` → :data:`fieldkit.chain.REACHABILITY_STEP`'s
    action). Future keys can be added to :data:`_BUILTIN_ACTIONS`.
  * ``manual`` — always yields a manual outcome with
    ``manual_message`` as the evidence text.

User-defined chains are auto-loaded from ``~/.fieldkit/chains/*.yaml``
on :mod:`fieldkit.chain` import. The CLI ``fieldkit chain register
--from-yaml <path>`` validates a candidate YAML and copies it into
that dir, so a new profile is available from the next invocation.
"""
import os
import shutil
from typing import Callable, Dict


class ChainYamlError(ValueError):
    """One YAML failed validation — invalid schema, unknown action,
    missing required field. Message is operator-facing."""


#: Where user-defined chain YAMLs live. Auto-loaded on
#: fieldkit.chain import.
USER_CHAINS_DIR = os.path.expanduser("~/.fieldkit/chains")


def _load_yaml(path):
    """Read one YAML file. Raises :class:`ChainYamlError` on
    parse failure or non-mapping root."""
    from .vendor import yaml as _yaml
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = _yaml.safe_load(fh)
    except (OSError, _yaml.YAMLError) as exc:
        raise ChainYamlError(f"{os.path.basename(path)}: "
                              f"cannot read/parse: {exc}") from exc
    if not isinstance(doc, dict):
        raise ChainYamlError(
            f"{os.path.basename(path)}: top-level must be a mapping")
    return doc


def _make_manual_action(message):
    """Return a Step action factory that always yields a manual
    outcome carrying ``message`` verbatim as its evidence."""
    from .chain import Outcome

    def _act(chain, ctx):
        _ = chain, ctx
        return Outcome(kind="manual", evidence=message)
    return _act


def _resolve_action(action_spec, manual_message, ttp_name):
    """Turn a YAML action string into a callable. Raises
    :class:`ChainYamlError` on unknown action kind."""
    if action_spec == "manual":
        if not manual_message:
            raise ChainYamlError(
                f"chain {ttp_name!r}: action=manual requires "
                "'manual_message'")
        return _make_manual_action(manual_message)
    if action_spec.startswith("builtin:"):
        key = action_spec.split(":", 1)[1]
        builtins: Dict[str, Callable] = _builtin_actions()
        if key not in builtins:
            raise ChainYamlError(
                f"chain {ttp_name!r}: unknown builtin action "
                f"{key!r}; supported: {sorted(builtins)}")
        return builtins[key]
    raise ChainYamlError(
        f"chain {ttp_name!r}: action must be 'manual' or "
        f"'builtin:<name>', got {action_spec!r}")


def _builtin_actions():
    """Lazy — the chain module can't be imported at module-load
    time (would circle-back through this loader). Called only
    from _resolve_action which fires during YAML parse."""
    from .chain import _reach_probe
    return {"reachability": _reach_probe}


def _parse_signals(sig_list, ttp_name):
    """List of {kind, identifier, count, note} dicts → tuple of
    DetectionSignal. Empty list → empty tuple."""
    from .chain import DetectionSignal, SIGNAL_KINDS
    if not sig_list:
        return ()
    if not isinstance(sig_list, list):
        raise ChainYamlError(
            f"chain {ttp_name!r}: signals must be a list, "
            f"got {type(sig_list).__name__}")
    out = []
    for i, s in enumerate(sig_list):
        if not isinstance(s, dict):
            raise ChainYamlError(
                f"chain {ttp_name!r}: signals[{i}] must be a "
                f"mapping, got {type(s).__name__}")
        kind = s.get("kind")
        if kind not in SIGNAL_KINDS:
            raise ChainYamlError(
                f"chain {ttp_name!r}: signals[{i}].kind must be "
                f"one of {sorted(SIGNAL_KINDS)}, got {kind!r}")
        ident = s.get("identifier") or ""
        count = int(s.get("count", 1))
        note = s.get("note") or ""
        out.append(DetectionSignal(
            kind=kind, identifier=str(ident), count=count, note=str(note)))
    return tuple(out)


def build_profile_from_doc(doc, source_label="<yaml>"):
    """Turn a parsed YAML dict into a (name, factory) tuple ready
    to register. Raises :class:`ChainYamlError` on schema issues.
    Does NOT register — the caller decides."""
    from .chain import Chain, Step
    name = doc.get("name")
    if not name or not isinstance(name, str):
        raise ChainYamlError(
            f"{source_label}: missing/invalid 'name' — must be a "
            "non-empty string")
    steps_raw = doc.get("steps")
    if not isinstance(steps_raw, list) or not steps_raw:
        raise ChainYamlError(
            f"chain {name!r}: 'steps' must be a non-empty list")

    # Build Step objects up-front so a broken step surfaces before
    # we register anything.
    built_steps = []
    for i, s in enumerate(steps_raw):
        if not isinstance(s, dict):
            raise ChainYamlError(
                f"chain {name!r}: steps[{i}] must be a mapping")
        step_name = s.get("name")
        step_kind = s.get("kind")
        if not step_name:
            raise ChainYamlError(
                f"chain {name!r}: steps[{i}].name is required")
        if not step_kind:
            raise ChainYamlError(
                f"chain {name!r}: steps[{i}].kind is required")
        det_cost = int(s.get("detection_cost", 0))
        action = s.get("action")
        if not action:
            raise ChainYamlError(
                f"chain {name!r}: steps[{i}].action is required "
                "('manual' or 'builtin:<name>')")
        act_fn = _resolve_action(action, s.get("manual_message"), name)
        signals = _parse_signals(s.get("signals") or (), name)
        built_steps.append(Step(
            name=step_name, kind=step_kind, action=act_fn,
            detection_cost=det_cost, signals=signals))

    def _factory(target, **_kw):
        return Chain(profile=name, target=target,
                      steps=tuple(built_steps))
    return name, _factory


def register_from_doc(doc, source_label="<yaml>"):
    """Validate + register a profile from a parsed YAML dict.
    Overwrites any existing registration for the same name (the
    convention: user-defined chains win over shipped ones with
    the same name, letting an operator override for their
    engagement). Returns the profile name."""
    from .chain import _PROFILES
    name, factory = build_profile_from_doc(doc, source_label)
    _PROFILES[name] = factory
    return name


def register_from_file(path):
    """Load one YAML + register. Returns the profile name."""
    doc = _load_yaml(path)
    return register_from_doc(doc, source_label=os.path.basename(path))


def install_yaml(source_path):
    """Copy a candidate YAML into :data:`USER_CHAINS_DIR` so it
    auto-loads on next invocation. Validates the YAML first —
    a bad file never lands in the load-path. Returns the
    installed path."""
    if not os.path.isfile(source_path):
        raise ChainYamlError(f"{source_path}: no such file")
    # Validate before copying so a bad profile can't wedge every
    # future fieldkit start.
    doc = _load_yaml(source_path)
    name, _ = build_profile_from_doc(doc,
                                       source_label=os.path.basename(source_path))
    os.makedirs(USER_CHAINS_DIR, mode=0o700, exist_ok=True)
    dest = os.path.join(USER_CHAINS_DIR, f"{name}.yaml")
    shutil.copy2(source_path, dest)
    return dest


def uninstall(name):
    """Remove a user-defined chain from :data:`USER_CHAINS_DIR`.
    Returns True if a file was deleted, False if the name wasn't
    installed."""
    from .chain import _PROFILES
    path = os.path.join(USER_CHAINS_DIR, f"{name}.yaml")
    removed = False
    if os.path.isfile(path):
        os.unlink(path)
        removed = True
    # Also drop from in-memory registry if present
    if name in _PROFILES:
        del _PROFILES[name]
    return removed


def load_user_chains():
    """Walk :data:`USER_CHAINS_DIR` and register every YAML. Called
    from :mod:`fieldkit.chain` at import time. Silently skips
    malformed files (with a stderr note) rather than blowing up
    the whole chain-module import — a broken user file shouldn't
    prevent the shipped profiles from loading."""
    import sys as _sys
    if not os.path.isdir(USER_CHAINS_DIR):
        return []
    loaded = []
    for f in sorted(os.listdir(USER_CHAINS_DIR)):
        if not f.endswith(".yaml"):
            continue
        path = os.path.join(USER_CHAINS_DIR, f)
        try:
            name = register_from_file(path)
            loaded.append(name)
        except (ChainYamlError, Exception) as exc:          # noqa: BLE001
            print(f"warning: skipping user chain {f}: {exc}",
                  file=_sys.stderr)
    return loaded
