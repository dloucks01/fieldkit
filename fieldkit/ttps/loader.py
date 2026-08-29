"""Load fieldkit TTP YAML files into typed :class:`~fieldkit.ttps.schema.TTP`
objects, with strict validation and clear error messages.

The loader is deliberately strict — a malformed file raises :class:`LoaderError`
naming the file + field so the operator can fix it, rather than silently
skipping the file (which would hide a whole class of coverage from the engine).
"""
import os
import re

import yaml   # vendored — fieldkit/__init__.py puts fieldkit/vendor on sys.path

from .schema import (
    SCHEMA_VERSION, VALID_DETECTION, VALID_EXPLOITABILITY, VALID_PLATFORMS,
    VALID_SAFETY,
    Cleanup, Detect, Execute, Playbook, Ranking, Report, TTP, Verify,
)

#: Directory the built-in TTP files live in. Callers can override to load from
#: an operator's own out-of-tree library too.
BUILTIN_DIR = os.path.dirname(os.path.abspath(__file__))

_T_CODE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class LoaderError(ValueError):
    """A TTP file is malformed. The message names the source path + field."""


# ---- validation helpers ---------------------------------------------------

def _require(doc, key, path, source):
    if key not in doc:
        raise LoaderError(f"{source}: missing required field {key!r} in {path}")
    return doc[key]


def _require_str(doc, key, path, source):
    v = _require(doc, key, path, source)
    if not isinstance(v, str) or not v.strip():
        raise LoaderError(f"{source}: {path}.{key} must be a non-empty string, got {v!r}")
    return v


def _require_list(doc, key, path, source):
    v = _require(doc, key, path, source)
    if not isinstance(v, list) or not v:
        raise LoaderError(f"{source}: {path}.{key} must be a non-empty list, got {v!r}")
    return v


def _require_in(v, allowed, path, source):
    if v not in allowed:
        raise LoaderError(
            f"{source}: {path} = {v!r} is not one of "
            f"{', '.join(sorted(allowed))}")


# ---- per-block parsers ----------------------------------------------------

def _parse_ranking(doc, source):
    r = _require(doc, "ranking", "<root>", source)
    if not isinstance(r, dict):
        raise LoaderError(f"{source}: ranking must be a mapping, got {r!r}")
    exp = _require_str(r, "exploitability", "ranking", source)
    saf = _require_str(r, "safety", "ranking", source)
    det = _require_str(r, "detection", "ranking", source)
    _require_in(exp, VALID_EXPLOITABILITY, "ranking.exploitability", source)
    _require_in(saf, VALID_SAFETY, "ranking.safety", source)
    _require_in(det, VALID_DETECTION, "ranking.detection", source)
    return Ranking(exploitability=exp, safety=saf, detection=det)


def _parse_detect(doc, source):
    d = _require(doc, "detect", "<root>", source)
    if not isinstance(d, dict) or not d:
        raise LoaderError(f"{source}: detect must be a non-empty mapping, got {d!r}")
    supported = {"always", "sudo_allows", "suid", "capability",
                 "capability_on_binary", "facts_match",
                 "privilege", "group_member", "linux_group",
                 "sudo_env_keep_any",
                 "version_range", "no_hotfix_from", "all_of",
                 "unquoted_services", "reconfigurable_services",
                 "writable_service_bins", "writable_service_dirs"}
    keys = [k for k in d if k in supported]
    if not keys:
        raise LoaderError(
            f"{source}: detect must have one of {sorted(supported)}; got keys {list(d)}")
    if len(keys) > 1:
        raise LoaderError(
            f"{source}: detect must have exactly one predicate; got {keys}")
    kind = keys[0]
    return Detect(kind=kind, value=d[kind])


def _parse_execute(doc, source):
    e = _require(doc, "execute", "<root>", source)
    if not isinstance(e, dict):
        raise LoaderError(f"{source}: execute must be a mapping, got {e!r}")
    command = _require_str(e, "command", "execute", source)
    transport = tuple(e.get("transport") or ())
    if transport and not all(isinstance(t, str) for t in transport):
        raise LoaderError(
            f"{source}: execute.transport must be a list of strings, got {transport!r}")
    shell = e.get("shell") or ""
    if shell and shell not in ("cmd", "powershell", "sh"):
        raise LoaderError(
            f"{source}: execute.shell must be one of cmd/powershell/sh, got {shell!r}")
    # stages: list of {name, as} dicts → tuple of (name, remote_path) tuples.
    # `as` is the yaml-friendly key for the remote path (matches how Ansible
    # names the same slot).
    stages_raw = e.get("stages") or []
    if not isinstance(stages_raw, list):
        raise LoaderError(f"{source}: execute.stages must be a list, got {stages_raw!r}")
    stages = []
    for i, s in enumerate(stages_raw):
        if not isinstance(s, dict) or "name" not in s or "as" not in s:
            raise LoaderError(
                f"{source}: execute.stages[{i}] must be a mapping with 'name' + 'as' keys, "
                f"got {s!r}")
        stages.append((str(s["name"]), str(s["as"])))
    # serves: list of arsenal artifact names
    serves_raw = e.get("serves") or []
    if not isinstance(serves_raw, list) or not all(isinstance(x, str) for x in serves_raw):
        raise LoaderError(
            f"{source}: execute.serves must be a list of strings, got {serves_raw!r}")
    # builds: list of {format, as, run} dicts → tuple of (format, remote_path,
    # build_command) triples. `run` is optional (None = poc's default proof).
    builds_raw = e.get("builds") or []
    if not isinstance(builds_raw, list):
        raise LoaderError(f"{source}: execute.builds must be a list, got {builds_raw!r}")
    builds = []
    for i, b in enumerate(builds_raw):
        if not isinstance(b, dict) or "format" not in b or "as" not in b:
            raise LoaderError(
                f"{source}: execute.builds[{i}] must be a mapping with 'format' + 'as' keys, "
                f"got {b!r}")
        run = b.get("run")
        if run is not None and not isinstance(run, str):
            raise LoaderError(
                f"{source}: execute.builds[{i}].run must be a string or absent, got {run!r}")
        builds.append((str(b["format"]), str(b["as"]), run))
    return Execute(command=command, transport=transport, shell=shell,
                    stages=tuple(stages), serves=tuple(serves_raw),
                    builds=tuple(builds))


def _parse_verify(doc, source):
    v = _require(doc, "verify", "<root>", source)
    if not isinstance(v, dict):
        raise LoaderError(f"{source}: verify must be a mapping, got {v!r}")
    success = _require_str(v, "success", "verify", source)
    proof = v.get("proof") or ""
    if proof and not isinstance(proof, str):
        raise LoaderError(f"{source}: verify.proof must be a string, got {proof!r}")
    return Verify(success=success, proof=proof)


def _parse_cleanup(doc, source):
    c = doc.get("cleanup") or {}
    if not isinstance(c, dict):
        raise LoaderError(f"{source}: cleanup must be a mapping, got {c!r}")
    command = c.get("command") or ""
    if command and not isinstance(command, str):
        raise LoaderError(f"{source}: cleanup.command must be a string, got {command!r}")
    return Cleanup(command=command)


def _parse_report(doc, source):
    r = _require(doc, "report", "<root>", source)
    if not isinstance(r, dict):
        raise LoaderError(f"{source}: report must be a mapping, got {r!r}")
    vector_type = _require_str(r, "vector_type", "report", source)
    description = r.get("description") or ""
    remediation = r.get("remediation") or ""
    refs = tuple(r.get("refs") or ())
    if refs and not all(isinstance(x, str) for x in refs):
        raise LoaderError(f"{source}: report.refs must be a list of strings, got {refs!r}")
    evidence = r.get("evidence") or ""
    if evidence and not isinstance(evidence, str):
        raise LoaderError(f"{source}: report.evidence must be a string, got {evidence!r}")
    return Report(vector_type=vector_type, description=description,
                  remediation=remediation, refs=refs, evidence=evidence)


def _parse_playbook(doc, source):
    """Optional top-level `playbook:` block for prepare-only routes. When
    absent, returns None and the emitted Vector has no playbook (auto-fires
    if safety allows). When present, `summary` + `place` + `steps` are all
    required; `restore` is optional."""
    p = doc.get("playbook")
    if p is None:
        return None
    if not isinstance(p, dict):
        raise LoaderError(f"{source}: playbook must be a mapping, got {p!r}")
    summary = _require_str(p, "summary", "playbook", source)
    place = _require_str(p, "place", "playbook", source)
    steps_raw = _require_list(p, "steps", "playbook", source)
    for i, s in enumerate(steps_raw):
        if not isinstance(s, str) or not s.strip():
            raise LoaderError(
                f"{source}: playbook.steps[{i}] must be a non-empty string, got {s!r}")
    restore = p.get("restore") or ""
    if restore and not isinstance(restore, str):
        raise LoaderError(f"{source}: playbook.restore must be a string, got {restore!r}")
    return Playbook(summary=summary, place=place,
                    steps=tuple(steps_raw), restore=restore)


# ---- public loaders -------------------------------------------------------

def load_file(path):
    """Parse one TTP file into a :class:`TTP`. Raises :class:`LoaderError` on
    malformed content — never returns a partially-populated TTP."""
    source = os.path.basename(path)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError) as exc:
        raise LoaderError(f"{source}: cannot read/parse YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise LoaderError(f"{source}: top-level YAML must be a mapping, got {type(doc).__name__}")

    # Optional schema version pin — if declared, must match SCHEMA_VERSION.
    ver = doc.get("schema", SCHEMA_VERSION)
    if ver != SCHEMA_VERSION:
        raise LoaderError(
            f"{source}: schema version {ver!r} not supported; this loader reads {SCHEMA_VERSION}")

    technique = _require_str(doc, "technique", "<root>", source)
    if not _T_CODE_RE.match(technique):
        raise LoaderError(
            f"{source}: technique must be a MITRE T-code (e.g. 'T1548.003'), got {technique!r}")
    name = _require_str(doc, "name", "<root>", source)
    tactic_list = _require_list(doc, "tactic", "<root>", source)
    platform_list = _require_list(doc, "platform", "<root>", source)
    for p in platform_list:
        _require_in(p, VALID_PLATFORMS, f"platform[{platform_list.index(p)}]", source)

    key = doc.get("key") or ""
    if key and not isinstance(key, str):
        raise LoaderError(f"{source}: top-level `key` must be a string, got {key!r}")
    family = doc.get("family") or ""
    if family and not isinstance(family, str):
        raise LoaderError(f"{source}: top-level `family` must be a string, got {family!r}")
    delivery = doc.get("delivery") or ""
    if delivery and not isinstance(delivery, str):
        raise LoaderError(f"{source}: top-level `delivery` must be a string, got {delivery!r}")

    return TTP(
        technique=technique,
        name=name,
        tactic=tuple(tactic_list),
        platform=tuple(platform_list),
        ranking=_parse_ranking(doc, source),
        detect=_parse_detect(doc, source),
        execute=_parse_execute(doc, source),
        verify=_parse_verify(doc, source),
        cleanup=_parse_cleanup(doc, source),
        report=_parse_report(doc, source),
        key=key,
        family=family,
        delivery=delivery,
        playbook=_parse_playbook(doc, source),
        source_path=path,
    )


def load_all(directory=None):
    """Load every ``*.yaml`` in ``directory`` (default: builtin :data:`BUILTIN_DIR`).

    Returns a list of :class:`TTP`, sorted by technique then filename for
    deterministic engine ordering. Raises the FIRST :class:`LoaderError` — no
    silent skips, so a broken file is impossible to miss.
    """
    directory = directory or BUILTIN_DIR
    files = sorted(
        os.path.join(directory, fn)
        for fn in os.listdir(directory)
        if fn.endswith(".yaml") or fn.endswith(".yml")
    )
    ttps = [load_file(p) for p in files]
    ttps.sort(key=lambda t: (t.technique, t.source_path))
    return ttps
