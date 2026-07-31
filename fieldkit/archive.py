"""Package the engagement into a single deliverable tarball for handoff or
retention.

The engagement leaves fieldkit as several files scattered across the tester's
working directory: the SQLite DB, a rendered report (md/docx/pdf), the cleanup
manifest, the recce export. Handing that off — to another tester mid-engagement,
or into long-term storage after — means remembering which files matter and
tarring the right subset. This automates that.

Design goals:
  * **One command produces one file.** ``fieldkit archive`` → a tar.gz named
    for the engagement + date. Nothing else to remember.
  * **Regenerate on demand.** The archive command runs report + cleanup +
    recce-export as part of assembly, so the tarball ALWAYS reflects current
    state — you don't have to remember to re-run each of those first.
  * **Extensible by one row.** New items get added by appending to
    :data:`ARCHIVE_ITEMS` — a table of `(name, generator, required)` tuples.
    Adding a new evidence type (a screenshot bundle, a new tool export) is
    one function + one row, not scattered work.
  * **Internal, not client-facing.** The archive contains the cleanup manifest
    (which has secrets), the raw DB (which has hashes), and the full evidence
    trail. It's for the operator's records; the customer-facing artifacts are
    the report .docx/.pdf separately.
  * **Manifest inside.** Every archive includes a MANIFEST.md that lists what
    it contains, when it was assembled, the fieldkit version, and the SQLite
    schema version. A future operator reading the tarball knows exactly what
    they have.
"""
import json
import os
import sqlite3
import tarfile
import tempfile
from datetime import datetime, timezone

from . import __version__
from . import bridge as bridge_mod
from . import report as report_mod


# ------------------------------------------------------------- item generators
# Each generator writes ONE file into `out_dir` and returns its filename (or None
# if it wasn't produced, e.g. the report has no findings). Runs inside a temp
# staging dir; nothing here writes to the operator's CWD.

def _copy_db(store, config, out_dir):
    """The SQLite engagement DB — the source of truth. Always included.

    Uses SQLite's online backup API rather than ``shutil.copy2`` so that
    uncommitted WAL pages land in the copy — with WAL journal mode a plain
    file copy captures the main db file only and drops any recent writes
    still sitting in ``.db-wal``.
    """
    dest = os.path.join(out_dir, "engagement.db")
    dest_conn = sqlite3.connect(dest)
    try:
        store.conn.backup(dest_conn)
    finally:
        dest_conn.close()
    return os.path.basename(dest)


def _write_report(store, config, out_dir, formats):
    """Render the report in each requested format. Returns the list of files
    written; skips empty-engagement gracefully."""
    engagement, findings = report_mod.build(store, config, proven_only=False)
    if not findings:
        return []
    md_path = os.path.join(out_dir, "report.md")
    with open(md_path, "w") as fh:
        fh.write(report_mod.render_markdown(engagement, findings))
    written = ["report.md"]
    # docx/pdf require pandoc; export() prints a hint if it's missing, we suppress
    lines = report_mod.export(md_path, os.path.join(out_dir, "report"),
                              [f for f in formats if f != "md"])
    for line in lines:
        if line.startswith("wrote "):
            written.append(os.path.basename(line[len("wrote "):]))
    return written


def _write_cleanup(store, config, out_dir):
    """The internal cleanup manifest. Empty if nothing changed the target."""
    engagement, findings = report_mod.build(store, config, proven_only=True)
    if not findings:
        return None
    text = report_mod.cleanup_manifest(engagement, findings)
    if not text.strip():
        return None
    dest = os.path.join(out_dir, "report.cleanup.md")
    with open(dest, "w") as fh:
        fh.write(text)
    return "report.cleanup.md"


def _write_recce_export(store, config, out_dir):
    """The recce JSON export — proven findings, KB-enriched. Skipped if empty."""
    engagement, findings = report_mod.build(store, config, proven_only=True)
    if not findings:
        return None
    dest = os.path.join(out_dir, "recce_findings.json")
    payload = bridge_mod.export_payload(engagement, findings)
    with open(dest, "w") as fh:
        json.dump(payload, fh, indent=2)
    return "recce_findings.json"


def _write_steps_jsonl(store, config, out_dir):
    """Every captured step, one JSON per line. This is the raw evidence trail —
    beyond what renders in the report, so a future auditor can independently
    verify every command fieldkit ran against a target."""
    dest = os.path.join(out_dir, "steps.jsonl")
    n = 0
    with open(dest, "w") as fh:
        for row in store.steps():
            fh.write(json.dumps({
                "id": row["id"],
                "ts": row["ts"],
                "host_id": row["host_id"],
                "finding_id": row["finding_id"],
                "label": row["label"],
                "transport": row["transport"],
                "cmd": row["cmd"],
                "exit_code": row["exit_code"],
                "output": row["output"],
            }) + "\n")
            n += 1
    return "steps.jsonl" if n else None


def _write_manifest(store, config, out_dir, iso_date, items, engagement_name):
    """MANIFEST.md — human-readable index of what's in the archive."""
    dest = os.path.join(out_dir, "MANIFEST.md")
    lines = [
        f"# Engagement archive — {engagement_name}",
        "",
        f"**Assembled:** {iso_date}",
        f"**fieldkit version:** {__version__}",
        f"**Schema version:** {store.schema_version()}",
        "",
        "## Contents",
        "",
    ]
    for name, note in items:
        lines.append(f"- **`{name}`** — {note}")
    lines.extend([
        "",
        "## Nature",
        "",
        "This archive is **internal** — it contains the cleanup manifest (which "
        "names credentials and reversible changes made to targets), the raw "
        "SQLite state (which holds recovered hashes and credentials in the "
        "clear), and the full evidence trail. Do not hand it to the client; "
        "the client-facing deliverable is `report.docx` (or `.pdf`) alone.",
        "",
        "## Restoring",
        "",
        "Extract and open the DB with fieldkit:",
        "",
        "```bash",
        "tar xzf <this-archive>.tar.gz",
        "cd <extracted-dir>",
        "fieldkit --db engagement.db status",
        "```",
        "",
        "Every command that reads state (`status`, `analyze`, `report`, "
        "`export-recce`) works against the extracted DB as it did on the "
        "engagement it was built for.",
        "",
    ])
    with open(dest, "w") as fh:
        fh.write("\n".join(lines))
    return "MANIFEST.md"


# ------------------------------------------------------------- item registry
#
# Extend fieldkit's archive by appending to this table.
# Each entry: (label_for_manifest, generator_callable, required).
# Generator signature: (store, config, out_dir, **kwargs) -> filename or None.
#
# Runtime kwargs threaded to specific generators are handled in `build_archive`
# below (e.g. `formats` for the report generator, `iso_date` for the manifest).

ARCHIVE_ITEMS = (
    ("engagement.db", "the SQLite source of truth — every host, credential, "
                      "step, finding, loot row, and cleanup obligation"),
    ("report.md / .docx / .pdf", "the customer report (findings + observations "
                                  "+ credentials recovered)"),
    ("report.cleanup.md", "internal checklist of reversible changes to undo on "
                          "the target(s) before departure"),
    ("recce_findings.json", "KB-enriched export of proven findings for recce "
                            "(`recce fieldkit-import <path>`)"),
    ("steps.jsonl", "every executed command with its captured output — the "
                    "raw evidence trail beyond what the report renders"),
    ("MANIFEST.md", "human-readable index of this archive's contents"),
)


# ------------------------------------------------------------- driver

def build_archive(store, config, *, out_path=None, formats=("md", "docx", "pdf")):
    """Assemble the whole engagement into ``out_path`` (a `.tar.gz`).

    ``out_path`` defaults to ``<engagement-slug>-<YYYY-MM-DD>.tar.gz`` in CWD.
    Returns ``(final_path, bundled_files, warnings)``. Never raises for an
    empty engagement — the DB always gets included, the rest is best-effort.
    """
    warnings = []
    engagement_row = store.require_engagement()
    engagement_name = engagement_row["name"]
    now = datetime.now(timezone.utc)
    iso_date = now.strftime("%Y-%m-%d %H:%M:%S UTC")
    date_slug = now.strftime("%Y-%m-%d")
    name_slug = "".join(c if c.isalnum() or c in "-_" else "_"
                        for c in engagement_name).strip("_") or "engagement"
    out_path = out_path or f"{name_slug}-{date_slug}.tar.gz"

    staged = []                                # (filename, note) for MANIFEST
    with tempfile.TemporaryDirectory(prefix="fk-archive-") as tmp:
        # Every generator is best-effort — the archive always contains at least
        # the DB. A generator that raises is logged as a warning and skipped.
        def _safe(fn, note, **kw):
            try:
                result = fn(store, config, tmp, **kw)
            except Exception as exc:                                # noqa: BLE001
                warnings.append(f"{fn.__name__}: {exc}")
                return
            if result is None:
                return
            if isinstance(result, list):
                for name in result:
                    staged.append((name, note))
            else:
                staged.append((result, note))

        _safe(_copy_db, "the SQLite source of truth")
        _safe(_write_report,
              "the customer report (auto-generated from current state)",
              formats=formats)
        _safe(_write_cleanup,
              "internal cleanup manifest — reversible changes to undo")
        _safe(_write_recce_export,
              "KB-enriched proven findings for recce")
        _safe(_write_steps_jsonl,
              "the full evidence trail — every captured command + output")
        # Add MANIFEST to the staged list BEFORE writing it, so the manifest's
        # own Contents section self-references (a reader sees "MANIFEST.md" in
        # its own list — no surprise files in the tarball).
        staged.append(("MANIFEST.md",
                       "human-readable index of this archive's contents"))
        _write_manifest(store, config, tmp, iso_date, staged, engagement_name)

        # Pack into a tarball; every path inside is prefixed with a folder
        # named for the archive (so extracting doesn't spill into CWD).
        prefix = name_slug + "-" + date_slug
        with tarfile.open(out_path, "w:gz") as tar:
            for filename, _note in staged:
                src = os.path.join(tmp, filename)
                if os.path.exists(src):
                    tar.add(src, arcname=os.path.join(prefix, filename))

    return out_path, [name for name, _ in staged], warnings
