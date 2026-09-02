"""Engagement-folder sync — walk a recce-owned folder + ingest
every recognized artifact into the current fieldkit engagement.

Recce (or any operator) stashes engagement artifacts in one
folder with a canonical layout; fieldkit reads them without the
operator having to remember which `ingest` subcommand handles
which format.

Folder layout (every entry is optional — sync ingests what it
finds):

    eng-<name>/
    ├── manifest.json          # optional; version-pins the layout
    ├── recce-bridge.json      # THE authoritative bridge (main data)
    ├── nmap/
    │   ├── *.xml              # nmap -oX
    │   ├── *.nmap             # nmap -oN
    │   ├── *.gnmap            # nmap -oG
    ├── nxc/
    │   ├── *.log              # nxc capture logs
    ├── bloodhound/
    │   ├── *.zip              # SharpHound zip
    │   ├── *.json             # loose SharpHound JSON
    ├── loot/
    │   ├── *.potfile          # hashcat potfile
    │   ├── hashcat.potfile
    ├── notes.md               # ignored by sync; for operator use

Sync is idempotent — every downstream ingest_* handler is
upsert-shaped, so re-running against a folder that recce has
updated folds only new material.

Reports are:
  * one line per artifact-type file processed (or "skipped")
  * a final counts-delta summary (`hosts: N→M`, etc.)
"""
import glob
import os
from dataclasses import dataclass, field
from typing import List


@dataclass
class SyncReport:
    """Outcome of one sync — one entry per artifact file
    processed + a delta of engagement counts."""
    processed: List[dict] = field(default_factory=list)
    skipped: List[dict] = field(default_factory=list)
    delta: dict = field(default_factory=dict)


def _entry(path, kind, action, note=""):
    return {"path": path, "kind": kind, "action": action, "note": note}


def _list_files(root, subdir, extensions):
    """Return sorted paths under root/subdir matching any of
    the given extensions. Missing dir → empty list."""
    d = os.path.join(root, subdir)
    if not os.path.isdir(d):
        return []
    out = []
    for ext in extensions:
        out.extend(glob.glob(os.path.join(d, f"*{ext}")))
    return sorted(out)


def sync_folder(store, root, *, source_prefix="folder-sync"):
    """Walk ``root`` + ingest every recognized artifact into
    ``store``. Returns a :class:`SyncReport`.

    Idempotent: re-running against the same folder is safe;
    downstream ingest handlers upsert.

    Reads:
      * root/recce-bridge.json (recce_mod.parse + apply)
      * root/nmap/*.xml / *.nmap / *.gnmap (nmap_mod.parse + apply)
      * root/nxc/*.log (ingest_mod.classify_nxc + apply_nxc)
      * root/bloodhound/*.zip and *.json (bloodhound_mod.import_graph)
      * root/loot/*.potfile (hashcat_mod.parse_potfile + apply)
    """
    from . import (bloodhound as bloodhound_mod,
                     hashcat as hashcat_mod,
                     ingest as ingest_mod,
                     nmap as nmap_mod,
                     recce as recce_mod)
    if not os.path.isdir(root):
        raise ValueError(f"{root}: not a directory")

    before = store.counts()
    report = SyncReport()

    # ---- recce-bridge.json (main data path) --------------------
    bridge = os.path.join(root, "recce-bridge.json")
    if os.path.isfile(bridge):
        try:
            with open(bridge, "r", errors="replace") as fh:
                intent = recce_mod.parse(fh.read())
            if intent.hosts:
                recce_mod.apply(store, intent)
                report.processed.append(_entry(
                    bridge, "recce-bridge", "applied",
                    note=f"{len(intent.hosts)} host(s)"))
            else:
                report.skipped.append(_entry(
                    bridge, "recce-bridge", "skipped",
                    note="bridge parses but has no hosts"))
        except (recce_mod.RecceBridgeError, OSError) as exc:
            report.skipped.append(_entry(
                bridge, "recce-bridge", "failed", note=str(exc)))

    # ---- nmap/*.xml / *.nmap / *.gnmap ---------------------------
    for path in _list_files(root, "nmap", (".xml", ".nmap", ".gnmap")):
        try:
            with open(path, "r", errors="replace") as fh:
                intent = nmap_mod.parse(fh.read())
            if intent.hosts:
                nmap_mod.apply(store, intent)
                report.processed.append(_entry(
                    path, "nmap", "applied",
                    note=f"{len(intent.hosts)} host(s)"))
            else:
                report.skipped.append(_entry(
                    path, "nmap", "skipped", note="no usable hosts"))
        except Exception as exc:                            # noqa: BLE001
            report.skipped.append(_entry(
                path, "nmap", "failed", note=str(exc)[:120]))

    # ---- nxc/*.log ------------------------------------------------
    for path in _list_files(root, "nxc", (".log", ".txt")):
        try:
            with open(path, "r", errors="replace") as fh:
                intent = ingest_mod.classify_nxc(fh.read())
            if intent.hosts or intent.creds:
                ingest_mod.apply_nxc(store, intent,
                                       source=f"{source_prefix}:nxc")
                report.processed.append(_entry(
                    path, "nxc", "applied",
                    note=f"{len(intent.hosts)} host(s), "
                         f"{len(intent.creds)} cred(s)"))
            else:
                report.skipped.append(_entry(
                    path, "nxc", "skipped",
                    note="no [+] auth lines or [*] banners"))
        except Exception as exc:                            # noqa: BLE001
            report.skipped.append(_entry(
                path, "nxc", "failed", note=str(exc)[:120]))

    # ---- bloodhound/*.zip and directory-of-json -------------------
    bh_dir = os.path.join(root, "bloodhound")
    if os.path.isdir(bh_dir):
        # Prefer a .zip if one exists; else the whole directory
        zips = sorted(glob.glob(os.path.join(bh_dir, "*.zip")))
        if zips:
            for path in zips:
                try:
                    counts = bloodhound_mod.import_graph(store, path)
                    report.processed.append(_entry(
                        path, "bloodhound", "applied",
                        note=f"{counts['nodes']} node(s), "
                             f"{counts['edges']} edge(s)"))
                except Exception as exc:                    # noqa: BLE001
                    report.skipped.append(_entry(
                        path, "bloodhound", "failed",
                        note=str(exc)[:120]))
        elif glob.glob(os.path.join(bh_dir, "*.json")):
            # loose JSON layout — import_graph accepts a dir
            try:
                counts = bloodhound_mod.import_graph(store, bh_dir)
                report.processed.append(_entry(
                    bh_dir, "bloodhound", "applied",
                    note=f"{counts['nodes']} node(s), "
                         f"{counts['edges']} edge(s)"))
            except Exception as exc:                        # noqa: BLE001
                report.skipped.append(_entry(
                    bh_dir, "bloodhound", "failed",
                    note=str(exc)[:120]))

    # ---- loot/*.potfile / hashcat.potfile -------------------------
    for path in _list_files(root, "loot", (".potfile",)):
        try:
            with open(path, "r", errors="replace") as fh:
                entries = hashcat_mod.parse_potfile(fh.read())
            if entries:
                rep = hashcat_mod.apply(store, entries)
                report.processed.append(_entry(
                    path, "hashcat", "applied",
                    note=f"{rep.matched}/{rep.entries} matched, "
                         f"{rep.creds_promoted} promoted"))
            else:
                report.skipped.append(_entry(
                    path, "hashcat", "skipped",
                    note="no hash:plain lines"))
        except Exception as exc:                            # noqa: BLE001
            report.skipped.append(_entry(
                path, "hashcat", "failed", note=str(exc)[:120]))

    after = store.counts()
    for k in ("hosts", "services", "credentials", "findings",
              "proven_findings", "access"):
        if after.get(k, 0) != before.get(k, 0):
            report.delta[k] = (before.get(k, 0), after.get(k, 0))
    return report
