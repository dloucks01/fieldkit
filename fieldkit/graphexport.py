"""Export the unified asset graph for visualization.

fieldkit stitches every domain — AD/hosts, web, cloud IAM, k8s RBAC, SaaS/IdP — into
one ``asset`` / ``asset_edge`` graph (see :mod:`fieldkit.assetgraph` and
:mod:`fieldkit.adbridge`). This renders that graph in two portable formats so an operator
can *see* it:

* **JSON** — a tool-agnostic ``{nodes, edges}`` document (load into Cytoscape, D3,
  Gephi, a notebook);
* **DOT** — a Graphviz digraph, coloured by domain, with owned footholds and high-value
  targets marked and pivot (cross-domain) edges dashed — ``dot -Tsvg`` straight to a
  picture.

Both are read-only over the current graph state; run ``fieldkit paths`` first (it bridges
AD/host + web and derives the pivot edges) so the export shows the cross-domain links.
"""
import json
from datetime import datetime, timezone

from .assetgraph import PIVOT_PREFIX, _domain_of_kind

#: Fill colour per domain (light, print-friendly). An unknown domain falls back to grey.
_DOMAIN_COLOR = {
    "ad": "#c9d7f0",        # blue
    "web": "#d7f0c9",       # green
    "external": "#f0d7c9",  # orange
    "cloud": "#f0e6c9",     # amber
    "k8s": "#c9f0ec",       # teal
    "saas": "#f0c9e6",      # pink
    "cross": "#eeeeee",
}
_DEFAULT_COLOR = "#e8e8e8"


def _node(store_row):
    """Normalize an asset row into an export node dict."""
    props = json.loads(store_row["props_json"] or "{}")
    return {
        "id": store_row["id"],
        "key": store_row["key"],
        "label": store_row["label"] or store_row["key"],
        "kind": store_row["kind"],
        "domain": _domain_of_kind(store_row["kind"]),
        "owned": bool(props.get("owned")),
        "admin": bool(props.get("admin")),
    }


def to_json(store):
    """The unified asset graph as a ``{engagement, generated, nodes, edges}`` document.
    Edges carry ``pivot`` (True for a cross-domain pivot edge)."""
    eng = store.require_engagement()
    nodes = [_node(a) for a in store.assets()]
    node_ids = {n["id"] for n in nodes}
    edges = []
    for e in store.asset_edges():
        if e["src_id"] in node_ids and e["dst_id"] in node_ids:
            edges.append({
                "src": e["src_id"], "dst": e["dst_id"], "kind": e["kind"],
                "pivot": e["kind"].startswith(PIVOT_PREFIX)})
    return {
        "engagement": eng["name"],
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "nodes": nodes,
        "edges": edges,
    }


def _dot_escape(s):
    r"""Escape a string for a DOT double-quoted id/label (``"`` and ``\``)."""
    return str(s).replace("\\", "\\\\").replace('"', '\\"')


def _node_attrs(n):
    """Graphviz attributes for a node: fill by domain, box(=principal)/doubleoctagon
    (=high-value target), and a bold green border for an owned foothold."""
    fill = _DOMAIN_COLOR.get(n["domain"], _DEFAULT_COLOR)
    shape = "doubleoctagon" if n["admin"] else "box"
    label = f"{n['label']}\\n({n['domain']})"
    attrs = [f'label="{_dot_escape(label)}"', "style=filled",
             f'fillcolor="{fill}"', f"shape={shape}"]
    if n["owned"]:
        attrs += ['color="#1a7f37"', "penwidth=3"]        # owned foothold
    return ", ".join(attrs)


def to_dot(store):
    """The unified asset graph as a Graphviz DOT digraph. Domain-coloured nodes,
    owned footholds bordered green, high-value targets as double-octagons, and
    cross-domain pivot edges dashed. ``dot -Tsvg -o graph.svg``."""
    data = to_json(store)
    lines = ["digraph fieldkit {", "  rankdir=LR;",
             '  node [fontname="Helvetica", fontsize=10];',
             '  edge [fontname="Helvetica", fontsize=8];']
    for n in data["nodes"]:
        lines.append(f'  n{n["id"]} [{_node_attrs(n)}];')
    for e in data["edges"]:
        style = ' style=dashed color="#888888"' if e["pivot"] else ""
        lines.append(f'  n{e["src"]} -> n{e["dst"]} '
                     f'[label="{_dot_escape(e["kind"])}"{style}];')
    lines.append("}")
    return "\n".join(lines)
