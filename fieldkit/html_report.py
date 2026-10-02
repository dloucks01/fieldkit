"""Standalone interactive HTML report with embedded SVG attack path.

Produces a single self-contained .html file: inline CSS + inline JS +
inline SVG. No external assets, no CDN dependency, no network — the
customer opens the file and everything renders.

Features that distinguish it from the Markdown-via-pandoc HTML the
existing report pipeline already produces:

  * **Embedded SVG attack path** — one SVG per walked chain, with host
    nodes + edges drawn directly in the DOM. Hover-highlight on nodes.
  * **Filters** — top-of-page controls to filter findings by severity
    (Critical/High/Medium/Low/Info), by status (proven/observation),
    and by host.
  * **Collapsible per-host sections** — click a host heading to collapse
    its findings; useful on big engagements with 50+ hosts.
  * **Dark/light theme** — follows ``prefers-color-scheme`` by default,
    with a persistent toggle (localStorage).

Pure render — reads the finding + chain dicts the report builder
already produces, writes the HTML string. No I/O inside the module;
the caller writes the string to disk."""
import html as _html


def _esc(s):
    return _html.escape(str(s) if s is not None else "")


_CSS = r"""
:root {
  --bg: #ffffff;
  --fg: #1a1a1a;
  --muted: #666;
  --accent: #0366d6;
  --card: #f6f8fa;
  --border: #e1e4e8;
  --critical: #cb2431;
  --high: #e36209;
  --medium: #dbab09;
  --low: #28a745;
  --info: #6a737d;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #0d1117;
    --fg: #c9d1d9;
    --muted: #8b949e;
    --accent: #58a6ff;
    --card: #161b22;
    --border: #30363d;
  }
}
:root[data-theme="dark"] {
  --bg: #0d1117;
  --fg: #c9d1d9;
  --muted: #8b949e;
  --accent: #58a6ff;
  --card: #161b22;
  --border: #30363d;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 2rem;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  background: var(--bg); color: var(--fg); line-height: 1.5;
}
h1, h2, h3 { margin-top: 1.5em; }
.controls {
  position: sticky; top: 0; background: var(--bg);
  border-bottom: 1px solid var(--border);
  padding: 0.75rem 0; margin-bottom: 1.5rem;
  display: flex; gap: 1rem; flex-wrap: wrap; align-items: center;
  z-index: 10;
}
.controls label { font-size: 0.9em; color: var(--muted); }
.controls select, .controls button {
  background: var(--card); color: var(--fg);
  border: 1px solid var(--border); border-radius: 4px;
  padding: 0.3rem 0.6rem; font-size: 0.9em; cursor: pointer;
}
.host-section { border: 1px solid var(--border); border-radius: 6px;
  margin: 1rem 0; background: var(--card); overflow: hidden; }
.host-heading {
  padding: 0.75rem 1rem; cursor: pointer;
  background: var(--card); border-bottom: 1px solid var(--border);
  font-weight: 600; user-select: none;
}
.host-heading::before { content: "▾ "; color: var(--muted); }
.host-section.collapsed .host-heading::before { content: "▸ "; }
.host-section.collapsed .host-body { display: none; }
.host-body { padding: 0.5rem 1rem 1rem; }
.finding {
  border: 1px solid var(--border); border-radius: 4px;
  padding: 0.75rem; margin: 0.5rem 0; background: var(--bg);
}
.finding-head { display: flex; gap: 0.75rem; align-items: baseline; }
.sev { font-weight: 600; font-size: 0.85em; padding: 0.1rem 0.4rem;
  border-radius: 3px; color: #fff; }
.sev-Critical { background: var(--critical); }
.sev-High     { background: var(--high); }
.sev-Medium   { background: var(--medium); color: #1a1a1a; }
.sev-Low      { background: var(--low); }
.sev-Info     { background: var(--info); }
.finding-title { flex: 1; font-weight: 500; }
.proof {
  background: var(--card); border: 1px solid var(--border);
  border-radius: 3px; padding: 0.5rem; margin-top: 0.5rem;
  font-family: ui-monospace, 'SFMono-Regular', Menlo, monospace;
  font-size: 0.85em; white-space: pre-wrap; overflow-x: auto;
}
.graph-wrap { margin: 1rem 0; }
svg.attack-path { max-width: 100%; height: auto; background: var(--card);
  border: 1px solid var(--border); border-radius: 6px; }
.attack-node { stroke: var(--border); stroke-width: 1; fill: var(--bg); }
.attack-node:hover { stroke: var(--accent); stroke-width: 2; }
.attack-node-text { font-size: 11px; fill: var(--fg); user-select: none; }
.attack-edge { stroke: var(--muted); stroke-width: 1.5; fill: none;
  marker-end: url(#arrow); }
"""


_JS = r"""
(function(){
  // Dark/light toggle — persists via localStorage, falls back to system
  function readTheme(){ try { return localStorage.getItem('fieldkit-theme'); } catch(e) { return null; } }
  function saveTheme(v){ try { localStorage.setItem('fieldkit-theme', v); } catch(e) {} }
  var stored = readTheme();
  if (stored) document.documentElement.setAttribute('data-theme', stored);
  var tbtn = document.getElementById('theme-toggle');
  if (tbtn) tbtn.addEventListener('click', function(){
    var cur = document.documentElement.getAttribute('data-theme');
    var next = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    saveTheme(next);
  });

  // Collapse-expand per-host
  document.querySelectorAll('.host-heading').forEach(function(h){
    h.addEventListener('click', function(){
      h.parentElement.classList.toggle('collapsed');
    });
  });

  // Filter by severity + proven status + host
  function applyFilters(){
    var sev = document.getElementById('f-sev').value;
    var status = document.getElementById('f-status').value;
    var host = document.getElementById('f-host').value;
    document.querySelectorAll('.finding').forEach(function(f){
      var show = true;
      if (sev && f.dataset.sev !== sev) show = false;
      if (status && f.dataset.status !== status) show = false;
      if (host && f.dataset.host !== host) show = false;
      f.style.display = show ? '' : 'none';
    });
    document.querySelectorAll('.host-section').forEach(function(s){
      var any = Array.prototype.some.call(
        s.querySelectorAll('.finding'),
        function(f){ return f.style.display !== 'none'; });
      s.style.display = any ? '' : 'none';
    });
  }
  ['f-sev','f-status','f-host'].forEach(function(id){
    var el = document.getElementById(id);
    if (el) el.addEventListener('change', applyFilters);
  });
})();
"""


_SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def _unique_hosts(findings):
    seen = []
    for f in findings:
        h = f.get("affected_host") or ""
        if h and h not in seen:
            seen.append(h)
    return seen


def _render_svg(host, chain_steps):
    """Render one chain as an SVG. ``chain_steps`` is a list of
    ``{name, outcome}`` dicts (names must be strings, outcome is one of
    ok/manual/skip/fail). Each step becomes a node; edges connect them
    in order."""
    if not chain_steps:
        return ""
    node_w, node_h, gap = 160, 44, 60
    width = len(chain_steps) * (node_w + gap) + 40
    height = node_h + 60
    outcome_color = {"ok": "#28a745", "manual": "#0366d6",
                     "skip": "#8b949e", "fail": "#cb2431"}
    parts = [f'<svg class="attack-path" viewBox="0 0 {width} {height}" '
             f'xmlns="http://www.w3.org/2000/svg">']
    parts.append(
        '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" '
        'markerWidth="6" markerHeight="6" orient="auto">'
        '<path d="M 0 0 L 10 5 L 0 10 z" fill="#8b949e"/></marker></defs>')
    parts.append(f'<text x="20" y="20" class="attack-node-text" '
                 f'font-weight="bold">host: {_esc(host)}</text>')
    y = 30
    for i, step in enumerate(chain_steps):
        x = 20 + i * (node_w + gap)
        color = outcome_color.get(step.get("outcome", ""), "#8b949e")
        name = _esc(step.get("name", "?"))
        parts.append(
            f'<rect class="attack-node" x="{x}" y="{y}" width="{node_w}" '
            f'height="{node_h}" rx="4" ry="4" stroke="{color}"/>')
        parts.append(
            f'<text class="attack-node-text" x="{x + node_w / 2}" '
            f'y="{y + node_h / 2 + 4}" text-anchor="middle">{name}</text>')
        if i < len(chain_steps) - 1:
            x2 = x + node_w
            x3 = x + node_w + gap
            ym = y + node_h / 2
            parts.append(
                f'<path class="attack-edge" d="M {x2} {ym} L {x3} {ym}"/>')
    parts.append('</svg>')
    return "".join(parts)


def _render_finding(f):
    sev = f.get("severity") or "Medium"
    proven = bool(f.get("proven", True))
    status = "proven" if proven else "observation"
    host = f.get("affected_host") or ""
    title = _esc(f.get("title") or f.get("vector_type") or "?")
    vt = _esc(f.get("vector_type") or "")
    evidence = _esc(f.get("evidence") or "")
    steps = f.get("steps") or []
    parts = [
        f'<div class="finding" data-sev="{_esc(sev)}" '
        f'data-status="{status}" data-host="{_esc(host)}">',
        '<div class="finding-head">',
        f'<span class="sev sev-{_esc(sev)}">{_esc(sev)}</span>',
        f'<span class="finding-title">{title}</span>',
        f'<span style="color:var(--muted);font-size:0.85em">[{vt}]</span>',
        '</div>']
    if evidence:
        parts.append(f'<div style="color:var(--muted);font-size:0.9em;'
                     f'margin-top:0.3rem">{evidence}</div>')
    if steps:
        for s in steps:
            cmd = _esc(s.get("cmd") or "")
            output = _esc((s.get("output") or "")[:1000])
            if cmd:
                parts.append(f'<div class="proof">$ {cmd}\n{output}</div>')
    parts.append('</div>')
    return "".join(parts)


def _render_host_section(host, host_findings, chain_viz=None):
    inner = "".join(_render_finding(f) for f in host_findings)
    svg = chain_viz or ""
    svg_wrap = f'<div class="graph-wrap">{svg}</div>' if svg else ""
    return (
        '<section class="host-section">'
        f'<div class="host-heading">{_esc(host or "(no host)")} — '
        f'{len(host_findings)} finding(s)</div>'
        '<div class="host-body">'
        f'{svg_wrap}'
        f'{inner}'
        '</div></section>')


def render(engagement, findings, chains_by_host=None):
    """Render a single self-contained interactive HTML document.

    ``engagement`` is the metadata dict (name, scope, ...).
    ``findings`` is the list the report builder produced.
    ``chains_by_host`` is an optional ``{host: [{name, outcome}, ...]}``
    map — if provided, each host section renders its SVG attack path."""
    hosts = _unique_hosts(findings)
    sev_options = sorted({f.get("severity") or "Medium" for f in findings},
                          key=lambda s: _SEV_ORDER.get(s, 99))
    sev_opts_html = "".join(
        f'<option value="{_esc(s)}">{_esc(s)}</option>' for s in sev_options)
    host_opts_html = "".join(
        f'<option value="{_esc(h)}">{_esc(h)}</option>' for h in hosts)

    sections = []
    for host in hosts:
        host_findings = sorted(
            [f for f in findings if f.get("affected_host") == host],
            key=lambda f: _SEV_ORDER.get(f.get("severity", "Info"), 99))
        chain_viz = ""
        if chains_by_host and host in chains_by_host:
            chain_viz = _render_svg(host, chains_by_host[host])
        sections.append(_render_host_section(host, host_findings, chain_viz))
    # Findings with no host go into a trailing bucket.
    no_host = [f for f in findings if not f.get("affected_host")]
    if no_host:
        sections.append(_render_host_section("(no host)", no_host))

    name = _esc(engagement.get("name") or "engagement")
    scope = _esc(engagement.get("scope") or "")

    html_body = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>fieldkit report — {name}</title>
<style>{_CSS}</style>
</head>
<body>
<h1>fieldkit report — {name}</h1>
<p style="color:var(--muted)">Scope: {scope}</p>

<div class="controls">
  <label>Severity
    <select id="f-sev"><option value="">(any)</option>{sev_opts_html}</select>
  </label>
  <label>Status
    <select id="f-status">
      <option value="">(any)</option>
      <option value="proven">proven</option>
      <option value="observation">observation</option>
    </select>
  </label>
  <label>Host
    <select id="f-host"><option value="">(any)</option>{host_opts_html}</select>
  </label>
  <button id="theme-toggle" type="button">toggle theme</button>
  <span style="color:var(--muted);font-size:0.85em;margin-left:auto">
    {len(findings)} finding(s) across {len(hosts)} host(s)
  </span>
</div>

{"".join(sections)}

<script>{_JS}</script>
</body></html>"""
    return html_body
