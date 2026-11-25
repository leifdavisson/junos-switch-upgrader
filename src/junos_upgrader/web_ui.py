# SPDX-License-Identifier: AGPL-3.0-or-later
"""Live web topology dashboard, Mermaid exporter, and Rich terminal dependency tree."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.markup import escape as rich_escape
from rich.tree import Tree

from junos_upgrader.topology import TopologyGraph

_STATE_STYLE = {
    "runner": "bold cyan",
    "not-ready": "dim white",
    "ready": "white",
    "staged": "bold cyan",
    "downloaded": "blue",
    "installing": "yellow",
    "rebooting": "magenta",
    "validated": "green",
    "completed": "bold green",
    "rolled-back": "bold magenta",
    "excluded": "dim",
    "replace-recommended": "bold red",
    "ancestor-hold": "bold yellow",
    "failed": "bold red",
}

_MERMAID_ESCAPE_MAP = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
    "#": "&#35;",
    ";": "&#59;",
    "`": "&#96;",
    "\r": " ",
    "\n": " ",
}
_MERMAID_ESCAPE_RE = re.compile(r'[&<>"\'#;`\r\n]')


def _escape_mermaid_label(raw: Any) -> str:
    """Escape dynamic text for safe interpolation into quoted Mermaid labels."""
    text = str(raw if raw is not None else "")
    return _MERMAID_ESCAPE_RE.sub(lambda m: _MERMAID_ESCAPE_MAP[m.group(0)], text)


def _escape_md_inline_code(raw: Any) -> str:
    """Sanitize dynamic text for inline Markdown code spans."""
    text = str(raw if raw is not None else "")
    return text.replace("\r", " ").replace("\n", " ").replace("`", "'")


def render_rich_topology_tree(graph: TopologyGraph, console: Console) -> None:
    """Print an origin-anchored dependency tree to the terminal."""
    origin = graph.origin
    root_label = (
        f"[bold cyan]{rich_escape(origin.hostname)}[/bold cyan] "
        f"({rich_escape(origin.outbound_iface)} {rich_escape(origin.outbound_ip)} "
        f"-> GW {rich_escape(origin.gateway_ip or 'direct')})"
    )
    tree = Tree(root_label)

    children_map: dict[str, list[tuple[str, str, str]]] = {}
    for edge in graph.edges:
        children_map.setdefault(edge.parent_id, []).append(
            (edge.child_id, edge.parent_port, edge.child_port)
        )

    def _add_children(branch: Tree, parent_id: str, seen: set[str]) -> None:
        for child_id, p_port, c_port in sorted(children_map.get(parent_id, [])):
            if child_id in seen:
                continue
            node = graph.nodes.get(child_id)
            if node is None:
                continue
            seen.add(child_id)
            state_str = str(node.get("state", ""))
            style = _STATE_STYLE.get(state_str, "white")
            port_tag = f"[dim]{rich_escape(p_port or '?')} <-> {rich_escape(c_port or '?')}[/dim] "
            target_str = str(node.get("next_hop") or node.get("final_target") or "-")
            leaf = branch.add(
                f"{port_tag}[{style}]{rich_escape(str(node.get('label', child_id)))}[/{style}] "
                f"({rich_escape(str(node.get('ip', '')))}, {rich_escape(str(node.get('model', '')))}, "
                f"{rich_escape(str(node.get('version', '')))} -> {rich_escape(target_str)}, "
                f"depth={rich_escape(str(node.get('depth', 0)))}, "
                f"[{style}]{rich_escape(state_str)}[/{style}])"
            )
            _add_children(leaf, child_id, seen)

    _add_children(tree, "__runner__", {"__runner__"})
    console.print(tree)


def export_topology_markdown(graph: TopologyGraph, output_path: Path) -> Path:
    """Write a Mermaid flowchart LR topology diagram showing ports, depth, and state."""
    lines = [
        "# Live Switch Dependency Topology",
        "",
        (
            f"- **Controller / Runner**: `{_escape_md_inline_code(graph.origin.hostname)}` "
            f"(`{_escape_md_inline_code(graph.origin.outbound_ip)}` on "
            f"`{_escape_md_inline_code(graph.origin.outbound_iface)}`)"
        ),
        f"- **First-Hop Gateway**: `{_escape_md_inline_code(graph.origin.gateway_ip or 'direct L2')}`",
        "",
        "```mermaid",
        "flowchart LR",
    ]
    for node_id, node in graph.nodes.items():
        safe_id = _safe_id(node_id)
        label = _escape_mermaid_label(node.get("label", node_id))
        ip = _escape_mermaid_label(node.get("ip", ""))
        model = _escape_mermaid_label(node.get("model", ""))
        if node.get("kind") == "runner":
            lines.append(f'  {safe_id}["{label}<br/>{ip} ({model})"]')
        else:
            ver = _escape_mermaid_label(node.get("version", ""))
            state = _escape_mermaid_label(node.get("state", ""))
            lines.append(f'  {safe_id}["{label}<br/>{ip} | {model}<br/>{ver} [{state}]"]')

    for edge in graph.edges:
        src = _safe_id(edge.parent_id)
        dst = _safe_id(edge.child_id)
        p_lbl = _escape_mermaid_label(edge.parent_port or "?")
        c_lbl = _escape_mermaid_label(edge.child_port or "?")
        lines.append(f'  {src} -->|"{p_lbl} ↔ {c_lbl}"| {dst}')

    lines.extend(["```", ""])
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")
    return output_path


def _safe_id(raw: str) -> str:
    base = "".join(ch if ch.isalnum() else "_" for ch in raw)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:8]
    return f"n_{base}_{digest}"


def render_topology_html() -> str:
    """Return a self-contained dark-mode real-time SVG topology dashboard."""
    return """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:;" />
<title>Junos Switch Upgrader — Live Topology</title>
<style>
  :root { --bg:#0d1117; --card:#161b22; --border:#30363d; --text:#e6edf3; --muted:#8b949e; }
  body { margin:0; font-family:ui-sans-serif,system-ui,-apple-system,sans-serif; background:var(--bg); color:var(--text); }
  header { padding:14px 20px; border-bottom:1px solid var(--border); display:flex; justify-content:space-between; align-items:center; background:#11161d; }
  header h1 { margin:0; font-size:16px; font-weight:600; }
  .pill { font-size:12px; padding:4px 10px; border-radius:999px; background:#1f2937; color:#93c5fd; border:1px solid #374151; }
  .legend { display:flex; gap:12px; flex-wrap:wrap; padding:10px 20px; border-bottom:1px solid var(--border); font-size:12px; color:var(--muted); }
  .dot { display:inline-block; width:10px; height:10px; border-radius:50%; margin-right:5px; vertical-align:middle; }
  #canvas { width:100%; height:calc(100vh - 104px); overflow:auto; }
  svg { display:block; min-width:100%; min-height:100%; }
  .link { stroke:#4b5563; stroke-width:2; fill:none; }
  .port-lbl { fill:#9ca3af; font-size:11px; font-family:ui-monospace,monospace; }
</style>
</head>
<body>
<header>
  <h1>Junos Switch Upgrader — Live Dependency Topology</h1>
  <span class="pill" id="meta">Connecting...</span>
</header>
<div class="legend">
  <span><i class="dot" style="background:#38bdf8"></i>Runner</span>
  <span><i class="dot" style="background:#94a3b8"></i>Not Ready</span>
  <span><i class="dot" style="background:#60a5fa"></i>Ready</span>
  <span><i class="dot" style="background:#06b6d4"></i>Staged</span>
  <span><i class="dot" style="background:#818cf8"></i>Downloaded</span>
  <span><i class="dot" style="background:#f59e0b"></i>Installing</span>
  <span><i class="dot" style="background:#c084fc"></i>Rebooting</span>
  <span><i class="dot" style="background:#22c55e"></i>Validated / Completed</span>
  <span><i class="dot" style="background:#e879f9"></i>Rolled Back</span>
  <span><i class="dot" style="background:#ef4444"></i>Replace / Failed</span>
  <span><i class="dot" style="background:#eab308"></i>Ancestor Hold</span>
  <span><i class="dot" style="background:#6b7280"></i>Excluded / EOL</span>
</div>
<div id="canvas"><svg id="svg"></svg></div>
<script>
const COLORS = {
  runner:"#38bdf8", "not-ready":"#94a3b8", ready:"#60a5fa", staged:"#06b6d4",
  downloaded:"#818cf8", installing:"#f59e0b", rebooting:"#c084fc",
  validated:"#34d399", completed:"#22c55e", "rolled-back":"#e879f9",
  "replace-recommended":"#ef4444", failed:"#ef4444", "ancestor-hold":"#eab308", excluded:"#6b7280"
};
let inFlight = false;
function esc(v) {
  return String(v ?? '')
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&#39;');
}
function stateColor(state) {
  return Object.hasOwn(COLORS, state) ? COLORS[state] : '#94a3b8';
}
async function refresh() {
  if (inFlight) return;
  inFlight = true;
  try {
    const res = await fetch('/api/topology');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    draw(data);
  } catch (e) {
    document.getElementById('meta').textContent = 'Poll error';
  } finally {
    inFlight = false;
  }
}
function draw(data) {
  const nodes = Array.isArray(data.nodes) ? data.nodes : [];
  const edges = Array.isArray(data.edges) ? data.edges : [];
  document.getElementById('meta').textContent =
    `Origin: ${data.origin?.hostname || '?'} (${data.origin?.ip || '?'}) | Devices: ${Math.max(0, nodes.length - 1)} | Auto-refresh 2s`;
  const byDepth = new Map();
  nodes.forEach(n => {
    const d = Number.isFinite(Number(n.depth)) ? Number(n.depth) : 0;
    if (!byDepth.has(d)) byDepth.set(d, []);
    byDepth.get(d).push(n);
  });
  const depths = Array.from(byDepth.keys()).sort((a,b) => a - b);
  const pos = new Map();
  const colW = 300, rowH = 112, padX = 32, padY = 32;
  let maxRows = 1;
  depths.forEach((d, ci) => {
    const list = byDepth.get(d);
    maxRows = Math.max(maxRows, list.length);
    list.forEach((n, ri) => { pos.set(String(n.id), { x: padX + ci * colW, y: padY + ri * rowH }); });
  });
  const svg = document.getElementById('svg');
  const w = Math.max(960, depths.length * colW + 120), h = Math.max(540, maxRows * rowH + 80);
  svg.setAttribute('width', w); svg.setAttribute('height', h);
  let html = '<defs><clipPath id="node-clip"><rect x="6" y="0" width="208" height="84"/></clipPath></defs>';
  edges.forEach(e => {
    const a = pos.get(String(e.from)), b = pos.get(String(e.to));
    if (!a || !b) return;
    const x1 = a.x + 220, y1 = a.y + 42, x2 = b.x, y2 = b.y + 42;
    const mx = (x1 + x2) / 2;
    html += `<path class="link" d="M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}"/>`;
    html += `<text class="port-lbl" x="${mx}" y="${(y1+y2)/2 - 5}" text-anchor="middle">${esc(e.from_port)} ↔ ${esc(e.to_port)}</text>`;
  });
  nodes.forEach(n => {
    const p = pos.get(String(n.id));
    if (!p) return;
    const c = stateColor(String(n.state || ''));
    const sub = `${esc(n.ip)} · ${esc(n.model)}`;
    const line3 = n.kind === 'runner' ? esc(n.version) : `${esc(n.version)} → ${esc(n.next_hop || n.final_target || 'OK')} (${esc(n.state)})`;
    const disk = n.free_mb != null ? ` · ${esc(n.free_mb)}MB free` : '';
    html += `<g transform="translate(${p.x},${p.y})">
      <rect width="220" height="84" rx="8" fill="#161b22" stroke="${c}" stroke-width="2"/>
      <g clip-path="url(#node-clip)">
        <text x="10" y="21" fill="#f8fafc" font-size="13" font-weight="600">${esc(n.label)}</text>
        <text x="10" y="40" fill="#94a3b8" font-size="11">${sub}</text>
        <text x="10" y="58" fill="${c}" font-size="11">${line3}</text>
        <text x="10" y="74" fill="#64748b" font-size="10">Depth ${esc(n.depth)}${disk}</text>
      </g>
    </g>`;
  });
  svg.innerHTML = html;
}
refresh();
setInterval(refresh, 2000);
</script>
</body>
</html>
"""
