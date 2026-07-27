"""
The relationship graph as one picture.

Layout is computed here, at build time, not in the reader's browser. A
force-directed simulation in JavaScript would mean shipping a physics loop,
watching the graph writhe for two seconds on every visit, and getting a
different picture each time - which for something people will screenshot into a
report is the wrong property. Solved once, deterministically, the page is a
static SVG the browser only has to filter and pan.

The simulation is Fruchterman-Reingold with a deterministic start: nodes begin
on a circle in slug order, so the same input always produces the same picture
and a rebuild does not reshuffle a layout someone has already cited.
"""

import math
from typing import Any

from apttrail.exporters.group_pages import STYLE, esc, head
from apttrail.relations import TIERS

SITE_URL = "https://trilwu.github.io/apttrail"
PROJECT_URL = "https://github.com/trilwu/apttrail"

WIDTH, HEIGHT = 1200.0, 820.0
ITERATIONS = 260

#: Drawing order and colour, weakest evidence underneath.
EVIDENCE_STYLE = {
    "infrastructure": ("var(--accent)", 1.6, 0.85),
    "reporting": ("var(--ink)", 1.1, 0.45),
    "software": ("var(--muted)", 0.9, 0.35),
    "technique": ("var(--muted)", 0.8, 0.22),
}

GRAPH_STYLE = """
main.solo { grid-column: 1 / -1; max-width: none; }
.board { border: 1px solid var(--line-firm); border-radius: 4px; background: var(--panel);
         margin-top: 1rem; overflow: hidden; touch-action: none; }
svg { display: block; width: 100%; height: auto; cursor: grab; }
svg.dragging { cursor: grabbing; }
.edge { stroke-linecap: round; }
.node circle { stroke: var(--bg); stroke-width: 1.5; fill: var(--muted); }
.node text { font: 10px var(--mono); fill: var(--faint); text-anchor: middle; pointer-events: none; }
.node.attack circle { fill: var(--accent); }
.node:hover circle { stroke: var(--accent); stroke-width: 2.5; }
.node:hover text { fill: var(--ink); }
.node.dim { opacity: .12; }
.edge.dim { opacity: .04; }
.node.lit circle { stroke: var(--accent); stroke-width: 3; }
.node.lit text { fill: var(--ink); font-weight: 600; }
.legend { display: flex; flex-wrap: wrap; gap: 1rem; margin-top: .8rem;
          font: .78rem/1.6 var(--mono); color: var(--muted); }
.legend label { display: flex; gap: .4rem; align-items: center; cursor: pointer; }
.legend .swatch { width: 1.6rem; height: 0; border-top-width: 2px; border-top-style: solid; }
#detail { margin-top: 1rem; min-height: 4rem; font: .85rem/1.7 var(--mono); }
#detail .pair { font: 500 1rem/1.5 var(--sans); }
#detail .ev { display: block; color: var(--muted); }
#detail a { color: var(--ink); }
"""

GRAPH_SCRIPT = """
(function () {
  var svg = document.getElementById('graph');
  if (!svg) return;
  var detail = document.getElementById('detail');
  var box = { x: 0, y: 0, w: %(width)s, h: %(height)s };

  function view() { svg.setAttribute('viewBox', box.x + ' ' + box.y + ' ' + box.w + ' ' + box.h); }

  // Pan by dragging, zoom on wheel. Enough to read a dense corner without
  // shipping a graph library to do it.
  var drag = null;
  svg.addEventListener('pointerdown', function (e) {
    drag = { x: e.clientX, y: e.clientY };
    svg.classList.add('dragging');
    svg.setPointerCapture(e.pointerId);
  });
  svg.addEventListener('pointermove', function (e) {
    if (!drag) return;
    var scale = box.w / svg.clientWidth;
    box.x -= (e.clientX - drag.x) * scale;
    box.y -= (e.clientY - drag.y) * scale;
    drag = { x: e.clientX, y: e.clientY };
    view();
  });
  var stop = function () { drag = null; svg.classList.remove('dragging'); };
  svg.addEventListener('pointerup', stop);
  svg.addEventListener('pointercancel', stop);
  svg.addEventListener('wheel', function (e) {
    e.preventDefault();
    var factor = e.deltaY > 0 ? 1.12 : 0.89;
    var rect = svg.getBoundingClientRect();
    var fx = box.x + ((e.clientX - rect.left) / rect.width) * box.w;
    var fy = box.y + ((e.clientY - rect.top) / rect.height) * box.h;
    box.x = fx - (fx - box.x) * factor;
    box.y = fy - (fy - box.y) * factor;
    box.w *= factor;
    box.h *= factor;
    view();
  }, { passive: false });

  document.getElementById('reset').addEventListener('click', function () {
    box = { x: 0, y: 0, w: %(width)s, h: %(height)s };
    view();
  });

  var kinds = Array.prototype.slice.call(document.querySelectorAll('.legend input'));
  var edges = Array.prototype.slice.call(svg.querySelectorAll('.edge'));
  var nodes = Array.prototype.slice.call(svg.querySelectorAll('.node'));

  function apply() {
    var on = {};
    kinds.forEach(function (k) { on[k.value] = k.checked; });
    var live = {};
    edges.forEach(function (edge) {
      var visible = edge.dataset.kinds.split(' ').some(function (k) { return on[k]; });
      edge.hidden = !visible;
      if (visible) { live[edge.dataset.a] = live[edge.dataset.b] = true; }
    });
    nodes.forEach(function (n) { n.classList.toggle('dim', !live[n.dataset.slug]); });
    document.getElementById('count').textContent =
      edges.filter(function (e) { return !e.hidden; }).length.toLocaleString();
  }
  kinds.forEach(function (k) { k.addEventListener('change', apply); });

  var q = document.getElementById('q');
  q.addEventListener('input', function () {
    var needle = q.value.trim().toLowerCase();
    var hit = null;
    nodes.forEach(function (n) {
      var match = needle && n.dataset.k.indexOf(needle) !== -1;
      n.classList.toggle('lit', !!match);
      if (match && !hit) { hit = n; }
    });
    if (hit) {
      // Centre on the first match rather than making the reader hunt for it.
      var cx = +hit.dataset.x, cy = +hit.dataset.y;
      box.x = cx - box.w / 2;
      box.y = cy - box.h / 2;
      view();
    }
  });

  svg.addEventListener('click', function (e) {
    var edge = e.target.closest('.edge');
    if (edge) {
      detail.innerHTML = edge.dataset.detail;
      return;
    }
    var node = e.target.closest('.node');
    if (node) { location.href = 'by-group/' + node.dataset.slug + '.html'; }
  });
  svg.addEventListener('mouseover', function (e) {
    var edge = e.target.closest('.edge');
    if (edge) { detail.innerHTML = edge.dataset.detail; }
  });

  view();
  apply();
})();
"""


def layout(nodes: list[dict[str, Any]], links: list[dict[str, Any]]) -> dict[str, tuple[float, float]]:
    """
    Place the nodes with a deterministic force-directed pass.

    Args:
        nodes: Graph nodes, each with a ``slug``
        links: Graph edges, referencing node slugs

    Returns:
        Slug to (x, y) inside the drawing area
    """
    count = len(nodes)
    if count == 0:
        return {}

    # A circle in slug order, so the same feed always draws the same picture.
    radius = min(WIDTH, HEIGHT) * 0.38
    pos = {
        node["slug"]: [
            WIDTH / 2 + radius * math.cos(2 * math.pi * i / count),
            HEIGHT / 2 + radius * math.sin(2 * math.pi * i / count),
        ]
        for i, node in enumerate(nodes)
    }
    slugs = list(pos)
    ideal = math.sqrt(WIDTH * HEIGHT / count)
    temperature = WIDTH / 8

    for _ in range(ITERATIONS):
        force = {slug: [0.0, 0.0] for slug in slugs}

        for i, a in enumerate(slugs):
            for b in slugs[i + 1 :]:
                dx, dy = pos[a][0] - pos[b][0], pos[a][1] - pos[b][1]
                distance = math.hypot(dx, dy) or 0.01
                push = ideal * ideal / distance
                ux, uy = dx / distance, dy / distance
                force[a][0] += ux * push
                force[a][1] += uy * push
                force[b][0] -= ux * push
                force[b][1] -= uy * push

        for link in links:
            a, b = link["source"], link["target"]
            dx, dy = pos[a][0] - pos[b][0], pos[a][1] - pos[b][1]
            distance = math.hypot(dx, dy) or 0.01
            pull = distance * distance / ideal
            ux, uy = dx / distance, dy / distance
            force[a][0] -= ux * pull
            force[a][1] -= uy * pull
            force[b][0] += ux * pull
            force[b][1] += uy * pull

        for slug in slugs:
            fx, fy = force[slug]
            magnitude = math.hypot(fx, fy) or 0.01
            step = min(magnitude, temperature)
            pos[slug][0] = min(WIDTH - 40, max(40.0, pos[slug][0] + fx / magnitude * step))
            pos[slug][1] = min(HEIGHT - 30, max(30.0, pos[slug][1] + fy / magnitude * step))

        temperature *= 0.965

    return {slug: (round(xy[0], 1), round(xy[1], 1)) for slug, xy in pos.items()}


def render_graph_page(graph: dict[str, Any], generated: str) -> str:
    """
    Render the relationship graph.

    Args:
        graph: Nodes and links from :func:`apttrail.relations.to_graph`
        generated: Feed generation timestamp

    Returns:
        A complete HTML document with the graph inlined as SVG
    """
    nodes, links = graph["nodes"], graph["links"]
    places = layout(nodes, links)
    labels = {node["slug"]: node["label"] for node in nodes}

    # Weakest evidence underneath, so a strong link is never hidden by a weak one.
    ordered = sorted(links, key=lambda link: -TIERS[link["evidence"][0]["kind"]])
    edges = []
    for link in ordered:
        a, b = link["source"], link["target"]
        if a not in places or b not in places:
            continue
        kinds = [item["kind"] for item in link["evidence"]]
        colour, width, opacity = EVIDENCE_STYLE[kinds[0]]
        detail = (
            f'<span class=pair><a href="by-group/{esc(a)}.html">{esc(labels[a])}</a> '
            f'&harr; <a href="by-group/{esc(b)}.html">{esc(labels[b])}</a></span>'
            + "".join(
                f'<span class=ev>{esc(item["kind"])} &mdash; {esc(item["detail"])}</span>' for item in link["evidence"]
            )
        )
        (x1, y1), (x2, y2) = places[a], places[b]
        edges.append(
            f'<line class=edge x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" '
            f'stroke="{colour}" stroke-width="{width}" opacity="{opacity}" '
            f'data-kinds="{esc(" ".join(kinds))}" data-a="{esc(a)}" data-b="{esc(b)}" '
            f'data-detail="{esc(detail)}"><title>{esc(labels[a])} &harr; {esc(labels[b])}</title></line>'
        )

    degree: dict[str, int] = {}
    for link in links:
        degree[link["source"]] = degree.get(link["source"], 0) + 1
        degree[link["target"]] = degree.get(link["target"], 0) + 1

    marks = []
    for node in nodes:
        slug = node["slug"]
        x, y = places[slug]
        # Size by how connected the group is, not by indicator count: this
        # picture is about relationships.
        size = 3.5 + math.sqrt(degree.get(slug, 1)) * 1.9
        key = f"{slug} {node['label']} {node['attack_id'] or ''}".lower()
        marks.append(
            f'<g class="node{" attack" if node["attack_id"] else ""}" data-slug="{esc(slug)}" '
            f'data-k="{esc(key)}" data-x="{x}" data-y="{y}">'
            f'<circle cx="{x}" cy="{y}" r="{size:.1f}"><title>{esc(node["label"])} &mdash; '
            f'{degree.get(slug, 0)} link{"s" if degree.get(slug, 0) != 1 else ""}</title></circle>'
            f'<text x="{x}" y="{y - size - 4:.1f}">{esc(node["label"][:22])}</text></g>'
        )

    legend = "".join(
        f'<label><input type=checkbox value="{kind}" checked>'
        f'<span class=swatch style="border-top-color:{EVIDENCE_STYLE[kind][0]}"></span>{kind}</label>'
        for kind in TIERS
    )

    return f"""<!doctype html>
<html lang=en>
<meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
{head(
    "How the groups relate · APTtrail",
    f"{len(links):,} relationships between {len(nodes)} APT groups, from shared infrastructure, "
    "shared reporting and shared tooling. Every edge names its evidence.",
    f"{SITE_URL}/graph.html",
)}
<style>{STYLE}{GRAPH_STYLE}</style>
<div class=wrap>
<div class=topbar>
  <a href="index.html">&larr; APTtrail</a>
  <a href="graph.json">graph.json</a>
</div>

<header class=masthead>
<h1>How the groups relate</h1>
<p class=lede>{len(links):,} relationships between {len(nodes)} groups. An edge means
the sources have something in common &mdash; the same indicator, the same
write-up, the same named tooling &mdash; <strong>not</strong> that the groups are
one actor or work together. Click an edge to see exactly what it rests on.</p>

<div class=tools id=tools>
  <input type=search id=q placeholder="highlight a group" aria-label="Highlight a group">
  <button type=button id=reset>reset view</button>
  <span class=note><b id=count>{len(links)}</b> edges shown</span>
</div>
<div class=legend>{legend}</div>
</header>

<div class=grid>
<main class=solo>
<div class=board>
<svg id=graph viewBox="0 0 {WIDTH:.0f} {HEIGHT:.0f}" role=img
     aria-label="Force-directed graph of relationships between APT groups">
{chr(10).join(edges)}
{chr(10).join(marks)}
</svg>
</div>
<div id=detail><span class=note>Hover or click an edge to see its evidence. Click a
group to open its page. Drag to pan, scroll to zoom.</span></div>

<h2>How an edge is decided</h2>
<p><strong>infrastructure</strong> &mdash; the same domain or address is attributed
to both groups. The strongest signal here and a rare one: 268 of 154,910 values
touch more than one group. Anything shared by eight or more groups is treated as
hosting or a sinkhole and dropped.</p>
<p><strong>reporting</strong> &mdash; the same write-up cites both. Corroborating,
not conclusive; a survey naming a dozen actors links none of them, which is why
the same eight-group cut applies.</p>
<p><strong>software</strong> &mdash; shared named malware or tooling, after
discarding anything commodity. Mimikatz, Cobalt Strike, PsExec and certutil appear
under a quarter of all profiled groups; two actors both using one says nothing.</p>
<p><strong>technique</strong> &mdash; overlap of published ATT&amp;CK techniques as
Jaccard, not a raw count. T1566.001 is attributed to 54 of 95 profiled groups.
Only four pairs in the whole corpus clear the bar, and technique overlap reflects
how much a group has been researched as much as what it does.</p>

<p class=note>Attribution is inherited from Maltrail and MITRE ATT&amp;CK, not
independently assessed, and an actor can only relate to another through what has
been published about both. Absence of an edge is not evidence of anything.</p>

<footer>
<p>Generated {esc(generated)} &middot; rebuilt hourly &middot;
<a href="graph.json">machine-readable</a> &middot; <a href="{PROJECT_URL}">source</a></p>
</footer>
</main>
</div>
</div>
<script>{GRAPH_SCRIPT % {"width": WIDTH, "height": HEIGHT}}</script>
</html>
"""
