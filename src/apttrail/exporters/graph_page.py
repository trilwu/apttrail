"""
How the groups relate.

The first version of this page drew all 116 groups at once with a
force-directed layout. It was unusable, and the data says why: the graph is one
component of 104 nodes and 194 edges in which 48 nodes have exactly one link.
That is a fuzzball, not a picture - and at the size a browser renders it, the
labels come out around seven pixels tall.

So the whole-graph view is gone. What replaced it is built around the two
questions someone actually arrives with:

- *Which relationships are the strongest?* A ranked list, strongest evidence
  first, each row naming what it rests on. Scannable, searchable, linkable, and
  it works with no JavaScript at all.
- *Who is this group near?* One group's immediate neighbourhood, drawn as a
  radial: focus in the middle, neighbours around it. Ego networks here run from
  1 to 21 nodes, which is a readable picture at any density in this corpus.

A hub list stands in for community detection. Naming clusters would mean
asserting a structure the evidence does not support; counting a group's
relationships does not.
"""

import json
from typing import Any

from apttrail.exporters.group_pages import STYLE, esc, head
from apttrail.relations import TIERS

SITE_URL = "https://trilwu.github.io/apttrail"
PROJECT_URL = "https://github.com/trilwu/apttrail"

#: Relationships listed before the reader is asked to filter.
TOP_RELATIONSHIPS = 40

#: Groups in the "most connected" list.
TOP_HUBS = 12

GRAPH_STYLE = """
main.solo { grid-column: 1 / -1; max-width: 62rem; }
.pairs { list-style: none; padding: 0; margin: 1rem 0 0; }
.pairs li { padding: .6rem 0; border-bottom: 1px solid var(--line); }
.pairs .who { font: 500 1rem/1.5 var(--sans); }
.pairs .who a { text-decoration: none; }
.pairs .who a:hover { color: var(--accent); }
.pairs .who .j { color: var(--faint); margin: 0 .45rem; }
.pairs .gidtag { font: .72rem/1 var(--mono); color: var(--faint); margin-left: .3rem; }
.pairs .ev { display: block; font: .78rem/1.7 var(--mono); }
.pairs .ev.infrastructure { color: var(--accent); }
.pairs .ev.reporting { color: var(--ink); }
.pairs .ev.software, .pairs .ev.technique { color: var(--muted); }
.pairs .look { float: right; font: .74rem/1.6 var(--mono); color: var(--faint);
               background: none; border: 0; cursor: pointer; padding: 0; }
.pairs .look:hover { color: var(--accent); }

.ego { border: 1px solid var(--line-firm); border-radius: 4px; background: var(--panel);
       margin-top: .8rem; }
.ego svg { display: block; width: 100%; height: auto; }
.ego .focus circle { fill: var(--accent); }
.ego .peer circle { fill: var(--muted); }
.ego g.n { cursor: pointer; }
.ego g.n:hover circle { stroke: var(--accent); stroke-width: 2.5; }
.ego g.n:hover text.name { fill: var(--accent); }
.ego circle { stroke: var(--bg); stroke-width: 1.5; }
.ego text.name { font: 12px var(--sans); fill: var(--ink); }
.ego text.why { font: 9.5px var(--mono); fill: var(--faint); }
.ego line { stroke-linecap: round; }
.ego .empty { font: 13px var(--sans); fill: var(--muted); }
.pick { display: flex; flex-wrap: wrap; gap: .5rem; align-items: center; margin-top: 1rem; }
.pick select, .pick input { background: var(--panel); color: inherit; border: 1px solid var(--line-firm);
                            border-radius: 3px; padding: .45rem .6rem; font: .85rem var(--mono); }
.hubs { list-style: none; padding: 0; margin: 1rem 0 0; columns: 2; column-gap: 2rem; }
.hubs li { break-inside: avoid; padding: .25rem 0; font: .86rem/1.6 var(--mono); }
.hubs .n { color: var(--faint); }
@media (max-width: 44rem) { .hubs { columns: 1; } }
"""

GRAPH_SCRIPT = """
(function () {
  var svg = document.getElementById('ego');
  if (!svg || typeof GRAPH === 'undefined') return;
  var picker = document.getElementById('focus');
  var caption = document.getElementById('egocap');

  var byId = {};
  GRAPH.nodes.forEach(function (n) { byId[n.slug] = n; });
  var neighbours = {};
  GRAPH.links.forEach(function (l) {
    (neighbours[l.source] = neighbours[l.source] || []).push({ slug: l.target, evidence: l.evidence });
    (neighbours[l.target] = neighbours[l.target] || []).push({ slug: l.source, evidence: l.evidence });
  });

  var COLOUR = {
    infrastructure: 'var(--accent)', reporting: 'var(--ink)',
    software: 'var(--muted)', technique: 'var(--muted)'
  };
  var WEIGHT = { infrastructure: 2.4, reporting: 1.6, software: 1.1, technique: 0.9 };
  var ns = 'http://www.w3.org/2000/svg';
  function make(tag, attrs, text) {
    var el = document.createElementNS(ns, tag);
    Object.keys(attrs).forEach(function (k) { el.setAttribute(k, attrs[k]); });
    if (text !== undefined) { el.textContent = text; }
    return el;
  }

  function draw(slug) {
    while (svg.firstChild) { svg.removeChild(svg.firstChild); }
    var peers = (neighbours[slug] || []).slice();
    // Strongest evidence nearest the top of the ring.
    peers.sort(function (a, b) {
      return (WEIGHT[b.evidence[0].kind] - WEIGHT[a.evidence[0].kind])
        || (b.evidence[0].weight - a.evidence[0].weight);
    });

    var W = 900;
    // Height follows the ring, so a group with two neighbours does not get a
    // screenful of empty panel.
    var radius = Math.max(70, Math.min(300, 40 + peers.length * 13));
    var H = peers.length ? radius * 2 + 90 : 150;
    svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
    var cx = W / 2, cy = H / 2;

    if (!peers.length) {
      svg.appendChild(make('text', { x: cx, y: cy, 'text-anchor': 'middle', class: 'empty' },
        byId[slug].label + ' has no recorded relationships.'));
      caption.textContent = '';
      return;
    }

    peers.forEach(function (peer, i) {
      var angle = (2 * Math.PI * i) / peers.length - Math.PI / 2;
      var x = cx + radius * Math.cos(angle);
      var y = cy + radius * Math.sin(angle);
      var top = peer.evidence[0];

      svg.appendChild(make('line', {
        x1: cx, y1: cy, x2: x, y2: y,
        stroke: COLOUR[top.kind], 'stroke-width': WEIGHT[top.kind],
        opacity: top.kind === 'infrastructure' ? 0.85 : 0.4
      }));

      var g = make('g', { class: 'n peer', 'data-slug': peer.slug });
      g.appendChild(make('circle', { cx: x, cy: y, r: 6 }));
      // Labels flip side so they never run back across the drawing.
      var right = Math.cos(angle) >= 0;
      var name = make('text', {
        x: x + (right ? 12 : -12), y: y + 4,
        'text-anchor': right ? 'start' : 'end', class: 'name'
      }, byId[peer.slug] ? byId[peer.slug].label : peer.slug);
      g.appendChild(name);
      g.appendChild(make('text', {
        x: x + (right ? 12 : -12), y: y + 17,
        'text-anchor': right ? 'start' : 'end', class: 'why'
      }, peer.evidence.map(function (e) { return e.detail; }).join(' · ')));
      svg.appendChild(g);
    });

    var focus = make('g', { class: 'n focus', 'data-slug': slug });
    focus.appendChild(make('circle', { cx: cx, cy: cy, r: 11 }));
    focus.appendChild(make('text', {
      x: cx, y: cy - 20, 'text-anchor': 'middle', class: 'name'
    }, byId[slug].label));
    svg.appendChild(focus);

    caption.textContent = peers.length + ' group' + (peers.length === 1 ? '' : 's')
      + ' related to ' + byId[slug].label + '. Click one to centre it, or open its page from the list above.';
  }

  function focusOn(slug) {
    if (!byId[slug]) return;
    picker.value = slug;
    draw(slug);
    if (history.replaceState) { history.replaceState(null, '', '?g=' + encodeURIComponent(slug)); }
  }

  picker.addEventListener('change', function () { focusOn(picker.value); });
  svg.addEventListener('click', function (e) {
    var g = e.target.closest('g.n');
    if (!g) return;
    if (g.classList.contains('focus')) { location.href = 'by-group/' + g.dataset.slug + '.html'; }
    else { focusOn(g.dataset.slug); }
  });
  document.addEventListener('click', function (e) {
    var btn = e.target.closest('button[data-focus]');
    if (!btn) return;
    focusOn(btn.dataset.focus);
    var target = document.getElementById('neighbourhood');
    if (target.scrollIntoView) { target.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
  });

  // Filtering the list.
  var q = document.getElementById('q');
  var kinds = Array.prototype.slice.call(document.querySelectorAll('.legend input'));
  var rows = Array.prototype.slice.call(document.querySelectorAll('.pairs li'));
  rows.forEach(function (r) { r.dataset.k = r.textContent.toLowerCase(); });
  function filter() {
    var needle = (q.value || '').trim().toLowerCase();
    var on = {};
    kinds.forEach(function (k) { on[k.value] = k.checked; });
    var shown = 0;
    rows.forEach(function (r) {
      var hit = (!needle || r.dataset.k.indexOf(needle) !== -1)
        && r.dataset.kinds.split(' ').some(function (k) { return on[k]; });
      r.hidden = !hit;
      if (hit) shown++;
    });
    document.getElementById('count').textContent = shown.toLocaleString();
    document.getElementById('empty').hidden = shown > 0;
  }
  q.addEventListener('input', filter);
  kinds.forEach(function (k) { k.addEventListener('change', filter); });
  document.addEventListener('keydown', function (e) {
    if (e.key === '/' && !/^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName)) {
      e.preventDefault(); q.focus(); q.select();
    }
  });

  var initial = /[?&]g=([^&]*)/.exec(location.search);
  focusOn(initial && byId[decodeURIComponent(initial[1])] ? decodeURIComponent(initial[1]) : picker.value);
  filter();
})();
"""


def _degrees(links: list[dict[str, Any]]) -> dict[str, int]:
    degree: dict[str, int] = {}
    for link in links:
        degree[link["source"]] = degree.get(link["source"], 0) + 1
        degree[link["target"]] = degree.get(link["target"], 0) + 1
    return degree


def _rank(link: dict[str, Any]) -> tuple[int, float]:
    """Strongest evidence first, then by how much of it there is."""
    top = link["evidence"][0]
    return (TIERS[top["kind"]], -top["weight"])


def render_graph_page(graph: dict[str, Any], generated: str) -> str:
    """
    Render the relationships page.

    Args:
        graph: Nodes and links from :func:`apttrail.relations.to_graph`
        generated: Feed generation timestamp

    Returns:
        A complete HTML document
    """
    nodes, links = graph["nodes"], graph["links"]
    labels = {node["slug"]: node["label"] for node in nodes}
    degree = _degrees(links)
    ranked = sorted(links, key=_rank)

    rows = []
    for link in ranked[:TOP_RELATIONSHIPS]:
        a, b = link["source"], link["target"]
        kinds = " ".join(item["kind"] for item in link["evidence"])
        evidence = "".join(
            f'<span class="ev {esc(item["kind"])}">{esc(item["kind"])} &mdash; {esc(item["detail"])}</span>'
            for item in link["evidence"]
        )
        rows.append(
            f'<li data-kinds="{esc(kinds)}">'
            f'<button class=look type=button data-focus="{esc(a)}">neighbourhood &rarr;</button>'
            f'<div class=who><a href="by-group/{esc(a)}.html">{esc(labels[a])}</a>'
            f'<span class=j>&harr;</span><a href="by-group/{esc(b)}.html">{esc(labels[b])}</a></div>'
            f"{evidence}</li>"
        )

    hubs = sorted(degree.items(), key=lambda kv: (-kv[1], kv[0]))[:TOP_HUBS]
    hub_items = "".join(
        f'<li><button class=look type=button data-focus="{esc(slug)}">{esc(labels[slug])}</button> '
        f'<span class=n>{count} link{"s" if count != 1 else ""}</span></li>'
        for slug, count in hubs
    )

    # Sorted by connectedness so the picker opens on something worth looking at.
    options = "".join(
        f'<option value="{esc(node["slug"])}">{esc(node["label"])} '
        f'&mdash; {degree.get(node["slug"], 0)} link{"s" if degree.get(node["slug"], 0) != 1 else ""}</option>'
        for node in sorted(nodes, key=lambda n: (-degree.get(n["slug"], 0), n["label"]))
    )

    legend = "".join(f'<label><input type=checkbox value="{kind}" checked> {kind}</label>' for kind in TIERS)

    # Only what the neighbourhood view needs, so the inlined payload stays small.
    payload = json.dumps(
        {
            "nodes": [{"slug": n["slug"], "label": n["label"]} for n in nodes],
            "links": links,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )

    return f"""<!doctype html>
<html lang=en>
<meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
{head(
    "How the groups relate · APTtrail",
    f"{len(links):,} relationships between {len(nodes)} APT groups, from shared infrastructure, "
    "shared reporting and shared tooling. Every one names its evidence.",
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
<p class=lede>{len(links):,} relationships between {len(nodes)} groups. A relationship
means the sources have something in common &mdash; the same indicator, the same
write-up, the same named tooling &mdash; <strong>not</strong> that the groups are
one actor or work together.</p>
</header>

<div class=grid>
<main class=solo>

<h2 id=strongest>Strongest relationships <span class=n>{len(links):,} total</span></h2>
<p class=note>Ordered by how much the evidence supports a claim: shared
infrastructure first, then shared reporting, then tooling and techniques.</p>
<div class=tools id=tools>
  <input type=search id=q placeholder="filter by group name  (press /)" aria-label="Filter relationships">
  <span class=note><b id=count>{min(len(ranked), TOP_RELATIONSHIPS)}</b> shown</span>
</div>
<div class=legend>{legend}</div>
<ul class=pairs>
{"".join(rows)}
</ul>
<p class=note id=empty hidden>Nothing matches that filter.</p>
<p class=note>Showing the {min(len(ranked), TOP_RELATIONSHIPS)} strongest of {len(links):,}.
All of them, with their evidence, are in <a href="graph.json">graph.json</a>.</p>

<h2 id=neighbourhood>One group's neighbourhood</h2>
<p class=note>Everything related to a single group, which is the readable unit here
&mdash; the full graph is one component of {len(nodes)} groups and would not be.</p>
<div class=pick>
  <label for=focus class=note>Centre on</label>
  <select id=focus>{options}</select>
</div>
<div class=ego><svg id=ego role=img aria-label="Groups related to the selected group"></svg></div>
<p class=note id=egocap></p>

<h2 id=hubs>Most connected</h2>
<p class=note>Not a ranking of importance &mdash; a group is here because a lot has
been published about it that overlaps with something else.</p>
<ul class=hubs>{hub_items}</ul>

<h2>How a relationship is decided</h2>
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
independently assessed, and one actor can only relate to another through what has
been published about both. Absence of a relationship is not evidence of anything.</p>

<footer>
<p>Generated {esc(generated)} &middot; rebuilt hourly &middot;
<a href="graph.json">machine-readable</a> &middot; <a href="{PROJECT_URL}">source</a></p>
</footer>
</main>
</div>
</div>
<script>var GRAPH={payload};</script>
<script>{GRAPH_SCRIPT}</script>
</html>
"""
