"""
The landing page, and the group directory it used to be.

Measured before rewriting: 87% of the old index was a 314-row table, and the
reason anyone should care about this feed was 209 words of prose in front of it.
A directory is a fine thing to have and a bad thing to open with.

So the table moved to ``groups.html``, one click away and still filterable and
sortable, and the landing page does three things instead:

- says what this is in one line, with the numbers that make it true;
- **proves it** with a real lookup taken from the live feed at build time -
  an actual indicator, its actor, its date and the report that published it -
  because "every indicator carries its source" is a claim, and a response body
  is evidence;
- points at the three places a reader might actually be going.

The worked example is chosen deterministically from the feed rather than
hardcoded, so it can never drift into describing something the feed no longer
contains.
"""

import json
from typing import Any

from apttrail.exporters.group_pages import STYLE, head

SITE_URL = "https://trilwu.github.io/apttrail"
PROJECT_URL = "https://github.com/trilwu/apttrail"

INDEX_STYLE = """
main.solo { grid-column: 1 / -1; max-width: 58rem; }
h1 { max-width: 20em; }
h1 em { font-style: italic; color: var(--accent); }
.masthead .lede { margin: .2rem 0 1.6rem; max-width: 38rem; }
code { font: .88em var(--mono); color: var(--muted); }

.go { display: flex; flex-wrap: wrap; gap: .6rem; margin: 0 0 1.8rem; }
.go a { display: inline-flex; align-items: baseline; gap: .5rem; text-decoration: none;
        border: 1px solid var(--line-firm); border-radius: 3px; padding: .6rem .9rem;
        font: .9rem/1.3 var(--sans); }
.go a:first-child { border-color: var(--accent); color: var(--accent); }
.go a:hover { border-color: var(--accent); color: var(--accent); }
.go a span { font: .72rem/1.3 var(--mono); color: var(--faint); }
.go a:hover span { color: inherit; }

.proof { border: 1px solid var(--line-firm); border-radius: 4px; padding: 1.1rem 1.2rem;
         margin: 1.2rem 0 0; background: var(--panel); }
.proof h3 { font: .68rem/1.4 var(--mono); letter-spacing: .09em; text-transform: uppercase;
            color: var(--faint); margin: 0 0 .6rem; }
.proof pre { background: none; border: 0; padding: 0; margin: 0; font-size: .8rem; }
.proof .out { margin-top: .7rem; padding-top: .7rem; border-top: 1px solid var(--line); }
.proof .k { color: var(--faint); }
.proof .v { color: var(--ink); }
.proof .said { margin: .9rem 0 0; font: .86rem/1.6 var(--sans); color: var(--muted); }

.worth { display: grid; grid-template-columns: repeat(auto-fit, minmax(15rem, 1fr));
         gap: 1px; background: var(--line); border: 1px solid var(--line); margin-top: 1rem; }
.worth div { background: var(--bg); padding: .9rem 1rem; }
.worth dt { font: .68rem/1.4 var(--mono); letter-spacing: .09em; text-transform: uppercase;
            color: var(--accent); }
.worth dd { margin: .35rem 0 0; font-size: .9rem; line-height: 1.6; }
.worth b { font: 500 1.05rem/1 var(--mono); font-variant-numeric: tabular-nums; display: block;
           margin-bottom: .15rem; }

.tools-grid { list-style: none; padding: 0; margin: 1rem 0 0; display: grid;
              grid-template-columns: repeat(auto-fit, minmax(16rem, 1fr)); gap: .1rem 1.6rem; }
.tools-grid li { padding: .35rem 0; border-bottom: 1px solid var(--line); font-size: .88rem; }
.tools-grid b { font-weight: 500; }
.tools-grid span { color: var(--muted); font: .8rem/1.6 var(--mono); }

.groups { margin-top: .8rem; }
.groups th { text-align: left; font: .68rem/1.4 var(--mono); letter-spacing: .09em;
             text-transform: uppercase; color: var(--faint); font-weight: 400;
             padding: 0 .8rem .4rem 0; border-bottom: 1px solid var(--line-firm); }
.groups th[data-col] { cursor: pointer; user-select: none; }
.groups th[data-col]:hover { color: var(--accent); }
.groups th[aria-sort=ascending]::after { content: " \\2191"; color: var(--accent); }
.groups th[aria-sort=descending]::after { content: " \\2193"; color: var(--accent); }
.groups td { padding: .45rem .8rem .45rem 0; border-bottom: 1px solid var(--line);
             vertical-align: baseline; }
.groups td.gid { font: .84rem/1.5 var(--mono); white-space: nowrap; }
.groups td.gid a { color: var(--accent); text-decoration: none; }
.groups td .who { text-decoration: none; }
.groups tr:hover td .who, .groups tr:hover td.gid a { color: var(--accent); }
.groups td.n { text-align: right; font: .88rem/1.5 var(--mono); font-variant-numeric: tabular-nums; }
.groups td.span { white-space: nowrap; font: .82rem/1.5 var(--mono); color: var(--muted);
                  font-variant-numeric: tabular-nums; }
.groups td.f { font: .78rem/1.5 var(--mono); white-space: nowrap; }
.groups td.f a { color: var(--muted); text-decoration: none; }
.groups td.f a:hover { color: var(--accent); }
.groups .aka { font: .76rem/1.5 var(--mono); color: var(--faint); margin-top: .1rem; }
.stale { color: var(--warn); }
@media (max-width: 40rem) { .groups td.span, .groups th.span { display: none; } }
"""

FRESHNESS_SCRIPT = """
(function () {
  var el = document.getElementById('generated');
  var out = document.getElementById('ago');
  if (!el || !out) return;
  // generated_at is timezone-aware ("...+00:00"). Appending Z to that makes it
  // unparseable, which is what shipped once: the clock read "unknown" for every
  // visitor. Only a naive stamp needs the suffix.
  var raw = el.getAttribute('datetime');
  var then = new Date(/(Z|[+-]\\d\\d:?\\d\\d)$/.test(raw) ? raw : raw + 'Z');
  if (isNaN(then)) { out.firstChild.textContent = 'unknown'; return; }
  var mins = Math.max(0, Math.round((Date.now() - then) / 60000));
  out.firstChild.textContent = mins < 1 ? 'just now'
    : mins < 60 ? mins + ' min ago'
    : mins < 1440 ? Math.round(mins / 60) + ' h ago'
    : Math.round(mins / 1440) + ' d ago';
  if (mins > 180) { out.classList.add('stale'); }
  el.textContent = then.toISOString().replace('T', ' ').replace('.000Z', '') + ' UTC';
})();
"""

GROUPS_SCRIPT = """
(function () {
  var list = document.getElementById('grouplist');
  var q = document.getElementById('q');
  var tools = document.getElementById('tools');
  var count = document.getElementById('shown');
  if (!list || !q) return;
  if (tools) tools.hidden = false;

  // data-k carries every alias, including the ones the row does not print.
  var rows = Array.prototype.slice.call(list.rows);
  rows.forEach(function (r) {
    if (!r.dataset.k) { r.dataset.k = r.textContent.toLowerCase(); }
  });

  var mapped = document.getElementById('mapped');
  var active = document.getElementById('active');
  var horizon = '';
  if (active) {
    var d = new Date();
    d.setDate(d.getDate() - 90);
    horizon = d.toISOString().slice(0, 10);
  }

  function apply() {
    var needle = q.value.trim().toLowerCase();
    var shown = 0;
    rows.forEach(function (r) {
      var hit = !needle || r.dataset.k.indexOf(needle) !== -1;
      if (hit && mapped && mapped.checked) { hit = r.dataset.attack === '1'; }
      if (hit && active && active.checked) { hit = (r.dataset.latest || '') >= horizon; }
      r.hidden = !hit;
      if (hit) shown++;
    });
    count.textContent = shown.toLocaleString();
    var empty = document.getElementById('empty');
    if (empty) { empty.hidden = shown > 0; }
    if (history.replaceState) {
      history.replaceState(null, '', needle ? '?q=' + encodeURIComponent(needle) : location.pathname);
    }
  }
  q.addEventListener('input', apply);
  if (mapped) mapped.addEventListener('change', apply);
  if (active) active.addEventListener('change', apply);

  // Sorting. Rows carry data-sort on the cells that are not plain text, so
  // "52,028" and "2017-2025" sort as a number and a date rather than as
  // whatever their rendered form happens to collate to.
  var head = list.parentNode.tHead;
  if (head) {
    var order = {};
    head.addEventListener('click', function (e) {
      var th = e.target.closest('th[data-col]');
      if (!th) return;
      var col = +th.dataset.col;
      var dir = order[col] = order[col] === 'asc' ? 'desc' : 'asc';
      var sign = dir === 'asc' ? 1 : -1;
      Array.prototype.forEach.call(head.querySelectorAll('th[data-col]'), function (h) {
        h.setAttribute('aria-sort', h === th ? (dir === 'asc' ? 'ascending' : 'descending') : 'none');
      });
      rows.slice().sort(function (a, b) {
        var x = a.cells[col], y = b.cells[col];
        var xv = x.dataset.sort, yv = y.dataset.sort;
        if (xv !== undefined && yv !== undefined) { return sign * (Number(xv) - Number(yv)); }
        return sign * x.textContent.trim().localeCompare(y.textContent.trim());
      }).forEach(function (r) { list.appendChild(r); });
    });
  }

  document.addEventListener('keydown', function (e) {
    var typing = /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName);
    if (e.key === '/' && !typing) { e.preventDefault(); q.focus(); q.select(); }
    else if (e.key === 'Escape' && typing) { q.value = ''; q.blur(); apply(); }
  });

  var initial = /[?&]q=([^&]*)/.exec(location.search);
  if (initial) { q.value = decodeURIComponent(initial[1].replace(/\\+/g, ' ')); }
  apply();
})();
"""

FORMATS = [
    ("MISP", "misp-feed/", "add the URL as a feed; one event per actor"),
    ("STIX 2.1", "apttrail_threat_feed_stix.json", "intrusion-set objects, merges with ATT&CK"),
    ("Suricata", "apttrail_threat_feed.rules", "~4,100 dataset-backed rules, validated in CI"),
    ("Sigma", "apttrail_threat_feed.yaml", "one rule per group, attack.gXXXX tagged"),
    ("Flat lists", "by-type/domain.txt", "one value per line, for a blocklist"),
    ("JSON / CSV", "by-group/G0007.json", "per actor, with dates and sources"),
]


def _esc(value: Any) -> str:
    """Minimal HTML escaping for values that come from upstream data."""
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _proof(sample: dict[str, Any] | None) -> str:
    """
    A real lookup, rendered.

    "Every indicator carries the report that published it" is a claim. An actual
    response body with an actual report URL in it is evidence, and it costs one
    example pulled from the feed being built.
    """
    if not sample:
        return ""

    rows = []
    for key in ("type", "groups", "attack_ids", "first_seen", "references"):
        if key not in sample["entry"]:
            continue
        value = sample["entry"][key]
        rendered = json.dumps(value, ensure_ascii=False)
        rows.append(f'  <span class=k>"{_esc(key)}"</span>: <span class=v>{_esc(rendered)}</span>,')

    body = "\n".join(rows).rstrip(",")
    return f"""<div class=proof>
<h3>One request, from an alert to an answer</h3>
<pre><span class=k># what do you know about this domain?</span>
IOC={_esc(sample["value"])}
shard=$(printf %s "$IOC" | sha256sum | cut -c1-2)
curl -s {SITE_URL}/by-indicator/$shard.json | jq --arg v "$IOC" '.[$v]'</pre>
<div class=out><pre>{{
{body}
}}</pre></div>
<p class=said>The actor, its ATT&amp;CK id, the date it appeared upstream, and the
write-up it came from &mdash; from one 178&nbsp;KB fetch, with no key and no
account. <a href="search.html">Try it in the browser</a>.</p>
</div>"""


def render_index_page(payload: dict[str, Any], stats: dict[str, Any], sample: dict[str, Any] | None) -> str:
    """
    Render the landing page.

    Args:
        payload: The index.json payload, for totals
        stats: Extra counts computed over the feed, so the claims on the page
            are recomputed each build rather than written down once
        sample: A real indicator and its lookup entry, or None

    Returns:
        A complete HTML document
    """
    totals = payload["totals"]
    generated = _esc(payload["generated_at"])
    sourced = stats["sourced"]
    indicators = max(stats["indicators"], 1)
    span = (
        f"{str(stats['earliest'])[:4]} &rarr; {str(stats['latest'])[:4]}"
        if stats.get("earliest") and stats.get("latest")
        else "Dated"
    )

    formats = "".join(f"<li><b>{_esc(name)}</b><br><span>{_esc(note)}</span></li>" for name, _, note in FORMATS)

    return f"""<!doctype html>
<html lang=en>
<meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
{head(
    "APTtrail · APT indicators that tell you whose they are",
    f"{stats['indicators']:,} APT indicators across {totals['slices']} actors. Every one carries "
    f"the actor it belongs to, its MITRE ATT&CK id, when it appeared and the report that published it. "
    "Static files, no API key.",
    f"{SITE_URL}/",
)}
<style>{STYLE}{INDEX_STYLE}</style>
<div class=wrap>
<div class=topbar>
  <span>APTtrail</span>
  <a href="{PROJECT_URL}">source &amp; docs</a>
</div>

<header class=masthead>
<h1>APT indicators that tell you <em>whose</em> they are</h1>
<p class=lede>Most free feeds hand you a list of bad domains. This one hands you
the actor, its ATT&amp;CK id, the date it appeared and the write-up it came from
&mdash; for every indicator.</p>

<dl class=stats>
<div><dt>Indicators</dt><dd>{stats["indicators"]:,}</dd></div>
<div><dt>Actors</dt><dd>{totals["slices"]:,}
  <small>{totals["attack_groups"]} carry an ATT&amp;CK id</small></dd></div>
<div><dt>Sourced</dt><dd>{round(100 * sourced / indicators)}%
  <small>name their report</small></dd></div>
<div><dt>Updated</dt><dd id=ago>&hellip;
  <small><time id=generated datetime="{generated}">{generated}</time></small></dd></div>
</dl>

<div class=go>
  <a href="search.html">Look up an indicator <span>an alert fired</span></a>
  <a href="groups.html">Browse {totals["slices"]} actors <span>by name or alias</span></a>
  <a href="activity.html">What moved recently <span>last 30 days</span></a>
  <a href="graph.html">How actors relate <span>{stats["relationships"]:,} links</span></a>
</div>
</header>

<div class=grid>
<main class=solo>

{_proof(sample)}

<h2>What you get that a blocklist does not</h2>
<dl class=worth>
<div><dt>Attribution</dt><dd><b>{totals["attack_groups"]} ATT&amp;CK sets</b>
resolved from {totals["maltrail_groups_mapped_to_attack"]} of {totals["maltrail_groups"]} upstream
groups, and the id travels into every export format &mdash; so a hit in Suricata or
MISP still says <em>whose</em>.</dd></div>

<div><dt>Provenance</dt><dd><b>{sourced:,} of {stats["indicators"]:,}</b>
indicators name the report that published them. Not a reference list at the bottom
of a page &mdash; the specific write-up behind that specific value.</dd></div>

<div><dt>History</dt><dd><b>{span}</b>
{f"{stats['exact']:,} carry an exact first-seen date" if stats.get("exact") else "first-seen dates"},
recovered from history upstream had discarded. Filter on age instead of blocking a
domain last used in 2016.</dd></div>

<div><dt>No friction</dt><dd><b>Static files</b>
on stable URLs. No account, no key, no rate limit, rebuilt hourly. Look-ups run in
your browser, so nothing you paste is sent anywhere.</dd></div>
</dl>

<h2>Into your tooling</h2>
<ul class=tools-grid>{formats}</ul>
<p class=note>The ATT&amp;CK id survives the trip: <code>metadata:apt_group SOFACY,
mitre_group_id G0007;</code> in Suricata, a <code>misp-galaxy:mitre-intrusion-set</code>
tag in MISP, an <code>external_references</code> entry in STIX.
<a href="{PROJECT_URL}#per-tool-setup">Setup for each tool</a>.</p>

<h2>Start here</h2>
<pre><span class=k># every domain APT28 has been seen using</span>
curl -sL {SITE_URL}/by-group/G0007-domain.txt

<span class=k># one actor, full detail: dates, sources, ATT&amp;CK</span>
curl -sL {SITE_URL}/by-group/G0007.json

<span class=k># what exists, with counts</span>
curl -sL {SITE_URL}/index.json</pre>

<p class=note>Also: <a href="activity.xml">Atom feed</a> of new indicators,
<a href="graph.json">graph.json</a>, and per-group
<a href="{PROJECT_URL}#per-tool-setup">ATT&amp;CK Navigator layers</a>.</p>

<footer>
<p>Indicators from <a href="https://github.com/stamparm/maltrail">Maltrail</a>;
attribution from <a href="https://attack.mitre.org/">MITRE ATT&amp;CK</a> and the
<a href="https://github.com/MISP/misp-galaxy">MISP galaxy</a>, inherited rather than
independently assessed. These are historical indicators: treat a hit as a lead to
triage, not proof of compromise.</p>
<p>Rebuilt hourly &middot; <a href="{PROJECT_URL}">source</a></p>
</footer>
</main>
</div>
</div>
<script>{FRESHNESS_SCRIPT}</script>
</html>
"""


def render_groups_page(payload: dict[str, Any], rows: str) -> str:
    """
    Render the group directory.

    Args:
        payload: The index.json payload, for totals
        rows: Pre-rendered table rows

    Returns:
        A complete HTML document
    """
    totals = payload["totals"]
    return f"""<!doctype html>
<html lang=en>
<meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
{head(
    "All groups · APTtrail",
    f"Every one of {totals['slices']} tracked APT groups, searchable by name, alias or ATT&CK id, "
    "with indicator counts and the span of first-seen dates.",
    f"{SITE_URL}/groups.html",
)}
<style>{STYLE}{INDEX_STYLE}</style>
<div class=wrap>
<div class=topbar>
  <a href="index.html">&larr; APTtrail</a>
  <a href="search.html">Look up an indicator</a>
</div>

<header class=masthead>
<h1>All groups</h1>
<p class=lede>{totals["slices"]} tracked actors, {totals["maltrail_groups_mapped_to_attack"]} of them
resolved onto {totals["attack_groups"]} MITRE ATT&amp;CK intrusion sets.</p>

<div class=tools id=tools hidden>
  <input type=search id=q placeholder="name, alias or G-id &mdash; try &quot;fancy bear&quot;  (press /)"
         aria-label="Filter groups">
  <label><input type=checkbox id=mapped> ATT&amp;CK only</label>
  <label><input type=checkbox id=active> active 90d</label>
  <span class=note><b id=shown>{totals["slices"]:,}</b> groups</span>
</div>
</header>

<div class=grid>
<main class=solo>
<p class=note>The filter matches aliases the row does not print &mdash; searching
<em>fancy bear</em> or <em>sofacy</em> finds APT28. <em>Seen</em> is the span of
first-seen dates, recovered from upstream history reaching back to 2014.</p>
<table class=groups>
<thead><tr><th data-col=0 aria-sort=none>ATT&amp;CK</th><th data-col=1 aria-sort=none>Group</th>
<th class=n data-col=2 aria-sort=none>IOCs</th><th class=span data-col=3 aria-sort=none>Seen</th>
<th>Files</th></tr></thead>
<tbody id=grouplist>
{rows}
</tbody>
</table>
<p class=note id=empty hidden>No group matches. <em>Active 90d</em> uses the date an
indicator entered Maltrail, so a long-quiet actor drops out even when its
infrastructure is still listed.</p>

<footer>
<p>Machine-readable: <a href="index.json">index.json</a> &middot;
Rebuilt hourly &middot; <a href="{PROJECT_URL}">source</a></p>
</footer>
</main>
</div>
</div>
<script>{GROUPS_SCRIPT}</script>
</html>
"""
