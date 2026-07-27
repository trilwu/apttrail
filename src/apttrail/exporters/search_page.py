"""
Client-side IOC search.

The lookup shards already answer "what do you know about this indicator"; what
was missing was somewhere to type it. There is no backend and there does not
need to be one: the browser canonicalises the input, hashes it with SubtleCrypto
and fetches the single shard that could hold it - 178KB, one request, no key, no
rate limit, and no record anywhere of what was searched. For an analyst pasting
a possible IOC out of an incident, that last property is not a detail.

Two modes:

- **Exact** is the default and is one shard fetch. Input is refanged first,
  because an indicator copied out of a ticket arrives as ``evil[.]example``,
  and several candidate spellings are tried, because the same host appears
  upstream with and without a scheme.
- **Deep** is opt-in and downloads the flat by-type lists - 0.9MB gzipped for
  all 155,000 values - to run substring matching in memory. Clicking a result
  falls back to the exact path for the detail, so the expensive index only ever
  has to hold values.
"""

from typing import Any

from apttrail.exporters.group_pages import STYLE, head

SITE_URL = "https://trilwu.github.io/apttrail"
PROJECT_URL = "https://github.com/trilwu/apttrail"

SEARCH_STYLE = """
main.solo { grid-column: 1 / -1; max-width: 54rem; }
.hunt { display: flex; gap: .5rem; margin: 1.4rem 0 .5rem; }
.hunt input { flex: 1; background: var(--panel); color: inherit; border: 1px solid var(--line-firm);
              border-radius: 3px; padding: .7rem .8rem; font: .95rem var(--mono); }
.hunt button { padding: .7rem 1.1rem; }
.opts { display: flex; flex-wrap: wrap; gap: 1rem; font: .8rem/1.6 var(--mono); color: var(--muted); }
.opts label { display: flex; gap: .35rem; align-items: center; cursor: pointer; }
#status { margin: 1.2rem 0 0; font: .85rem/1.6 var(--mono); color: var(--muted); min-height: 1.6em; }
.hit { border: 1px solid var(--line-firm); border-radius: 3px; padding: 1rem 1.1rem; margin-top: 1rem; }
.hit .val { font: 1.05rem/1.4 var(--mono); word-break: break-all; }
.hit .kind { font: .72rem/1 var(--mono); letter-spacing: .08em; text-transform: uppercase;
             color: var(--faint); margin-bottom: .5rem; }
.hit dl { display: grid; grid-template-columns: max-content 1fr; gap: .3rem .9rem; margin: .9rem 0 0; }
.hit dt { font: .7rem/1.6 var(--mono); letter-spacing: .07em; text-transform: uppercase; color: var(--faint); }
.hit dd { margin: 0; font: .88rem/1.6 var(--mono); word-break: break-all; }
.hit dd a { color: var(--ink); }
.miss { color: var(--muted); }
.miss b { color: var(--ink); }
.cands { list-style: none; padding: 0; margin: .8rem 0 0; }
.cands li { padding: .3rem 0; border-bottom: 1px solid var(--line); font: .88rem/1.6 var(--mono); }
.cands button { border: 0; padding: 0; color: inherit; text-align: left; font: inherit; }
.cands button:hover { color: var(--accent); }
.cands .t { color: var(--faint); font-size: .78rem; margin-left: .5rem; }
"""

SEARCH_SCRIPT = """
(function () {
  var SHARDS = 'by-indicator/';
  var form = document.getElementById('hunt');
  var input = document.getElementById('ioc');
  var deep = document.getElementById('deep');
  var status = document.getElementById('status');
  var out = document.getElementById('out');
  var shardCache = {};
  var corpus = null;

  function refang(v) {
    return v.replace(/\\[\\.\\]/g, '.').replace(/\\[:\\]/g, ':')
            .replace(/^hxxp/i, 'http').replace(/\\[at\\]/gi, '@');
  }
  // Must match CANONICAL_RULE in lookup.py: lowercase, and no :port on an IPv4.
  function canonical(v) {
    v = refang(v).trim().toLowerCase();
    if (/^\\d{1,3}(\\.\\d{1,3}){3}:\\d+$/.test(v)) { v = v.split(':')[0]; }
    return v;
  }
  // The same host appears upstream bare and with a scheme; try both rather
  // than making the reader guess which spelling we hold.
  function candidates(raw) {
    var base = canonical(raw);
    var list = [base];
    var stripped = base.replace(/^https?:\\/\\//, '');
    if (stripped !== base) { list.push(stripped, stripped.replace(/\\/.*$/, '')); }
    else { list.push('http://' + base, 'https://' + base); }
    if (base.slice(-1) === '/') { list.push(base.slice(0, -1)); }
    return list.filter(function (v, i, a) { return v && a.indexOf(v) === i; });
  }

  async function shardOf(value) {
    var buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
    return Array.from(new Uint8Array(buf).slice(0, 1))
      .map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
  }
  async function load(name) {
    if (!(name in shardCache)) {
      var res = await fetch(SHARDS + name + '.json');
      shardCache[name] = res.ok ? await res.json() : {};
    }
    return shardCache[name];
  }

  function esc(s) {
    return String(s).replace(/[&<>"]/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
    });
  }
  function render(value, hit) {
    var rows = '';
    var add = function (label, html) { rows += '<dt>' + label + '</dt><dd>' + html + '</dd>'; };
    add('Groups', hit.groups.map(esc).join(' &middot; '));
    if (hit.attack_ids && hit.attack_ids.length) {
      add('ATT&CK', hit.attack_ids.map(function (id) {
        return '<a href="by-group/' + esc(id) + '.html">' + esc(id) + '</a>';
      }).join(' &middot; '));
    }
    if (hit.first_seen) {
      add('First seen', esc(hit.first_seen) +
        (hit.first_seen_precision === 'at-or-before' ? ' <span class=miss>or earlier</span>' : ''));
    }
    if (hit.seen_as) { add('Seen as', hit.seen_as.map(esc).join('<br>')); }
    if (hit.references) {
      add('Source', hit.references.map(function (u) {
        return '<a href="' + esc(u) + '" rel="noopener nofollow">' + esc(u.replace(/^https?:\\/\\//, '')) + '</a>';
      }).join('<br>'));
    }
    out.innerHTML = '<div class=hit><div class=kind>' + esc(hit.type) + ' &middot; known indicator</div>' +
      '<div class=val>' + esc(value) + '</div><dl>' + rows + '</dl></div>';
  }

  async function exact(raw) {
    for (var _i = 0, list = candidates(raw); _i < list.length; _i++) {
      var value = list[_i];
      var shard = await load(await shardOf(value));
      if (shard[value]) { render(value, shard[value]); return true; }
    }
    return false;
  }

  var TYPES = ['domain', 'ipv4', 'url', 'url_path', 'ipv6', 'md5', 'sha1', 'sha256'];
  async function loadCorpus() {
    if (corpus) return corpus;
    status.textContent = 'Downloading the full value list once (about 1 MB)...';
    var parts = await Promise.all(TYPES.map(function (t) {
      return fetch('by-type/' + t + '.txt').then(function (r) {
        return r.ok ? r.text().then(function (body) { return [t, body]; }) : null;
      }).catch(function () { return null; });
    }));
    corpus = [];
    parts.filter(Boolean).forEach(function (pair) {
      pair[1].split('\\n').forEach(function (line) {
        if (line && line[0] !== '#') { corpus.push([line, pair[0]]); }
      });
    });
    return corpus;
  }
  async function substring(raw) {
    var needle = canonical(raw);
    var rows = (await loadCorpus()).filter(function (e) { return e[0].toLowerCase().indexOf(needle) !== -1; });
    if (!rows.length) {
      out.innerHTML = '<p class=miss>No indicator contains <b>' + esc(raw) + '</b>.</p>';
      return 0;
    }
    var shown = rows.slice(0, 200);
    out.innerHTML = '<ul class=cands>' + shown.map(function (e) {
      return '<li><button type=button data-v="' + esc(e[0]) + '">' + esc(e[0]) +
        '</button><span class=t>' + esc(e[1]) + '</span></li>';
    }).join('') + '</ul>' +
      (rows.length > shown.length
        ? '<p class=miss>' + (rows.length - shown.length).toLocaleString() + ' more matches not shown.</p>'
        : '');
    return rows.length;
  }

  async function run(raw) {
    if (!raw.trim()) { out.innerHTML = ''; status.textContent = ''; return; }
    status.textContent = 'Looking up...';
    out.innerHTML = '';
    if (history.replaceState) {
      history.replaceState(null, '', '?q=' + encodeURIComponent(raw.trim()));
    }
    try {
      if (deep.checked) {
        var n = await substring(raw);
        status.textContent = n ? n.toLocaleString() + ' values contain that string' : '';
        return;
      }
      if (await exact(raw)) { status.textContent = 'Found in one shard fetch.'; return; }
      status.textContent = '';
      out.innerHTML = '<p class=miss>Not a known indicator: <b>' + esc(raw.trim()) + '</b>. ' +
        'That means it is not in this feed, which is not the same as it being safe. ' +
        'Try <em>deep search</em> for a partial match.</p>';
    } catch (err) {
      status.textContent = 'Lookup failed: ' + err.message;
    }
  }

  form.addEventListener('submit', function (e) { e.preventDefault(); run(input.value); });
  out.addEventListener('click', function (e) {
    var btn = e.target.closest('button[data-v]');
    if (!btn) return;
    input.value = btn.dataset.v;
    deep.checked = false;
    run(input.value);
  });
  deep.addEventListener('change', function () { if (input.value.trim()) run(input.value); });

  document.addEventListener('keydown', function (e) {
    if (e.key === '/' && !/^(INPUT|TEXTAREA)$/.test(e.target.tagName)) {
      e.preventDefault();
      input.focus();
      input.select();
    }
  });

  var initial = /[?&]q=([^&]*)/.exec(location.search);
  if (initial) {
    input.value = decodeURIComponent(initial[1].replace(/\\+/g, ' '));
    run(input.value);
  }
  input.focus();
})();
"""


def render_search_page(totals: dict[str, Any]) -> str:
    """
    Render the standalone IOC search page.

    Args:
        totals: Index totals, for the honest count of what is searchable

    Returns:
        A complete HTML document
    """
    return f"""<!doctype html>
<html lang=en>
<meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
{head(
    "Search indicators · APTtrail",
    f"Look up a domain, IP, URL or hash against {totals['indicators']:,} attributed APT indicators. "
    "Runs in your browser - nothing you type is sent anywhere.",
    f"{SITE_URL}/search.html",
)}
<style>{STYLE}{SEARCH_STYLE}</style>
<div class=wrap>
<div class=topbar>
  <a href="index.html">&larr; APTtrail</a>
  <a href="activity.html">Recent activity</a>
</div>

<header class=masthead>
<h1>Search indicators</h1>
<p class=lede>An alert fired and you have a domain, an address or a hash. This
checks it against {totals["indicators"]:,} indicators, each one attributed to an
actor and carrying the report that published it.</p>

<form class=hunt id=hunt>
  <input id=ioc name=q type=search autocomplete=off spellcheck=false
         placeholder="evil.example, 8.8.8.8, hxxps://bad[.]site/path  (press /)"
         aria-label="Indicator to look up">
  <button type=submit>Look up</button>
</form>
<div class=opts>
  <label><input type=checkbox id=deep> deep search &mdash; substring, downloads ~1&nbsp;MB once</label>
  <span>defanged input is fine</span>
</div>
<p id=status></p>
</header>

<div class=grid>
<main class=solo>
<div id=out></div>

<h2>How this works</h2>
<p>Indicators are sharded by <code>sha256</code> of their canonical form
&mdash; lowercased, and without the <code>:port</code> on an IPv4. Your browser
computes that hash locally and fetches the one shard of 256 that could hold it,
about 178&nbsp;KB. <strong>Nothing you type leaves your machine</strong>: there
is no server here to send it to, and no log of it anywhere.</p>

<p>The same lookup from a shell, if you would rather script it:</p>
<pre><span class=c># canonical form: lowercase, no port on an IPv4</span>
IOC=evil.example
shard=$(printf %s "$IOC" | sha256sum | cut -c1-2)
curl -s {SITE_URL}/by-indicator/$shard.json | jq --arg v "$IOC" '.[$v]'</pre>

<p class=note>A miss means the indicator is not in this feed. It does not mean
the indicator is safe &mdash; this is one corpus of historical APT reporting,
not a verdict service.</p>

<footer>
<p>Indicators from <a href="https://github.com/stamparm/maltrail">Maltrail</a>;
attribution from <a href="https://attack.mitre.org/">MITRE ATT&amp;CK</a>.
Rebuilt hourly &middot; <a href="{PROJECT_URL}">source</a></p>
</footer>
</main>
</div>
</div>
<script>{SEARCH_SCRIPT}</script>
</html>
"""
