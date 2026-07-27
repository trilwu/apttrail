"""
Per-actor dossier pages.

The reader is a responder mid-triage: an alert has fired, a name has come back,
and they have about ninety seconds to decide whether this matters. The page is
laid out for that order of questions - who is this, how recently were they seen,
what exactly do you have, where did it come from, how do I pull it into my tools
- and everything is one screen away rather than one scroll away.

Design constraints that come from the audience rather than from taste:

- **No external requests.** No webfont CDN, no analytics, no icon pack. SOC
  networks block third-party origins, and these pages get saved and attached to
  tickets, where anything remote is dead weight. Character comes from the
  typographic pairing, density and colour semantics, all of which cost nothing.
- **Self-contained.** The stylesheet is inlined rather than shared so a saved
  page still renders correctly from disk a year later.
- **Colour carries meaning, never decoration.** Amber marks a date that is a
  floor rather than a sighting; the accent marks recency. Nothing else is
  coloured, so the colour that is there means something.
- **Progressive enhancement.** Filter, defang and copy are conveniences added by
  script; with script off the page is still a complete, readable document.

Indicators are shown as a timeline. Upstream files them in batches - a report
lands, its indicators are added together - so the batch is the unit that carries
meaning: this date, this write-up, these domains. A flat table with references
parked at the foot of the page leaves the reader unable to tell which of 1,600
references explains the row in front of them.

Large groups are not rendered in full. GAMAREDON alone has over 50,000
indicators; the page shows the most recent batches and links to the complete
files.
"""

import hashlib
import html
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import quote

from apttrail.profiles import ActorProfile

#: Indicators rendered inline. Beyond this the page links to the full files.
MAX_ROWS = 300

#: Group-level references listed at the foot of the page.
MAX_REFERENCES = 40

#: Reports ranked in the sourcing panel.
MAX_SOURCES = 8

PROJECT_URL = "https://github.com/trilwu/apttrail"
SITE_URL = "https://trilwu.github.io/apttrail"
ATTACK_GROUP_URL = "https://attack.mitre.org/groups/{group_id}/"
MALTRAIL_URL = "https://github.com/stamparm/maltrail"
MALTRAIL_TRAIL_URL = "https://github.com/stamparm/maltrail/blob/master/trails/static/malware/{filename}"

STYLE = """
:root {
  color-scheme: dark light;
  --bg: #0b0d11; --panel: #11151b; --ink: #e7e5e1; --muted: #8b919b;
  /* --faint is the floor: 4.5:1 on --bg, because these labels are 11px mono
     and the whole page depends on them being legible, not decorative. */
  --faint: #767d87; --line: #ffffff16; --line-firm: #ffffff2b;
  --accent: #e86f4a; --warn: #d6a03f;
  --serif: ui-serif, Iowan Old Style, Palatino Linotype, Palatino, Georgia, serif;
  --sans: ui-sans-serif, -apple-system, Segoe UI, Helvetica Neue, sans-serif;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, Liberation Mono, monospace;
}
@media (prefers-color-scheme: light) {
  :root { --bg: #fbfaf8; --panel: #fff; --ink: #17181a; --muted: #5d636b;
          --faint: #6b7178; --line: #0f172014; --line-firm: #0f172030;
          --accent: #b8412a; --warn: #9a6b12; }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink); font: 15px/1.6 var(--sans);
       -webkit-text-size-adjust: 100%; }
.wrap { max-width: 80rem; margin: 0 auto; padding: 0 1.6rem 5rem; }
a { color: inherit; text-underline-offset: .18em; text-decoration-color: var(--line-firm); }
a:hover { color: var(--accent); text-decoration-color: currentColor; }
h1, h2, h3 { font-weight: 500; }
p { margin: 0 0 .9rem; }

.topbar { display: flex; justify-content: space-between; align-items: baseline;
          padding: 1.1rem 0; font: .78rem/1 var(--mono); letter-spacing: .08em;
          text-transform: uppercase; color: var(--muted); }
.topbar .brand { color: var(--faint); }

.masthead { border-top: 1px solid var(--line-firm); padding-top: 1.6rem; }
/* Flex with baseline alignment: the G-id tag sits on the title's baseline at
   any clamp size, which vertical-align could not do reliably. */
h1 { font: 400 clamp(2.1rem, 5.5vw, 3.4rem)/1.05 var(--serif); letter-spacing: -.02em;
     margin: 0 0 .5rem; display: flex; flex-wrap: wrap; align-items: baseline; gap: .1em .5em; }
h1 .gid { font: 500 .3em/1 var(--mono); letter-spacing: .06em;
          color: var(--accent); border: 1px solid currentColor; border-radius: 3px;
          padding: .32em .5em; text-decoration: none; white-space: nowrap; }
.aka { font: .84rem/1.7 var(--mono); color: var(--muted); margin: 0 0 1.4rem;
       max-width: 62rem; word-spacing: .1em; }
.aka b { color: var(--ink); font-weight: 500; }

.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(9rem, 1fr));
         gap: 1px; background: var(--line); border: 1px solid var(--line);
         margin: 0 0 1.5rem; }
.stats div { background: var(--bg); padding: .7rem .9rem; }
.stats dt { font: .68rem/1.4 var(--mono); letter-spacing: .09em; text-transform: uppercase;
            color: var(--faint); }
.stats dd { margin: .15rem 0 0; font: 1.3rem/1.2 var(--mono); font-variant-numeric: tabular-nums; }
.stats dd small { font-size: .62em; color: var(--muted); letter-spacing: .04em; }

.spark { display: flex; align-items: flex-end; gap: 2px; height: 46px; margin: 0 0 .3rem; }
.spark span { flex: 1; background: var(--line-firm); min-height: 1px; height: var(--h);
              border-radius: 1px 1px 0 0; }
.spark span.hot { background: var(--accent); }
.spark-axis { display: flex; justify-content: space-between; font: .68rem/1 var(--mono);
              color: var(--faint); padding-bottom: 1.8rem; border-bottom: 1px solid var(--line-firm); }

.grid { display: grid; grid-template-columns: 16.5rem 1fr; gap: 3.4rem; padding-top: 2rem; }
@media (max-width: 64rem) { .grid { grid-template-columns: 1fr; gap: 2.2rem; } }
aside { position: sticky; top: 1.2rem; align-self: start; font-size: .88rem; }
@media (max-width: 64rem) { aside { position: static; } }
aside h3, .panel h3 { font: .68rem/1.4 var(--mono); letter-spacing: .09em; text-transform: uppercase;
                      color: var(--faint); margin: 1.8rem 0 .5rem; }
aside h3:first-child { margin-top: 0; }
nav ul { list-style: none; margin: 0; padding: 0; }
nav a { display: block; padding: .16rem 0; text-decoration: none; color: var(--muted); }
nav a:hover { color: var(--accent); }
dl.facts { margin: 0; }
dl.facts dt { font: .68rem/1.5 var(--mono); letter-spacing: .07em; text-transform: uppercase;
              color: var(--faint); margin-top: .7rem; }
dl.facts dd { margin: .1rem 0 0; }

main h2 { font: 400 1.5rem/1.2 var(--serif); letter-spacing: -.01em; margin: 3rem 0 .2rem;
          padding-bottom: .4rem; border-bottom: 1px solid var(--line-firm); }
main h2:first-child { margin-top: 0; }
main h2 .n { font: .58em/1 var(--mono); color: var(--faint); letter-spacing: .04em; }
.lede { font: 1.05rem/1.75 var(--serif); max-width: 44rem; }
.note { color: var(--muted); font-size: .86rem; }

.chips { display: flex; flex-wrap: wrap; gap: .32rem; padding: 0; margin: .8rem 0 0; list-style: none; }
.chips li { border: 1px solid var(--line-firm); border-radius: 2px; padding: .12rem .5rem;
            font: .8rem/1.5 var(--mono); color: var(--muted); }
.chips a { text-decoration: none; }
.chips li b { color: var(--ink); font-weight: 500; }

table { border-collapse: collapse; width: 100%; }
.coverage { margin-top: .9rem; max-width: 34rem; }
.coverage td { padding: .3rem 0; border-bottom: 1px solid var(--line); font: .88rem/1.5 var(--mono); }
.coverage td.n { text-align: right; font-variant-numeric: tabular-nums; }
.coverage td.f { text-align: right; font-size: .8rem; }

.rank { margin: .9rem 0 0; padding: 0; list-style: none; }
.rank li { margin: 0 0 .6rem; font: .84rem/1.6 var(--mono); }
.rank .bar { height: 3px; background: var(--accent); opacity: .55; width: var(--w); margin-top: .25rem; }
.rank .c { float: right; font: .78rem/1.6 var(--mono); color: var(--faint); }

.tools { display: flex; flex-wrap: wrap; gap: .6rem; align-items: center; margin: .9rem 0 0;
         font: .8rem/1 var(--mono); }
.tools input[type=search] { flex: 1; min-width: 12rem; background: var(--panel); color: inherit;
        border: 1px solid var(--line-firm); border-radius: 2px; padding: .42rem .6rem; font: inherit; }
.tools label { color: var(--muted); display: flex; gap: .35rem; align-items: center; cursor: pointer; }
button { background: none; color: var(--muted); border: 1px solid var(--line-firm); border-radius: 2px;
         padding: .4rem .6rem; font: inherit; cursor: pointer; }
button:hover { color: var(--accent); border-color: currentColor; }
#types { margin-top: .5rem; }
#types button { font: .78rem/1.5 var(--mono); padding: .1rem .5rem; border-radius: 999px; }
#types button[aria-pressed=true] { color: var(--bg); background: var(--ink); border-color: var(--ink); }

ol.timeline { list-style: none; margin: 1.4rem 0 0; padding: 0; }
ol.timeline > li { position: relative; padding: 0 0 1.9rem 1.5rem; border-left: 1px solid var(--line-firm); }
ol.timeline > li:last-child { border-left-color: transparent; }
ol.timeline > li::before { content: ""; position: absolute; left: -3.5px; top: .5rem;
        width: 6px; height: 6px; border-radius: 50%; background: var(--faint); }
ol.timeline > li.hot::before { background: var(--accent); box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 22%, transparent); }
.when { display: flex; flex-wrap: wrap; align-items: baseline; gap: .55rem;
        font: .92rem/1.5 var(--mono); }
.when .date { color: var(--ink); text-decoration: none; font-variant-numeric: tabular-nums; }
.when .approx { color: var(--warn); font-size: .8rem; border-bottom: 1px dotted currentColor; cursor: help; }
.when .cnt { color: var(--faint); font-size: .8rem; }
.when .ago { color: var(--faint); font-size: .8rem; margin-left: auto; }
.src { margin: .3rem 0 0; font: .82rem/1.6 var(--mono); }
.src a { text-decoration: none; color: var(--muted); }
.src a:hover .host { color: var(--accent); }
.src .host { color: var(--ink); border-bottom: 1px solid var(--line-firm); }
.src .path { color: var(--faint); }
.src .nosrc { color: var(--faint); font-style: italic; }
.iocs { margin-top: .5rem; }
.iocs td { padding: .16rem .8rem .16rem 0; border-bottom: 1px solid var(--line);
           font: .86rem/1.6 var(--mono); word-break: break-all; }
.iocs td.kind { width: 5.5rem; color: var(--faint); font-size: .76rem; white-space: nowrap;
                text-align: right; padding-right: 1rem; }
.batch-foot { margin: .35rem 0 0; font: .76rem/1.6 var(--mono); color: var(--faint); }
.batch-foot button { border: 0; padding: 0; color: var(--faint); }

.refs { list-style: none; padding: 0; margin: .9rem 0 0; columns: 2; column-gap: 2rem; }
@media (max-width: 52rem) { .refs { columns: 1; } }
.refs li { break-inside: avoid; margin-bottom: .3rem; font: .8rem/1.5 var(--mono); }
.refs a { color: var(--muted); text-decoration: none; }
.refs a:hover { color: var(--accent); }

pre { background: var(--panel); border: 1px solid var(--line); border-radius: 3px;
      padding: .7rem .8rem; overflow-x: auto; font: .78rem/1.7 var(--mono); margin: .5rem 0 0; }
pre .c { color: var(--faint); }
footer { margin-top: 4rem; padding-top: 1.2rem; border-top: 1px solid var(--line-firm);
         font-size: .82rem; color: var(--muted); }
[hidden] { display: none !important; }
/* "/" and Escape make the keyboard a real path through this page, so the focus
   ring has to be ours rather than whatever the browser defaults to on a dark
   background. */
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 2px; }
"""

SCRIPT = """
(function () {
  var root = document.getElementById('timeline-list');
  if (!root) return;
  var rows = Array.prototype.slice.call(root.querySelectorAll('tr'));
  if (!rows.length) return;
  rows.forEach(function (r) { r.dataset.v = r.querySelector('.val').textContent; });

  var tools = document.getElementById('tools');
  var q = document.getElementById('q');
  var fang = document.getElementById('defang');
  var count = document.getElementById('shown');
  var recent = document.getElementById('recent');
  var cutoff = tools ? tools.getAttribute('data-recent') : '';
  var kind = 'all';
  if (tools) tools.hidden = false;

  // http -> hxxp, https -> hxxps. Capturing the whole scheme and prefixing it
  // produced "hxxphttp://", which is what shipped and what a reader pasting
  // into a ticket would have had to clean up by hand.
  function defanged(v) {
    return v.replace(/^http(s?):/i, 'hxxp$1:').replace(/\\./g, '[.]');
  }
  function meta(row) {
    var li = row.closest('li');
    var when = li.querySelector('time');
    var src = li.querySelector('.src a');
    return {
      date: when ? when.getAttribute('datetime') : '',
      source: src ? src.getAttribute('href') : ''
    };
  }
  function apply() {
    var needle = (q.value || '').trim().toLowerCase();
    var bite = fang.checked;
    var visible = 0;
    rows.forEach(function (r) {
      var v = r.dataset.v;
      var hit = (!needle || v.toLowerCase().indexOf(needle) !== -1)
        && (kind === 'all' || r.dataset.t === kind);
      if (hit && recent && recent.checked && cutoff) {
        hit = (meta(r).date || '') >= cutoff;
      }
      r.hidden = !hit;
      if (hit) visible++;
      r.querySelector('.val').textContent = bite ? defanged(v) : v;
    });
    Array.prototype.forEach.call(root.children, function (li) {
      li.hidden = !li.querySelector('tr:not([hidden])');
    });
    count.textContent = visible.toLocaleString();
    document.getElementById('empty').hidden = visible > 0;

    // The filtered view is worth sharing, so put it in the URL.
    if (history.replaceState) {
      history.replaceState(null, '', needle ? '?q=' + encodeURIComponent(needle) : location.pathname);
    }
  }
  q.addEventListener('input', apply);
  fang.addEventListener('change', apply);
  if (recent) recent.addEventListener('change', apply);

  var chips = document.getElementById('types');
  if (chips) {
    chips.addEventListener('click', function (e) {
      var chip = e.target.closest('button[data-type]');
      if (!chip) return;
      kind = chip.dataset.type;
      Array.prototype.forEach.call(chips.querySelectorAll('button'), function (b) {
        b.setAttribute('aria-pressed', String(b === chip));
      });
      apply();
    });
  }

  // "/" is the filter, everywhere. Escape backs out.
  document.addEventListener('keydown', function (e) {
    var typing = /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName);
    if (e.key === '/' && !typing) { e.preventDefault(); q.focus(); q.select(); }
    else if (e.key === 'Escape' && typing) { q.value = ''; q.blur(); apply(); }
  });

  document.addEventListener('click', function (e) {
    var btn = e.target.closest('button[data-copy]');
    if (!btn) return;
    var how = btn.getAttribute('data-copy');
    var scope = how === 'batch' ? btn.closest('li') : root;
    var cells = Array.prototype.slice.call(scope.querySelectorAll('tr:not([hidden]) .val'));
    var text;
    if (how === 'csv') {
      // Columns an analyst pastes into a ticket or a spreadsheet.
      text = 'indicator,type,first_seen,source\\n' + cells.map(function (c) {
        var row = c.closest('tr');
        var m = meta(row);
        return [c.textContent, row.dataset.t, m.date, m.source].map(function (f) {
          return /[",\\n]/.test(f) ? '"' + f.replace(/"/g, '""') + '"' : f;
        }).join(',');
      }).join('\\n');
    } else {
      text = cells.map(function (c) { return c.textContent; }).join('\\n');
    }
    var done = function () {
      var was = btn.textContent;
      btn.textContent = 'copied ' + cells.length;
      setTimeout(function () { btn.textContent = was; }, 1400);
    };
    if (navigator.clipboard) { navigator.clipboard.writeText(text).then(done, function () {}); }
  });

  var initial = /[?&]q=([^&]*)/.exec(location.search);
  if (initial) { q.value = decodeURIComponent(initial[1].replace(/\\+/g, ' ')); }
  apply();
})();
"""


def esc(value: Any) -> str:
    """Escape untrusted values for HTML."""
    return html.escape(str(value), quote=True)


# A data URI, not a file: the no-external-request rule applies to the favicon
# too, and this way a page saved to disk still carries its own mark.
FAVICON = "data:image/svg+xml," + quote(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
    '<rect width="32" height="32" rx="6" fill="#0b0d11"/>'
    '<path d="M11 7v18" stroke="#767d87" stroke-width="2"/>'
    '<circle cx="11" cy="11" r="4" fill="#e86f4a"/>'
    '<path d="M17 19h9M17 24h6" stroke="#767d87" stroke-width="2"/></svg>',
    safe="",
)


def head(title: str, description: str, canonical: str) -> str:
    """
    The shared document head.

    Link previews are how this gets shared: pasted into Slack or a ticket
    without them, the site renders as a bare URL and reads as somebody's
    scratch repo. og:image is deliberately absent - a card with no image
    still renders as title and description everywhere, whereas a broken
    image reference renders as a broken card.

    Args:
        title: Page title, already human-readable
        description: One sentence, under ~160 characters
        canonical: Absolute URL of this page

    Returns:
        The meta block, including a self-contained favicon
    """
    return f"""<title>{esc(title)}</title>
<meta name=description content="{esc(description)}">
<link rel=canonical href="{esc(canonical)}">
<link rel=icon href="{FAVICON}">
<meta property="og:type" content="website">
<meta property="og:site_name" content="APTtrail">
<meta property="og:title" content="{esc(title)}">
<meta property="og:description" content="{esc(description)}">
<meta property="og:url" content="{esc(canonical)}">
<meta name="twitter:card" content="summary">"""


def build_timeline(entry: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Group a merged entry's indicators into dated batches sharing a source.

    Upstream adds indicators a report at a time, so date plus report is what
    distinguishes one batch from another: two domains seen the same day under
    different write-ups are separate events, and the same write-up cited a year
    apart is two separate events too.

    Args:
        entry: Merged group entry from the slice exporter

    Returns:
        Batches newest first, undated last, each with its references, counts
        and indicator values
    """
    batches: dict[tuple[str, str, tuple[str, ...]], dict[str, Any]] = {}

    for type_name, values in entry["indicators"].items():
        for value, record in values.items():
            seen = record.get("first_seen")
            date = seen.date().isoformat() if seen else ""
            precision = record.get("precision") or ""
            references = tuple(record.get("references") or ())

            batch = batches.setdefault(
                (date, precision, references),
                {
                    "first_seen": date or None,
                    "precision": precision or None,
                    "references": list(references),
                    "indicators": {},
                },
            )
            batch["indicators"].setdefault(type_name, []).append(value)

    ordered: list[dict[str, Any]] = []
    for batch in batches.values():
        batch["indicators"] = {kind: sorted(values) for kind, values in sorted(batch["indicators"].items())}
        batch["counts"] = {kind: len(values) for kind, values in batch["indicators"].items()}
        batch["total"] = sum(batch["counts"].values())
        ordered.append(batch)

    # Newest first; within a date the larger batch leads. The reference tuple is
    # the final tiebreak purely to keep the order stable between runs.
    ordered.sort(key=lambda b: (b["first_seen"] or "", b["total"], b["references"]), reverse=True)
    return ordered


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #


def split_url(url: str) -> tuple[str, str]:
    """Split a reference into host and a shortened path, for a readable link."""
    rest = url.split("://", 1)[-1]
    host, _, path = rest.partition("/")
    if host.startswith("www."):
        host = host[4:]
    path = path.rstrip("/")
    if len(path) > 40:
        path = path[:39] + "…"
    return host, ("/" + path if path else "")


def _year(date: str | None) -> int | None:
    return int(date[:4]) if date else None


def _ago(date: str | None, now: int) -> str:
    """A coarse age, in the units an analyst triages by."""
    year = _year(date)
    if year is None:
        return ""
    span = now - year
    if span <= 0:
        return "this year"
    return "1 yr ago" if span == 1 else f"{span} yrs ago"


def _tags(values: list[str], mark: bool = False) -> str:
    body = "".join(f"<li>{'<b>' if mark else ''}{esc(v)}{'</b>' if mark else ''}</li>" for v in values)
    return f"<ul class=chips>{body}</ul>"


# --------------------------------------------------------------------------- #
# page sections
# --------------------------------------------------------------------------- #


def _masthead(slug: str, entry: dict[str, Any], batches: list[dict[str, Any]], now: int) -> str:
    """Identity, the numbers that decide relevance, and the activity shape."""
    attack_id = entry.get("attack_id")
    title = entry.get("attack_name") or ", ".join(entry.get("maltrail_groups") or [slug])

    heading = esc(title)
    if attack_id:
        url = ATTACK_GROUP_URL.format(group_id=attack_id)
        heading += f' <a class=gid href="{esc(url)}">{esc(attack_id)}</a>'

    names = list(entry.get("maltrail_groups") or [])
    aliases = sorted({a for a in (entry.get("aliases") or []) if a.lower() not in {n.lower() for n in names}})
    aka = ""
    if names or aliases:
        parts = [f"<b>{esc(n)}</b>" for n in names] + [esc(a) for a in aliases[:40]]
        aka = f'<p class=aka>{" &middot; ".join(parts)}</p>'

    return f"<h1>{heading}</h1>\n{aka}\n{_stats(entry, batches, now)}\n{_spark(batches, now)}"


def _stats(entry: dict[str, Any], batches: list[dict[str, Any]], now: int) -> str:
    """
    Four numbers that decide whether this page is worth reading.

    Not vanity metrics: how much is here, how well sourced it is, whether the
    actor is historical or current, and whether upstream still tracks them.
    """
    total = sum(b["total"] for b in batches)
    reports = {url for b in batches for url in b["references"]}
    span = entry.get("first_seen_range") or {}
    latest = str(span.get("latest") or "")
    last_modified = entry.get("last_modified")

    cells = [
        ("Indicators", f"{total:,}"),
        ("Source reports", f"{len(reports):,}"),
        (
            "Activity span",
            (f"{str(span['earliest'])[:4]}&ndash;{latest[:4]}" if span else "<small>not dated</small>"),
        ),
        (
            "Newest indicator",
            f"{esc(latest)} <small>{esc(_ago(latest, now))}</small>" if latest else "<small>unknown</small>",
        ),
        (
            "Upstream change",
            f"{esc(last_modified.date().isoformat())}" if last_modified else "<small>unknown</small>",
        ),
    ]
    body = "\n".join(f"<div><dt>{label}</dt><dd>{value}</dd></div>" for label, value in cells)
    return f"<dl class=stats>\n{body}\n</dl>"


def _spark(batches: list[dict[str, Any]], now: int) -> str:
    """
    Indicators per year.

    Answers "is this a live actor or a 2016 artefact?" before any scrolling,
    which a list of dates cannot. Bars are square-rooted so a single 10,000
    indicator dump does not flatten every other year to nothing.
    """
    per_year: Counter[int] = Counter()
    for batch in batches:
        year = _year(batch["first_seen"])
        if year is not None:
            per_year[year] += batch["total"]

    if len(per_year) < 2:
        return "<div class=spark-axis></div>"

    first, last = min(per_year), max(per_year)
    peak = max(per_year.values()) ** 0.5
    bars = []
    for year in range(first, last + 1):
        count = per_year.get(year, 0)
        height = round(100 * (count**0.5) / peak) if count else 0
        hot = " class=hot" if year >= now - 1 and count else ""
        bars.append(f'<span{hot} style="--h:{height}%" title="{year}: {count:,} indicators"></span>')

    return (
        f"<div class=spark>{''.join(bars)}</div>\n"
        f"<div class=spark-axis><span>{first}</span><span>{last}</span></div>"
    )


def _rail(slug: str, entry: dict[str, Any], profile: ActorProfile | None, sections: list[tuple[str, str]]) -> str:
    """Jump navigation, attribution facts, and the commands to take the data."""
    nav = "".join(f'<li><a href="#{anchor}">{esc(label)}</a></li>' for anchor, label in sections)

    rows: list[tuple[str, str]] = []
    if profile and profile.country:
        origin = esc(profile.country)
        if profile.sponsor:
            origin += f"<br><span class=note>{esc(profile.sponsor)}</span>"
        rows.append(("Suspected origin", origin))
    if profile and profile.activity:
        rows.append(("Activity", ", ".join(esc(a) for a in profile.activity)))
    if profile and profile.sectors:
        rows.append(("Targeted sectors", _tags(profile.sectors)))
    if profile and profile.victims:
        rows.append(("Suspected victims", _tags(profile.victims[:24])))

    # The upstream file is the primary source; a reader checking our work
    # should be one click from it, not left to guess the path.
    upstream = [
        f'<a href="{esc(MALTRAIL_TRAIL_URL.format(filename=filename))}">{esc(name)}</a>'
        for name, filename in sorted((entry.get("filenames") or {}).items())
    ]
    if upstream:
        rows.append(("Upstream trail", " &middot; ".join(upstream)))

    facts = ""
    if rows:
        body = "\n".join(f"<dt>{label}</dt><dd>{value}</dd>" for label, value in rows)
        facts = f"<h3>Attribution</h3>\n<dl class=facts>\n{body}\n</dl>"

    has_domains = bool(entry["indicators"].get("domain"))
    files = [f'<a href="{esc(slug)}.json">{esc(slug)}.json</a>']
    lines = [f"<span class=c># everything, with sources</span>\ncurl -sL {SITE_URL}/by-group/{esc(slug)}.json"]
    if has_domains:
        files.append(f'<a href="{esc(slug)}-domain.txt">{esc(slug)}-domain.txt</a>')
        lines.append(
            f"<span class=c># domains, one per line</span>\ncurl -sL {SITE_URL}/by-group/{esc(slug)}-domain.txt"
        )

    return (
        f"<h3>On this page</h3>\n<nav><ul>{nav}</ul></nav>\n"
        f"{facts}\n"
        f"<h3>Take the data</h3>\n<pre>" + "\n\n".join(lines) + "</pre>\n"
        # The same files as links, because not every reader wants a shell.
        f'<p class=note>{" &middot; ".join(files)}</p>'
    )


def _description(profile: ActorProfile | None) -> str:
    if profile and profile.description:
        return f"<p class=lede>{esc(profile.description)}</p>"
    return (
        '<p class="lede note">No published description. This group is tracked by '
        "Maltrail from vendor reporting but is not named in MITRE ATT&amp;CK, so "
        "there is no curated profile to show.</p>"
    )


def _coverage(slug: str, entry: dict[str, Any]) -> str:
    """What is actually held, by type, and where the complete list lives."""
    counts = {kind: len(values) for kind, values in sorted(entry["indicators"].items())}
    if not counts:
        return ""

    rows = []
    for kind, count in sorted(counts.items(), key=lambda kv: -kv[1]):
        link = (
            f'<a href="{esc(slug)}-domain.txt">{esc(slug)}-domain.txt</a>'
            if kind == "domain"
            else f'<a href="{esc(slug)}.json">{esc(slug)}.json</a>'
        )
        rows.append(f"<tr><td>{esc(kind)}</td><td class=n>{count:,}</td><td class=f>{link}</td></tr>")

    return "<table class=coverage>\n" + "\n".join(rows) + "\n</table>"


def _techniques(slug: str, profile: ActorProfile | None) -> str:
    """
    ATT&CK techniques as chips rather than a 95-row table.

    A responder scans this for one they recognise; a table of ninety-five rows
    is a wall, a wrapped grid of ids is scannable in a second.
    """
    if not profile or not profile.techniques:
        return ""

    chips = "".join(f'<li><a href="{esc(t.url)}"><b>{esc(t.id)}</b> {esc(t.name)}</a></li>' for t in profile.techniques)
    return (
        f"<h2 id=techniques>Techniques <span class=n>{len(profile.techniques)} ATT&amp;CK</span></h2>\n"
        # Detection engineers plan coverage in Navigator, not by reading ids
        # off a page and retyping them.
        "<p class=note>Load in ATT&amp;CK Navigator: "
        f'<a href="{esc(slug)}-navigator.json">{esc(slug)}-navigator.json</a></p>\n'
        f"<ul class=chips>{chips}</ul>"
    )


def _software(profile: ActorProfile | None) -> str:
    """
    Named malware and tooling, linked to ATT&CK where it has an id.

    Not everything the galaxy names is catalogued by ATT&CK, so entries without
    an id render as plain text rather than as a link that would 404.
    """
    if not profile or not profile.software:
        return ""

    chips = []
    for item in profile.software:
        label = f"<b>{esc(item.name)}</b>"
        chips.append(f'<li><a href="{esc(item.url)}">{label}</a></li>' if item.url else f"<li>{label}</li>")

    return (
        f"<h2 id=software>Software <span class=n>{len(profile.software)}</span></h2>\n"
        f'<ul class=chips>{"".join(chips)}</ul>'
    )


def _reporting(batches: list[dict[str, Any]]) -> str:
    """
    Which write-ups actually account for this actor's infrastructure.

    A flat list of 1,600 references says nothing about weight. Ranked by the
    number of indicators each brought, the list says where the body of the
    evidence came from - and which single report a sceptical reader should
    open first.
    """
    weight: Counter[str] = Counter()
    for batch in batches:
        for url in batch["references"]:
            weight[url] += batch["total"]

    if not weight:
        return ""

    top = weight.most_common(MAX_SOURCES)
    peak = top[0][1]
    items = []
    for url, count in top:
        host, path = split_url(url)
        items.append(
            f"<li><span class=c>{count:,}</span>"
            f'<a href="{esc(url)}" rel="noopener nofollow">'
            f"<span class=host>{esc(host)}</span><span class=path>{esc(path)}</span></a>"
            f'<div class=bar style="--w:{round(100 * count / peak)}%"></div></li>'
        )

    return (
        f"<h2 id=reporting>Principal sources <span class=n>{len(weight):,} reports</span></h2>\n"
        f"<p class=note>Ranked by how many of this actor's indicators each report brought in.</p>\n"
        f"<ul class=rank>\n" + "\n".join(items) + "\n</ul>"
    )


def _timeline(slug: str, batches: list[dict[str, Any]], now: int) -> str:
    """
    The batches, newest first, within the row budget.

    Whole batches are rendered until the budget runs out, so an indicator is
    never shown detached from the report that explains it.
    """
    total = sum(batch["total"] for batch in batches)
    if not total:
        return ""

    items: list[str] = []
    shown = 0
    for batch in batches:
        if shown >= MAX_ROWS:
            break
        pairs = [(kind, value) for kind, values in batch["indicators"].items() for value in values]
        visible = pairs[: MAX_ROWS - shown]
        shown += len(visible)
        items.append(_batch(batch, visible, len(pairs), now))

    truncated = ""
    if shown < total:
        truncated = (
            f"<p class=note>Showing the {shown:,} most recent of {total:,}. "
            f'Complete: <a href="{esc(slug)}.json">{esc(slug)}.json</a>.</p>'
        )

    # Chips for the types actually present, so a reader chasing DNS logs can
    # drop the IPs without typing anything.
    present: Counter[str] = Counter()
    for batch in batches:
        present.update(batch["counts"])
    chips = "<button type=button data-type=all aria-pressed=true>all</button>"
    chips += "".join(
        f'<button type=button data-type="{esc(kind)}" aria-pressed=false>{esc(kind)} {count:,}</button>'
        for kind, count in sorted(present.items(), key=lambda kv: -kv[1])
    )

    # Two years back from the newest indicator, not from today: for an actor
    # dormant since 2019 a "recent" cut against today would empty the page.
    newest = next((b["first_seen"] for b in batches if b["first_seen"]), "")
    cutoff = f"{int(newest[:4]) - 2}-01-01" if newest[:4].isdigit() else ""
    age = ""
    if cutoff and any((b["first_seen"] or "") < cutoff for b in batches):
        age = f"<label><input type=checkbox id=recent> since {esc(cutoff[:4])}</label>"

    tools = (
        f'<div class=tools id=tools hidden data-recent="{esc(cutoff)}">'
        '<input type=search id=q placeholder="filter indicators  (press /)" aria-label="Filter indicators">'
        "<label><input type=checkbox id=defang> defang</label>"
        f"{age}"
        "<button type=button data-copy=all>copy</button>"
        "<button type=button data-copy=csv>copy CSV</button>"
        f"<span class=note><b id=shown>{shown:,}</b> shown</span>"
        "</div>\n"
        f"<div class=chips id=types>{chips}</div>"
    )

    return (
        f"<h2 id=timeline>Timeline <span class=n>{total:,} indicators</span></h2>\n"
        "<p class=note>Each entry is a batch of indicators that appeared upstream on one date, "
        "under the report it was filed with.</p>\n"
        f"{tools}\n{truncated}\n"
        "<p class=note id=empty hidden>No indicator matches. Only the most recent "
        f"{MAX_ROWS:,} are on this page &mdash; the rest are in the JSON.</p>\n"
        "<ol class=timeline id=timeline-list>\n" + "\n".join(items) + "\n</ol>"
    )


def batch_anchor(batch: dict[str, Any]) -> str:
    """
    A stable id for one batch.

    Position would be simpler and would break every citation the moment a newer
    batch lands above it. Keying on the date plus a short digest of the sources
    survives a rebuild, so a link pasted into a ticket still lands on the right
    entry a month later.
    """
    date = batch["first_seen"] or "undated"
    if not batch["references"]:
        return f"b-{date}"
    digest = hashlib.sha256("\n".join(batch["references"]).encode("utf-8")).hexdigest()[:6]
    return f"b-{date}-{digest}"


def _batch(batch: dict[str, Any], visible: list[tuple[str, str]], size: int, now: int) -> str:
    """Render one timeline entry: when, from where, and what."""
    date = batch["first_seen"]
    year = _year(date)
    anchor = batch_anchor(batch)

    if not date:
        when = "<span class=approx>date unknown</span>"
    else:
        # The <time> is not decoration: the age filter and the CSV export both
        # read the batch date out of it.
        when = f'<a class=date href="#{anchor}"><time datetime="{esc(date)}">{esc(date)}</time></a>'
        if batch["precision"] == "at-or-before":
            # Upstream reset its history; these dates are a floor, not a sighting.
            when += (
                ' <span class=approx title="Upstream history does not reach further back; '
                'the indicator may be older">or earlier</span>'
            )

    label = ", ".join(f"{count:,} {kind}" for kind, count in batch["counts"].items())
    ago = f"<span class=ago>{esc(_ago(date, now))}</span>" if date else ""
    hot = " class=hot" if year is not None and year >= now - 1 else ""

    mixed = len(batch["counts"]) > 1
    # data-t on every row, printed only when the batch mixes types: the filter
    # chips need the type on each row, the reader does not.
    rows = "\n".join(
        f'<tr data-t="{esc(kind)}">'
        + (f"<td class=kind>{esc(kind)}</td>" if mixed else "")
        + f"<td class=val>{esc(value)}</td></tr>"
        for kind, value in visible
    )

    foot = "<p class=batch-foot><button type=button data-copy=batch>copy batch</button>"
    if len(visible) < size:
        foot += f" &middot; {size - len(visible):,} more in this batch, in the JSON"
    foot += "</p>"

    return (
        f'<li id="{anchor}"{hot}>\n'
        f'<div class=when>{when} <span class=cnt>{esc(label)}</span>{ago}</div>\n'
        f'<p class=src>{_sources(batch["references"])}</p>\n'
        f'<table class=iocs>\n{rows}\n</table>\n{foot}\n</li>'
    )


def _sources(references: list[str]) -> str:
    """The report links that explain where a batch came from."""
    if not references:
        return "<span class=nosrc>no upstream reference for this batch</span>"

    links = []
    for url in references:
        host, path = split_url(url)
        links.append(
            f'<a href="{esc(url)}" rel="noopener nofollow">'
            f"<span class=host>{esc(host)}</span><span class=path>{esc(path)}</span></a>"
        )
    return " &middot; ".join(links)


def _further_reading(slug: str, entry: dict[str, Any], profile: ActorProfile | None) -> str:
    """
    Group-level background.

    Every batch in the timeline already links the report that introduced its
    indicators, so this section is background, not provenance. It is capped:
    one group carries 1,607 upstream references, and rendering them all put a
    quarter of a megabyte of link text under the page for no one to read.
    """
    seen: list[str] = []
    for url in (profile.references if profile else []) + list(entry.get("references") or []):
        if url not in seen:
            seen.append(url)

    if not seen:
        return ""

    shown = seen[:MAX_REFERENCES]
    items = "\n".join(
        f'<li><a href="{esc(url)}" rel="noopener nofollow">{esc("".join(split_url(url)))}</a></li>' for url in shown
    )
    more = ""
    if len(seen) > len(shown):
        more = (
            f"<p class=note>{len(seen) - len(shown):,} more, and the report behind every indicator, "
            f'in <a href="{esc(slug)}.json">{esc(slug)}.json</a>.</p>'
        )

    return (
        f"<h2 id=reading>Further reading <span class=n>{len(seen):,}</span></h2>\n"
        f"<ul class=refs>\n{items}\n</ul>\n{more}"
    )


def render(
    slug: str,
    entry: dict[str, Any],
    profile: ActorProfile | None,
    generated: str,
    timeline: list[dict[str, Any]] | None = None,
) -> str:
    """
    Render one actor page.

    Args:
        slug: File stem, an ATT&CK id where the group is mapped
        entry: Merged group entry from the slice exporter
        profile: Vendored actor profile, when ATT&CK tracks the group
        generated: Feed generation timestamp
        timeline: Prebuilt batches, so the page and the JSON slice cannot
            disagree; built from the entry when omitted

    Returns:
        A complete HTML document
    """
    if timeline is None:
        timeline = build_timeline(entry)

    title = entry.get("attack_name") or ", ".join(entry.get("maltrail_groups") or [slug])
    # Ages are rendered at build time; the site is rebuilt hourly, so they stay
    # honest without asking the reader's browser to run anything.
    now = int(str(generated)[:4]) if str(generated)[:4].isdigit() else 0

    techniques = _techniques(slug, profile)
    software = _software(profile)
    reporting = _reporting(timeline)
    reading = _further_reading(slug, entry, profile)

    sections = [("overview", "Overview")]
    if techniques:
        sections.append(("techniques", "Techniques"))
    if software:
        sections.append(("software", "Software"))
    if reporting:
        sections.append(("reporting", "Principal sources"))
    sections.append(("timeline", "Timeline"))
    if reading:
        sections.append(("reading", "Further reading"))

    total = sum(len(values) for values in entry["indicators"].values())
    # What a link preview shows: who the actor is and how much is held, not a
    # truncated sentence of ATT&CK prose that stops mid-word.
    reports = len({url for batch in timeline for url in batch["references"]})
    summary = f"{total:,} indicators attributed to {title}"
    if entry.get("attack_id"):
        summary += f" ({entry['attack_id']})"
    summary += f", from {reports:,} source reports, each dated and linked to the write-up that published it."

    return f"""<!doctype html>
<html lang=en>
<meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
{head(f"{title} · APTtrail", summary, f"{SITE_URL}/by-group/{slug}.html")}
<style>{STYLE}</style>
<div class=wrap>
<div class=topbar>
  <a href="../index.html">&larr; All groups</a>
  <a href="../activity.html">Recent activity</a>
</div>

<header class=masthead>
{_masthead(slug, entry, timeline, now)}
</header>

<div class=grid>
<aside>
{_rail(slug, entry, profile, sections)}
</aside>

<main>
<h2 id=overview>Overview <span class=n>{total:,} indicators</span></h2>
{_description(profile)}
{_coverage(slug, entry)}

{techniques}

{software}

{reporting}

{_timeline(slug, timeline, now)}

{reading}

<footer>
<p>Indicators from <a href="{MALTRAIL_URL}">Maltrail</a>; actor profile from the
<a href="https://github.com/MISP/misp-galaxy">MISP galaxy</a> and
<a href="https://attack.mitre.org/">MITRE ATT&amp;CK</a>. Attribution is inherited
from those sources, not independently assessed. Dates are when an indicator entered
Maltrail, not when the actor first used it; those marked <span class=approx>or
earlier</span> are a floor, because upstream reset its history in January 2026.</p>
<p>Generated {esc(generated)} &middot; rebuilt hourly &middot;
<a href="{PROJECT_URL}">source</a></p>
</footer>
</main>
</div>
</div>
<script>{SCRIPT}</script>
</html>
"""


def write_group_page(
    directory: Path,
    slug: str,
    entry: dict[str, Any],
    profile: ActorProfile | None,
    generated: str,
    timeline: list[dict[str, Any]] | None = None,
) -> Path:
    """Write one actor page and return its path."""
    path = directory / f"{slug}.html"
    path.write_text(render(slug, entry, profile, generated, timeline), encoding="utf-8", newline="\n")
    return path
