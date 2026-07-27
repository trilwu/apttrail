"""
Analyst-facing slices of the feed.

The single 7MB JSON is the wrong shape for most day-to-day work. A responder
chasing one actor wants that actor's indicators; someone filling a blocklist
wants a flat list of domains. Both are one HTTP GET away here, with no parsing:

    by-type/domain.txt          every domain, one per line
    by-type/ipv4.txt            every IPv4 address, no ports
    by-group/G0007.json         one ATT&CK group, full detail
    by-group/G0007-domain.txt   one ATT&CK group, flat list
    index.json                  what exists, with counts

File names use exactly the type tokens that appear in the JSON feed, so a
client can build any path mechanically.

Files are named by ATT&CK group id where the actor is mapped, falling back to
the Maltrail name, so a lookup from an ATT&CK-driven workflow lands directly on
the right file.
"""

import json
from itertools import groupby
from pathlib import Path
from typing import Any

from apttrail.exporters.group_pages import (
    STYLE,
    batch_anchor,
    build_timeline,
    head,
    split_url,
    write_group_page,
)
from apttrail.models import APTGroup, FeedMetadata, IndicatorType
from apttrail.profiles import load_profiles

#: Types that make sense as flat, directly consumable lists.
FLAT_TYPES = (
    IndicatorType.DOMAIN,
    IndicatorType.IPV4,
    IndicatorType.IPV6,
    IndicatorType.URL,
    IndicatorType.URL_PATH,
    IndicatorType.MD5,
    IndicatorType.SHA1,
    IndicatorType.SHA256,
)

BANNER = "# APTtrail - {title}\n# {count} indicators | {url}\n# Generated {generated}\n"
PROJECT_URL = "https://github.com/trilwu/apttrail"
SITE_URL = "https://trilwu.github.io/apttrail"

# The landing page shares the actor pages' tokens and base rules so the site
# reads as one thing; only what is unique to a 314-row directory lives here.
INDEX_STYLE = """
h1 em { font-style: italic; color: var(--accent); }
.masthead .lede { margin: 0 0 1.6rem; max-width: 40rem; }
code { font: .88em var(--mono); color: var(--muted); }
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

#: Batches on the activity page. A fixed count rather than a fixed number of
#: days: never empty in a quiet week, never unbounded in a busy one.
ACTIVITY_BATCHES = 150

#: Entries in the Atom feed. Fewer than the page carries: a reader checking
#: daily wants what changed, not a month of backlog on first subscribe.
ATOM_ENTRIES = 50

ACTIVITY_SCRIPT = """
(function () {
  var feed = document.getElementById('feed');
  var q = document.getElementById('q');
  var tools = document.getElementById('tools');
  var count = document.getElementById('shown');
  if (!feed || !q) return;
  tools.hidden = false;

  var events = Array.prototype.slice.call(feed.querySelectorAll('.event'));
  events.forEach(function (e) { e.dataset.k = e.textContent.toLowerCase(); });

  function apply() {
    var needle = q.value.trim().toLowerCase();
    var shown = 0;
    events.forEach(function (e) {
      var hit = !needle || e.dataset.k.indexOf(needle) !== -1;
      e.hidden = !hit;
      if (hit) shown++;
    });
    // A day with nothing left in it is noise.
    Array.prototype.forEach.call(feed.querySelectorAll('.day'), function (day) {
      day.hidden = !day.querySelector('.event:not([hidden])');
    });
    count.textContent = shown.toLocaleString();
    document.getElementById('empty').hidden = shown > 0;
    if (history.replaceState) {
      history.replaceState(null, '', needle ? '?q=' + encodeURIComponent(needle) : location.pathname);
    }
  }
  q.addEventListener('input', apply);

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

ACTIVITY_STYLE = """
main.solo { grid-column: 1 / -1; max-width: 58rem; }
.day { margin-top: 2rem; }
.daymark { font: .78rem/1 var(--mono); letter-spacing: .09em; color: var(--faint);
           margin: 0 0 .6rem; padding-bottom: .35rem; border-bottom: 1px solid var(--line-firm); }
.event { padding: .55rem 0; border-bottom: 1px solid var(--line); }
.event .who { font: 500 .98rem/1.5 var(--sans); text-decoration: none; }
.event .who:hover { color: var(--accent); }
.event .gid { font: .76rem/1.5 var(--mono); color: var(--accent); margin-left: .45rem; }
.event .cnt { font: .78rem/1.5 var(--mono); color: var(--faint); margin-left: .5rem; }
.event .src { margin-top: .12rem; font: .78rem/1.6 var(--mono); }
.event .src a { text-decoration: none; color: var(--muted); }
.event .src a:hover .host { color: var(--accent); }
.event .src .host { color: var(--ink); }
.event .src .path { color: var(--faint); }
.event .src .nosrc { color: var(--faint); font-style: italic; }
"""

INDEX_SCRIPT = """
(function () {
  var el = document.getElementById('generated');
  var out = document.getElementById('ago');
  if (el && out) {
    // generated_at is timezone-aware ("...+00:00"). Appending Z to that makes
    // it unparseable, which is what shipped: the clock read "unknown" for
    // every visitor. Only a naive stamp needs the suffix.
    var raw = el.getAttribute('datetime');
    var then = new Date(/(Z|[+-]\\d\\d:?\\d\\d)$/.test(raw) ? raw : raw + 'Z');
    if (isNaN(then)) {
      out.firstChild.textContent = 'unknown';
    } else {
      // Rendered client-side so the age is right whenever the page is opened,
      // not whenever it was generated.
      var mins = Math.max(0, Math.round((Date.now() - then) / 60000));
      out.firstChild.textContent = mins < 1 ? 'just now'
        : mins < 60 ? mins + ' min ago'
        : mins < 1440 ? Math.round(mins / 60) + ' h ago'
        : Math.round(mins / 1440) + ' d ago';
      if (mins > 180) { out.classList.add('stale'); }
      el.textContent = then.toISOString().replace('T', ' ').replace('.000Z', '') + ' UTC';
    }
  }

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


class SliceExporter:
    """Writes per-type and per-group slices under an output directory."""

    def __init__(self, output_dir: Path | str) -> None:
        """
        Args:
            output_dir: Directory to populate; created if absent
        """
        self.output_dir = Path(output_dir)

    def export(self, apt_groups: dict[str, APTGroup], metadata: FeedMetadata) -> dict[str, int]:
        """
        Write every slice.

        Args:
            apt_groups: Collected APT groups
            metadata: Feed metadata, used for the generation banner

        Returns:
            Counts of files written, keyed by slice kind
        """
        by_type_dir = self.output_dir / "by-type"
        by_group_dir = self.output_dir / "by-group"
        by_type_dir.mkdir(parents=True, exist_ok=True)
        by_group_dir.mkdir(parents=True, exist_ok=True)

        generated = metadata.generated_at.isoformat()
        written = {"by_type": 0, "by_group": 0}

        for indicator_type in FLAT_TYPES:
            values = self._collect_type(apt_groups, indicator_type)
            if not values:
                continue

            self._write_list(
                by_type_dir / f"{indicator_type.value}.txt",
                title=f"all {indicator_type.value} indicators",
                values=values,
                generated=generated,
            )
            written["by_type"] += 1

        index: list[dict[str, Any]] = []
        activity: list[dict[str, Any]] = []
        for slug, entry in sorted(self._merge_by_slug(apt_groups).items()):
            timeline = self._write_group(by_group_dir, slug, entry, generated)
            index.append(self._index_entry(slug, entry))
            activity.extend(self._activity_entries(slug, entry, timeline))
            written["by_group"] += 1

        self._write_index(index, metadata, written)
        self._write_activity(activity, metadata)
        self._write_discovery([entry["slug"] for entry in index], metadata)
        return written

    @staticmethod
    def _slug(group: APTGroup, name: str) -> str:
        """Prefer the ATT&CK id so ATT&CK-driven lookups resolve directly."""
        return group.metadata.attack_id or name

    def _merge_by_slug(self, apt_groups: dict[str, APTGroup]) -> dict[str, dict[str, Any]]:
        """
        Combine Maltrail groups that resolve to the same ATT&CK intrusion set.

        Maltrail tracks DONOT, PATCHWORK and HANGOVER separately; ATT&CK calls
        all three G0040. Writing them to the same slug without merging meant the
        last one won, so a request for Patchwork's infrastructure returned 984
        of its 2,225 indicators. 22 ATT&CK ids are affected.

        Args:
            apt_groups: Collected groups, keyed by Maltrail name

        Returns:
            Merged entries keyed by slug, skipping groups with no indicators
        """
        merged: dict[str, dict[str, Any]] = {}

        for name in sorted(apt_groups):
            group = apt_groups[name]
            if not group.total_indicators:
                continue

            metadata = group.metadata
            slug = self._slug(group, name)
            entry = merged.setdefault(
                slug,
                {
                    "maltrail_groups": [],
                    "attack_id": metadata.attack_id,
                    "attack_name": metadata.attack_name,
                    "attack_url": metadata.attack_url,
                    "aliases": set(),
                    "references": set(),
                    "last_modified": None,
                    # Maltrail name to its upstream file, so a reader checking
                    # our work is one click from the primary source.
                    "filenames": {},
                    "indicators": {},
                },
            )

            entry["maltrail_groups"].append(name)
            entry["filenames"][name] = metadata.filename
            entry["aliases"].update(metadata.aliases)
            entry["references"].update(metadata.references)
            if metadata.last_modified and (
                entry["last_modified"] is None or metadata.last_modified > entry["last_modified"]
            ):
                entry["last_modified"] = metadata.last_modified

            for indicator_type, indicators in group.indicators.items():
                bucket = entry["indicators"].setdefault(indicator_type.value, {})
                for indicator in indicators:
                    known = bucket.get(indicator.value)
                    if known is None:
                        bucket[indicator.value] = {
                            "first_seen": indicator.first_seen,
                            "precision": indicator.first_seen_precision,
                            "references": list(indicator.references),
                        }
                        continue

                    # The same value can arrive from two merged groups; keep
                    # the earlier sighting and every source that cited it.
                    seen = indicator.first_seen
                    if seen and (known["first_seen"] is None or seen < known["first_seen"]):
                        known["first_seen"] = seen
                        known["precision"] = indicator.first_seen_precision
                    for url in indicator.references:
                        if url not in known["references"]:
                            known["references"].append(url)

        return merged

    @staticmethod
    def _collect_type(apt_groups: dict[str, APTGroup], indicator_type: IndicatorType) -> list[str]:
        values: set[str] = set()
        for group in apt_groups.values():
            for indicator in group.indicators.get(indicator_type, set()):
                # Ports belong to the observation, not to the address; a
                # blocklist consumer wants the bare address.
                values.add(indicator.value.split(":")[0] if indicator_type is IndicatorType.IPV4 else indicator.value)
        return sorted(values)

    def _write_list(self, path: Path, title: str, values: list[str], generated: str) -> None:
        banner = BANNER.format(title=title, count=len(values), url=PROJECT_URL, generated=generated)
        path.write_text(banner + "\n".join(values) + "\n", encoding="utf-8", newline="\n")

    def _write_group(self, directory: Path, slug: str, entry: dict[str, Any], generated: str) -> list[dict[str, Any]]:
        last_modified = entry["last_modified"]
        profile = load_profiles().get(entry["attack_id"])
        # Built once so the page and the JSON slice cannot drift apart.
        timeline = build_timeline(entry)
        payload = {
            "slug": slug,
            "maltrail_groups": sorted(entry["maltrail_groups"]),
            "attack_id": entry["attack_id"],
            "attack_name": entry["attack_name"],
            "attack_url": entry["attack_url"],
            "aliases": sorted(entry["aliases"]),
            "references": sorted(entry["references"]),
            "last_modified": last_modified.isoformat() if last_modified else None,
            "generated_at": generated,
            "first_seen_range": self._first_seen_range(entry),
            "counts": self._counts(entry),
            "indicators": {
                indicator_type: sorted(values) for indicator_type, values in sorted(entry["indicators"].items())
            },
            "first_seen": {
                indicator_type: {
                    value: record["first_seen"].date().isoformat()
                    for value, record in sorted(values.items())
                    if record["first_seen"]
                }
                for indicator_type, values in sorted(entry["indicators"].items())
            },
            # Only the dates that are a floor rather than a sighting are listed;
            # anything absent here and present in first_seen is exact.
            "first_seen_precision": {
                indicator_type: {
                    value: record["precision"]
                    for value, record in sorted(values.items())
                    if record["precision"] and record["precision"] != "exact"
                }
                for indicator_type, values in sorted(entry["indicators"].items())
            },
            # Where each batch of indicators came from: the date it appeared
            # upstream and the report it was filed under.
            "timeline": timeline,
        }
        (directory / f"{slug}.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )

        # The human-readable actor page: description, targeting, techniques and
        # the indicator timeline.
        write_group_page(directory, slug, entry, profile, generated, timeline)

        # Flat domain list per group: the single most requested shape for
        # hunting one actor in DNS logs.
        domains = sorted(entry["indicators"].get(IndicatorType.DOMAIN.value, {}))
        if domains:
            label = f"{entry['attack_id']} {entry['attack_name']}" if entry["attack_id"] else slug
            self._write_list(directory / f"{slug}-domain.txt", f"{label} domains", domains, generated)

        self._write_navigator_layer(directory, slug, entry, profile)
        return timeline

    def _write_navigator_layer(self, directory: Path, slug: str, entry: dict[str, Any], profile: Any | None) -> None:
        """
        Write an ATT&CK Navigator layer for the group.

        Navigator is where a lot of detection engineers actually plan coverage,
        and the techniques are already vendored here. Dropping a file they can
        load directly beats making them copy ninety-five ids by hand.

        Groups ATT&CK does not track get no layer: an empty one would be a file
        that opens to nothing.
        """
        if not profile or not profile.techniques:
            return

        name = entry["attack_name"] or slug
        layer = {
            "name": f"{name} ({entry['attack_id']}) - APTtrail",
            "description": (
                f"Techniques attributed to {name} by MITRE ATT&CK, packaged by APTtrail. "
                f"Indicators: {SITE_URL}/by-group/{slug}.json"
            ),
            "domain": "enterprise-attack",
            "versions": {"layer": "4.5", "navigator": "5.1.0"},
            "techniques": [{"techniqueID": t.id, "score": 1, "enabled": True} for t in profile.techniques],
            "gradient": {"colors": ["#ffffff", "#e86f4a"], "minValue": 0, "maxValue": 1},
            "legendItems": [{"label": f"Used by {name}", "color": "#e86f4a"}],
            "hideDisabled": False,
        }
        (directory / f"{slug}-navigator.json").write_text(
            json.dumps(layer, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
            newline="\n",
        )

    @staticmethod
    def _activity_entries(slug: str, entry: dict[str, Any], timeline: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Flatten a group's recent batches into feed-wide activity rows.

        Only dated batches qualify: an undated indicator says nothing about
        when anything happened, and padding the feed with them would make a
        quiet week look busy.
        """
        name = entry["attack_name"] or ", ".join(entry["maltrail_groups"])
        return [
            {
                "date": batch["first_seen"],
                "slug": slug,
                "attack_id": entry["attack_id"],
                "group": name,
                "anchor": batch_anchor(batch),
                "counts": batch["counts"],
                "total": batch["total"],
                "references": batch["references"],
            }
            for batch in timeline
            if batch["first_seen"]
        ]

    @staticmethod
    def _first_seen_range(entry: dict[str, Any]) -> dict[str, str] | None:
        """
        Earliest and latest first_seen across a group's indicators.

        Answers "how long has this actor's infrastructure been known?" without
        downloading the group's indicators, and is the only place the recovered
        history is visible from the site.
        """
        dates = [
            record["first_seen"]
            for bucket in entry["indicators"].values()
            for record in bucket.values()
            if record["first_seen"]
        ]
        if not dates:
            return None
        return {"earliest": min(dates).date().isoformat(), "latest": max(dates).date().isoformat()}

    @staticmethod
    def _counts(entry: dict[str, Any]) -> dict[str, int]:
        return {indicator_type: len(values) for indicator_type, values in sorted(entry["indicators"].items())}

    def _index_entry(self, slug: str, entry: dict[str, Any]) -> dict[str, Any]:
        counts = self._counts(entry)
        return {
            "slug": slug,
            "maltrail_groups": sorted(entry["maltrail_groups"]),
            "attack_id": entry["attack_id"],
            "attack_name": entry["attack_name"],
            "aliases": sorted(entry["aliases"]),
            "total": sum(counts.values()),
            "counts": counts,
            "first_seen_range": self._first_seen_range(entry),
        }

    def _write_index(self, index: list[dict[str, Any]], metadata: FeedMetadata, written: dict[str, int]) -> None:
        # Two different counts, and conflating them is misleading: several
        # Maltrail groups can share one ATT&CK id, so the number of mapped
        # source groups exceeds the number of distinct intrusion sets.
        attack_ids = {entry["attack_id"] for entry in index if entry["attack_id"]}
        mapped_sources = sum(len(entry["maltrail_groups"]) for entry in index if entry["attack_id"])
        source_groups = sum(len(entry["maltrail_groups"]) for entry in index)

        payload = {
            "generated_at": metadata.generated_at.isoformat(),
            "project": PROJECT_URL,
            "totals": {
                "slices": len(index),
                "maltrail_groups": source_groups,
                "maltrail_groups_mapped_to_attack": mapped_sources,
                "attack_groups": len(attack_ids),
                "indicators": sum(entry["total"] for entry in index),
                "by_type_files": written["by_type"],
            },
            "groups": index,
        }
        (self.output_dir / "index.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        self._write_html_index(payload)

    def _write_html_index(self, payload: dict[str, Any]) -> None:
        """
        Write the landing page.

        This is the first thing a responder sees, and most of them arrive with
        one of two errands: *I have a name, give me its indicators*, or *I have
        an indicator, tell me whose it is*. Both are answered above the fold -
        the second by a command they can copy, the first by a filter over every
        group that matches on ATT&CK id, name and alias, because analysts are
        handed vendor names like "Fancy Bear", not G-ids.
        """
        totals = payload["totals"]
        groups = sorted(payload["groups"], key=lambda g: -g["total"])

        rows = "\n".join(self._index_row(g) for g in groups)

        lists = " &middot; ".join(
            f'<a href="by-type/{t.value}.txt">{t.value}.txt</a>'
            for t in FLAT_TYPES
            if (self.output_dir / "by-type" / f"{t.value}.txt").exists()
        )

        generated = self._esc(payload["generated_at"])
        coverage = round(100 * totals["maltrail_groups_mapped_to_attack"] / max(totals["maltrail_groups"], 1))

        html = f"""<!doctype html>
<html lang=en>
<meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
{head(
    "APTtrail · APT indicators with ATT&CK attribution",
    f"{totals['indicators']:,} APT indicators across {totals['maltrail_groups']} groups, each carrying the actor "
    f"it belongs to and its MITRE ATT&CK id. Static files on stable URLs, no API key.",
    f"{SITE_URL}/",
)}
<style>{STYLE}{INDEX_STYLE}</style>
<div class=wrap>
<div class=topbar>
  <span>APTtrail</span>
  <a href="{PROJECT_URL}">source &amp; docs</a>
</div>

<header class=masthead>
<h1>APT indicators, <em>attributed</em></h1>
<p class=lede>Every indicator arrives tagged with the group it belongs to and,
where MITRE tracks that group, its <code>Gxxxx</code> id. Plain files on stable
URLs &mdash; no account, no API key, no rate limit.</p>

<dl class=stats>
<div><dt>Indicators</dt><dd>{totals["indicators"]:,}</dd></div>
<div><dt>APT groups</dt><dd>{totals["maltrail_groups"]:,}</dd></div>
<div><dt>ATT&amp;CK mapped</dt><dd>{totals["maltrail_groups_mapped_to_attack"]:,}
  <small>{coverage}% &rarr; {totals["attack_groups"]} sets</small></dd></div>
<div><dt>Updated</dt><dd id=ago>&hellip;
  <small><time id=generated datetime="{generated}">{generated}</time></small></dd></div>
</dl>
</header>

<div class=grid>
<aside>
<h3>Start here</h3>
<nav><ul>
  <li><a href="activity.html">Recent activity</a></li>
  <li><a href="#lookup">Look up one indicator</a></li>
  <li><a href="#groups">Browse by group</a></li>
  <li><a href="#files">Whole-feed files</a></li>
</ul></nav>

<h3>Formats</h3>
<p class=note>MISP feed, STIX 2.1 bundle, Suricata rules with datasets, Sigma,
CSV and JSON. <a href="{PROJECT_URL}#per-tool-setup">All of them</a>.</p>
</aside>

<main>
<h2 id=recent>Recent activity <span class=n>what moved</span></h2>
<p>Every other view here is keyed on an actor, which only helps a reader who
already has a name. <a href="activity.html">Recent activity</a> is the view for
one who does not: the newest batches of indicators across every group, by day,
each linked to the report that published it.</p>

<h2 id=lookup>Look up one indicator <span class=n>an alert just fired</span></h2>
<p>Indicators are sharded by <code>sha256(value)</code>, so the URL is
computable offline. The reply carries the actor, its ATT&amp;CK id, when the
indicator was first seen and the report it came from.</p>
<pre><span class=c># what do you know about this domain?</span>
IOC=evil.example
shard=$(printf %s "$IOC" | sha256sum | cut -c1-2)
curl -s {SITE_URL}/by-indicator/$shard.json | jq --arg v "$IOC" '.[$v]'</pre>

<h2 id=groups>By group <span class=n>{totals["slices"]:,} profiles</span></h2>
<p class=note>Filter matches ATT&amp;CK id, name and alias &mdash; type
<em>fancy bear</em> or <em>G0007</em>. <em>Seen</em> is the span of first-seen
dates, recovered from upstream history reaching back to 2014.</p>
<div class=tools id=tools hidden>
  <input type=search id=q placeholder="filter groups &mdash; name, alias or G-id  (press /)" aria-label="Filter groups">
  <label><input type=checkbox id=mapped> ATT&amp;CK only</label>
  <label><input type=checkbox id=active> active 90d</label>
  <span class=note><b id=shown>{totals["slices"]:,}</b> groups</span>
</div>
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

<h2 id=files>Whole-feed files</h2>
<p>Flat lists, one value per line, safe to point a blocklist at &mdash; with the
caveat that these are historical indicators, not a live blocklist.</p>
<p class=note>{lists} &middot; <a href="index.json">index.json</a> &middot;
<a href="misp-feed/manifest.json">misp-feed/</a></p>
<pre><span class=c># every domain APT28 has been seen using</span>
curl -sL {SITE_URL}/by-group/G0007-domain.txt</pre>

<footer>
<p>Indicators from <a href="https://github.com/stamparm/maltrail">Maltrail</a>;
attribution from <a href="https://attack.mitre.org/">MITRE ATT&amp;CK</a> and the
<a href="https://github.com/MISP/misp-galaxy">MISP galaxy</a>, inherited rather
than independently assessed. Historical indicators: treat a hit as a lead to
triage, not proof of compromise.</p>
<p>Rebuilt hourly &middot; <a href="{PROJECT_URL}">source</a></p>
</footer>
</main>
</div>
</div>
<script>{INDEX_SCRIPT}</script>
</html>
"""
        (self.output_dir / "index.html").write_text(html, encoding="utf-8", newline="\n")

    #: Alternative names shown under a group. The rest stay searchable.
    VISIBLE_ALIASES = 6

    def _write_activity(self, activity: list[dict[str, Any]], metadata: FeedMetadata) -> None:
        """
        Write the feed-wide "what moved recently" page.

        Everything else here is organised by actor, which only helps a reader
        who already has a name. This is the view for the reader who has none:
        the batches that landed most recently, across every group, so a daily
        check answers "is anything I care about active" in one screen.

        The window is a fixed number of batches rather than a number of days
        so the page is never empty in a quiet week and never unbounded in a
        busy one; the dates it actually covers are stated on the page.
        """
        batches = sorted(activity, key=lambda b: (b["date"], b["total"]), reverse=True)[:ACTIVITY_BATCHES]
        if not batches:
            return

        payload = {
            "generated_at": metadata.generated_at.isoformat(),
            "project": PROJECT_URL,
            "window": {"from": batches[-1]["date"], "to": batches[0]["date"]},
            "batches": batches,
        }
        (self.output_dir / "activity.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )

        groups = {b["slug"] for b in batches}
        indicators = sum(b["total"] for b in batches)

        days: list[str] = []
        for date, rows in groupby(batches, key=lambda b: str(b["date"])):
            entries = "\n".join(self._activity_row(row) for row in rows)
            days.append(
                f'<section class=day><h3 class=daymark><time datetime="{date}">{date}</time></h3>\n{entries}</section>'
            )

        html = f"""<!doctype html>
<html lang=en>
<meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
{head(
    "Recent activity · APTtrail",
    f"{indicators:,} APT indicators across {len(groups)} groups appeared upstream between "
    f"{batches[-1]['date']} and {batches[0]['date']}, each dated and linked to the report that published it.",
    f"{SITE_URL}/activity.html",
)}
<link rel=alternate type="application/atom+xml" title="APTtrail recent activity" href="activity.xml">
<style>{STYLE}{INDEX_STYLE}{ACTIVITY_STYLE}</style>
<div class=wrap>
<div class=topbar>
  <a href="index.html">&larr; APTtrail</a>
  <a href="activity.json">activity.json</a>
</div>

<header class=masthead>
<h1>Recent activity</h1>
<p class=lede>The newest batches of indicators across every tracked group. Each
one is a set of indicators that appeared upstream on a single day, under the
report it was filed with.</p>

<dl class=stats>
<div><dt>Batches</dt><dd>{len(batches):,}</dd></div>
<div><dt>Indicators</dt><dd>{indicators:,}</dd></div>
<div><dt>Groups</dt><dd>{len(groups):,}</dd></div>
<div><dt>Window</dt><dd>{self._esc(batches[-1]["date"])}
  <small>&rarr; {self._esc(batches[0]["date"])}</small></dd></div>
</dl>
</header>

<main class=solo>
<p class=note>Dates are when an indicator entered Maltrail, not when the actor
first used it. A batch appearing today can still describe old infrastructure.
For additions and <em>removals</em> at this project's own level, see
<a href="{PROJECT_URL}/tree/main/feeds/changes">feeds/changes</a>.</p>

<div class=tools id=tools hidden>
  <input type=search id=q placeholder="filter by group or source  (press /)" aria-label="Filter activity">
  <span class=note><b id=shown>{len(batches):,}</b> batches</span>
</div>

<p class=note id=empty hidden>Nothing in this window matches.</p>

<div id=feed>
{"".join(days)}
</div>

<footer>
<p>Indicators from <a href="https://github.com/stamparm/maltrail">Maltrail</a>;
attribution from <a href="https://attack.mitre.org/">MITRE ATT&amp;CK</a>.
Historical indicators: treat a hit as a lead to triage, not proof of compromise.</p>
<p>Rebuilt hourly &middot; <a href="{PROJECT_URL}">source</a></p>
</footer>
</main>
</div>
<script>{ACTIVITY_SCRIPT}</script>
</html>
"""
        (self.output_dir / "activity.html").write_text(html, encoding="utf-8", newline="\n")
        self._write_activity_feed(batches, metadata)

    def _write_activity_feed(self, batches: list[dict[str, Any]], metadata: FeedMetadata) -> None:
        """
        Write the activity page as Atom.

        A page you have to remember to visit is a page nobody visits twice.
        Analysts already live in feed readers and Slack RSS integrations, so
        this is the mechanism by which the project gets checked daily rather
        than found once.
        """
        generated = metadata.generated_at.isoformat()
        entries = []
        for batch in batches[:ATOM_ENTRIES]:
            label = ", ".join(f"{count:,} {kind}" for kind, count in batch["counts"].items())
            url = f"{SITE_URL}/by-group/{batch['slug']}.html#{batch['anchor']}"
            sources = "".join(
                f'&lt;li&gt;&lt;a href="{self._xml(url_)}"&gt;{self._xml(url_)}&lt;/a&gt;&lt;/li&gt;'
                for url_ in batch["references"]
            )
            body = f"&lt;p&gt;{self._xml(label)} first seen upstream on {batch['date']}.&lt;/p&gt;"
            if sources:
                body += f"&lt;p&gt;Source:&lt;/p&gt;&lt;ul&gt;{sources}&lt;/ul&gt;"

            entries.append(
                "<entry>\n"
                f"  <title>{self._xml(batch['group'])} &#183; {self._xml(label)}</title>\n"
                f'  <link href="{self._xml(url)}"/>\n'
                # A tag URI keyed on the stable anchor: a reader that has seen
                # this batch will not show it again after the next rebuild.
                f"  <id>tag:trilwu.github.io,2026:{self._xml(batch['slug'])}/{self._xml(batch['anchor'])}</id>\n"
                f"  <updated>{batch['date']}T00:00:00Z</updated>\n"
                f'  <content type="html">{body}</content>\n'
                "</entry>"
            )

        feed = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<feed xmlns="http://www.w3.org/2005/Atom">\n'
            "<title>APTtrail recent activity</title>\n"
            f"<subtitle>APT indicators as they appear upstream, attributed and dated</subtitle>\n"
            f'<link href="{SITE_URL}/activity.xml" rel="self"/>\n'
            f'<link href="{SITE_URL}/activity.html"/>\n'
            f"<id>tag:trilwu.github.io,2026:apttrail/activity</id>\n"
            f"<updated>{generated}</updated>\n"
            f"<author><name>APTtrail</name><uri>{PROJECT_URL}</uri></author>\n" + "\n".join(entries) + "\n</feed>\n"
        )
        (self.output_dir / "activity.xml").write_text(feed, encoding="utf-8", newline="\n")

    def _write_discovery(self, slugs: list[str], metadata: FeedMetadata) -> None:
        """
        Write sitemap.xml and robots.txt.

        314 actor pages that nothing points a crawler at are 314 pages nobody
        finds by searching for the actor's name.
        """
        day = metadata.generated_at.date().isoformat()
        urls = [f"{SITE_URL}/", f"{SITE_URL}/activity.html"]
        urls += [f"{SITE_URL}/by-group/{slug}.html" for slug in slugs]

        body = "\n".join(f"  <url><loc>{self._xml(url)}</loc><lastmod>{day}</lastmod></url>" for url in urls)
        (self.output_dir / "sitemap.xml").write_text(
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' + body + "\n</urlset>\n",
            encoding="utf-8",
            newline="\n",
        )
        (self.output_dir / "robots.txt").write_text(
            f"User-agent: *\nAllow: /\nSitemap: {SITE_URL}/sitemap.xml\n",
            encoding="utf-8",
            newline="\n",
        )

    @staticmethod
    def _xml(value: str) -> str:
        """Escape a value for XML text or an attribute."""
        return (
            str(value)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&apos;")
        )

    def _activity_row(self, row: dict[str, Any]) -> str:
        """One batch: which actor, how much, and what published it."""
        label = ", ".join(f"{count:,} {kind}" for kind, count in row["counts"].items())
        gid = f'<span class=gid>{self._esc(row["attack_id"])}</span>' if row["attack_id"] else ""
        target = f'by-group/{self._esc(row["slug"])}.html#{self._esc(row["anchor"])}'

        sources = "<span class=nosrc>no upstream reference</span>"
        if row["references"]:
            links = []
            for url in row["references"][:3]:
                host, path = split_url(url)
                links.append(
                    f'<a href="{self._esc(url)}" rel="noopener nofollow">'
                    f"<span class=host>{self._esc(host)}</span><span class=path>{self._esc(path)}</span></a>"
                )
            extra = len(row["references"]) - len(links)
            sources = " &middot; ".join(links) + (f" &middot; +{extra}" if extra > 0 else "")

        return (
            "<div class=event>"
            f'<a class=who href="{target}">{self._esc(row["group"])}</a> {gid}'
            f"<span class=cnt>{self._esc(label)}</span>"
            f"<div class=src>{sources}</div>"
            "</div>"
        )

    def _index_row(self, group: dict[str, Any]) -> str:
        """
        One group row.

        Two names matter and neither is the heading: the Maltrail group name,
        because that is what the feed's own files are keyed on, and whichever
        vendor alias the reader happens to be holding. Both are shown. The rest
        of the aliases go into a search key rather than on screen - APT28 has 24
        and a row of them would drown the table - so the filter still matches
        "fancy bear" even though the row does not print it.
        """
        slug = self._esc(group["slug"])
        heading = group["attack_name"] or ", ".join(group["maltrail_groups"])

        taken = {heading.lower()}
        sources = [n for n in group["maltrail_groups"] if n.lower() not in taken]
        taken.update(n.lower() for n in sources)
        aliases = [a for a in group["aliases"] if a.lower() not in taken]

        shown = sources + aliases[: self.VISIBLE_ALIASES]
        hidden = len(aliases) - len(aliases[: self.VISIBLE_ALIASES])
        also = ""
        if shown:
            body = " &middot; ".join(self._esc(name) for name in shown)
            if hidden:
                body += f" &middot; +{hidden}"
            also = f"<div class=aka>{body}</div>"

        # Every name this actor is known by, so the filter matches on any of
        # them without the table having to print them all.
        key = self._esc(" ".join([slug, group["attack_id"] or "", heading, *sources, *aliases]).lower())

        # "profile" as a separate link was redundant once the name itself opens
        # the page - and an accent-coloured G-id that was not clickable read as
        # a broken link.
        files = [f'<a href="by-group/{slug}.json">json</a>']
        if group["counts"].get("domain"):
            files.append(f'<a href="by-group/{slug}-domain.txt">domains</a>')

        span = group.get("first_seen_range") or {}
        latest = str(span.get("latest") or "")

        return (
            f'<tr data-k="{key}" data-attack="{1 if group["attack_id"] else 0}" data-latest="{self._esc(latest)}">'
            f'<td class=gid><a href="by-group/{slug}.html">'
            f'{self._esc(group["attack_id"]) if group["attack_id"] else "&mdash;"}</a></td>'
            f'<td><a class=who href="by-group/{slug}.html">{self._esc(heading)}</a>{also}</td>'
            f'<td class=n data-sort="{group["total"]}">{group["total"]:,}</td>'
            f'<td class=span data-sort="{latest.replace("-", "") or 0}">{self._span(group)}</td>'
            f'<td class=f>{" &middot; ".join(files)}</td>'
            "</tr>"
        )

    @staticmethod
    def _span(group: dict[str, Any]) -> str:
        """Render a group's first-seen span for the table."""
        span = group.get("first_seen_range")
        if not span:
            return "&ndash;"

        earliest, latest = str(span["earliest"])[:4], str(span["latest"])[:4]
        return earliest if earliest == latest else f"{earliest}&ndash;{latest}"

    @staticmethod
    def _esc(value: str) -> str:
        """Minimal HTML escaping for values that come from upstream data."""
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
