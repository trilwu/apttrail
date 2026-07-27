"""
Per-actor profile pages.

A responder who lands on an APT group wants what a vendor actor page gives
them: who the group is, where it is believed to operate from, who it targets,
which ATT&CK techniques it uses, and then the indicators - with the date each
one was first seen, and somewhere to read further.

Everything here is rendered from data the project already holds: the recovered
first_seen history, the report each indicator was filed under upstream, the
ATT&CK attribution, and the vendored MISP galaxy profiles.

Indicators are shown as a timeline rather than a flat table. Upstream files them
in batches - a report lands, its indicators are added together - so the batch is
the unit that carries meaning: this date, this write-up, these domains. A flat
table with the references parked at the bottom of the page leaves the reader
unable to tell which of 300 references explains the row in front of them.

Large groups are not rendered in full. GAMAREDON alone has over 50,000
indicators; a page listing them would be unusable and enormous. The page shows
the most recent batches - the part an analyst actually reads - and links to the
complete files.
"""

import html
from pathlib import Path
from typing import Any

from apttrail.profiles import ActorProfile

#: Indicators rendered inline. Beyond this the page links to the full files.
MAX_ROWS = 300

#: Group-level references listed at the foot of the page.
MAX_REFERENCES = 40

PROJECT_URL = "https://github.com/trilwu/apttrail"
ATTACK_GROUP_URL = "https://attack.mitre.org/groups/{group_id}/"

STYLE = """
 :root { color-scheme: light dark; }
 body { font: 15px/1.6 ui-sans-serif, system-ui, sans-serif; max-width: 62rem;
        margin: 2rem auto; padding: 0 1rem; }
 a { color: inherit; }
 h1 { margin-bottom: .1rem; }
 h2 { margin-top: 2rem; border-bottom: 1px solid #8883; padding-bottom: .2rem; }
 .sub, .meta { opacity: .75; }
 .back { display: inline-block; margin-bottom: 1rem; }
 code, pre { font-family: ui-monospace, monospace; font-size: .9em; }
 pre { background: #8881; padding: .8rem; overflow-x: auto; border-radius: 6px; }
 dl.facts { display: grid; grid-template-columns: max-content 1fr; gap: .3rem 1rem; margin: 1rem 0; }
 dl.facts dt { opacity: .7; }
 dl.facts dd { margin: 0; }
 table { border-collapse: collapse; width: 100%; margin-top: .5rem; }
 th, td { text-align: left; padding: .25rem .6rem; border-bottom: 1px solid #8883;
          vertical-align: top; }
 td.date { white-space: nowrap; font-variant-numeric: tabular-nums; opacity: .8; }
 td.val { font-family: ui-monospace, monospace; word-break: break-all; }
 td.kind { white-space: nowrap; opacity: .6; font-size: .85em; width: 6rem; }
 .tags { display: flex; flex-wrap: wrap; gap: .3rem; padding: 0; list-style: none; }
 .tags li { border: 1px solid #8884; border-radius: 999px; padding: .05rem .55rem; font-size: .85em; }
 .note { opacity: .7; font-size: .9em; }
 ol.timeline { list-style: none; padding: 0; margin: 1.2rem 0 0; }
 ol.timeline > li { position: relative; padding: 0 0 1.8rem 1.3rem;
                    border-left: 2px solid #8883; }
 ol.timeline > li:last-child { border-left-color: transparent; }
 ol.timeline > li::before { content: ""; position: absolute; left: -.42rem; top: .45rem;
                            width: .68rem; height: .68rem; border-radius: 50%;
                            background: currentColor; opacity: .4; }
 .when { font-weight: 600; font-variant-numeric: tabular-nums; }
 .when .approx { font-weight: 400; opacity: .7; }
 .batch { opacity: .7; font-weight: 400; }
 .src { margin: .2rem 0 0; font-size: .93em; }
 .src .nosrc { opacity: .55; }
 table.iocs { margin-top: .4rem; }
 table.iocs td { border-bottom: 1px solid #8882; padding: .18rem .6rem .18rem 0; }
"""


def esc(value: Any) -> str:
    """Escape untrusted values for HTML."""
    return html.escape(str(value), quote=True)


def _facts(entry: dict[str, Any], profile: ActorProfile | None) -> str:
    """The at-a-glance block: origin, targeting, aliases, activity span."""
    rows: list[tuple[str, str]] = []

    if profile and profile.country:
        origin = esc(profile.country)
        if profile.sponsor:
            origin = f"{origin} &mdash; {esc(profile.sponsor)}"
        rows.append(("Suspected origin", origin))
    if profile and profile.activity:
        rows.append(("Activity", ", ".join(esc(a) for a in profile.activity)))
    if profile and profile.sectors:
        rows.append(("Targeted sectors", _tags(profile.sectors)))
    if profile and profile.victims:
        rows.append(("Suspected victims", _tags(profile.victims[:20])))

    span = entry.get("first_seen_range")
    if span:
        rows.append(("Indicators seen", f"{esc(span['earliest'])} &rarr; {esc(span['latest'])}"))

    aliases = entry.get("aliases") or []
    if aliases:
        rows.append(("Aliases", _tags(sorted(aliases)[:30])))

    maltrail = entry.get("maltrail_groups") or []
    if maltrail:
        rows.append(("Maltrail groups", ", ".join(esc(name) for name in maltrail)))

    if not rows:
        return ""

    body = "\n".join(f"<dt>{label}</dt><dd>{value}</dd>" for label, value in rows)
    return f"<dl class=facts>\n{body}\n</dl>"


def _tags(values: list[str]) -> str:
    return "<ul class=tags>" + "".join(f"<li>{esc(v)}</li>" for v in values) + "</ul>"


def _techniques(profile: ActorProfile | None) -> str:
    if not profile or not profile.techniques:
        return ""

    rows = "\n".join(
        f'<tr><td><a href="{esc(t.url)}">{esc(t.id)}</a></td><td>{esc(t.name)}</td></tr>' for t in profile.techniques
    )
    return (
        f"<h2>Techniques <span class=sub>({len(profile.techniques)} ATT&amp;CK)</span></h2>\n"
        f"<table><tr><th>ID</th><th>Technique</th></tr>\n{rows}\n</table>"
    )


def _software(profile: ActorProfile | None) -> str:
    if not profile or not profile.software:
        return ""

    return f"<h2>Software <span class=sub>({len(profile.software)})</span></h2>\n" + _tags(
        [s.name for s in profile.software]
    )


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


def _timeline(slug: str, batches: list[dict[str, Any]]) -> str:
    """
    Render the batches, newest first, within the row budget.

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
        items.append(_batch(batch, visible, len(pairs)))

    heading = f"<h2>Timeline <span class=sub>({total:,} indicators)</span></h2>"
    lead = (
        "<p class=note>Each entry is a batch of indicators that appeared upstream on that date, "
        "linked to the report it was filed under.</p>"
    )
    truncated = ""
    if shown < total:
        truncated = (
            f"<p class=note>Showing the {shown:,} most recent of {total:,}. "
            f'Full list: <a href="{esc(slug)}.json">{esc(slug)}.json</a>'
            f' &middot; <a href="{esc(slug)}-domain.txt">{esc(slug)}-domain.txt</a></p>'
        )

    return f"{heading}\n{lead}\n{truncated}\n<ol class=timeline>\n" + "\n".join(items) + "\n</ol>"


def _batch(batch: dict[str, Any], visible: list[tuple[str, str]], size: int) -> str:
    """Render one timeline entry: when, from where, and what."""
    date = batch["first_seen"]
    if not date:
        when = "<span class=approx>date unknown</span>"
    elif batch["precision"] == "at-or-before":
        # Upstream reset its history; these dates are a floor, not a sighting.
        when = (
            f'<time datetime="{esc(date)}">{esc(date)}</time> '
            '<span class=approx title="Upstream history does not reach further back; '
            'the indicator may be older">or earlier</span>'
        )
    else:
        when = f'<time datetime="{esc(date)}">{esc(date)}</time>'

    label = ", ".join(f"{count:,} {kind}" for kind, count in batch["counts"].items())
    # A per-row type column only earns its width when the batch mixes types;
    # otherwise the heading above has already said what these are.
    mixed = len(batch["counts"]) > 1
    rows = "\n".join(
        (f"<tr><td class=kind>{esc(kind)}</td>" if mixed else "<tr>") + f"<td class=val>{esc(value)}</td></tr>"
        for kind, value in visible
    )
    more = ""
    if len(visible) < size:
        more = f"<p class=note>&hellip; and {size - len(visible):,} more in this batch.</p>"

    return (
        "<li>\n"
        f'<div class=when>{when} <span class=batch>&middot; {esc(label)}</span></div>\n'
        f"<p class=src>{_sources(batch['references'])}</p>\n"
        f"<table class=iocs>\n{rows}\n</table>\n{more}</li>"
    )


def _sources(references: list[str]) -> str:
    """The report links that explain where a batch came from."""
    if not references:
        return "<span class=nosrc>No upstream reference for this batch</span>"

    links = " &middot; ".join(
        f'<a href="{esc(url)}" rel="noopener nofollow">{esc(_label(url))}</a>' for url in references
    )
    return f"Source: {links}"


def _label(url: str) -> str:
    """A readable link label: the URL without its scheme, shortened."""
    label = url.split("://", 1)[-1].rstrip("/")
    return label if len(label) <= 64 else label[:63] + "…"


def _files(slug: str, entry: dict[str, Any]) -> str:
    """Counts per type, and where to get the complete lists."""
    counts = {kind: len(values) for kind, values in sorted(entry["indicators"].items())}
    if not counts:
        return ""

    tags = _tags([f"{kind} {count:,}" for kind, count in counts.items()])
    links = [f'<a href="{esc(slug)}.json">{esc(slug)}.json</a>']
    if counts.get("domain"):
        links.append(f'<a href="{esc(slug)}-domain.txt">{esc(slug)}-domain.txt</a>')

    return f"<h2>Indicators</h2>\n{tags}\n<p class=note>Complete lists: " + " &middot; ".join(links) + "</p>"


def _references(slug: str, entry: dict[str, Any], profile: ActorProfile | None) -> str:
    """
    Group-level further reading.

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
    items = "\n".join(f'<li><a href="{esc(url)}" rel="noopener nofollow">{esc(url)}</a></li>' for url in shown)
    more = ""
    if len(seen) > len(shown):
        more = (
            f"<p class=note>{len(seen) - len(shown):,} more, and the report behind each indicator, "
            f'in <a href="{esc(slug)}.json">{esc(slug)}.json</a>.</p>'
        )

    return f"<h2>Further reading <span class=sub>({len(seen)})</span></h2>\n<ul>\n{items}\n</ul>\n{more}"


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

    attack_id = entry.get("attack_id")
    title = entry.get("attack_name") or ", ".join(entry.get("maltrail_groups") or [slug])
    total = sum(len(v) for v in entry["indicators"].values())

    heading = esc(title)
    if attack_id:
        heading += f' <a class=sub href="{esc(ATTACK_GROUP_URL.format(group_id=attack_id))}">{esc(attack_id)}</a>'

    description = (
        f"<p>{esc(profile.description)}</p>"
        if profile and profile.description
        else "<p class=note>No published description for this group.</p>"
    )

    return f"""<!doctype html>
<html lang=en>
<meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>{esc(title)} - APTtrail</title>
<style>{STYLE}</style>
<a class=back href="../index.html">&larr; All groups</a>
<h1>{heading}</h1>
<p class=sub>{total:,} indicators &middot; generated {esc(generated)}</p>

{description}

{_facts(entry, profile)}

<h2>Machine-readable</h2>
<pre>curl -sL {PROJECT_URL.replace("github.com/trilwu", "trilwu.github.io")}/by-group/{esc(slug)}.json</pre>

{_techniques(profile)}

{_software(profile)}

{_files(slug, entry)}

{_timeline(slug, timeline)}

{_references(slug, entry, profile)}

<p class=note>Indicators from <a href="https://github.com/stamparm/maltrail">Maltrail</a>;
actor profile from the <a href="https://github.com/MISP/misp-galaxy">MISP galaxy</a>
and <a href="https://attack.mitre.org/">MITRE ATT&amp;CK</a>.
Built by <a href="{PROJECT_URL}">APTtrail</a>.</p>
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
