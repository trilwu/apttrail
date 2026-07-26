"""
Per-actor profile pages.

A responder who lands on an APT group wants what a vendor actor page gives
them: who the group is, where it is believed to operate from, who it targets,
which ATT&CK techniques it uses, and then the indicators - with the date each
one was first seen, and somewhere to read further.

Everything here is rendered from data the project already holds: the recovered
first_seen history, the ATT&CK attribution, and the vendored MISP galaxy
profiles.

Large groups are not rendered in full. GAMAREDON alone has over 50,000
indicators; a page listing them would be unusable and enormous. The page shows
the most recently seen ones - the part an analyst actually reads - and links to
the complete files.
"""

import html
from pathlib import Path
from typing import Any

from apttrail.models import IndicatorType
from apttrail.profiles import ActorProfile

#: Indicators rendered inline. Beyond this the page links to the full files.
MAX_ROWS = 300

PROJECT_URL = "https://github.com/trilwu/apttrail"
ATTACK_GROUP_URL = "https://attack.mitre.org/groups/{group_id}/"

# Only these get their own column of dated rows; hashes and paths are listed
# through the JSON file.
LISTED_TYPES = (
    IndicatorType.DOMAIN,
    IndicatorType.IPV4,
    IndicatorType.URL,
    IndicatorType.URL_PATH,
)

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
 .tags { display: flex; flex-wrap: wrap; gap: .3rem; padding: 0; list-style: none; }
 .tags li { border: 1px solid #8884; border-radius: 999px; padding: .05rem .55rem; font-size: .85em; }
 .note { opacity: .7; font-size: .9em; }
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


def _indicator_tables(slug: str, entry: dict[str, Any]) -> str:
    """
    Dated indicator tables, newest first.

    Newest-first because the question on an actor page is "what is current",
    and because for the biggest groups only the head of the list is rendered.
    """
    sections: list[str] = []

    for indicator_type in LISTED_TYPES:
        # value -> first_seen datetime (or None), straight off the merged entry.
        values: dict[str, Any] = entry["indicators"].get(indicator_type.value) or {}
        if not values:
            continue

        by_date = {value: seen.date().isoformat() for value, seen in values.items() if seen}
        # Undated indicators sort last but are still shown.
        ordered = sorted(values, key=lambda v: (by_date.get(v, ""), v), reverse=True)
        shown = ordered[:MAX_ROWS]

        rows = "\n".join(
            f'<tr><td class=date>{esc(by_date[value]) if value in by_date else "&mdash;"}</td>'
            f"<td class=val>{esc(value)}</td></tr>"
            for value in shown
        )

        truncated = ""
        if len(ordered) > MAX_ROWS:
            truncated = (
                f"<p class=note>Showing the {MAX_ROWS} most recent of {len(ordered):,}. "
                f'Full list: <a href="{esc(slug)}.json">{esc(slug)}.json</a>'
                + (
                    f' &middot; <a href="{esc(slug)}-domain.txt">{esc(slug)}-domain.txt</a>'
                    if indicator_type is IndicatorType.DOMAIN
                    else ""
                )
                + "</p>"
            )

        sections.append(
            f"<h2>{esc(indicator_type.value)} <span class=sub>({len(ordered):,})</span></h2>\n"
            f"{truncated}"
            f"<table><tr><th>First seen</th><th>Indicator</th></tr>\n{rows}\n</table>"
        )

    return "\n".join(sections)


def _references(entry: dict[str, Any], profile: ActorProfile | None) -> str:
    """Maltrail's per-group references plus ATT&CK's further reading."""
    seen: list[str] = []
    for url in list(entry.get("references") or []) + (profile.references if profile else []):
        if url not in seen:
            seen.append(url)

    if not seen:
        return ""

    items = "\n".join(f'<li><a href="{esc(url)}">{esc(url)}</a></li>' for url in seen)
    return f"<h2>References <span class=sub>({len(seen)})</span></h2>\n<ul>\n{items}\n</ul>"


def render(slug: str, entry: dict[str, Any], profile: ActorProfile | None, generated: str) -> str:
    """
    Render one actor page.

    Args:
        slug: File stem, an ATT&CK id where the group is mapped
        entry: Merged group entry from the slice exporter
        profile: Vendored actor profile, when ATT&CK tracks the group
        generated: Feed generation timestamp

    Returns:
        A complete HTML document
    """
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

{_indicator_tables(slug, entry)}

{_references(entry, profile)}

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
) -> Path:
    """Write one actor page and return its path."""
    path = directory / f"{slug}.html"
    path.write_text(render(slug, entry, profile, generated), encoding="utf-8", newline="\n")
    return path
