"""
Reading Maltrail trail files.

A trail file is not a flat list. Indicators are filed under the report they
came from:

    # Reference: https://vendor.example/apt28-write-up
    evil.example
    1.2.3.4

    # Reference: https://other.example/follow-up
    later.example

The comment applies to every indicator until the next reference block. That
association is the only per-indicator provenance upstream carries, and
collecting the URLs into one flat per-group list - which is all this project
did before - threw it away, leaving an analyst with 300 references at the
bottom of a page and no way to tell which one explains the domain in front of
them.
"""

from dataclasses import dataclass, field
from pathlib import Path

REFERENCE_MARKER = "Reference:"
ALIAS_MARKERS = ("Aliases:", "Alias:")


@dataclass
class ParsedTrail:
    """
    One parsed trail file.

    Attributes:
        indicators: Indicator line to the reference URLs that introduced it,
            in file order
        aliases: Alternative names declared in the file header
        references: Every reference URL in the file, deduplicated, in order
    """

    indicators: dict[str, list[str]] = field(default_factory=dict)
    aliases: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


def read_trail(filepath: Path) -> ParsedTrail:
    """
    Read a Maltrail trail file, keeping each indicator's source reference.

    Args:
        filepath: Path to an ``apt_*.txt`` file

    Returns:
        The indicators, their references, and the file's aliases
    """
    trail = ParsedTrail()
    # References accumulate while a comment block runs, then apply to every
    # indicator until the next block opens.
    pending: list[str] = []
    current: list[str] = []

    with open(filepath, encoding="utf-8", errors="ignore") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue

            if line.startswith("#"):
                _read_comment(line, trail, pending)
                continue

            if pending:
                current, pending = pending, []

            # The same value can appear under more than one report; keep every
            # source rather than letting the last write win.
            sources = trail.indicators.setdefault(line, [])
            for url in current:
                if url not in sources:
                    sources.append(url)

    return trail


def _read_comment(line: str, trail: ParsedTrail, pending: list[str]) -> None:
    """Pull references and aliases out of a comment line."""
    if REFERENCE_MARKER in line:
        url = line.split(REFERENCE_MARKER, 1)[1].strip()
        # Anything that is not a plain web link is a note, not a source, and
        # must never reach an href.
        if url.startswith(("http://", "https://")):
            pending.append(url)
            if url not in trail.references:
                trail.references.append(url)
        return

    for marker in ALIAS_MARKERS:
        if marker in line:
            names = line.split(":", 1)[1].strip()
            trail.aliases.extend(name.strip() for name in names.split(",") if name.strip())
            return
