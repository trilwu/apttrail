from datetime import datetime, timezone
from pathlib import Path

from apttrail.utils.git import GitOperations

BLAME_PORCELAIN = """4c0b1e5a3f2d1c9b8a7f6e5d4c3b2a1908070605 1 1 1
author Someone
author-time 1772360000
author-tz +0000
summary add demo
filename trails/static/malware/apt_demo.txt
\tevil-demo.com
4c0b1e5a3f2d1c9b8a7f6e5d4c3b2a1908070605 2 2 1
author Someone
author-time 1772360000
author-tz +0000
filename trails/static/malware/apt_demo.txt
\t# Reference: https://example.com
"""

# Shape of `git log --format=%aI --name-only`: a date line, then the paths
# touched by that commit, newest commit first.
SAMPLE_LOG = """2026-07-25T13:23:55+02:00

trails/static/malware/apt_bluenoroff.txt
trails/static/malware/apt_oceanlotus.txt

2026-07-20T09:00:00+02:00

trails/static/malware/apt_bluenoroff.txt
trails/static/malware/apt_12.txt
"""


def test_parse_log_name_only_takes_most_recent_commit_per_file():
    times = GitOperations.parse_log_name_only(SAMPLE_LOG)

    assert times["trails/static/malware/apt_bluenoroff.txt"] == datetime.fromisoformat("2026-07-25T13:23:55+02:00")
    assert times["trails/static/malware/apt_oceanlotus.txt"] == datetime.fromisoformat("2026-07-25T13:23:55+02:00")
    assert times["trails/static/malware/apt_12.txt"] == datetime.fromisoformat("2026-07-20T09:00:00+02:00")


def test_parse_log_name_only_handles_empty_output():
    assert GitOperations.parse_log_name_only("") == {}


def test_parse_blame_porcelain_extracts_timestamp_and_commit():
    parsed = GitOperations.parse_blame_porcelain(BLAME_PORCELAIN)

    assert parsed["evil-demo.com"]["commit"] == "4c0b1e5a3f2d1c9b8a7f6e5d4c3b2a1908070605"
    assert parsed["evil-demo.com"]["first_seen"] == datetime.fromtimestamp(1772360000, tz=timezone.utc)


def test_parse_blame_porcelain_skips_comment_lines():
    parsed = GitOperations.parse_blame_porcelain(BLAME_PORCELAIN)

    assert all(not key.startswith("#") for key in parsed)


def test_get_file_last_commit_time_returns_none_outside_repo(tmp_path):
    # A wall-clock fallback here would make the exported feed churn every run.
    git_ops = GitOperations(tmp_path)
    assert git_ops.get_file_last_commit_time(Path("/elsewhere/apt_x.txt")) is None
