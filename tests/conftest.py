import subprocess
from datetime import datetime

import pytest

from apttrail.models import APTGroup, APTGroupMetadata, FeedMetadata, Indicator, IndicatorType

FIRST_COMMIT_DATE = "2026-03-01T10:00:00+00:00"
SECOND_COMMIT_DATE = "2026-04-01T10:00:00+00:00"

APT_DEMO = """# Reference: https://example.com/report
# Aliases: demo-group, demoapt
keep.com
1.2.3.4
http://keep.com/payload.php
d41d8cd98f00b204e9800998ecf8427e
"""

APT_OTHER = "other.com\n"


@pytest.fixture
def sample_indicator():
    return Indicator(
        value="1.2.3.4", indicator_type=IndicatorType.IPV4, first_seen=datetime(2024, 1, 1), commit_hash="abc1234"
    )


@pytest.fixture
def sample_apt_group(sample_indicator):
    metadata = APTGroupMetadata(
        filename="apt_test.txt",
        aliases=["Test Group", "APT-Test"],
        references=["http://example.com"],
        last_modified=datetime(2024, 1, 1),
    )

    group = APTGroup(name="TEST", metadata=metadata)
    group.add_indicator(sample_indicator)
    group.add_indicator(
        Indicator(value="evil.com", indicator_type=IndicatorType.DOMAIN, first_seen=datetime(2024, 1, 1))
    )
    group.add_indicator(Indicator(value="d41d8cd98f00b204e9800998ecf8427e", indicator_type=IndicatorType.MD5))
    return group


@pytest.fixture
def sample_metadata():
    return FeedMetadata(total_apt_groups=1, total_indicators=2, maltrail_commit="HEAD")


def git(repo, *args, date=None):
    """Run a git command in `repo`, optionally pinning the commit date."""
    env = None
    if date:
        env = {"GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date}
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
        env={**subprocess_env(), **(env or {})},
    )


def subprocess_env():
    import os

    return dict(os.environ)


@pytest.fixture
def git_commit():
    """Commit everything in a repo at a fixed date. `tests/` is not a package,
    so helpers reach test modules as fixtures rather than imports."""

    def _commit(repo, message, date=SECOND_COMMIT_DATE):
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", message, date=date)

    return _commit


@pytest.fixture
def maltrail_repo(tmp_path):
    """
    A miniature stand-in for the Maltrail repository.

    Real git history is required: the collector reads commit times and runs
    `git blame` to derive first_seen, so mocking git away would leave the code
    paths that actually broke in production untested.
    """
    repo = tmp_path / "maltrail"
    malware = repo / "trails" / "static" / "malware"
    malware.mkdir(parents=True)

    git(repo.parent, "init", "-q", str(repo))
    git(repo, "config", "user.email", "test@example.com")
    git(repo, "config", "user.name", "Test")

    (malware / "apt_demo.txt").write_text(APT_DEMO, encoding="utf-8")
    (malware / "apt_other.txt").write_text(APT_OTHER, encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "initial trails", date=FIRST_COMMIT_DATE)

    return repo


@pytest.fixture
def collector_config(maltrail_repo, tmp_path):
    """Config wired to the fixture repo, writing everything under tmp_path."""
    from apttrail.models import CollectorConfig, FeedExportConfig

    return CollectorConfig(
        maltrail_path=str(maltrail_repo),
        auto_update=False,
        cache_dir=str(tmp_path / "cache"),
        export_config=FeedExportConfig(output_dir=str(tmp_path / "out")),
    )
