
import pytest
from pathlib import Path
from datetime import datetime
from apttrail.models import Indicator, IndicatorType, APTGroup, APTGroupMetadata, FeedMetadata

@pytest.fixture
def sample_indicator():
    return Indicator(
        value="1.2.3.4",
        indicator_type=IndicatorType.IPV4,
        first_seen=datetime(2024, 1, 1),
        commit_hash="abc1234"
    )

@pytest.fixture
def sample_apt_group(sample_indicator):
    metadata = APTGroupMetadata(
        filename="apt_test.txt",
        aliases=["Test Group", "APT-Test"],
        references=["http://example.com"],
        last_modified=datetime(2024, 1, 1)
    )
    
    group = APTGroup(
        name="TEST",
        metadata=metadata
    )
    group.add_indicator(sample_indicator)
    group.add_indicator(Indicator(
        value="evil.com",
        indicator_type=IndicatorType.DOMAIN,
        first_seen=datetime(2024, 1, 1)
    ))
    return group

@pytest.fixture
def sample_metadata():
    return FeedMetadata(
        total_apt_groups=1,
        total_indicators=2,
        maltrail_commit="HEAD"
    )
