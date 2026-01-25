"""
APTtrail - Automated APT Threat Feed Collector

A Python package for collecting and processing APT threat indicators
from the Maltrail repository.
"""

__version__ = "2.0.0"
__author__ = "trilwu"

from apttrail.collector import APTThreatFeedCollector
from apttrail.models import APTGroup, FeedMetadata, Indicator

__all__ = [
    "APTThreatFeedCollector",
    "Indicator",
    "APTGroup",
    "FeedMetadata",
    "__version__",
]
