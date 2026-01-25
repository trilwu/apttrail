"""
Indicator classifier for determining IOC types.

Classifies indicators into categories like IP addresses, domains,
URLs, file hashes, etc.
"""

import ipaddress
import re
from typing import ClassVar

from apttrail.models import IndicatorType


class IndicatorClassifier:
    """
    Classifies threat indicators by their type.

    Supports classification of:
    - IPv4 and IPv6 addresses
    - Domain names
    - URLs
    - File hashes (MD5, SHA1, SHA256)
    - File paths

    Example:
        >>> classifier = IndicatorClassifier()
        >>> classifier.classify("192.168.1.1")
        IndicatorType.IPV4
        >>> classifier.classify("evil.com")
        IndicatorType.DOMAIN
    """

    # Regex patterns for classification
    MD5_PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE)
    SHA1_PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"^[a-f0-9]{40}$", re.IGNORECASE)
    SHA256_PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE)
    
    # Domain pattern: segments separated by dots, last segment (TLD) must not be all-numeric
    DOMAIN_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?::[0-9]+)?$"
    )

    URL_PREFIXES: ClassVar[tuple[str, ...]] = (
        "http://",
        "https://",
        "ftp://",
        "tcp://",
        "udp://",
    )

    def classify(self, indicator: str) -> IndicatorType:
        """
        Classify an indicator by its type.

        Args:
            indicator: The indicator value to classify

        Returns:
            IndicatorType enum value representing the classification
        """
        indicator = indicator.strip()

        if not indicator:
            return IndicatorType.UNKNOWN

        # Check for hashes first (most specific patterns)
        if self._is_hash(indicator):
            return self._classify_hash(indicator)

        # Check for IP addresses
        ip_type = self._classify_ip(indicator)
        if ip_type != IndicatorType.UNKNOWN:
            return ip_type

        # Check for URLs
        if self._is_url(indicator):
            return IndicatorType.URL

        # Check for file paths
        if self._is_file_path(indicator):
            return IndicatorType.FILE_PATH

        # Check for domains
        if self._is_domain(indicator):
            return IndicatorType.DOMAIN

        return IndicatorType.UNKNOWN

    def _is_hash(self, indicator: str) -> bool:
        """Check if indicator matches any hash pattern."""
        return (
            self.MD5_PATTERN.match(indicator) is not None
            or self.SHA1_PATTERN.match(indicator) is not None
            or self.SHA256_PATTERN.match(indicator) is not None
        )

    def _classify_hash(self, indicator: str) -> IndicatorType:
        """Classify a hash indicator by its length."""
        if self.MD5_PATTERN.match(indicator):
            return IndicatorType.MD5
        if self.SHA1_PATTERN.match(indicator):
            return IndicatorType.SHA1
        if self.SHA256_PATTERN.match(indicator):
            return IndicatorType.SHA256
        return IndicatorType.UNKNOWN

    def _classify_ip(self, indicator: str) -> IndicatorType:
        """Classify an IP address indicator."""
        # Try full string first (IPv6 or IPv4 without port)
        try:
            ip = ipaddress.ip_address(indicator)
            if isinstance(ip, ipaddress.IPv4Address):
                return IndicatorType.IPV4
            return IndicatorType.IPV6
        except ValueError:
            pass
            
        # Handle IPv4:port
        if "." in indicator and ":" in indicator:
            try:
                ip_part = indicator.split(":")[0]
                ip = ipaddress.ip_address(ip_part)
                if isinstance(ip, ipaddress.IPv4Address):
                    return IndicatorType.IPV4
            except ValueError:
                pass
                
        # Handle [IPv6]:port if standard format used
        if indicator.startswith("[") and "]" in indicator:
            try:
                ip_str = indicator.split("]")[0][1:]
                ip = ipaddress.ip_address(ip_str)
                return IndicatorType.IPV6
            except ValueError:
                pass
                
        return IndicatorType.UNKNOWN

    def _is_url(self, indicator: str) -> bool:
        """Check if indicator is a URL."""
        return indicator.startswith(self.URL_PREFIXES)

    def _is_file_path(self, indicator: str) -> bool:
        """Check if indicator looks like a file path."""
        has_path_separator = "/" in indicator or "\\" in indicator
        if not has_path_separator:
            return False

        # Check if the last component has a file extension
        last_component = indicator.split("/")[-1].split("\\")[-1]
        return "." in last_component

    def _is_domain(self, indicator: str) -> bool:
        """Check if indicator is a valid domain name."""
        if "." not in indicator:
            return False
            
        # TLD cannot be all numeric
        tld = indicator.split(".")[-1].split(":")[0]
        if tld.isdigit():
            return False
            
        return self.DOMAIN_PATTERN.match(indicator) is not None


# Convenience function for direct use
def classify_indicator(indicator: str) -> IndicatorType:
    """
    Classify an indicator by its type.

    Convenience function that creates a classifier instance.

    Args:
        indicator: The indicator value to classify

    Returns:
        IndicatorType enum value
    """
    return IndicatorClassifier().classify(indicator)
