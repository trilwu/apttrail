from apttrail.classifiers.indicator import IndicatorClassifier, IndicatorType


def test_ipv4_classification():
    classifier = IndicatorClassifier()
    assert classifier.classify("192.168.1.1") == IndicatorType.IPV4
    assert classifier.classify("10.0.0.1:8080") == IndicatorType.IPV4
    assert classifier.classify("256.0.0.1") == IndicatorType.UNKNOWN  # Invalid IP


def test_ipv6_classification():
    classifier = IndicatorClassifier()
    assert classifier.classify("2001:db8::1") == IndicatorType.IPV6
    assert classifier.classify("::1") == IndicatorType.IPV6


def test_domain_classification():
    classifier = IndicatorClassifier()
    assert classifier.classify("example.com") == IndicatorType.DOMAIN
    assert classifier.classify("sub.test.co.uk") == IndicatorType.DOMAIN
    assert classifier.classify("invalid-domain") == IndicatorType.UNKNOWN


def test_url_classification():
    classifier = IndicatorClassifier()
    assert classifier.classify("http://example.com/malware") == IndicatorType.URL
    assert classifier.classify("https://evil.site") == IndicatorType.URL
    assert classifier.classify("tcp://1.2.3.4:80") == IndicatorType.URL


def test_hash_classification():
    classifier = IndicatorClassifier()
    # MD5
    assert classifier.classify("d41d8cd98f00b204e9800998ecf8427e") == IndicatorType.MD5
    # SHA1
    assert classifier.classify("da39a3ee5e6b4b0d3255bfef95601890afd80709") == IndicatorType.SHA1
    # SHA256
    assert (
        classifier.classify("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == IndicatorType.SHA256
    )


def test_file_path_classification():
    classifier = IndicatorClassifier()
    assert classifier.classify("/tmp/malware.exe") == IndicatorType.FILE_PATH
    assert classifier.classify("C:\\Windows\\System32\\evil.dll") == IndicatorType.FILE_PATH
