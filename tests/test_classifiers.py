import pytest

from apttrail.classifiers.indicator import IndicatorClassifier, IndicatorType


@pytest.fixture
def classifier():
    return IndicatorClassifier()


def test_ipv4_classification(classifier):
    assert classifier.classify("192.168.1.1") == IndicatorType.IPV4
    assert classifier.classify("10.0.0.1:8080") == IndicatorType.IPV4
    assert classifier.classify("256.0.0.1") == IndicatorType.UNKNOWN  # Invalid IP


def test_ipv6_classification(classifier):
    assert classifier.classify("2001:db8::1") == IndicatorType.IPV6
    assert classifier.classify("::1") == IndicatorType.IPV6


def test_domain_classification(classifier):
    assert classifier.classify("example.com") == IndicatorType.DOMAIN
    assert classifier.classify("sub.test.co.uk") == IndicatorType.DOMAIN
    assert classifier.classify("invalid-domain") == IndicatorType.UNKNOWN


def test_url_classification(classifier):
    assert classifier.classify("http://example.com/malware") == IndicatorType.URL
    assert classifier.classify("https://evil.site") == IndicatorType.URL
    assert classifier.classify("tcp://1.2.3.4:80") == IndicatorType.URL


def test_hash_classification(classifier):
    assert classifier.classify("d41d8cd98f00b204e9800998ecf8427e") == IndicatorType.MD5
    assert classifier.classify("da39a3ee5e6b4b0d3255bfef95601890afd80709") == IndicatorType.SHA1
    assert (
        classifier.classify("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == IndicatorType.SHA256
    )


def test_empty_input_is_unknown(classifier):
    assert classifier.classify("   ") == IndicatorType.UNKNOWN


class TestUriPaths:
    """Maltrail records bare request paths; they are not filesystem paths.

    Roughly 2,300 indicators in the live feed are of this shape, and every one
    of them used to be exported as a STIX [file:name = '/index.php'] pattern.
    """

    @pytest.mark.parametrize(
        "value",
        [
            "/AhmedMajdalani.php",
            "/enterprise/Senterprise.php",
            "/bbs/data/cjdc/proc.php",
            "/tmp/malware.exe",
        ],
    )
    def test_leading_slash_is_a_uri_path(self, classifier, value):
        assert classifier.classify(value) == IndicatorType.URL_PATH


class TestSchemelessUrls:
    """Maltrail also records host+path with no scheme."""

    @pytest.mark.parametrize(
        "value",
        [
            "artmuseums.or.kr/swfupload/fla/1.jpg",
            "daily.alltop.asia/blog/article/d2.php",
            "dailynk.com/wp-includes/js/jquery/jquery.min.js",
            "1.2.3.4/gate.php",
        ],
    )
    def test_host_and_path_is_a_url(self, classifier, value):
        assert classifier.classify(value) == IndicatorType.URL

    def test_bare_domain_is_still_a_domain(self, classifier):
        assert classifier.classify("dailynk.com") == IndicatorType.DOMAIN

    def test_non_host_prefix_is_not_a_url(self, classifier):
        assert classifier.classify("notahost/thing") == IndicatorType.UNKNOWN


class TestFilePaths:
    @pytest.mark.parametrize(
        "value",
        [
            "C:\\Windows\\System32\\evil.dll",
            "C:/Users/victim/AppData/evil.exe",
            "..\\..\\relative\\evil.dll",
        ],
    )
    def test_windows_paths(self, classifier, value):
        assert classifier.classify(value) == IndicatorType.FILE_PATH
