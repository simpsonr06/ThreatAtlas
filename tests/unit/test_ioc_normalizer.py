
import pytest

from app.services.ioc_normalizer import (
    detect_ioc_type,
    normalize_domain,
    normalize_hash,
    normalize_ip,
    normalize_ioc,
    normalize_url,
)


# ---------------------------------------------------------
# IP ADDRESS TESTS
# ---------------------------------------------------------

@pytest.mark.parametrize(
    "value, expected",
    [
        ("192.0.2.10", "192.0.2.10"),
        (" 192.0.2.10 ", "192.0.2.10"),
        ("2001:db8::1", "2001:db8::1"),
        ("2001:0db8:0000:0000:0000:0000:0000:0001",
         "2001:db8::1"),
    ],
)
def test_normalize_ip_valid(value, expected):
    assert normalize_ip(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "999.999.999.999",
        "192.0.2",
        "not-an-ip",
        "",
    ],
)
def test_normalize_ip_invalid(value):
    with pytest.raises(ValueError):
        normalize_ip(value)


# ---------------------------------------------------------
# DOMAIN TESTS
# ---------------------------------------------------------

def test_normalize_domain_lowercases():
    assert normalize_domain(
        "MALICIOUS.Example.COM"
    ) == "malicious.example.com"


def test_normalize_domain_removes_trailing_dot():
    assert normalize_domain(
        "malicious.example.com."
    ) == "malicious.example.com"


def test_normalize_domain_strips_whitespace():
    assert normalize_domain(
        " malicious.example.com "
    ) == "malicious.example.com"


def test_normalize_domain_supports_idna():
    result = normalize_domain("bücher.de")
    assert result == "xn--bcher-kva.de"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "localhost",
        ".example.com",
        "example..com",
        "-example.com",
        "example-.com",
        "example.com/path",
    ],
)
def test_normalize_domain_invalid(value):
    with pytest.raises(ValueError):
        normalize_domain(value)


# ---------------------------------------------------------
# FILE HASH TESTS
# ---------------------------------------------------------

@pytest.mark.parametrize(
    "length",
    [32, 40, 64],
)
def test_normalize_hash_supported_lengths(length):
    value = "A" * length

    assert normalize_hash(value) == "a" * length


@pytest.mark.parametrize(
    "value",
    [
        "abc",
        "G" * 32,
        "Z" * 64,
        "",
    ],
)
def test_normalize_hash_invalid(value):
    with pytest.raises(ValueError):
        normalize_hash(value)


# ---------------------------------------------------------
# URL TESTS
# ---------------------------------------------------------

def test_normalize_url_lowercases_scheme_and_hostname():
    result = normalize_url(
        "HTTPS://EXAMPLE.COM/login"
    )

    assert result == "https://example.com/login"


def test_normalize_url_removes_default_https_port():
    result = normalize_url(
        "https://example.com:443/login"
    )

    assert result == "https://example.com/login"


def test_normalize_url_removes_default_http_port():
    result = normalize_url(
        "http://example.com:80/login"
    )

    assert result == "http://example.com/login"


def test_normalize_url_preserves_path_query_and_fragment():
    result = normalize_url(
        "https://example.com/login?id=10#section"
    )

    assert result == (
        "https://example.com/login?id=10#section"
    )


def test_normalize_url_preserves_non_default_port():
    result = normalize_url(
        "https://example.com:8443/login"
    )

    assert result == "https://example.com:8443/login"


@pytest.mark.parametrize(
    "value",
    [
        "ftp://example.com",
        "javascript:alert(1)",
        "https:///missing-host",
        "https://user:password@example.com",
        "https://example.com:99999",
        r"https://example.com\bad",
        "",
    ],
)
def test_normalize_url_invalid(value):
    with pytest.raises(ValueError):
        normalize_url(value)


# ---------------------------------------------------------
# IOC TYPE DETECTION TESTS
# ---------------------------------------------------------

@pytest.mark.parametrize(
    "value, expected",
    [
        ("192.0.2.10", "ip"),
        ("2001:db8::1", "ip"),
        ("malicious.example.com", "domain"),
        ("https://example.com", "url"),
        ("A" * 32, "file_hash"),
        ("B" * 40, "file_hash"),
        ("C" * 64, "file_hash"),
    ],
)
def test_detect_ioc_type(value, expected):
    assert detect_ioc_type(value) == expected


# ---------------------------------------------------------
# UNIFIED NORMALIZATION TESTS
# ---------------------------------------------------------

def test_normalize_ioc_preserves_original_value():
    original = "MALICIOUS.Example.COM."

    result = normalize_ioc(original)

    assert result.original_value == original
    assert result.normalized_value == "malicious.example.com"
    assert result.ioc_type == "domain"


def test_normalize_ioc_explicit_type():
    result = normalize_ioc(
        "192.0.2.10",
        ioc_type="ip",
    )

    assert result.ioc_type == "ip"
    assert result.normalized_value == "192.0.2.10"


def test_normalize_ioc_rejects_invalid_explicit_type_value():
    with pytest.raises(ValueError):
        normalize_ioc(
            "not-an-ip",
            ioc_type="ip",
        )


def test_normalize_ioc_rejects_empty_value():
    with pytest.raises(ValueError):
        normalize_ioc("")


def test_normalize_ioc_rejects_non_string_value():
    with pytest.raises(TypeError):
        normalize_ioc(None)
