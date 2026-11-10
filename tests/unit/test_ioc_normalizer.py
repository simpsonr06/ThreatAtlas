
import pytest

from app.services.ioc_normalizer import (
    detect_ioc_type,
    normalize_domain,
    normalize_hash,
    normalize_ioc,
    normalize_ip,
    normalize_url,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("192.0.2.10", "192.0.2.10"),
        ("2001:db8::1", "2001:db8::1"),
        ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
    ],
)
def test_valid_ip_normalization(value, expected):
    assert normalize_ip(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "999.999.999.999",
        "not-an-ip",
        "",
        "192.0.2.999",
    ],
)
def test_invalid_ip_rejected(value):
    with pytest.raises(ValueError):
        normalize_ip(value)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("EXAMPLE.COM", "example.com"),
        ("Malicious.Example.COM.", "malicious.example.com"),
        ("example.com", "example.com"),
    ],
)
def test_valid_domain_normalization(value, expected):
    assert normalize_domain(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "localhost",
        "-example.com",
        "example-.com",
        "example..com",
        "invalid_domain.com",
    ],
)
def test_invalid_domain_rejected(value):
    with pytest.raises(ValueError):
        normalize_domain(value)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (
            "HTTPS://Example.com:443/login",
            "https://example.com/login",
        ),
        (
            "HTTP://Example.com:80/test",
            "http://example.com/test",
        ),
        (
            "https://EXAMPLE.com:8443/path",
            "https://example.com:8443/path",
        ),
        (
            "https://example.com/path?token=123",
            "https://example.com/path?token=123",
        ),
    ],
)
def test_valid_url_normalization(value, expected):
    assert normalize_url(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "ftp://example.com",
        "https://",
        "https://user:password@example.com",
        "https://example.com:99999",
        "https://example.com\\@evil.com",
    ],
)
def test_invalid_url_rejected(value):
    with pytest.raises(ValueError):
        normalize_url(value)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (
            "d41d8cd98f00b204e9800998ecf8427e",
            "d41d8cd98f00b204e9800998ecf8427e",
        ),
        (
            "A" * 32,
            "a" * 32,
        ),
        (
            "A" * 40,
            "a" * 40,
        ),
        (
            "A" * 64,
            "a" * 64,
        ),
    ],
)
def test_valid_hash_normalization(value, expected):
    assert normalize_hash(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "invalidhash",
        "g" * 32,
        "a" * 31,
        "a" * 33,
        "",
    ],
)
def test_invalid_hash_rejected(value):
    with pytest.raises(ValueError):
        normalize_hash(value)


def test_ioc_type_detection():
    assert detect_ioc_type("192.0.2.10") == "ip"
    assert detect_ioc_type("2001:db8::1") == "ip"
    assert detect_ioc_type("example.com") == "domain"
    assert detect_ioc_type("https://example.com") == "url"
    assert detect_ioc_type("a" * 64) == "file_hash"


def test_normalize_ioc_preserves_original_value():
    result = normalize_ioc("MALICIOUS.Example.COM.")

    assert result.original_value == "MALICIOUS.Example.COM."
    assert result.normalized_value == "malicious.example.com"
    assert result.ioc_type == "domain"


def test_explicit_ioc_type():
    result = normalize_ioc("192.0.2.10", ioc_type="ip")

    assert result.ioc_type == "ip"
    assert result.normalized_value == "192.0.2.10"


def test_type_mismatch_is_rejected():
    with pytest.raises(ValueError):
        normalize_ioc("not-an-ip", ioc_type="ip")


def test_unsupported_ioc_type_is_rejected():
    with pytest.raises(ValueError):
        normalize_ioc("example.com", ioc_type="unknown")


def test_non_string_ioc_is_rejected():
    with pytest.raises(TypeError):
        normalize_ioc(12345)
