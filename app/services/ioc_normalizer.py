
from dataclasses import dataclass
from ipaddress import ip_address
import re
from typing import Literal
from urllib.parse import urlsplit, urlunsplit


IOCType = Literal["ip", "domain", "url", "file_hash"]

SUPPORTED_HASH_LENGTHS = {
    32: "MD5",
    40: "SHA-1",
    64: "SHA-256",
}

HASH_PATTERN = re.compile(r"^[a-fA-F0-9]+$")


@dataclass(frozen=True)
class NormalizedIOC:
    original_value: str
    normalized_value: str
    ioc_type: IOCType


def normalize_domain(value: str) -> str:
    """Validate and normalize a domain name."""

    domain = value.strip().rstrip(".")

    if not domain:
        raise ValueError("Domain cannot be empty")

    if len(domain) > 253:
        raise ValueError("Domain exceeds maximum length")

    try:
        domain = domain.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Invalid internationalized domain") from exc

    labels = domain.split(".")

    if len(labels) < 2:
        raise ValueError("A public domain must contain at least two labels")

    for label in labels:
        if not label:
            raise ValueError("Domain contains an empty label")

        if len(label) > 63:
            raise ValueError("Domain label exceeds 63 characters")

        if label.startswith("-") or label.endswith("-"):
            raise ValueError("Domain labels cannot start or end with a hyphen")

        if not re.fullmatch(r"[a-z0-9-]+", label):
            raise ValueError("Domain contains invalid characters")

    return domain


def normalize_ip(value: str) -> str:
    """Validate and return canonical IPv4 or IPv6 representation."""

    try:
        return str(ip_address(value.strip()))
    except ValueError as exc:
        raise ValueError("Invalid IPv4 or IPv6 address") from exc


def normalize_hash(value: str) -> str:
    """Validate MD5, SHA-1 or SHA-256 file hashes."""

    digest = value.strip()

    if len(digest) not in SUPPORTED_HASH_LENGTHS:
        raise ValueError("Unsupported hash length")

    if not HASH_PATTERN.fullmatch(digest):
        raise ValueError("Hash must contain only hexadecimal characters")

    return digest.lower()


def normalize_url(value: str) -> str:
    """Normalize URL scheme and hostname without rewriting its path or query."""

    url = value.strip()

    if not url:
        raise ValueError("URL cannot be empty")

    if "\\" in url:
        raise ValueError("URL cannot contain backslashes")

    if any(ord(char) < 32 or ord(char) == 127 for char in url):
        raise ValueError("URL cannot contain control characters")

    try:
        parsed = urlsplit(url)

        scheme = parsed.scheme.lower()

        if scheme not in {"http", "https"}:
            raise ValueError("Only HTTP and HTTPS URLs are supported")

        if not parsed.netloc or not parsed.hostname:
            raise ValueError("URL must contain a valid hostname")

        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URLs containing credentials are not supported")

        hostname = parsed.hostname

        try:
            normalized_host = str(ip_address(hostname))
            is_ipv6 = ":" in normalized_host
        except ValueError:
            normalized_host = normalize_domain(hostname)
            is_ipv6 = False

        if is_ipv6:
            normalized_host = f"[{normalized_host}]"

        port = parsed.port

        if port is not None and not (1 <= port <= 65535):
            raise ValueError("Invalid URL port")

        if port is not None:
            if not (
                (scheme == "http" and port == 80)
                or (scheme == "https" and port == 443)
            ):
                normalized_host = f"{normalized_host}:{port}"

        return urlunsplit(
            (
                scheme,
                normalized_host,
                parsed.path,
                parsed.query,
                parsed.fragment,
            )
        )

    except ValueError as exc:
        raise ValueError(f"Invalid URL: {exc}") from exc


def detect_ioc_type(value: str) -> IOCType:
    """Infer the IOC type from its representation."""

    candidate = value.strip()

    if not candidate:
        raise ValueError("IOC value cannot be empty")

    try:
        ip_address(candidate)
        return "ip"
    except ValueError:
        pass

    if "://" in candidate:
        return "url"

    if (
        len(candidate) in SUPPORTED_HASH_LENGTHS
        and HASH_PATTERN.fullmatch(candidate)
    ):
        return "file_hash"

    return "domain"


def normalize_ioc(
    value: str,
    ioc_type: IOCType | None = None,
) -> NormalizedIOC:
    """
    Validate and normalize an IOC.

    If ioc_type is omitted, the type is inferred automatically.
    The original value is preserved separately from its normalized form.
    """

    if not isinstance(value, str):
        raise TypeError("IOC value must be a string")

    if not value.strip():
        raise ValueError("IOC value cannot be empty")

    detected_type = ioc_type or detect_ioc_type(value)

    normalizers = {
        "ip": normalize_ip,
        "domain": normalize_domain,
        "url": normalize_url,
        "file_hash": normalize_hash,
    }

    normalizer = normalizers.get(detected_type)

    if normalizer is None:
        raise ValueError(f"Unsupported IOC type: {detected_type}")

    normalized_value = normalizer(value)

    return NormalizedIOC(
        original_value=value,
        normalized_value=normalized_value,
        ioc_type=detected_type,
    )
