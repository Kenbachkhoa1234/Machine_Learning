"""27 lexical URL features matching the trained PhiUSIIL Random Forest model."""

import ipaddress
import math
from collections import Counter
from urllib.parse import urlsplit
import numpy as np

SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "verification", "secure", "account",
    "update", "confirm", "password", "credential", "bank", "wallet",
    "payment", "invoice", "support", "auth", "recover", "security"
]

FEATURE_GROUPS = {
    "length": [
        "url_length",
        "hostname_length",
        "path_length",
        "query_length",
        "log_url_length",
    ],
    "structure": [
        "num_subdomains",
        "has_ip",
        "has_https",
        "has_at",
        "has_double_slash_path",
        "has_punycode",
        "suspicious_word_count",
        "entropy",
    ],
    "char_counts": [
        "num_dots",
        "num_hyphens",
        "num_underscores",
        "num_slashes",
        "num_at",
        "num_question",
        "num_equal",
        "num_ampersand",
        "num_percent",
        "num_digits",
        "num_letters",
        "num_special_chars",
        "digit_ratio",
        "letter_ratio",
    ],
}


def shannon_entropy(text: str) -> float:
    """Compute Shannon entropy (bits per character) of a string."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def is_ip_address(hostname: str) -> int:
    """Return 1 if hostname is a valid IPv4/IPv6 literal, else 0."""
    try:
        ipaddress.ip_address(hostname)
        return 1
    except (ValueError, TypeError):
        return 0


def extract_url_features(url: str) -> dict:
    """Extract the exact 27 lexical features expected by the trained model."""
    url = str(url)
    url_lower = url.lower()
    parse_target = url if "://" in url else "//" + url
    try:
        parsed = urlsplit(parse_target)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
    except (ValueError, TypeError):
        hostname = ""
        path = ""
        query = ""

    num_digits = sum(char.isdigit() for char in url)
    num_letters = sum(char.isalpha() for char in url)
    num_special_chars = sum(not char.isalnum() for char in url)
    domain_parts = hostname.split(".") if hostname else []
    num_subdomains = max(len(domain_parts) - 2, 0)
    suspicious_word_count = sum(word in url_lower for word in SUSPICIOUS_WORDS)

    return {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_underscores": url.count("_"),
        "num_slashes": url.count("/"),
        "num_at": url.count("@"),
        "num_question": url.count("?"),
        "num_equal": url.count("="),
        "num_ampersand": url.count("&"),
        "num_percent": url.count("%"),
        "num_digits": num_digits,
        "num_letters": num_letters,
        "num_special_chars": num_special_chars,
        "digit_ratio": num_digits / max(len(url), 1),
        "letter_ratio": num_letters / max(len(url), 1),
        "num_subdomains": num_subdomains,
        "has_ip": is_ip_address(hostname),
        "has_https": int(url_lower.startswith("https://")),
        "has_at": int("@" in url),
        "has_double_slash_path": int("//" in path),
        "has_punycode": int("xn--" in hostname.lower()),
        "suspicious_word_count": suspicious_word_count,
        "entropy": shannon_entropy(url),
        "log_url_length": float(np.log1p(len(url))),
    }
