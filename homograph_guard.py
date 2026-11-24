"""Two-way IDNA & Unicode Homograph Inspector for URLs (Greek, Cyrillic, mixed-script, brand spoofing)."""

import unicodedata
from urllib.parse import urlsplit

# High-frequency confusable characters (Greek, Cyrillic, Latin lookalikes) -> ASCII skeleton
CONFUSABLE_MAP = {
    # Greek lowercase & uppercase
    "\u03b1": "a", "\u0391": "a",  # alpha
    "\u03b2": "b", "\u0392": "b",  # beta
    "\u03b5": "e", "\u0395": "e",  # epsilon
    "\u03b6": "z", "\u0396": "z",  # zeta
    "\u03b7": "n", "\u0397": "h",  # eta
    "\u03b9": "i", "\u0399": "i",  # iota
    "\u03ba": "k", "\u039a": "k",  # kappa
    "\u03bc": "m", "\u039c": "m",  # mu
    "\u03bd": "v", "\u039d": "n",  # nu
    "\u03bf": "o", "\u039f": "o",  # omicron
    "\u03c1": "p", "\u03a1": "p",  # rho
    "\u03c2": "c", "\u03c3": "s",  # sigma
    "\u03c4": "t", "\u03a4": "t",  # tau
    "\u03c5": "u", "\u03a5": "y",  # upsilon
    "\u03c7": "x", "\u03a7": "x",  # chi
    # Cyrillic lowercase & uppercase
    "\u0430": "a", "\u0410": "a",  # а
    "\u0432": "b", "\u0412": "b",  # в
    "\u0435": "e", "\u0415": "e",  # е
    "\u0454": "e", "\u0404": "e",  # є
    "\u0456": "i", "\u0406": "i",  # і
    "\u0457": "i", "\u0407": "i",  # ї
    "\u0458": "j", "\u0408": "j",  # ј
    "\u043a": "k", "\u041a": "k",  # к
    "\u04cf": "l", "\u04c0": "l",  # palochka ӏ / Ӏ
    "\u043c": "m", "\u041c": "m",  # м
    "\u043d": "h", "\u041d": "h",  # н
    "\u043e": "o", "\u041e": "o",  # о
    "\u0440": "p", "\u0420": "p",  # р
    "\u0441": "c", "\u0421": "c",  # с
    "\u0442": "t", "\u0422": "t",  # т
    "\u0443": "y", "\u0423": "y",  # у
    "\u0445": "x", "\u0425": "x",  # х
    "\u0455": "s", "\u0405": "s",  # ѕ
    "\u04bb": "h", "\u04ba": "h",  # һ
    "\u0501": "d", "\u0500": "d",  # ԁ
    "\u051b": "q", "\u051a": "q",  # ԛ
    "\u051d": "w", "\u051c": "w",  # ԝ
    # Common Latin/Fullwidth lookalikes
    "\u0131": "i",  # dotless i ı
    "\u0261": "g",  # script g ɡ
    "\u1d04": "c",
}

ZERO_WIDTH_CHARS = {
    "\u200b", "\u200c", "\u200d", "\u200e", "\u200f", "\ufeff", "\u00ad", "\u2060"
}

PROTECTED_BRANDS = {
    "google.com", "youtube.com", "gmail.com", "facebook.com", "instagram.com",
    "whatsapp.com", "paypal.com", "apple.com", "icloud.com", "microsoft.com",
    "office.com", "live.com", "amazon.com", "netflix.com", "github.com",
    "linkedin.com", "twitter.com", "x.com", "binance.com", "coinbase.com",
    "vietcombank.com.vn", "techcombank.com", "bidv.com.vn", "mbbank.com.vn",
    "acb.com.vn", "tpb.vn", "momo.vn", "zalopay.vn", "zalo.me", "shopee.vn",
    "tiki.vn", "lazada.vn",
}


def _classify_char_script(ch: str) -> tuple[str, str]:
    """Return (script_group, unicode_name) for a single character."""
    if ch in ZERO_WIDTH_CHARS:
        return "ZERO_WIDTH", unicodedata.name(ch, "ZERO WIDTH CHAR")
    if ord(ch) <= 127:
        if ch.isalpha():
            return "LATIN", f"ASCII LATIN '{ch}'"
        return "ASCII_SYMBOL", "ASCII"
    name = unicodedata.name(ch, "UNKNOWN")
    first_word = name.split()[0] if name else "UNKNOWN"
    if first_word in {"GREEK", "CYRILLIC", "LATIN", "ARABIC", "HEBREW", "HAN", "HIRAGANA", "KATAKANA"}:
        return first_word, name
    return "OTHER_NON_ASCII", name


def _to_skeleton(hostname: str) -> str:
    """Fold confusable characters and diacritics into an ASCII Latin skeleton."""
    out = []
    for ch in hostname.lower():
        if ch in ZERO_WIDTH_CHARS:
            continue
        if ch in CONFUSABLE_MAP:
            out.append(CONFUSABLE_MAP[ch])
            continue
        decomposed = unicodedata.normalize("NFKD", ch)
        ascii_only = "".join(c for c in decomposed if ord(c) < 128)
        out.append(ascii_only if ascii_only else ch)
    return "".join(out)


def _match_protected_brand(skeleton_host: str, punycode_host: str) -> str | None:
    """Check whether a non-identical hostname impersonates a protected brand."""
    if not skeleton_host:
        return None
    for brand in PROTECTED_BRANDS:
        # Exact domain or subdomain of the spoofed skeleton (e.g. www.google.com)
        if (skeleton_host == brand or skeleton_host.endswith("." + brand)) and not (
            punycode_host == brand or punycode_host.endswith("." + brand)
        ):
            return brand
    return None


def analyze_url_homograph(url: str) -> dict:
    """Inspect URL hostname using 2-way IDNA decoding and Unicode script analysis."""
    raw = str(url).strip()
    parse_target = raw if "://" in raw else "//" + raw

    try:
        parsed = urlsplit(parse_target)
        scheme = (parsed.scheme or "").lower()
        raw_hostname = (parsed.hostname or "").strip().lower()
        path = parsed.path or ""
        query = parsed.query or ""
        fragment = parsed.fragment or ""
    except (ValueError, TypeError):
        scheme, raw_hostname, path, query, fragment = "", "", "", "", ""

    # 2-way IDNA: first encode to punycode if possible, and also decode xn-- back to Unicode
    punycode_host = raw_hostname
    unicode_host = raw_hostname
    idna_error = False

    if raw_hostname:
        if "xn--" in raw_hostname:
            try:
                unicode_host = raw_hostname.encode("ascii").decode("idna")
            except Exception:
                idna_error = True
        else:
            try:
                punycode_host = raw_hostname.encode("idna").decode("ascii")
            except Exception:
                idna_error = True

        # Ensure unicode_host reflects decoded form when input was punycode
        if "xn--" in punycode_host and unicode_host == raw_hostname and "xn--" in raw_hostname:
            try:
                unicode_host = punycode_host.encode("ascii").decode("idna")
            except Exception:
                idna_error = True

    # Build canonical URL with punycode hostname for consistent hashing & ML has_punycode detection
    if raw_hostname and punycode_host != raw_hostname and "://" in raw:
        normalized_url = raw.replace(raw_hostname, punycode_host, 1)
    else:
        normalized_url = raw

    # Per-character X-Ray across unicode_host
    char_xray = []
    suspicious_chars = []
    all_scripts = set()
    has_zero_width = False

    for idx, ch in enumerate(unicode_host):
        script, uname = _classify_char_script(ch)
        is_non_latin_risk = script in {"GREEK", "CYRILLIC", "ZERO_WIDTH", "OTHER_NON_ASCII"}
        if script == "ZERO_WIDTH":
            has_zero_width = True
        if script not in {"ASCII_SYMBOL"}:
            all_scripts.add(script)

        lookalike = CONFUSABLE_MAP.get(ch)
        if is_non_latin_risk or ord(ch) > 127:
            suspicious_chars.append({
                "index": idx,
                "char": ch,
                "codepoint": f"U+{ord(ch):04X}",
                "script": script,
                "unicode_name": uname,
                "lookalike_latin": lookalike,
            })

        char_xray.append({
            "char": ch,
            "codepoint": f"U+{ord(ch):04X}",
            "script": script,
            "unicode_name": uname,
            "lookalike_latin": lookalike,
            "flagged": is_non_latin_risk,
        })

    # Check mixed scripts at label level (e.g. "gοοgle" mixes LATIN + GREEK)
    mixed_labels = []
    for label in unicode_host.split("."):
        label_scripts = {
            _classify_char_script(c)[0]
            for c in label
            if _classify_char_script(c)[0] not in {"ASCII_SYMBOL"}
        }
        if len(label_scripts) > 1:
            mixed_labels.append({"label": label, "scripts": sorted(label_scripts)})

    has_greek = "GREEK" in all_scripts
    has_cyrillic = "CYRILLIC" in all_scripts
    is_mixed_script = len(mixed_labels) > 0 or (len(all_scripts - {"ASCII_SYMBOL"}) > 1)
    has_non_ascii = any(ord(c) > 127 for c in unicode_host)
    is_punycode = "xn--" in punycode_host

    skeleton_host = _to_skeleton(unicode_host)
    spoofed_brand = _match_protected_brand(skeleton_host, punycode_host)

    # Risk tiering:
    # HIGH: Mixed-script, Brand spoofing, Zero-width invisible chars, or Greek/Cyrillic impersonating Latin
    # NOTICE: Pure single non-Latin script IDN (e.g., valid Vietnamese/Russian IDN without mixing or brand spoofing)
    if is_mixed_script or spoofed_brand or has_zero_width or idna_error:
        homograph_risk = "HIGH"
    elif has_non_ascii or is_punycode:
        homograph_risk = "NOTICE"
    else:
        homograph_risk = "NONE"

    # Extract clean subdomain/root display
    parts = [p for p in unicode_host.split(".") if p]
    subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
    root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else unicode_host

    return {
        "raw_hostname": raw_hostname,
        "unicode_hostname": unicode_host,
        "punycode_hostname": punycode_host,
        "normalized_url_for_ml": normalized_url,
        "scheme": scheme or "(none)",
        "subdomain": subdomain or "(none)",
        "root_domain": root_domain or "(none)",
        "path": path or "/",
        "query": query or "(none)",
        "fragment": fragment or "(none)",
        "scripts": sorted(all_scripts),
        "mixed_labels": mixed_labels,
        "has_greek": has_greek,
        "has_cyrillic": has_cyrillic,
        "has_zero_width": has_zero_width,
        "has_non_ascii": has_non_ascii,
        "is_punycode": is_punycode,
        "is_mixed_script": is_mixed_script,
        "skeleton_hostname": skeleton_host,
        "spoofed_brand": spoofed_brand,
        "homograph_risk": homograph_risk,
        "suspicious_chars": suspicious_chars,
        "char_xray": char_xray,
    }
