"""Two-way IDNA, Dangerous Scheme & Unicode Homograph Inspector for URLs."""

import ipaddress
import re
import unicodedata
from urllib.parse import urlsplit, urlunsplit

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

DANGEROUS_SCHEMES = ("javascript:", "data:", "vbscript:", "file:")
BENIGN_ANCHOR_RE = re.compile(r"^[A-Za-z0-9_\-]{1,24}$")

PROTECTED_BRANDS = {
    "google.com", "youtube.com", "gmail.com", "facebook.com", "instagram.com",
    "whatsapp.com", "paypal.com", "apple.com", "icloud.com", "microsoft.com",
    "office.com", "live.com", "amazon.com", "netflix.com", "github.com",
    "linkedin.com", "twitter.com", "x.com", "binance.com", "coinbase.com",
    "cloudflare.com", "discord.com", "telegram.org", "steampowered.com", "openai.com",
    "vietcombank.com.vn", "techcombank.com", "bidv.com.vn", "mbbank.com.vn",
    "acb.com.vn", "tpb.vn", "momo.vn", "zalopay.vn", "zalo.me", "shopee.vn",
    "tiki.vn", "lazada.vn",
}


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except (ValueError, TypeError):
        return False


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
        if (skeleton_host == brand or skeleton_host.endswith("." + brand)) and not (
            punycode_host == brand or punycode_host.endswith("." + brand)
        ):
            return brand
    return None


def analyze_url_homograph(url: str) -> dict:
    """Inspect URL hostname using 2-way IDNA decoding, scheme validation, and Unicode X-Ray."""
    raw = str(url).strip()
    raw_lower = raw.lower()

    # Check dangerous non-HTTP schemes (javascript:, data:, vbscript:, file:)
    if raw_lower.startswith(DANGEROUS_SCHEMES):
        scheme_used = raw_lower.split(":", 1)[0]
        return {
            "raw_hostname": "",
            "unicode_hostname": "",
            "punycode_hostname": f"({scheme_used}-uri)",
            "normalized_url_for_ml": raw,
            "scheme": scheme_used,
            "subdomain": "(none)",
            "root_domain": f"({scheme_used}: payload)",
            "path": raw[len(scheme_used) + 1 :][:120] or "/",
            "query": "(none)",
            "fragment": "(none)",
            "dangerous_scheme": scheme_used,
            "scripts": [],
            "mixed_labels": [],
            "has_greek": False,
            "has_cyrillic": False,
            "has_zero_width": any(c in ZERO_WIDTH_CHARS for c in raw),
            "has_non_ascii": any(ord(c) > 127 for c in raw),
            "is_punycode": False,
            "is_mixed_script": False,
            "skeleton_hostname": "",
            "spoofed_brand": None,
            "homograph_risk": "HIGH",
            "suspicious_chars": [],
            "char_xray": [],
        }

    has_explicit_scheme = "://" in raw
    parse_target = raw if has_explicit_scheme else "//" + raw

    try:
        parsed = urlsplit(parse_target)
        scheme = (parsed.scheme or "").lower()
        raw_hostname = (parsed.hostname or "").strip().lower()
        path = parsed.path or ""
        query = parsed.query or ""
        fragment = parsed.fragment or ""
        # Preserve userinfo@ if present (e.g. google.com@evil.xyz) and port if valid
        userinfo = ""
        if parsed.username:
            userinfo = parsed.username
            if parsed.password:
                userinfo += f":{parsed.password}"
            userinfo += "@"
        try:
            port_str = f":{parsed.port}" if parsed.port else ""
        except ValueError:
            port_str = ""
    except (ValueError, TypeError):
        scheme, raw_hostname, path, query, fragment, userinfo, port_str = "", "", "", "", "", "", ""

    # Default browser HTTPS-First scheme when user omits scheme on domain (HTTP for bare IP)
    if not scheme:
        scheme = "http" if _is_ip_literal(raw_hostname) else "https"

    # Strip zero-width characters before encoding to IDNA punycode, while still recording them in X-Ray
    clean_for_idna = "".join(c for c in raw_hostname if c not in ZERO_WIDTH_CHARS)
    punycode_host = clean_for_idna
    unicode_host = raw_hostname
    idna_error = False

    if clean_for_idna:
        if "xn--" in clean_for_idna:
            try:
                decoded = clean_for_idna.encode("ascii").decode("idna")
                unicode_host = decoded
                punycode_host = clean_for_idna
            except Exception:
                idna_error = True
        else:
            try:
                punycode_host = clean_for_idna.encode("idna").decode("ascii")
            except Exception:
                idna_error = True

    # Build normalized URL for ML matching PhiUSIIL canonical structure:
    # - lowercase scheme + punycode hostname (preserves userinfo@, port, IPv6 brackets)
    # - strip benign short client-side #anchor (keep long/obfuscated #payloads)
    # - strip browser-added trailing '/' on bare root domains (https://www.google.com/ -> https://www.google.com)
    if raw_hostname:
        host_netloc = f"[{punycode_host}]" if ":" in punycode_host else punycode_host
        netloc_for_ml = f"{userinfo}{host_netloc}{port_str}"
        kept_frag = "" if (not fragment or BENIGN_ANCHOR_RE.match(fragment)) else fragment
        ml_path = "" if (path == "/" and not query and not kept_frag) else path
        normalized_url = urlunsplit((scheme, netloc_for_ml, ml_path, query, kept_frag))
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

    if is_mixed_script or spoofed_brand or has_zero_width or idna_error:
        homograph_risk = "HIGH"
    elif has_non_ascii or is_punycode:
        homograph_risk = "NOTICE"
    else:
        homograph_risk = "NONE"

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
        "dangerous_scheme": None,
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
