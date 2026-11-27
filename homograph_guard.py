"""Hardened Two-Way IDNA, Homograph, eTLD+1 Typosquatting, Multi-Decode Open-Redirect & Domain Guard."""

import ipaddress
import posixpath
import re
import unicodedata
from urllib.parse import unquote, unquote_plus, urlsplit, urlunsplit

# High-frequency confusable characters (Greek, Cyrillic, IPA, Phonetic, Roman numerals) -> ASCII skeleton
CONFUSABLE_MAP = {
    # Greek lowercase & uppercase
    "\u03b1": "a", "\u0391": "a",
    "\u03b2": "b", "\u0392": "b",
    "\u03b5": "e", "\u0395": "e",
    "\u03b6": "z", "\u0396": "z",
    "\u03b7": "n", "\u0397": "h",
    "\u03b9": "i", "\u0399": "i",
    "\u03ba": "k", "\u039a": "k",
    "\u03bc": "m", "\u039c": "m",
    "\u03bd": "v", "\u039d": "n",
    "\u03bf": "o", "\u039f": "o",
    "\u03c1": "p", "\u03a1": "p",
    "\u03c2": "c", "\u03c3": "s",
    "\u03c4": "t", "\u03a4": "t",
    "\u03c5": "u", "\u03a5": "y",
    "\u03c7": "x", "\u03a7": "x",
    # Cyrillic lowercase & uppercase
    "\u0430": "a", "\u0410": "a",
    "\u0432": "b", "\u0412": "b",
    "\u0435": "e", "\u0415": "e",
    "\u0454": "e", "\u0404": "e",
    "\u0456": "i", "\u0406": "i",
    "\u0457": "i", "\u0407": "i",
    "\u0458": "j", "\u0408": "j",
    "\u043a": "k", "\u041a": "k",
    "\u04cf": "l", "\u04c0": "l",
    "\u043c": "m", "\u041c": "m",
    "\u043d": "h", "\u041d": "h",
    "\u043e": "o", "\u041e": "o",
    "\u0440": "p", "\u0420": "p",
    "\u0441": "c", "\u0421": "c",
    "\u0442": "t", "\u0422": "t",
    "\u0443": "y", "\u0423": "y",
    "\u0445": "x", "\u0425": "x",
    "\u0455": "s", "\u0405": "s",
    "\u04bb": "h", "\u04ba": "h",
    "\u0501": "d", "\u0500": "d",
    "\u051b": "q", "\u051a": "q",
    "\u051d": "w", "\u051c": "w",
    # IPA, Latin Extended & Roman Numeral lookalikes (UTS #39 vectors)
    "\u0251": "a",  # IPA ɑ
    "\u0261": "g",  # IPA ɡ
    "\u0131": "i",  # dotless ı
    "\u0269": "i",  # IPA ɩ
    "\u026a": "i",  # IPA ɪ
    "\u029f": "l",  # small cap ʟ
    "\u0274": "n",  # small cap ɴ
    "\u0280": "r",  # small cap ʀ
    "\u028f": "y",  # small cap ʏ
    "\u1d00": "a",
    "\u1d04": "c",
    "\u1d05": "d",
    "\u1d07": "e",
    "\u1d0f": "o",
    "\u1d18": "p",
    "\u1d1b": "t",
    "\u1d1c": "u",
    "\u1d20": "v",
    "\u1d21": "w",
    "\u1d22": "z",
    "\u217c": "l",  # Roman numeral fifty ⅼ
    "\u2160": "i",  # Roman numeral one Ⅰ
    "\u00df": "ss", # sharp s ß
}

ZERO_WIDTH_CHARS = {
    "\u200b", "\u200c", "\u200d", "\u200e", "\u200f", "\ufeff", "\u00ad", "\u2060"
}
ASCII_CTRL_WHITESPACE_RE = re.compile(r"[\x00-\x20]+")

DANGEROUS_SCHEMES = ("javascript:", "data:", "vbscript:", "file:")
BENIGN_ANCHOR_RE = re.compile(r"^[A-Za-z0-9_\-]{1,24}$")
OPEN_REDIRECT_RE = re.compile(
    r"(?:^|[?&])(?:url|redirect|redirect_uri|redirect_url|redir|next|continue|continueurl|return|returnurl|return_to|goto|dest|destination|target|out|view|uri|callback|q|u)=[\s+]*?(?:https?:|[\\/]{2})",
    re.IGNORECASE,
)
INJECTION_PATTERN_RE = re.compile(
    r"(?:<script|onerror\s*=|onload\s*=|javascript:|'\s*or\s*'1'\s*=\s*'1|union\s+select)",
    re.IGNORECASE,
)
INSTITUTIONAL_PHISH_PATH_RE = re.compile(
    r"(?:login|signin|verify|password|credential|wallet|bank|pay|update-account|webmail-auth)",
    re.IGNORECASE,
)
FILE_LIKE_TLDS = (".zip", ".mov")

MULTI_PART_PUBLIC_SUFFIXES = (
    ".com.vn", ".edu.vn", ".gov.vn", ".net.vn", ".org.vn", ".info.vn", ".ac.vn",
    ".co.uk", ".org.uk", ".ac.uk", ".gov.uk",
    ".com.au", ".gov.au", ".edu.au", ".com.br", ".co.jp", ".co.kr", ".com.sg",
)

PROTECTED_BRANDS = {
    "google.com", "youtube.com", "gmail.com", "facebook.com", "instagram.com",
    "whatsapp.com", "paypal.com", "apple.com", "icloud.com", "microsoft.com",
    "office.com", "live.com", "amazon.com", "netflix.com", "github.com",
    "linkedin.com", "twitter.com", "x.com", "binance.com", "coinbase.com",
    "cloudflare.com", "discord.com", "telegram.org", "steampowered.com", "openai.com",
    "kaggle.com", "canva.com", "wikipedia.org",
    "vietcombank.com.vn", "techcombank.com", "bidv.com.vn", "mbbank.com.vn",
    "acb.com.vn", "tpb.vn", "momo.vn", "zalopay.vn", "zalo.me", "shopee.vn",
    "tiki.vn", "lazada.vn",
}

# Shared user-content / serverless / raw-file hosts frequently abused for phishing — NEVER auto-trust!
SHARED_USER_CONTENT_HOSTS = (
    "github.io", "githubusercontent.com", "gist.github.com", "my.canva.site",
    "pages.dev", "workers.dev", "firebaseapp.com", "web.app", "appspot.com",
    "storage.googleapis.com", "storage.cloud.google.com",
    "blogspot.com", "sites.google.com", "forms.gle",
    "vercel.app", "netlify.app", "herokuapp.com", "onrender.com", "glitch.me",
    "repl.co", "replit.dev", "ngrok.io", "ngrok-free.app", "trycloudflare.com",
    "weebly.com", "wixsite.com", "yolasite.com", "pantheonsite.io",
    "000webhostapp.com", "duckdns.org", "servehttp.com", "emlnk.com", "sendgrid.net",
)

# Verified first-party domains eligible for deep-path bias calibration ONLY when all 10 anti-abuse gates pass
VERIFIED_OFFICIAL_DOMAINS = {
    "google.com", "youtube.com", "github.com", "microsoft.com", "office.com", "apple.com",
    "cloudflare.com", "wikipedia.org", "python.org", "scikit-learn.org", "pytorch.org",
    "kaggle.com", "canva.com", "openai.com", "linkedin.com", "stackoverflow.com", "mozilla.org", "ubuntu.com",
    "paypal.com", "amazon.com", "facebook.com", "instagram.com", "whatsapp.com", "netflix.com",
    "bbc.co.uk", "shopee.vn", "tiki.vn", "lazada.vn", "momo.vn", "zalopay.vn", "zalo.me",
    "vietcombank.com.vn", "bidv.com.vn", "mbbank.com.vn", "techcombank.com", "acb.com.vn", "tpb.vn",
}

VERIFIED_INSTITUTIONAL_SUFFIXES = (".edu.vn", ".gov.vn", ".ac.uk")
UNTRUSTED_PLATFORM_PATH_PREFIXES = (
    "/forms", "/url", "/amp", "/redirect", "/link-tracker",
    "/presentation/d/e", "/document/d/e", "/spreadsheets/d/e", "/uc",
)


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except (ValueError, TypeError):
        return False


def _extract_etld_plus_1(host: str) -> tuple[str, str]:
    """Return (sld_label, etld_plus_1) handling multi-part ccTLDs like .com.vn and .co.uk."""
    h = host.strip(".").lower()
    if not h or _is_ip_literal(h):
        return h, h
    for suf in MULTI_PART_PUBLIC_SUFFIXES:
        if h.endswith(suf):
            prefix = h[: -len(suf)].strip(".")
            if not prefix:
                return "", h
            sld = prefix.split(".")[-1]
            return sld, f"{sld}{suf}"
    parts = h.split(".")
    if len(parts) >= 2:
        return parts[-2], f"{parts[-2]}.{parts[-1]}"
    return h, h


_BRAND_SPECS: tuple[tuple[str, str, str, str], ...] = tuple(
    (b, _extract_etld_plus_1(b)[0], _extract_etld_plus_1(b)[1], "." + b)
    for b in PROTECTED_BRANDS
)


def _multi_unquote(text: str, rounds: int = 3) -> str:
    cur = text
    for _ in range(rounds):
        nxt = unquote_plus(cur)
        if nxt == cur:
            break
        cur = nxt
    return cur


def _classify_char_script(ch: str) -> tuple[str, str]:
    """Return (script_group, unicode_name) separating ASCII Latin from Extended/IPA Latin."""
    if ch in ZERO_WIDTH_CHARS:
        return "ZERO_WIDTH", unicodedata.name(ch, "ZERO WIDTH CHAR")
    cp = ord(ch)
    if cp <= 127:
        if ch.isalpha():
            return "LATIN", f"ASCII LATIN '{ch}'"
        return "ASCII_SYMBOL", "ASCII"
    name = unicodedata.name(ch, "UNKNOWN")
    if 0x0250 <= cp <= 0x02AF or 0x1D00 <= cp <= 0x1DBF:
        return "IPA_SPOOF", name
    first_word = name.split()[0] if name else "UNKNOWN"
    if first_word == "LATIN":
        return "LATIN_EXT", name
    if first_word in {"GREEK", "CYRILLIC", "ARABIC", "HEBREW", "HAN", "HIRAGANA", "KATAKANA"}:
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


def _damerau_levenshtein_1(a: str, b: str) -> bool:
    """Return True if strings a and b have Damerau-Levenshtein edit distance == 1."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diffs = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diffs) == 1:
            return True
        if len(diffs) == 2 and diffs[1] == diffs[0] + 1 and a[diffs[0]] == b[diffs[1]] and a[diffs[1]] == b[diffs[0]]:
            return True
        return False
    longer, shorter = (a, b) if len(a) > len(b) else (b, a)
    i = j = diffs = 0
    while i < len(longer) and j < len(shorter):
        if longer[i] != shorter[j]:
            diffs += 1
            if diffs > 1:
                return False
            i += 1
        else:
            i += 1
            j += 1
    return True


def _detect_ascii_typosquat(raw_case_host: str, punycode_host: str) -> tuple[str | None, str | None, set[int]]:
    """Detect ASCII homoglyphs (I->l, rn->m, vv->w, 0->o, 1->l) & 1-edit typosquat across ANY subdomain."""
    if not punycode_host or "xn--" in punycode_host or _is_ip_literal(punycode_host):
        return None, None, set()

    for brand, _, _, dot_brand in _BRAND_SPECS:
        if punycode_host == brand or punycode_host.endswith(dot_brand):
            return None, None, set()

    # Check mixed-case 'I' masquerading as 'l' in ANY label of raw_case_host (e.g. m.paypaI.com, paypaI.com)
    case_indices: set[int] = set()
    offset = 0
    for label in raw_case_host.split("."):
        if "I" in label and any(c.islower() for c in label):
            folded_label = label.replace("I", "l").lower()
            for brand, brand_sld, _, _ in _BRAND_SPECS:
                if folded_label == brand_sld:
                    for idx_in_lbl, ch in enumerate(label):
                        if ch == "I":
                            case_indices.add(offset + idx_in_lbl)
                    return brand, "Thay chữ 'l' thường bằng chữ 'I' hoa (ASCII Homoglyph)", case_indices
        offset += len(label) + 1

    # Extract eTLD+1 registrable domain (works for m.rnicrosoft.com, login.g00gle.com, etc.)
    sld, reg_domain = _extract_etld_plus_1(punycode_host)
    if not sld:
        return None, None, set()

    folded_sld = sld.replace("0", "o").replace("1", "l").replace("rn", "m").replace("vv", "w")
    if folded_sld != sld:
        for brand, brand_sld, brand_reg, _ in _BRAND_SPECS:
            if folded_sld == brand_sld:
                if reg_domain.endswith(brand_reg[len(brand_sld):]) or len(brand_sld) >= 5:
                    return brand, "Giả mạo thị giác bằng cụm ký tự ASCII tương tự (rn→m / 0→o / 1→l / vv→w)", set()

    for brand, brand_sld, _, _ in _BRAND_SPECS:
        if len(brand_sld) >= 4 and _damerau_levenshtein_1(reg_domain, brand):
            return brand, "Sai lệch 1 ký tự so với tên miền thương hiệu gốc (Typosquatting)", set()

    return None, None, set()


def _match_protected_brand(skeleton_host: str, punycode_host: str) -> str | None:
    """Check whether a non-identical hostname impersonates a protected brand across any subdomain."""
    if not skeleton_host:
        return None
    _, skel_reg = _extract_etld_plus_1(skeleton_host)
    _, puny_reg = _extract_etld_plus_1(punycode_host)
    for brand, _, _, dot_brand in _BRAND_SPECS:
        if (skeleton_host == brand or skeleton_host.endswith(dot_brand) or skel_reg == brand) and not (
            punycode_host == brand or punycode_host.endswith(dot_brand) or puny_reg == brand
        ):
            return brand
    return None


def _is_known_clean_domain(punycode_host: str) -> bool:
    if not punycode_host:
        return False
    if any(punycode_host == sh or punycode_host.endswith("." + sh) for sh in SHARED_USER_CONTENT_HOSTS):
        return False
    if any(punycode_host.endswith(suf) for suf in VERIFIED_INSTITUTIONAL_SUFFIXES):
        return True
    return any(punycode_host == od or punycode_host.endswith("." + od) for od in VERIFIED_OFFICIAL_DOMAINS)


def _check_verified_official_context(
    scheme: str,
    had_explicit_http: bool,
    port: int | None,
    punycode_host: str,
    path: str,
    raw_url: str,
    homograph_risk: str,
    has_backslash: bool,
    has_open_redirect: bool,
) -> bool:
    """Hardened 10-gate verification for official domains (blocks dot-segments, ports, UGC, compromised .edu)."""
    if scheme != "https" or had_explicit_http or homograph_risk != "NONE" or not punycode_host:
        return False
    if port not in (None, 443):
        return False
    if has_backslash or has_open_redirect:
        return False

    decoded_all = _multi_unquote(raw_url, rounds=2)
    if "@" in raw_url or "@" in decoded_all or "//" in path:
        return False
    if INJECTION_PATTERN_RE.search(decoded_all):
        return False

    for shared in SHARED_USER_CONTENT_HOSTS:
        if punycode_host == shared or punycode_host.endswith("." + shared):
            return False

    # Canonicalize dot-segments (/./forms -> /forms) and percent-encoding (/%66orms -> /forms)
    decoded_path = _multi_unquote(path or "/", rounds=2).replace("\\", "/")
    norm_path = posixpath.normpath(decoded_path).lower()
    if not norm_path.startswith("/"):
        norm_path = "/" + norm_path

    for prefix in UNTRUSTED_PLATFORM_PATH_PREFIXES:
        if norm_path == prefix or norm_path.startswith(prefix + "/"):
            return False

    # Compromised institutional subdomain or Canva design-slug phishing guard
    if any(punycode_host.endswith(suf) for suf in VERIFIED_INSTITUTIONAL_SUFFIXES):
        if INSTITUTIONAL_PHISH_PATH_RE.search(norm_path):
            return False
        return True

    if punycode_host == "canva.com" or punycode_host.endswith(".canva.com"):
        if INSTITUTIONAL_PHISH_PATH_RE.search(norm_path):
            return False

    for official in VERIFIED_OFFICIAL_DOMAINS:
        if punycode_host == official or punycode_host.endswith("." + official):
            return True
    return False


def analyze_url_homograph(url: str) -> dict:
    """Inspect URL hostname using 2-way IDNA, eTLD+1 typosquatting, multi-unquote redirect, and Unicode X-Ray."""
    raw = str(url).strip()
    # Strip ASCII control/whitespace before checking dangerous schemes (defeats 'java\tscript:')
    compact_lower = ASCII_CTRL_WHITESPACE_RE.sub("", raw).lower()

    if compact_lower.startswith(DANGEROUS_SCHEMES):
        scheme_used = compact_lower.split(":", 1)[0]
        return {
            "raw_hostname": "",
            "display_hostname": f"({scheme_used}: payload)",
            "unicode_hostname": "",
            "punycode_hostname": f"({scheme_used}-uri)",
            "normalized_url_for_ml": raw,
            "scheme": scheme_used,
            "subdomain": "(none)",
            "root_domain": f"({scheme_used}: payload)",
            "path": raw.split(":", 1)[-1][:120] or "/",
            "query": "(none)",
            "fragment": "(none)",
            "dangerous_scheme": scheme_used,
            "has_backslash_confusion": False,
            "has_open_redirect": False,
            "suspicious_file_tld": False,
            "verified_official_context": False,
            "case_spoof_indices": [],
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
            "typosquat_reason": None,
            "homograph_risk": "HIGH",
            "suspicious_chars": [],
            "char_xray": [],
        }

    authority_part = raw.split("?", 1)[0].split("#", 1)[0]
    if "://" in authority_part:
        authority_part = authority_part.split("://", 1)[1]
    authority_head = authority_part.split("/", 1)[0]
    has_backslash_confusion = "\\" in authority_head

    has_explicit_scheme = "://" in raw
    had_explicit_http = raw.lower().startswith("http://")
    parse_target = raw.replace("\\", "/") if has_backslash_confusion else raw
    parse_target = parse_target if "://" in parse_target else "//" + parse_target

    port_num: int | None = None
    invalid_port = False
    try:
        parsed = urlsplit(parse_target)
        scheme = (parsed.scheme or "").lower()
        raw_case_hostname = (parsed.netloc.split("@")[-1].split(":")[0] if parsed.netloc else "").strip("[] ")
        raw_hostname = (parsed.hostname or "").strip().lower()
        path = parsed.path or ""
        query = parsed.query or ""
        fragment = parsed.fragment or ""
        userinfo = ""
        if parsed.username:
            userinfo = parsed.username
            if parsed.password:
                userinfo += f":{parsed.password}"
            userinfo += "@"
        try:
            port_num = parsed.port
            port_str = f":{port_num}" if port_num else ""
        except ValueError:
            invalid_port = True
            port_str = ""
    except (ValueError, TypeError):
        scheme, raw_case_hostname, raw_hostname, path, query, fragment, userinfo, port_str = "", "", "", "", "", "", "", ""

    decoded_query = _multi_unquote(query, rounds=3) if query else ""
    has_open_redirect = bool(OPEN_REDIRECT_RE.search("?" + decoded_query)) if decoded_query else False
    suspicious_file_tld = raw_hostname.endswith(FILE_LIKE_TLDS)

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

    # Only default missing scheme to 'https' for known verified domains (prevents scheme-less phishing like www.seedjfly.top from escaping!)
    is_known_clean = _is_known_clean_domain(punycode_host)
    if not scheme:
        scheme = "https" if is_known_clean else "http"

    if raw_hostname:
        if not has_explicit_scheme and not is_known_clean:
            # Keep raw scheme-less string for ML so unknown domains like 'www.seedjfly.top' retain has_https=0
            normalized_url = raw
        else:
            host_netloc = f"[{punycode_host}]" if ":" in punycode_host else punycode_host
            netloc_for_ml = f"{userinfo}{host_netloc}{port_str}"
            kept_frag = "" if (not fragment or BENIGN_ANCHOR_RE.match(fragment)) else fragment
            ml_path = "" if (path == "/" and not query and not kept_frag and is_known_clean) else path
            normalized_url = urlunsplit((scheme, netloc_for_ml, ml_path, query, kept_frag))
    else:
        normalized_url = raw

    skeleton_host = _to_skeleton(unicode_host)
    spoofed_brand = _match_protected_brand(skeleton_host, punycode_host)
    typosquat_brand, typosquat_reason, case_spoof_indices = (None, None, set())
    if not spoofed_brand:
        typosquat_brand, typosquat_reason, case_spoof_indices = _detect_ascii_typosquat(raw_case_hostname, punycode_host)
        if typosquat_brand:
            spoofed_brand = typosquat_brand

    # Preserve raw case in display_hostname when mixed-case ASCII homoglyph (e.g. paypaI.com) is detected
    display_host = raw_case_hostname if case_spoof_indices else unicode_host

    char_xray = []
    suspicious_chars = []
    all_scripts = set()
    has_zero_width = False

    for idx, ch in enumerate(display_host):
        script, uname = _classify_char_script(ch)
        is_case_spoof = idx in case_spoof_indices
        is_non_latin_risk = (
            script in {"GREEK", "CYRILLIC", "ZERO_WIDTH", "IPA_SPOOF", "OTHER_NON_ASCII"}
            or is_case_spoof
            or (script == "LATIN_EXT" and bool(spoofed_brand))
        )
        if script == "ZERO_WIDTH":
            has_zero_width = True
        if script not in {"ASCII_SYMBOL"}:
            all_scripts.add(script)

        lookalike = "l" if is_case_spoof else CONFUSABLE_MAP.get(ch)
        if is_non_latin_risk or ord(ch) > 127:
            suspicious_chars.append({
                "index": idx,
                "char": ch,
                "codepoint": f"U+{ord(ch):04X}",
                "script": "ASCII_SPOOF" if is_case_spoof else script,
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
        # Flag mixing ASCII LATIN with GREEK/CYRILLIC/IPA/OTHER, or mixing LATIN_EXT on commercial ASCII TLDs (.com/.org/.net/.io)
        if len(label_scripts - {"LATIN_EXT"}) > 1 or (
            "LATIN_EXT" in label_scripts
            and "LATIN" in label_scripts
            and unicode_host.endswith((".com", ".org", ".net", ".io", ".co", ".app", ".dev"))
        ):
            mixed_labels.append({"label": label, "scripts": sorted(label_scripts)})

    # Highlight LATIN_EXT chars too if label was flagged as mixed-script on commercial TLD
    if mixed_labels:
        for c_item in char_xray:
            if c_item["script"] == "LATIN_EXT":
                c_item["flagged"] = True

    has_greek = "GREEK" in all_scripts
    has_cyrillic = "CYRILLIC" in all_scripts
    is_mixed_script = len(mixed_labels) > 0 or (len(all_scripts - {"ASCII_SYMBOL", "LATIN_EXT"}) > 1)
    has_non_ascii = any(ord(c) > 127 for c in unicode_host)
    is_punycode = "xn--" in punycode_host

    if (
        is_mixed_script
        or spoofed_brand
        or has_zero_width
        or idna_error
        or invalid_port
        or has_backslash_confusion
        or has_open_redirect
        or suspicious_file_tld
    ):
        homograph_risk = "HIGH"
    elif has_non_ascii or is_punycode:
        homograph_risk = "NOTICE"
    else:
        homograph_risk = "NONE"

    verified_official_context = _check_verified_official_context(
        scheme=scheme,
        had_explicit_http=had_explicit_http,
        port=port_num,
        punycode_host=punycode_host,
        path=path,
        raw_url=raw,
        homograph_risk=homograph_risk,
        has_backslash=has_backslash_confusion,
        has_open_redirect=has_open_redirect,
    )

    parts = [p for p in display_host.split(".") if p]
    subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
    root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else display_host

    return {
        "raw_hostname": raw_hostname,
        "display_hostname": display_host,
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
        "has_backslash_confusion": has_backslash_confusion,
        "has_open_redirect": has_open_redirect,
        "suspicious_file_tld": suspicious_file_tld,
        "verified_official_context": verified_official_context,
        "case_spoof_indices": sorted(case_spoof_indices),
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
        "typosquat_reason": typosquat_reason,
        "homograph_risk": homograph_risk,
        "suspicious_chars": suspicious_chars,
        "char_xray": char_xray,
    }
