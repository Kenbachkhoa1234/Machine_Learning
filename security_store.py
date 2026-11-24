"""SHA-256 URL Scan Database (VirusTotal-style Hash Lookup & History) and Rate Limiter."""

from contextlib import closing
import hashlib
import json
import re
import sqlite3
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

DEFAULT_TTL_SECONDS = 86400 * 7  # Keep saved scan records for 7 days
SHA256_HEX_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def is_sha256_query(text: str) -> bool:
    """Return True if user pasted a 64-hex SHA-256 identifier to look up."""
    return bool(SHA256_HEX_RE.match(text.strip()))


def canonicalize_url(raw_url: str, punycode_host: str = "") -> str:
    """Normalize scheme and hostname (to punycode) before SHA-256 hashing."""
    cleaned = str(raw_url).strip()
    parse_target = cleaned if "://" in cleaned else "https://" + cleaned
    try:
        parsed = urlsplit(parse_target)
        scheme = (parsed.scheme or "https").lower()
        host = (punycode_host or parsed.hostname or "").lower()
        try:
            port = f":{parsed.port}" if parsed.port else ""
        except ValueError:
            port = ""
        netloc = f"{host}{port}"
        path = parsed.path or "/"
        return urlunsplit((scheme, netloc, path, parsed.query, ""))
    except Exception:
        return cleaned


def mask_url_for_storage(raw_url: str, unicode_host: str, scheme: str, path: str, query: str) -> str:
    """Build privacy-safe display URL (redacts query values so tokens/passwords are never stored)."""
    if not unicode_host:
        return raw_url.split("?", 1)[0][:120]
    clean_path = "" if path in ("", "/") else path
    if query and query != "(none)":
        return f"{scheme}://{unicode_host}{clean_path}?[...]"
    return f"{scheme}://{unicode_host}{clean_path}"


def compute_url_sha256(canonical_url: str) -> str:
    """Compute SHA-256 identifier of canonicalized URL."""
    return hashlib.sha256(canonical_url.encode("utf-8")).hexdigest()


class ScanHistoryStore:
    """SQLite store for VirusTotal-style SHA-256 scan persistence, lookup, and history."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock, closing(self._connect()) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_records (
                    url_hash TEXT PRIMARY KEY,
                    target_display TEXT NOT NULL,
                    unicode_host TEXT NOT NULL,
                    punycode_host TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    reasons_json TEXT NOT NULL,
                    highlights_json TEXT NOT NULL,
                    internal_ml_prob REAL NOT NULL,
                    internal_homograph TEXT NOT NULL,
                    hit_count INTEGER NOT NULL DEFAULT 1,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    expires_at REAL NOT NULL
                )
                """
            )
            conn.commit()

    def _row_to_dict(self, row: sqlite3.Row) -> dict:
        d = dict(row)
        d["reasons"] = json.loads(d.pop("reasons_json", "[]"))
        d["char_highlights"] = json.loads(d.pop("highlights_json", "[]"))
        return d

    def get_by_hash(self, url_hash: str, increment_hit: bool = True) -> dict | None:
        """Look up saved report by SHA-256 hash."""
        h = url_hash.strip().lower()
        now_ts = time.time()
        now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._lock, closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT * FROM scan_records WHERE url_hash = ?",
                (h,),
            ).fetchone()
            if not row or row["expires_at"] <= now_ts:
                return None

            result = self._row_to_dict(row)
            if increment_hit:
                new_hits = int(row["hit_count"]) + 1
                conn.execute(
                    "UPDATE scan_records SET hit_count = ?, last_seen = ? WHERE url_hash = ?",
                    (new_hits, now_iso, h),
                )
                conn.commit()
                result["hit_count"] = new_hits
                result["last_seen"] = now_iso
            return result

    def save_record(
        self,
        url_hash: str,
        target_display: str,
        unicode_host: str,
        punycode_host: str,
        verdict: str,
        reasons: list[str],
        char_highlights: list[dict],
        internal_ml_prob: float,
        internal_homograph: str,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> dict:
        """Save or update a scan report without storing sensitive query tokens."""
        h = url_hash.strip().lower()
        now_ts = time.time()
        now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
        expires_at = now_ts + ttl_seconds
        reasons_str = json.dumps(reasons, ensure_ascii=False)
        highlights_str = json.dumps(char_highlights, ensure_ascii=False)

        with self._lock, closing(self._connect()) as conn:
            existing = conn.execute(
                "SELECT hit_count, first_seen FROM scan_records WHERE url_hash = ?",
                (h,),
            ).fetchone()
            if existing:
                hit_count = int(existing["hit_count"]) + 1
                first_seen = existing["first_seen"]
            else:
                hit_count = 1
                first_seen = now_iso

            conn.execute(
                """
                INSERT INTO scan_records (
                    url_hash, target_display, unicode_host, punycode_host,
                    verdict, reasons_json, highlights_json, internal_ml_prob, internal_homograph,
                    hit_count, first_seen, last_seen, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(url_hash) DO UPDATE SET
                    target_display = excluded.target_display,
                    unicode_host = excluded.unicode_host,
                    punycode_host = excluded.punycode_host,
                    verdict = excluded.verdict,
                    reasons_json = excluded.reasons_json,
                    highlights_json = excluded.highlights_json,
                    internal_ml_prob = excluded.internal_ml_prob,
                    internal_homograph = excluded.internal_homograph,
                    hit_count = ?,
                    last_seen = excluded.last_seen,
                    expires_at = excluded.expires_at
                """,
                (
                    h, target_display, unicode_host, punycode_host,
                    verdict, reasons_str, highlights_str, internal_ml_prob, internal_homograph,
                    hit_count, first_seen, now_iso, expires_at,
                    hit_count,
                ),
            )
            conn.commit()
            return {
                "url_hash": h,
                "target_display": target_display,
                "unicode_host": unicode_host,
                "punycode_host": punycode_host,
                "verdict": verdict,
                "reasons": reasons,
                "char_highlights": char_highlights,
                "internal_ml_prob": internal_ml_prob,
                "internal_homograph": internal_homograph,
                "hit_count": hit_count,
                "first_seen": first_seen,
                "last_seen": now_iso,
            }

    def list_recent(self, limit: int = 10) -> list[dict]:
        """Return recent saved scan summaries for the history panel."""
        now_ts = time.time()
        with self._lock, closing(self._connect()) as conn:
            rows = conn.execute(
                """
                SELECT url_hash, target_display, punycode_host, verdict, hit_count, first_seen, last_seen
                FROM scan_records
                WHERE expires_at > ?
                ORDER BY last_seen DESC
                LIMIT ?
                """,
                (now_ts, limit),
            ).fetchall()
            return [dict(r) for r in rows]


class SlidingWindowRateLimiter:
    """Silent per-IP rate limiter to prevent automated probing."""

    def __init__(self, max_requests: int = 35, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> bool:
        now = time.time()
        cutoff = now - self.window_seconds
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= cutoff:
                q.popleft()
            if len(q) >= self.max_requests:
                return False
            q.append(now)
            return True
