"""Server-side SHA-256 Threat Cache, Sliding-Window Rate Limiter, and SOC Auth Guard."""

from contextlib import closing
import hashlib
import hmac
import secrets
import sqlite3
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

DEFAULT_TTL_SECONDS = 86400  # 24 hours


def canonicalize_url(raw_url: str, punycode_host: str = "") -> str:
    """Normalize scheme and hostname (to punycode) before SHA-256 hashing."""
    cleaned = str(raw_url).strip()
    parse_target = cleaned if "://" in cleaned else "http://" + cleaned
    try:
        parsed = urlsplit(parse_target)
        scheme = (parsed.scheme or "http").lower()
        host = (punycode_host or parsed.hostname or "").lower()
        port = f":{parsed.port}" if parsed.port else ""
        netloc = f"{host}{port}"
        path = parsed.path or "/"
        return urlunsplit((scheme, netloc, path, parsed.query, ""))
    except Exception:
        return cleaned


def compute_url_sha256(canonical_url: str) -> str:
    """Compute VirusTotal-style SHA-256 identifier of canonicalized URL."""
    return hashlib.sha256(canonical_url.encode("utf-8")).hexdigest()


class ThreatCacheStore:
    """SQLite-backed SHA-256 threat intelligence cache and audit log."""

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
                CREATE TABLE IF NOT EXISTS threat_cache (
                    url_hash TEXT PRIMARY KEY,
                    masked_host TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    homograph_risk TEXT NOT NULL,
                    ml_phishing_prob REAL NOT NULL,
                    hit_count INTEGER NOT NULL DEFAULT 1,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    expires_at REAL NOT NULL
                )
                """
            )
            conn.commit()

    def lookup(self, url_hash: str) -> dict | None:
        """Return non-expired cache record and increment hit counter."""
        now_ts = time.time()
        now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._lock, closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT * FROM threat_cache WHERE url_hash = ?",
                (url_hash,),
            ).fetchone()
            if not row:
                return None
            if row["expires_at"] <= now_ts:
                return None
            new_hits = int(row["hit_count"]) + 1
            conn.execute(
                "UPDATE threat_cache SET hit_count = ?, last_seen = ? WHERE url_hash = ?",
                (new_hits, now_iso, url_hash),
            )
            conn.commit()
            result = dict(row)
            result["hit_count"] = new_hits
            result["last_seen"] = now_iso
            return result

    def upsert(
        self,
        url_hash: str,
        masked_host: str,
        verdict: str,
        risk_level: str,
        risk_score: float,
        homograph_risk: str,
        ml_phishing_prob: float,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> dict:
        """Insert or refresh a SHA-256 scan entry without storing sensitive query paths."""
        now_ts = time.time()
        now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
        expires_at = now_ts + ttl_seconds
        with self._lock, closing(self._connect()) as conn:
            existing = conn.execute(
                "SELECT hit_count, first_seen FROM threat_cache WHERE url_hash = ?",
                (url_hash,),
            ).fetchone()
            if existing:
                hit_count = int(existing["hit_count"]) + 1
                first_seen = existing["first_seen"]
            else:
                hit_count = 1
                first_seen = now_iso

            conn.execute(
                """
                INSERT INTO threat_cache (
                    url_hash, masked_host, verdict, risk_level, risk_score,
                    homograph_risk, ml_phishing_prob, hit_count, first_seen, last_seen, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(url_hash) DO UPDATE SET
                    masked_host = excluded.masked_host,
                    verdict = excluded.verdict,
                    risk_level = excluded.risk_level,
                    risk_score = excluded.risk_score,
                    homograph_risk = excluded.homograph_risk,
                    ml_phishing_prob = excluded.ml_phishing_prob,
                    hit_count = ?,
                    last_seen = excluded.last_seen,
                    expires_at = excluded.expires_at
                """,
                (
                    url_hash, masked_host, verdict, risk_level, risk_score,
                    homograph_risk, ml_phishing_prob, hit_count, first_seen, now_iso, expires_at,
                    hit_count,
                ),
            )
            conn.commit()
            return {
                "url_hash": url_hash,
                "masked_host": masked_host,
                "verdict": verdict,
                "risk_level": risk_level,
                "risk_score": risk_score,
                "homograph_risk": homograph_risk,
                "ml_phishing_prob": ml_phishing_prob,
                "hit_count": hit_count,
                "first_seen": first_seen,
                "last_seen": now_iso,
            }

    def recent_logs(self, limit: int = 30) -> list[dict]:
        """Return recent SHA-256 threat entries for SOC Analyst audit view."""
        with self._lock, closing(self._connect()) as conn:
            rows = conn.execute(
                """
                SELECT url_hash, masked_host, verdict, risk_level, risk_score,
                       homograph_risk, ml_phishing_prob, hit_count, first_seen, last_seen
                FROM threat_cache
                ORDER BY last_seen DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]


class SlidingWindowRateLimiter:
    """In-memory per-IP rate limiter to mitigate black-box model probing."""

    def __init__(self, max_requests: int = 30, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> tuple[bool, int, int]:
        """Return (allowed, remaining_quota, retry_after_seconds)."""
        now = time.time()
        cutoff = now - self.window_seconds
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= cutoff:
                q.popleft()
            if len(q) >= self.max_requests:
                retry_after = max(1, int(q[0] + self.window_seconds - now) + 1)
                return False, 0, retry_after
            q.append(now)
            remaining = max(0, self.max_requests - len(q))
            return True, remaining, 0


class SocAuthManager:
    """Server-side SOC key verification with 3-strike lockout and ephemeral session tokens."""

    def __init__(self, access_key: str, max_attempts: int = 3, lockout_seconds: int = 60):
        self.access_key = access_key
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_seconds
        self._failed: dict[str, int] = defaultdict(int)
        self._locked_until: dict[str, float] = {}
        self._sessions: dict[str, float] = {}
        self._lock = threading.Lock()

    def authenticate(self, client_ip: str, provided_key: str) -> tuple[bool, str | None, str, int]:
        """Verify SOC access key; return (ok, token, message, remaining_attempts)."""
        now = time.time()
        with self._lock:
            locked_until = self._locked_until.get(client_ip, 0.0)
            if locked_until > now:
                wait_sec = max(1, int(locked_until - now))
                return False, None, f"Tài khoản SOC tạm khóa do nhập sai nhiều lần. Thử lại sau {wait_sec}s.", 0

            if hmac.compare_digest(provided_key.strip(), self.access_key):
                self._failed.pop(client_ip, None)
                self._locked_until.pop(client_ip, None)
                token = secrets.token_urlsafe(32)
                self._sessions[token] = now + 7200  # 2h session
                return True, token, "Đã mở khóa chế độ SOC Analyst.", self.max_attempts

            self._failed[client_ip] += 1
            attempts_left = max(0, self.max_attempts - self._failed[client_ip])
            if attempts_left == 0:
                self._locked_until[client_ip] = now + self.lockout_seconds
                self._failed[client_ip] = 0
                return False, None, f"Nhập sai {self.max_attempts} lần! Đã khóa xác thực SOC trong {self.lockout_seconds}s.", 0
            return False, None, f"Sai mã SOC Access Key. Còn {attempts_left} lần thử.", attempts_left

    def validate_token(self, token: str | None) -> bool:
        """Check whether a server-issued SOC session token is active."""
        if not token:
            return False
        now = time.time()
        with self._lock:
            expiry = self._sessions.get(token)
            if not expiry:
                return False
            if expiry <= now:
                self._sessions.pop(token, None)
                return False
            return True

    def revoke_token(self, token: str | None) -> None:
        """Invalidate a SOC session token on logout."""
        if token:
            with self._lock:
                self._sessions.pop(token, None)
