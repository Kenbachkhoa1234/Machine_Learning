"""URL Security Checker with Safe User-Facing Reasons & VirusTotal-Style SHA-256 Persistence."""

from pathlib import Path

import joblib
import pandas as pd
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from homograph_guard import analyze_url_homograph
from security_store import (
    ScanHistoryStore,
    SlidingWindowRateLimiter,
    canonicalize_url,
    compute_url_sha256,
    is_sha256_query,
    mask_url_for_storage,
)
from url_features import extract_url_features

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
MODEL_PATH = BASE_DIR / "phishing_url_model.pkl"
CACHE_DB_PATH = BASE_DIR / "threat_cache.db"

DEFAULT_THRESHOLD = 0.50

SCRIPT_LABEL_VI = {
    "GREEK": "Hy Lạp (Greek)",
    "CYRILLIC": "Kirin (Cyrillic)",
    "LATIN": "Latin",
    "ZERO_WIDTH": "Ký tự ẩn (Zero-Width)",
}


class ModelEngine:
    """Internal ML model wrapper — model name, features & scores never exposed to clients."""

    def __init__(self):
        self.loaded = False
        self.model = None
        self.feature_names: list[str] = []
        self.reload()

    def reload(self) -> None:
        if not MODEL_PATH.exists():
            self.loaded = False
            return
        try:
            artifact = joblib.load(MODEL_PATH)
            self.model = artifact["model"]
            self.feature_names = list(artifact["feature_names"])
            self.loaded = True
        except Exception:
            self.loaded = False

    def analyze(self, normalized_url: str) -> tuple[float, dict]:
        if not self.loaded or self.model is None:
            raise RuntimeError("Service unavailable")

        features = extract_url_features(normalized_url)
        x_df = pd.DataFrame([features], columns=self.feature_names).astype("float32")

        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(x_df)[0]
            idx_phish = list(self.model.classes_).index(0)
            return float(probs[idx_phish]), features

        pred = int(self.model.predict(x_df)[0])
        return (1.0 if pred == 0 else 0.0), features


engine = ModelEngine()
history_store = ScanHistoryStore(CACHE_DB_PATH)
rate_limiter = SlidingWindowRateLimiter(max_requests=35, window_seconds=60)

# Disable Swagger /docs, /redoc, /openapi.json to prevent endpoint reconnaissance
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.exception_handler(RequestValidationError)
async def _opaque_validation_error(_request: Request, _exc: RequestValidationError):
    return JSONResponse(
        status_code=400,
        content={"error": "Vui lòng nhập địa chỉ URL hoặc mã băm SHA-256 hợp lệ."},
    )


class CheckRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096)
    reanalyze: bool = False

    @field_validator("url")
    @classmethod
    def _validate_input(cls, v: str) -> str:
        s = v.strip()
        if not s:
            raise ValueError("Empty input")
        if is_sha256_query(s):
            return s
        if "." not in s and ":" not in s:
            raise ValueError("Invalid URL")
        return s


def _build_safe_reasons(verdict: str, homograph: dict, features: dict) -> list[str]:
    """Generate clear, user-friendly reasons WITHOUT exposing model architecture, weights, or thresholds."""
    if verdict == "LEGITIMATE":
        reasons = [
            "Tên miền sử dụng bảng ký tự chuẩn, không phát hiện dấu hiệu giả mạo IDN / Punycode.",
            "Cấu trúc định danh và giao thức kết nối phù hợp với trang web hợp lệ.",
        ]
        return reasons

    reasons: list[str] = []

    if homograph.get("dangerous_scheme"):
        reasons.append(
            f"Sử dụng giao thức URI thực thi hoặc nhúng nội dung trực tiếp không an toàn ({homograph['dangerous_scheme']}:)."
        )

    if homograph["has_zero_width"]:
        reasons.append(
            "Phát hiện ký tự tàng hình (Zero-Width) chèn ẩn trong tên miền nhằm đánh lừa hiển thị."
        )

    if homograph["is_mixed_script"] or homograph["spoofed_brand"]:
        non_latin = [
            f"'{c['char']}' ({SCRIPT_LABEL_VI.get(c['script'], c['script'])})"
            for c in homograph["suspicious_chars"]
            if c["script"] != "ZERO_WIDTH"
        ]
        char_note = f": {', '.join(non_latin[:4])}" if non_latin else ""
        brand_note = f" nhằm giả mạo '{homograph['spoofed_brand']}'" if homograph["spoofed_brand"] else ""
        reasons.append(
            f"Giả mạo tên miền quốc tế (IDN Homograph){brand_note} — phát hiện ký tự đồng hình khác bảng mã{char_note} "
            f"(tên miền thực tế: {homograph['punycode_hostname']})."
        )
    elif homograph["is_punycode"] or homograph["has_non_ascii"]:
        reasons.append(
            f"Tên miền sử dụng mã hóa quốc tế IDN / Punycode ({homograph['punycode_hostname']}), cần đối chiếu kỹ địa chỉ gốc."
        )

    if features.get("has_ip"):
        reasons.append("Sử dụng trực tiếp địa chỉ IP thay vì tên miền định danh hợp lệ.")

    if features.get("has_at"):
        reasons.append("Đường dẫn chứa ký tự '@' có thể đánh lừa trình duyệt chuyển hướng sang máy chủ đích khác.")

    if features.get("has_double_slash_path"):
        reasons.append("Đường dẫn chứa cấu trúc chuyển hướng lồng nhau bất thường ('//').")

    if not features.get("has_https") and not homograph.get("dangerous_scheme"):
        reasons.append("Kết nối sử dụng giao thức HTTP không được mã hóa bảo mật.")

    if features.get("suspicious_word_count", 0) > 0:
        reasons.append("Đường dẫn chứa từ khóa nhạy cảm thường xuất hiện ở trang giả mạo đăng nhập / xác thực tài khoản.")

    if not reasons:
        reasons.append("Hình thái cấu trúc và độ phức tạp của đường dẫn mang đặc trưng của liên kết lừa đảo (Phishing).")

    return reasons[:4]


def _format_client_payload(record: dict, from_cache: bool) -> dict:
    is_phish = record["verdict"] == "PHISHING"
    return {
        "verdict": record["verdict"],
        "title": "Cảnh báo nguy hiểm (Phishing)" if is_phish else "Liên kết an toàn (Legitimate)",
        "advice": (
            "Liên kết có dấu hiệu không an toàn. Tuyệt đối không truy cập hoặc cung cấp mật khẩu, mã OTP."
            if is_phish
            else "Chưa ghi nhận dấu hiệu bất thường. Vẫn nên kiểm tra kỹ tên miền trước khi đăng nhập."
        ),
        "reasons": record["reasons"],
        "sha256": record["url_hash"],
        "target_display": record["target_display"],
        "unicode_host": record["unicode_host"],
        "punycode_host": record["punycode_host"],
        "char_highlights": record["char_highlights"],
        "from_cache": from_cache,
        "hit_count": record["hit_count"],
        "first_seen": record["first_seen"],
        "last_seen": record["last_seen"],
    }


def _evaluate_and_store(raw_input: str, reanalyze: bool = False) -> tuple[dict, bool, dict]:
    """Evaluate URL or look up SHA-256 hash; returns (record, from_cache, internal_debug)."""
    text = raw_input.strip()

    # Case 1: Direct VirusTotal-style 64-char SHA-256 hash lookup
    if is_sha256_query(text):
        found = history_store.get_by_hash(text, increment_hit=True)
        if not found:
            raise LookupError("Không tìm thấy bản ghi nào khớp với mã SHA-256 này trong cơ sở dữ liệu.")
        return found, True, {"ml_prob": found["internal_ml_prob"], "homograph_risk": found["internal_homograph"]}

    # Case 2: URL inspection
    homograph = analyze_url_homograph(text)
    canonical = canonicalize_url(text, homograph["punycode_hostname"])
    url_hash = compute_url_sha256(canonical)

    if not reanalyze:
        cached = history_store.get_by_hash(url_hash, increment_hit=True)
        if cached:
            return cached, True, {"ml_prob": cached["internal_ml_prob"], "homograph_risk": cached["internal_homograph"]}

    ml_prob, features = engine.analyze(homograph["normalized_url_for_ml"])
    is_phishing = (homograph["homograph_risk"] == "HIGH") or (ml_prob >= DEFAULT_THRESHOLD)
    verdict = "PHISHING" if is_phishing else "LEGITIMATE"

    reasons = _build_safe_reasons(verdict, homograph, features)
    char_highlights = [
        {"char": c["char"], "flagged": bool(c["flagged"])}
        for c in homograph["char_xray"]
    ]
    target_display = mask_url_for_storage(
        text,
        homograph["unicode_hostname"],
        homograph["scheme"],
        homograph["path"],
        homograph["query"],
    )

    saved = history_store.save_record(
        url_hash=url_hash,
        target_display=target_display,
        unicode_host=homograph["unicode_hostname"],
        punycode_host=homograph["punycode_hostname"],
        verdict=verdict,
        reasons=reasons,
        char_highlights=char_highlights,
        internal_ml_prob=ml_prob,
        internal_homograph=homograph["homograph_risk"],
    )
    return saved, False, {"ml_prob": ml_prob, "homograph_risk": homograph["homograph_risk"]}


@app.get("/")
def serve_home():
    return FileResponse(STATIC_DIR / "index.html")


@app.post("/api/check")
def check_url(req: CheckRequest, request: Request):
    ip = request.client.host if request.client else "127.0.0.1"
    if not rate_limiter.check(ip):
        return JSONResponse(
            status_code=429,
            content={"error": "Yêu cầu tạm thời bị giới hạn. Vui lòng thử lại sau ít phút."},
        )

    if not engine.loaded:
        return JSONResponse(
            status_code=503,
            content={"error": "Dịch vụ kiểm tra hiện chưa sẵn sàng."},
        )

    try:
        record, from_cache, _ = _evaluate_and_store(req.url, reanalyze=req.reanalyze)
    except LookupError as not_found_err:
        return JSONResponse(status_code=404, content={"error": str(not_found_err)})

    return _format_client_payload(record, from_cache=from_cache)


@app.get("/api/history")
def recent_history(request: Request):
    ip = request.client.host if request.client else "127.0.0.1"
    if not rate_limiter.check(ip):
        return JSONResponse(status_code=429, content={"items": []})
    return {"items": history_store.list_recent(limit=10)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000)
