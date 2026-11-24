"""FastAPI server implementing Defense-in-Depth Phishing URL detection without retraining."""

import csv
import io
import json
import os
from pathlib import Path

import joblib
import pandas as pd
from fastapi import FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from homograph_guard import analyze_url_homograph
from security_store import (
    SlidingWindowRateLimiter,
    SocAuthManager,
    ThreatCacheStore,
    canonicalize_url,
    compute_url_sha256,
)
from url_features import FEATURE_GROUPS, extract_url_features

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
MODEL_PATH = BASE_DIR / "phishing_url_model.pkl"
FEATURES_PATH = BASE_DIR / "model_features.json"
CACHE_DB_PATH = BASE_DIR / "threat_cache.db"

# Default demo key for presentation; override via SOC_ACCESS_KEY environment variable in production
SOC_ACCESS_KEY = os.environ.get("SOC_ACCESS_KEY", "SOC-NHOM6-2026")

# PhiUSIIL Legitimate baseline averages observed in notebook CELL 5/7
PHIUSIIL_LEGIT_BASELINE = {
    "url_length_mean": 27.23,
    "url_length_max": 58,
    "num_digits_mean": 0.05,
    "num_slashes_mean": 2.0,
    "num_hyphens_mean": 0.08,
}


class ModelEngine:
    """Wrapper around the pre-trained 27-feature Random Forest artifact."""

    def __init__(self):
        self.loaded = False
        self.model = None
        self.model_name = "Unavailable"
        self.feature_names: list[str] = []
        self.label_mapping: dict[int, str] = {0: "Phishing", 1: "Legitimate"}
        self.load_error: str | None = None
        self.reload()

    def reload(self) -> None:
        if not MODEL_PATH.exists():
            self.loaded = False
            self.load_error = (
                f"Chưa tìm thấy file model tại {MODEL_PATH.name}. "
                "Hãy chạy xong CELL 18 trên Colab và chép phishing_url_model.pkl + model_features.json vào thư mục dự án."
            )
            return

        try:
            artifact = joblib.load(MODEL_PATH)
            self.model = artifact["model"]
            self.model_name = artifact.get("model_name", "Random Forest")
            self.feature_names = list(artifact["feature_names"])
            self.label_mapping = {int(k): v for k, v in artifact.get("label_mapping", {0: "Phishing", 1: "Legitimate"}).items()}

            if FEATURES_PATH.exists():
                with FEATURES_PATH.open("r", encoding="utf-8") as f:
                    meta = json.load(f)
                if meta.get("feature_names") != self.feature_names:
                    raise ValueError("Thứ tự feature giữa .pkl và model_features.json không khớp.")

            self.loaded = True
            self.load_error = None
        except Exception as exc:
            self.loaded = False
            self.load_error = f"Không thể load model: {exc}"

    def predict(self, normalized_url: str) -> dict:
        if not self.loaded or self.model is None:
            raise HTTPException(status_code=503, detail=self.load_error or "Model chưa sẵn sàng.")

        features = extract_url_features(normalized_url)
        X_new = pd.DataFrame([features], columns=self.feature_names).astype("float32")

        phishing_prob = 0.0
        legit_prob = 0.0
        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(X_new)[0]
            classes = list(self.model.classes_)
            idx_phish = classes.index(0)
            idx_legit = classes.index(1)
            phishing_prob = float(probs[idx_phish])
            legit_prob = float(probs[idx_legit])
        else:
            pred = int(self.model.predict(X_new)[0])
            phishing_prob = 1.0 if pred == 0 else 0.0
            legit_prob = 1.0 - phishing_prob

        return {
            "model_name": self.model_name,
            "phishing_prob": phishing_prob,
            "legit_prob": legit_prob,
            "features": features,
        }


engine = ModelEngine()
cache_store = ThreatCacheStore(CACHE_DB_PATH)
rate_limiter = SlidingWindowRateLimiter(max_requests=40, window_seconds=60)
soc_auth = SocAuthManager(access_key=SOC_ACCESS_KEY, max_attempts=3, lockout_seconds=60)

app = FastAPI(title="URL Phishing Defense-in-Depth Inspector", version="1.0.0")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class ScanRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096)
    force_rescan: bool = False


class SocAuthRequest(BaseModel):
    access_key: str = Field(..., min_length=1, max_length=256)


class SocInspectRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096)
    threshold: float = Field(0.50, ge=0.05, le=0.95)
    force_rescan: bool = False


class SocBatchTextRequest(BaseModel):
    urls: list[str]
    threshold: float = Field(0.50, ge=0.05, le=0.95)


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "127.0.0.1"


def _require_soc(x_soc_token: str | None) -> None:
    if not soc_auth.validate_token(x_soc_token):
        raise HTTPException(
            status_code=401,
            detail="Chưa xác thực SOC Analyst hoặc phiên đăng nhập đã hết hạn.",
        )


def _build_findings(homograph: dict, features: dict, ml_prob: float, threshold: float) -> list[dict]:
    """Generate human-readable SOC findings (never exposed on public End-User API)."""
    findings: list[dict] = []

    if homograph["spoofed_brand"]:
        findings.append({
            "severity": "critical",
            "title": f"Giả mạo thương hiệu: {homograph['spoofed_brand']}",
            "detail": f"Skeleton tên miền '{homograph['skeleton_hostname']}' trùng với '{homograph['spoofed_brand']}' nhưng Punycode thật là '{homograph['punycode_hostname']}'.",
        })
    if homograph["is_mixed_script"]:
        findings.append({
            "severity": "critical",
            "title": "IDN Homograph Attack (Trộn bảng chữ cái)",
            "detail": f"Phát hiện trộn các bảng chữ cái {homograph['scripts']} trong cùng tên miền '{homograph['unicode_hostname']}'.",
        })
    elif homograph["has_greek"] or homograph["has_cyrillic"]:
        findings.append({
            "severity": "warning",
            "title": "Tên miền quốc tế Non-Latin (IDN)",
            "detail": f"Hostname dùng ký tự {', '.join(homograph['scripts'])} (Punycode: {homograph['punycode_hostname']}). Cần kiểm tra nguồn gốc.",
        })
    if homograph["has_zero_width"]:
        findings.append({
            "severity": "critical",
            "title": "Phát hiện ký tự tàng hình (Zero-Width)",
            "detail": "URL chứa ký tự điều khiển vô hình dùng để đánh lừa bộ lọc văn bản.",
        })

    if features["has_ip"]:
        findings.append({
            "severity": "critical",
            "title": "Dùng địa chỉ IP thay vì tên miền",
            "detail": "Trang hợp lệ hiếm khi yêu cầu người dùng truy cập trực tiếp qua IP.",
        })
    if not features["has_https"]:
        findings.append({
            "severity": "warning",
            "title": "Không sử dụng giao thức HTTPS",
            "detail": "Kết nối HTTP không được mã hóa TLS.",
        })
    if features["has_at"]:
        findings.append({
            "severity": "warning",
            "title": "Chứa ký tự '@' trong URL",
            "detail": "Kỹ thuật đánh lừa trình duyệt bỏ qua phần trước dấu '@' để chuyển hướng sang domain phía sau.",
        })
    if features["suspicious_word_count"] > 0:
        findings.append({
            "severity": "warning",
            "title": f"Chứa {int(features['suspicious_word_count'])} từ khóa nhạy cảm",
            "detail": "Xuất hiện các từ khóa đánh vào tâm lý như login, verify, secure, bank, account...",
        })
    if features["url_length"] > PHIUSIIL_LEGIT_BASELINE["url_length_max"]:
        findings.append({
            "severity": "info",
            "title": f"Độ dài URL ({int(features['url_length'])}) vượt ngưỡng tập sạch PhiUSIIL",
            "detail": (
                f"Trong dataset PhiUSIIL, lớp Legitimate có trung bình {PHIUSIIL_LEGIT_BASELINE['url_length_mean']} "
                f"và tối đa {PHIUSIIL_LEGIT_BASELINE['url_length_max']} ký tự (lưu ý Dataset Bias với link có path/query dài)."
            ),
        })
    if features["entropy"] >= 4.3:
        findings.append({
            "severity": "info",
            "title": f"Entropy chuỗi URL cao ({features['entropy']:.2f} bits)",
            "detail": "Mức độ ngẫu nhiên ký tự cao thường gặp ở chuỗi token/hash hoặc đường dẫn sinh tự động.",
        })

    if not findings and ml_prob < threshold:
        findings.append({
            "severity": "ok",
            "title": "Không phát hiện bất thường cấu trúc hay Unicode",
            "detail": "Tên miền thuần ASCII Latin và các chỉ số hình thái khớp với phân bố URL hợp lệ.",
        })
    return findings


def _fuse_verdict(homograph: dict, ml_prob: float, threshold: float) -> tuple[str, str, float, str, str]:
    """Combine Layer 1 (Homograph Guard) and Layer 2 (ML Random Forest) into a unified verdict."""
    # Layer 1 override on confirmed Homograph/Mixed-script/Brand spoofing
    if homograph["homograph_risk"] == "HIGH":
        fused_score = max(ml_prob, 0.96)
        return (
            "PHISHING",
            "HIGH",
            fused_score,
            "CẢNH BÁO NGUY HIỂM — PHÁT HIỆN GIẢ MẠO TÊN MIỀN",
            "Không truy cập hoặc nhập mật khẩu/OTP. Liên kết có dấu hiệu giả mạo ký tự quốc tế (Homograph) nhằm đánh lừa thị giác.",
        )

    if ml_prob >= max(threshold, 0.75):
        return (
            "PHISHING",
            "HIGH",
            ml_prob,
            "CẢNH BÁO NGUY HIỂM — NGHI VẤN PHISHING",
            "Không đăng nhập hoặc cung cấp thông tin cá nhân trên trang này. Hãy tự gõ lại địa chỉ chính thức vào trình duyệt.",
        )

    if ml_prob >= threshold or homograph["homograph_risk"] == "NOTICE":
        fused_score = max(ml_prob, 0.55 if homograph["homograph_risk"] == "NOTICE" else ml_prob)
        return (
            "SUSPICIOUS",
            "MEDIUM",
            fused_score,
            "THẬN TRỌNG — LIÊN KẾT CÓ DẤU HIỆU BẤT THƯỜNG",
            "Kiểm tra kỹ tên miền chính thức và chứng chỉ bảo mật trước khi tiếp tục thao tác.",
        )

    return (
        "SAFE",
        "LOW",
        ml_prob,
        "AN TOÀN — CHƯA PHÁT HIỆN DẤU HIỆU PHISHING",
        "Liên kết hợp lệ theo đánh giá hiện tại. Tuy nhiên vẫn luôn kiểm tra kỹ tên miền khi nhập mật khẩu.",
    )


def _run_full_pipeline(
    raw_url: str,
    threshold: float = 0.50,
    force_rescan: bool = False,
    include_details: bool = False,
) -> dict:
    homograph = analyze_url_homograph(raw_url)
    canonical = canonicalize_url(raw_url, homograph["punycode_hostname"])
    url_hash = compute_url_sha256(canonical)

    cached = None if force_rescan else cache_store.lookup(url_hash)
    use_cache_only = bool(cached and not include_details and abs(threshold - 0.50) < 1e-6)

    if use_cache_only:
        verdict = cached["verdict"]
        risk_level = cached["risk_level"]
        fused_score = cached["risk_score"]
        _, _, _, headline, advice = _fuse_verdict(homograph, cached["ml_phishing_prob"], threshold)
        return {
            "url_sha256": url_hash,
            "cache_hit": True,
            "hit_count": cached["hit_count"],
            "last_scanned": cached["last_seen"],
            "verdict": verdict,
            "risk_level": risk_level,
            "risk_score": fused_score,
            "headline": headline,
            "user_advice": advice,
            "homograph": homograph,
            "ml_res": None,
        }

    ml_res = engine.predict(homograph["normalized_url_for_ml"])
    ml_prob = ml_res["phishing_prob"]
    verdict, risk_level, fused_score, headline, advice = _fuse_verdict(homograph, ml_prob, threshold)

    if cached and abs(threshold - 0.50) < 1e-6:
        cache_hit = True
        hit_count = cached["hit_count"]
        last_scanned = cached["last_seen"]
    else:
        cache_hit = False
        saved = cache_store.upsert(
            url_hash=url_hash,
            masked_host=homograph["punycode_hostname"] or "(unknown)",
            verdict=verdict,
            risk_level=risk_level,
            risk_score=fused_score,
            homograph_risk=homograph["homograph_risk"],
            ml_phishing_prob=ml_prob,
        )
        hit_count = saved["hit_count"]
        last_scanned = saved["last_seen"]

    return {
        "url_sha256": url_hash,
        "cache_hit": cache_hit,
        "hit_count": hit_count,
        "last_scanned": last_scanned,
        "verdict": verdict,
        "risk_level": risk_level,
        "risk_score": fused_score,
        "headline": headline,
        "user_advice": advice,
        "homograph": homograph,
        "ml_res": ml_res,
    }


@app.get("/")
def serve_home():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health_check():
    return {
        "status": "ok",
        "model_loaded": engine.loaded,
        "model_name": engine.model_name,
        "feature_count": len(engine.feature_names),
        "model_error": engine.load_error,
    }


@app.post("/api/scan")
def public_scan(req: ScanRequest, request: Request):
    """Public End-User endpoint: strict anti-evasion output (no features, thresholds, or ML scores leaked)."""
    ip = _client_ip(request)
    allowed, remaining, retry_after = rate_limiter.check(ip)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Bạn thao tác quá nhanh (Anti-Probing Rate Limit). Vui lòng thử lại sau {retry_after}s.",
        )

    res = _run_full_pipeline(req.url, threshold=0.50, force_rescan=req.force_rescan)
    homograph = res["homograph"]

    # High-level IDN alert for user safety without exposing rule internals or ML weights
    idn_notice = None
    if homograph["homograph_risk"] == "HIGH":
        idn_notice = "Cảnh báo thị giác: Tên miền chứa ký tự quốc tế giả mạo giống chữ Latin."
    elif homograph["homograph_risk"] == "NOTICE":
        idn_notice = "Lưu ý: Đây là tên miền quốc tế (IDN / Punycode), hãy kiểm tra kỹ đúng trang web."

    return {
        "verdict": res["verdict"],
        "risk_level": res["risk_level"],
        "headline": res["headline"],
        "user_advice": res["user_advice"],
        "idn_notice": idn_notice,
        "url_sha256": res["url_sha256"],
        "cache_hit": res["cache_hit"],
        "hit_count": res["hit_count"],
        "last_scanned": res["last_scanned"],
        "rate_limit_remaining": remaining,
    }


@app.post("/api/soc/auth")
def soc_login(req: SocAuthRequest, request: Request):
    ip = _client_ip(request)
    ok, token, msg, attempts_left = soc_auth.authenticate(ip, req.access_key)
    if not ok:
        raise HTTPException(status_code=403, detail={"message": msg, "attempts_left": attempts_left})
    return {"authenticated": True, "token": token, "message": msg}


@app.post("/api/soc/logout")
def soc_logout(x_soc_token: str | None = Header(default=None)):
    soc_auth.revoke_token(x_soc_token)
    return {"authenticated": False}


@app.post("/api/soc/inspect")
def soc_inspect(req: SocInspectRequest, x_soc_token: str | None = Header(default=None)):
    """Protected SOC Analyst endpoint: exposes full X-Ray, ML probabilities, threshold & 27 features."""
    _require_soc(x_soc_token)
    res = _run_full_pipeline(
        req.url,
        threshold=req.threshold,
        force_rescan=req.force_rescan,
        include_details=True,
    )
    homograph = res["homograph"]
    ml_res = res["ml_res"]
    features = ml_res["features"]

    findings = _build_findings(homograph, features, ml_res["phishing_prob"], req.threshold)

    grouped_features = {
        group_name: [
            {"name": fname, "value": round(float(features[fname]), 4)}
            for fname in cols
        ]
        for group_name, cols in FEATURE_GROUPS.items()
    }

    return {
        "verdict": res["verdict"],
        "risk_level": res["risk_level"],
        "risk_score": round(res["risk_score"], 4),
        "headline": res["headline"],
        "url_sha256": res["url_sha256"],
        "cache_hit": res["cache_hit"],
        "hit_count": res["hit_count"],
        "last_scanned": res["last_scanned"],
        "layer1_homograph": {
            "homograph_risk": homograph["homograph_risk"],
            "raw_hostname": homograph["raw_hostname"],
            "unicode_hostname": homograph["unicode_hostname"],
            "punycode_hostname": homograph["punycode_hostname"],
            "skeleton_hostname": homograph["skeleton_hostname"],
            "spoofed_brand": homograph["spoofed_brand"],
            "scripts": homograph["scripts"],
            "is_mixed_script": homograph["is_mixed_script"],
            "has_greek": homograph["has_greek"],
            "has_cyrillic": homograph["has_cyrillic"],
            "has_zero_width": homograph["has_zero_width"],
            "suspicious_chars": homograph["suspicious_chars"],
            "char_xray": homograph["char_xray"],
        },
        "layer2_ml": {
            "model_name": ml_res["model_name"],
            "phishing_prob": round(ml_res["phishing_prob"], 4),
            "legit_prob": round(ml_res["legit_prob"], 4),
            "threshold": req.threshold,
            "ml_prediction": "PHISHING" if ml_res["phishing_prob"] >= req.threshold else "LEGITIMATE",
        },
        "url_anatomy": {
            "scheme": homograph["scheme"],
            "subdomain": homograph["subdomain"],
            "root_domain": homograph["root_domain"],
            "punycode": homograph["punycode_hostname"] or "(none)",
            "path": homograph["path"],
            "query": homograph["query"],
        },
        "eda_baseline": PHIUSIIL_LEGIT_BASELINE,
        "findings": findings,
        "features_grouped": grouped_features,
    }


@app.post("/api/soc/batch")
def soc_batch_urls(req: SocBatchTextRequest, x_soc_token: str | None = Header(default=None)):
    _require_soc(x_soc_token)
    cleaned = [u.strip() for u in req.urls if u and u.strip()][:200]
    if not cleaned:
        raise HTTPException(status_code=400, detail="Danh sách URL trống.")

    rows = []
    summary = {"SAFE": 0, "SUSPICIOUS": 0, "PHISHING": 0}
    for u in cleaned:
        res = _run_full_pipeline(u, threshold=req.threshold, force_rescan=False, include_details=True)
        summary[res["verdict"]] = summary.get(res["verdict"], 0) + 1
        rows.append({
            "url": u,
            "verdict": res["verdict"],
            "risk_score": round(res["risk_score"], 4),
            "ml_phishing_prob": round(res["ml_res"]["phishing_prob"], 4),
            "homograph_risk": res["homograph"]["homograph_risk"],
            "punycode": res["homograph"]["punycode_hostname"],
            "url_sha256": res["url_sha256"],
            "cache_hit": res["cache_hit"],
        })
    return {"total": len(rows), "summary": summary, "results": rows}


@app.post("/api/soc/batch-csv")
async def soc_batch_csv(
    file: UploadFile = File(...),
    threshold: float = 0.50,
    x_soc_token: str | None = Header(default=None),
):
    _require_soc(x_soc_token)
    raw_bytes = await file.read()
    text = raw_bytes.decode("utf-8-sig", errors="replace")
    reader = csv.reader(io.StringIO(text))
    urls: list[str] = []
    for row in reader:
        if not row:
            continue
        candidate = row[0].strip()
        if candidate.lower() in {"url", "urls", "link"} and not urls:
            continue
        if candidate:
            urls.append(candidate)
        if len(urls) >= 200:
            break

    if not urls:
        raise HTTPException(status_code=400, detail="Không đọc được URL nào từ cột đầu tiên của file CSV.")
    return soc_batch_urls(SocBatchTextRequest(urls=urls, threshold=threshold), x_soc_token=x_soc_token)


@app.get("/api/soc/logs")
def soc_threat_logs(limit: int = 30, x_soc_token: str | None = Header(default=None)):
    _require_soc(x_soc_token)
    return {"logs": cache_store.recent_logs(limit=min(limit, 100))}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
