"""Full QA, Edge-Case, Safe-Reasons & VirusTotal SHA-256 Persistence Test Suite."""

import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from fastapi.testclient import TestClient
import app as app_module

TEST_DB = ROOT_DIR / "tests" / "_qa_temp_cache.db"
if TEST_DB.exists():
    TEST_DB.unlink()
app_module.history_store = app_module.ScanHistoryStore(TEST_DB)

client = TestClient(app_module.app)


URL_TEST_CASES = [
    # --- Nhóm 1: URL hợp lệ chuẩn & biến thể nhập liệu thực tế ---
    ("TC-L01", "Legitimate", "Root HTTPS chuẩn (Google)", "https://www.google.com", {"LEGITIMATE"}),
    ("TC-L02", "Legitimate", "Cloudflare chính chủ HTTPS", "https://www.cloudflare.com/", {"LEGITIMATE"}),
    ("TC-L03", "Legitimate", "Ngân hàng VN HTTPS root", "https://www.vietcombank.com.vn", {"LEGITIMATE"}),
    ("TC-L04", "Legitimate", "Domain đại học có dấu gạch ngang", "https://www.uni-mainz.de", {"LEGITIMATE"}),
    ("TC-L05", "Legitimate-Edge", "Thiếu scheme https:// (gõ tắt www.microsoft.com)", "www.microsoft.com", {"LEGITIMATE"}),
    ("TC-L06", "Legitimate-Edge", "Chữ in hoa toàn bộ + dấu / cuối", "HTTPS://WWW.GITHUB.COM/", {"LEGITIMATE"}),
    ("TC-L07", "Legitimate-Edge", "URL hợp lệ có anchor #fragment", "https://www.wikipedia.org/#top", {"LEGITIMATE"}),
    ("TC-L08", "Legitimate-Edge", "Domain .co.uk hợp lệ", "https://www.voicefmradio.co.uk", {"LEGITIMATE"}),

    # --- Nhóm 2: Đo lường giới hạn dữ liệu PhiUSIIL (Dataset Bias) ---
    ("TC-B01", "Dataset-Bias", "Link GitHub repo hợp lệ có path sâu", "https://github.com/scikit-learn/scikit-learn", {"PHISHING", "LEGITIMATE"}),
    ("TC-B02", "Dataset-Bias", "Link bài báo hợp lệ có số & .html", "https://vnexpress.net/ai-bao-mat-2026-4819203.html", {"PHISHING", "LEGITIMATE"}),
    ("TC-B03", "Dataset-Bias", "Link Google Search có query ?q=&hl=", "https://www.google.com/search?q=machine+learning&hl=vi", {"PHISHING", "LEGITIMATE"}),

    # --- Nhóm 3: Phishing cổ điển & kỹ thuật che giấu lexical ---
    ("TC-P01", "Phishing-Lexical", "IPv4 trực tiếp + login/verify", "http://192.168.1.1/secure-login/verify-account.php?id=9981", {"PHISHING"}),
    ("TC-P02", "Phishing-Lexical", "Public IPv4 + PHP script", "http://91.239.125.28/postchs/sms.php", {"PHISHING"}),
    ("TC-P03", "Phishing-Lexical", "Kỹ thuật đánh lừa dấu @ trong URL", "https://www.google.com@evil-login-stealer.xyz/auth", {"PHISHING"}),
    ("TC-P04", "Phishing-Lexical", "Nhồi nhét nhiều subdomain giả mạo", "http://paypal.com.secure.account-update.verify-now.top/signin", {"PHISHING"}),
    ("TC-P05", "Phishing-Lexical", "Double-slash // trong path", "https://cdn-redirect.example.net//https://fake-bank-login.tk/login", {"PHISHING"}),
    ("TC-P06", "Phishing-Lexical", "Mã hóa phần trăm (%xx) che giấu từ khóa", "http://secure-update.xyz/%6c%6f%67%69%6e/%76%65%72%69%66%79?user=admin%40bank.com", {"PHISHING"}),
    ("TC-P07", "Phishing-Lexical", "Subdomain ngẫu nhiên + token entropy cao", "https://b4e921f0.sso-mailsrvr-4344e5teed.pages.dev/auth?session=9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c", {"PHISHING"}),
    ("TC-P08", "Phishing-Edge", "Root domain phishing ngắn có HTTPS", "https://secure-vietcombank-login.com", {"PHISHING"}),
    ("TC-P09", "Phishing-Lexical", "IPv6 trực tiếp kèm trang verify", "http://[2001:db8:85a3::8a2e:370:7334]/bank/verify.php", {"PHISHING"}),
    ("TC-P10", "Phishing-Lexical", "Cổng lạ :8080 kèm từ khóa đăng nhập", "http://login-apple-id.servehttp.com:8080/signin", {"PHISHING"}),
    ("TC-P11", "Phishing-Lexical", "Payload Base64 ẩn sau dấu #fragment dài", "https://xwebhostapp.github.io/freehost//#eyJ2ZXJpZnkiOiJwaGlzaGluZyIsInRva2VuIjoiMTIzNDU2Nzg5MCJ9", {"PHISHING"}),

    # --- Nhóm 4: IDN Homograph (Latin vs Hy Lạp, Cyrillic, Punycode, Zero-width) ---
    ("TC-H01", "Homograph", "Cloudflare giả mạo bằng chữ α Hy Lạp (cloudflαre.com)", "https://www.cloudfl\u03b1re.com/", {"PHISHING"}),
    ("TC-H02", "Homograph", "Chữ Hy Lạp Omicron 'ο' trộn Latin (gοοgle.com)", "https://www.g\u03bf\u03bfgle.com/login", {"PHISHING"}),
    ("TC-H03", "Homograph", "Chữ Cyrillic giả mạo paypal.com (раураӏ.com)", "https://www.\u0440\u0430\u0443\u0440\u0430\u04cf.com", {"PHISHING"}),
    ("TC-H04", "Homograph", "Chữ Cyrillic giả mạo apple.com (аррӏе.com)", "https://www.\u0430\u0440\u0440\u04cf\u0435.com", {"PHISHING"}),
    ("TC-H05", "Homograph", "Dán trực tiếp Punycode xn--ggle-0nda.com (gοοgle)", "https://www.xn--ggle-0nda.com/login", {"PHISHING"}),
    ("TC-H06", "Homograph", "Punycode chữ HOA (XN--80AK6AA92E.COM = apple)", "HTTPS://WWW.XN--80AK6AA92E.COM/", {"PHISHING"}),
    ("TC-H07", "Homograph", "Chèn ký tự tàng hình Zero-Width U+200B", "https://www.goo\u200bgle.com", {"PHISHING"}),
    ("TC-H08", "Homograph", "Trộn Latin + Hy Lạp giả mạo ngân hàng VN", "https://vietc\u03bfmbank.com.vn/dang-nhap", {"PHISHING"}),
    ("TC-H09", "Homograph", "Subdomain Punycode giả mạo kèm domain lạ", "https://xn--pple-43d.evil-host.org/verify", {"PHISHING"}),

    # --- Nhóm 5: Giao thức nguy hiểm, XSS/SQLi Injection & Malformed ---
    ("TC-M01", "Dangerous-Scheme", "JavaScript URI (XSS/Phishing vector)", "javascript:alert(document.cookie)", {"PHISHING"}),
    ("TC-M02", "Dangerous-Scheme", "Data URI HTML giả mạo form đăng nhập", "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", {"PHISHING"}),
    ("TC-M03", "Injection", "Payload Reflected XSS trong path & query", "https://example.com/<script>alert(1)</script>?q=\"><img src=x onerror=alert(1)>", {"PHISHING"}),
    ("TC-M04", "Injection", "Payload SQL Injection trong tham số URL", "https://example.com/login?user=admin' OR '1'='1'--", {"PHISHING"}),
    ("TC-M05", "Malformed", "Port vượt giới hạn hợp lệ (:99999)", "http://example.com:99999/test", {"PHISHING"}),
    ("TC-M06", "Malformed", "IPv6 thiếu dấu đóng ngoặc vuông", "http://[2001:db8::1/login", {"PHISHING"}),
    ("TC-M07", "Boundary", "URL siêu dài 4000 ký tự", "https://evil.example.com/" + ("a" * 3970), {"PHISHING"}),
]


def run_all():
    report = {"url_cases": [], "security_cases": []}

    for tc_id, category, desc, url, expected_set in URL_TEST_CASES:
        app_module.rate_limiter._hits.clear()
        res = client.post("/api/check", json={"url": url, "reanalyze": True})
        ok = res.status_code == 200
        body = res.json() if ok else {"error": res.text}
        verdict = body.get("verdict", f"HTTP_{res.status_code}")

        _, _, dbg = app_module._evaluate_and_store(url, reanalyze=False) if ok else ({}, False, {})
        passed = ok and (verdict in expected_set) and len(body.get("reasons", [])) >= 1

        report["url_cases"].append({
            "id": tc_id,
            "category": category,
            "description": desc,
            "url_preview": url if len(url) <= 95 else url[:92] + "...",
            "expected": sorted(expected_set),
            "actual_verdict": verdict,
            "reasons": body.get("reasons", []),
            "sha256": body.get("sha256"),
            "internal_ml_prob": round(float(dbg.get("ml_prob", 0.0)), 4) if ok else None,
            "internal_homograph": dbg.get("homograph_risk") if ok else None,
            "passed": passed,
        })

    # --- Security, Anti-Leakage & VirusTotal Persistence Checks ---

    # TC-S01: Swagger / OpenAPI disabled
    s_docs = client.get("/docs").status_code
    s_openapi = client.get("/openapi.json").status_code
    report["security_cases"].append({
        "id": "TC-S01",
        "name": "Tắt hoàn toàn /docs & /openapi.json chống dò API",
        "passed": (s_docs, s_openapi) == (404, 404),
        "detail": f"/docs={s_docs}, /openapi.json={s_openapi}",
    })

    # TC-S02: Zero ML/architecture leakage in HTML & API responses
    html_text = client.get("/").text.lower()
    sample_resp = json.dumps(client.post("/api/check", json={"url": "https://www.cloudfl\u03b1re.com/"}).json(), ensure_ascii=False).lower()
    banned_ml_words = ["random forest", "27 features", "layer 1", "layer 2", "3 layer", "threshold", "phiusiil", "sklearn", "predict_proba"]
    leaked_words = [w for w in banned_ml_words if w in html_text or w in sample_resp]
    report["security_cases"].append({
        "id": "TC-S02",
        "name": "Không rò rỉ kiến trúc ML (Random Forest, 27 features, Layer, Threshold...) trong HTML & JSON",
        "passed": len(leaked_words) == 0,
        "detail": f"Leaked={leaked_words}",
    })

    # TC-S03: VirusTotal-style Save -> Hash Lookup -> Reanalyze workflow
    app_module.rate_limiter._hits.clear()
    r_first = client.post("/api/check", json={"url": "https://www.cloudfl\u03b1re.com/", "reanalyze": True}).json()
    saved_hash = r_first["sha256"]
    r_by_hash = client.post("/api/check", json={"url": saved_hash}).json()
    r_reanalyze = client.post("/api/check", json={"url": "https://www.cloudfl\u03b1re.com/", "reanalyze": True}).json()
    vt_ok = (
        r_first["from_cache"] is False
        and r_by_hash["from_cache"] is True
        and r_by_hash["sha256"] == saved_hash
        and r_by_hash["verdict"] == "PHISHING"
        and "cloudflare.com" in " ".join(r_by_hash["reasons"])
        and r_reanalyze["from_cache"] is False
    )
    report["security_cases"].append({
        "id": "TC-S03",
        "name": "Cơ chế VirusTotal: Quét mới -> Lưu SHA-256 -> Dán mã SHA-256 tra cứu lại -> Phân tích lại",
        "passed": vt_ok,
        "detail": f"hash={saved_hash[:16]}..., by_hash_cache={r_by_hash['from_cache']}, reason={r_by_hash['reasons'][0]}",
    })

    # TC-S04: History list & Query Secret Redaction
    secret_url = "https://portal.example.org/reset?token=SECRET_XYZ_999&user=admin"
    client.post("/api/check", json={"url": secret_url, "reanalyze": True})
    hist_resp = client.get("/api/history").json()
    hist_str = json.dumps(hist_resp)
    privacy_ok = len(hist_resp.get("items", [])) > 0 and "SECRET_XYZ_999" not in hist_str
    report["security_cases"].append({
        "id": "TC-S04",
        "name": "Lịch sử lưu trữ ẩn tham số nhạy cảm (?token=...) thành ?[...]",
        "passed": privacy_ok,
        "detail": f"History count={len(hist_resp.get('items', []))}, Token leaked={'SECRET_XYZ_999' in hist_str}",
    })

    # TC-S05: Unknown SHA-256 returns clean 404 & invalid inputs return 400
    r_unknown_hash = client.post("/api/check", json={"url": "a" * 64})
    r_blank = client.post("/api/check", json={"url": "    "})
    err_ok = r_unknown_hash.status_code == 404 and r_blank.status_code == 400
    report["security_cases"].append({
        "id": "TC-S05",
        "name": "Xử lý mã SHA-256 chưa tồn tại (404) và đầu vào lỗi (400)",
        "passed": err_ok,
        "detail": f"UnknownHash={r_unknown_hash.status_code}, Blank={r_blank.status_code}",
    })

    # TC-S06: Rate Limiter blocks automated burst scanning
    app_module.rate_limiter._hits.clear()
    statuses = [client.post("/api/check", json={"url": "https://www.google.com"}).status_code for _ in range(37)]
    rate_ok = statuses[:35] == [200] * 35 and statuses[35] == 429
    report["security_cases"].append({
        "id": "TC-S06",
        "name": "Chặn quét tự động (Rate Limit ngầm) không lộ con số quota",
        "passed": rate_ok,
        "detail": f"Req 36={statuses[35]}",
    })

    out_json = ROOT_DIR / "tests" / "qa_results.json"
    out_json.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    url_pass = sum(1 for c in report["url_cases"] if c["passed"])
    sec_pass = sum(1 for c in report["security_cases"] if c["passed"])
    print(f"URL Cases Passed: {url_pass}/{len(report['url_cases'])}")
    print(f"Security Cases Passed: {sec_pass}/{len(report['security_cases'])}")
    for c in report["url_cases"]:
        if not c["passed"]:
            print(f"  [URL FAIL] {c['id']}: actual={c['actual_verdict']} expected={c['expected']}")
    for s in report["security_cases"]:
        if not s["passed"]:
            print(f"  [SEC FAIL] {s['id']}: {s['detail']}")

    if TEST_DB.exists():
        TEST_DB.unlink()


if __name__ == "__main__":
    run_all()
