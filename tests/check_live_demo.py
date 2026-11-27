"""Live End-to-End Smoke & Accuracy Check against running http://127.0.0.1:8000 server."""

import time
import httpx

BASE_URL = "http://127.0.0.1:8000"

LIVE_CASES = [
    ("IDN Cyrillic (Apple 2017 PoC)", "https://www.\u0430\u0440\u0440\u04cf\u0435.com", "PHISHING"),
    ("Punycode thô (xn--80ak6aa92e)", "https://www.xn--80ak6aa92e.com", "PHISHING"),
    ("IDN 1 ký tự Cyrillic (аpple)", "https://\u0430pple.com", "PHISHING"),
    ("IDN Hy Lạp α (cloudflαre)", "https://www.cloudfl\u03b1re.com/", "PHISHING"),
    ("IDN Hy Lạp ο (gοοgle)", "https://www.g\u03bf\u03bfgle.com", "PHISHING"),
    ("IDN Cyrillic (раураӏ)", "https://www.\u0440\u0430\u0443\u0440\u0430\u04cf.com", "PHISHING"),
    ("IDN Hy Lạp VN (vietcοmbank)", "https://www.vietc\u03bfmbank.com.vn", "PHISHING"),
    ("Zero-Width U+200B (goo​gle)", "https://www.goo\u200bgle.com", "PHISHING"),
    ("Đối chứng chống Cache Poison: Google thật", "https://www.google.com", "LEGITIMATE"),
    ("Dấu nặng ẩn (amạzon)", "https://www.am\u1ea1zon.com", "PHISHING"),
    ("IPA ɑ giả a (exɑmple.org)", "https://www.ex\u0251mple.org/login", "PHISHING"),
    ("ASCII I hoa giả l (paypaI)", "https://www.paypaI.com", "PHISHING"),
    ("Subdomain m.paypaI.com", "https://m.paypaI.com/signin", "PHISHING"),
    ("Subdomain m.rnicrosoft.com", "https://m.rnicrosoft.com/auth", "PHISHING"),
    ("ASCII rn giả m (rnicrosoft)", "https://www.rnicrosoft.com", "PHISHING"),
    ("ASCII số 0 giả o (g00gle)", "https://www.g00gle.com", "PHISHING"),
    ("Typosquat dư 1 chữ (cloudflaure)", "https://www.cloudflaure.com", "PHISHING"),
    ("Combosquatting Microsoft", "https://microsoft-security-update.com", "PHISHING"),
    ("Combosquatting Vietcombank", "https://vietcombank-digibank-verify.com", "PHISHING"),
    ("Cú pháp .zip + @ + ⁄", "https://drive.google.com/file/d/1uh\u2044@invoice-2026.zip", "PHISHING"),
    ("Cú pháp @ Authority", "https://www.vietcombank.com.vn@secure-auth-vn.xyz/login", "PHISHING"),
    ("Cloudflare Workers AiTM", "https://microsoft-sso-portal.auth-9x2a.workers.dev/login", "PHISHING"),
    ("Cloudflare Pages Phishing", "https://netflix-billing-verify.pages.dev/account", "PHISHING"),
    ("Firebase Hosting Phishing", "https://google-workspace-drive-share.firebaseapp.com/auth", "PHISHING"),
    ("Subdomain lồng thương hiệu", "https://login.paypal.com.account-security-check.top/verify", "PHISHING"),
    ("Đối chứng thật: Cloudflare", "https://www.cloudflare.com/", "LEGITIMATE"),
    ("Đối chứng thật: Vietcombank", "https://www.vietcombank.com.vn", "LEGITIMATE"),
    ("Đối chứng thật: Microsoft gõ tắt", "www.microsoft.com", "LEGITIMATE"),
    ("Đối chứng thật: BBC .co.uk", "https://www.bbc.co.uk", "LEGITIMATE"),
]


def main():
    passed = 0
    latencies = []
    sample_hash = None

    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        home = client.get("/")
        assert home.status_code == 200, f"Trang chủ lỗi HTTP {home.status_code}"
        print(f"[OK] Web UI đang online tại {BASE_URL} (HTTP 200)\n")
        print(f"{'Kịch bản':34s} | {'Kỳ vọng':10s} | {'Thực tế':10s} | {'Time':7s} | {'KQ'}")
        print("-" * 78)

        for name, url, expected in LIVE_CASES:
            t0 = time.perf_counter()
            # Test cached lookup (reanalyze=False) for Google right after goo\u200bgle.com to prove zero cache poisoning!
            reanalyze_flag = False if url == "https://www.google.com" else True
            r = client.post("/api/check", json={"url": url, "reanalyze": reanalyze_flag})
            ms = (time.perf_counter() - t0) * 1000
            latencies.append(ms)
            data = r.json()
            actual = data.get("verdict", f"ERR_{r.status_code}")
            ok = r.status_code == 200 and actual == expected
            if ok:
                passed += 1
            if sample_hash is None and ok:
                sample_hash = data.get("sha256")
            mark = "PASS" if ok else "FAIL"
            print(f"{name:34s} | {expected:10s} | {actual:10s} | {ms:5.1f}ms | {mark}")

        # Verify VirusTotal SHA-256 hash lookup & history API
        r_hash = client.post("/api/check", json={"url": sample_hash})
        hash_ok = r_hash.status_code == 200 and r_hash.json().get("from_cache") is True
        r_hist = client.get("/api/history")
        hist_ok = r_hist.status_code == 200 and len(r_hist.json().get("items", [])) > 0

        print("-" * 78)
        print(f"Kết quả phân loại URL : {passed}/{len(LIVE_CASES)} PASS")
        print(f"Tra cứu ngược SHA-256 : {'PASS' if hash_ok else 'FAIL'}")
        print(f"API Lịch sử lưu trữ   : {'PASS' if hist_ok else 'FAIL'}")
        print(f"Độ trễ trung bình     : {sum(latencies)/len(latencies):.1f} ms / request (max {max(latencies):.1f} ms)")


if __name__ == "__main__":
    main()
