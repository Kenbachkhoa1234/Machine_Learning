"""PhD-Grade Evaluation: 10,000 Held-Out PhiUSIIL URLs + 60 Adversarial/OOD Cases (Before vs After)."""

import json
import sys
import tempfile
import time
from pathlib import Path

import numpy as np
import pandas as pd
from fastapi.testclient import TestClient
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import app as app_mod
from homograph_guard import analyze_url_homograph

CSV_PATH = Path(r"G:\My Drive\ML\archive(3)\PhiUSIIL_Phishing_URL_Dataset.csv")


def compute_metrics(y_true_phish: np.ndarray, y_pred_phish: np.ndarray) -> dict:
    """Compute security metrics where 1 = Phishing (positive class), 0 = Legitimate."""
    tn, fp, fn, tp = confusion_matrix(y_true_phish, y_pred_phish, labels=[0, 1]).ravel()
    total = len(y_true_phish)
    return {
        "total": int(total),
        "correct": int(tp + tn),
        "wrong": int(fp + fn),
        "tp_phish_caught": int(tp),
        "fn_phish_missed": int(fn),
        "tn_legit_ok": int(tn),
        "fp_legit_false_alarm": int(fp),
        "phish_total": int(tp + fn),
        "legit_total": int(tn + fp),
        "accuracy_pct": round(float(accuracy_score(y_true_phish, y_pred_phish) * 100), 3),
        "precision_phish_pct": round(float(precision_score(y_true_phish, y_pred_phish, zero_division=0) * 100), 3),
        "recall_phish_pct": round(float(recall_score(y_true_phish, y_pred_phish, zero_division=0) * 100), 3),
        "f1_phish_pct": round(float(f1_score(y_true_phish, y_pred_phish, zero_division=0) * 100), 3),
        "fpr_pct": round(float(fp / max(tn + fp, 1) * 100), 3),
        "fnr_pct": round(float(fn / max(tp + fn, 1) * 100), 3),
    }


def run_10k_benchmark() -> dict:
    print("1) Reproducing exact held-out Test Split from PhiUSIIL (CELL 4 + CELL 10, random_state=42)...", flush=True)
    df = pd.read_csv(CSV_PATH, usecols=["URL", "label"], low_memory=False)
    df["URL"] = df["URL"].astype("string").str.strip()
    df["label"] = pd.to_numeric(df["label"], errors="coerce")
    df = df.dropna(subset=["URL", "label"])
    df = df[df["URL"].str.len() > 0]
    df["label"] = df["label"].astype(int)
    df_clean = df.drop_duplicates(subset="URL", keep="first").reset_index(drop=True)

    # Exact 70 / 15 / 15 stratified split used during training in CELL 10
    _, df_temp = train_test_split(df_clean, test_size=0.30, stratify=df_clean["label"], random_state=42)
    _, df_test = train_test_split(df_temp, test_size=0.50, stratify=df_temp["label"], random_state=42)

    # Stratified 10,000-URL subset from the strictly held-out df_test (never seen during training!)
    df_10k, _ = train_test_split(df_test, train_size=10000, stratify=df_test["label"], random_state=42)
    urls_10k = df_10k["URL"].tolist()
    # Original label: 0 = Phishing, 1 = Legitimate -> convert to binary 1 = Phishing for clear TP/FP reporting
    y_true_phish = (df_10k["label"].to_numpy() == 0).astype(int)

    print(f"   Held-out Test Pool: {len(df_test)} URLs | Sampled Stratified Benchmark: {len(urls_10k)} URLs", flush=True)

    # A. Raw ML Model Only (as in original Colab CELL 20: raw URL -> extract_url_features -> RF)
    t0 = time.perf_counter()
    raw_probs = app_mod.engine.predict_batch_probs(urls_10k)
    raw_preds = (raw_probs >= 0.50).astype(int)
    raw_time_s = time.perf_counter() - t0
    raw_metrics = compute_metrics(y_true_phish, raw_preds)
    raw_metrics["batch_seconds"] = round(raw_time_s, 2)

    # B. Full Optimized Hybrid Pipeline (Layer 1 Guard + Normalization + Domain Context + Layer 2 RF)
    t1 = time.perf_counter()
    homographs = [analyze_url_homograph(u) for u in urls_10k]
    norm_urls = [h["normalized_url_for_ml"] for h in homographs]
    hyb_probs = app_mod.engine.predict_batch_probs(norm_urls)
    hyb_preds = np.array(
        [1 if app_mod._fuse_decision(h, float(p)) else 0 for h, p in zip(homographs, hyb_probs)],
        dtype=int,
    )
    hyb_time_s = time.perf_counter() - t1
    hyb_metrics = compute_metrics(y_true_phish, hyb_preds)
    hyb_metrics["batch_seconds"] = round(hyb_time_s, 2)

    # Collect sample FN and FP examples from Hybrid 10k for error analysis
    fn_examples = [urls_10k[i] for i in range(len(urls_10k)) if y_true_phish[i] == 1 and hyb_preds[i] == 0][:8]
    fp_examples = [urls_10k[i] for i in range(len(urls_10k)) if y_true_phish[i] == 0 and hyb_preds[i] == 1][:8]

    return {
        "clean_dataset_total": int(len(df_clean)),
        "heldout_test_total": int(len(df_test)),
        "raw_ml_10k": raw_metrics,
        "hybrid_web_10k": hyb_metrics,
        "sample_fn_missed_phish": fn_examples,
        "sample_fp_false_alarm": fp_examples,
    }


OOD_TEST_CASES = [
    # --- Group 1: Standard & Browser-Formatted Legitimate URLs (10 cases) ---
    ("G1-01", "Legit-Standard", "Google HTTPS root", "https://www.google.com", "LEGITIMATE"),
    ("G1-02", "Legit-Browser", "Copy Chrome có dấu / cuối", "https://www.cloudflare.com/", "LEGITIMATE"),
    ("G1-03", "Legit-Browser", "Toàn bộ chữ IN HOA + / cuối", "HTTPS://WWW.GITHUB.COM/", "LEGITIMATE"),
    ("G1-04", "Legit-Browser", "Gõ tắt không có https://", "www.microsoft.com", "LEGITIMATE"),
    ("G1-05", "Legit-Browser", "Có #anchor điều hướng nội trang", "https://www.wikipedia.org/#top", "LEGITIMATE"),
    ("G1-06", "Legit-Standard", "Ngân hàng VN .com.vn", "https://www.vietcombank.com.vn", "LEGITIMATE"),
    ("G1-07", "Legit-Standard", "Tên miền đại học có dấu gạch ngang", "https://www.uni-mainz.de", "LEGITIMATE"),
    ("G1-08", "Legit-Standard", "Tên miền báo chí Anh .co.uk", "https://www.bbc.co.uk", "LEGITIMATE"),
    ("G1-09", "Legit-Standard", "Cổng giáo dục Việt Nam .edu.vn", "https://huit.edu.vn", "LEGITIMATE"),
    ("G1-10", "Legit-Standard", "Cổng dịch vụ công .gov.vn", "https://dichvucong.gov.vn", "LEGITIMATE"),

    # --- Group 2: Real-World Deep-Path & Query Legitimate URLs (10 cases - OOD Stress Test!) ---
    ("G2-01", "Legit-DeepPath", "Link Kaggle Dataset của nhóm", "https://www.kaggle.com/datasets/ndarvind/phiusiil-phishing-url-dataset", "LEGITIMATE"),
    ("G2-02", "Legit-DeepPath", "Link Google Colab của nhóm", "https://colab.research.google.com/drive/1FES0v_ukQRNdw4bNZ7Bi8VvQHlxh6P3t?usp=sharing", "LEGITIMATE"),
    ("G2-03", "Legit-DeepPath", "Link Canva Slide của nhóm", "https://www.canva.com/design/DAHbPfWDpJA/-l8L6TY_B7c5B5_CVv8_8Q/edit", "LEGITIMATE"),
    ("G2-04", "Legit-DeepPath", "Link GitHub Repo của nhóm", "https://github.com/Kenbachkhoa1234/Machine_Learning", "LEGITIMATE"),
    ("G2-05", "Legit-DeepPath", "Link Google Search có query ?q=&hl=", "https://www.google.com/search?q=machine+learning&hl=vi", "LEGITIMATE"),
    ("G2-06", "Legit-DeepPath", "Link YouTube video ?v=", "https://www.youtube.com/watch?v=dQw4w9WgXcQ", "LEGITIMATE"),
    ("G2-07", "Legit-DeepPath", "Link tài liệu Python chính thức", "https://docs.python.org/3/library/urllib.parse.html", "LEGITIMATE"),
    ("G2-08", "Legit-DeepPath", "Link thông báo trường ĐH .edu.vn có path dài", "https://huit.edu.vn/tin-tuc/thong-bao-lich-thi-hoc-ky-2026.html", "LEGITIMATE"),
    ("G2-09", "Legit-DeepPath", "Link Wikipedia bài viết chuyên ngành", "https://en.wikipedia.org/wiki/IDN_homograph_attack", "LEGITIMATE"),
    ("G2-10", "Legit-UnlistedDeep", "Link báo ngoài danh sách (đo giới hạn OOD còn lại)", "https://vnexpress.net/ai-bao-mat-2026-4819203.html", "PHISHING"),

    # --- Group 3: IDN Homograph, Unicode, Roman Numeral & Zero-Width (10 cases) ---
    ("G3-01", "IDN-Homograph", "Apple 100% Cyrillic (PoC Xudong Zheng 2017)", "https://www.\u0430\u0440\u0440\u04cf\u0435.com", "PHISHING"),
    ("G3-02", "IDN-Homograph", "Punycode thô xn--80ak6aa92e.com", "https://www.xn--80ak6aa92e.com", "PHISHING"),
    ("G3-03", "IDN-Homograph", "Cloudflare trộn chữ α Hy Lạp", "https://www.cloudfl\u03b1re.com/", "PHISHING"),
    ("G3-04", "IDN-Homograph", "Google trộn 2 chữ ο Hy Lạp", "https://www.g\u03bf\u03bfgle.com/login", "PHISHING"),
    ("G3-05", "IDN-Homograph", "Cloudflare dùng chữ số La Mã ⅼ (U+217C)", "https://www.c\u217coudflare.com/", "PHISHING"),
    ("G3-06", "IDN-Homograph", "PayPal chữ Cyrillic (раураӏ.com)", "https://www.\u0440\u0430\u0443\u0440\u0430\u04cf.com", "PHISHING"),
    ("G3-07", "IDN-Homograph", "Vietcombank trộn chữ ο Hy Lạp", "https://www.vietc\u03bfmbank.com.vn", "PHISHING"),
    ("G3-08", "IDN-Homograph", "Chèn ký tự tàng hình Zero-Width U+200B", "https://www.goo\u200bgle.com", "PHISHING"),
    ("G3-09", "IDN-Homograph", "Amazon giấu dấu nặng dưới chữ ạ", "https://www.am\u1ea1zon.com", "PHISHING"),
    ("G3-10", "IDN-Homograph", "Punycode chữ IN HOA + đường dẫn sạch", "HTTPS://WWW.XN--GGLE-0NDA.COM/", "PHISHING"),

    # --- Group 4: ASCII Visual Homoglyphs, Typosquatting & Combosquatting (8 cases) ---
    ("G4-01", "ASCII-Spoof", "Chữ I hoa giả dạng chữ l thường (paypaI.com)", "https://www.paypaI.com", "PHISHING"),
    ("G4-02", "ASCII-Spoof", "Ghép r+n giả dạng chữ m (rnicrosoft.com)", "https://www.rnicrosoft.com", "PHISHING"),
    ("G4-03", "ASCII-Spoof", "Số 0 giả dạng chữ o (g00gle.com)", "https://www.g00gle.com", "PHISHING"),
    ("G4-04", "ASCII-Spoof", "Ghép v+v giả dạng chữ w (vvhatsapp.com)", "https://www.vvhatsapp.com", "PHISHING"),
    ("G4-05", "Typosquat", "Dư 1 ký tự (cloudflaure.com)", "https://www.cloudflaure.com", "PHISHING"),
    ("G4-06", "Typosquat", "Đảo 2 ký tự kề nhau (googel.com)", "https://www.googel.com", "PHISHING"),
    ("G4-07", "Combosquat", "Tên hãng + từ khóa bảo mật (HTTPS ngắn)", "https://microsoft-security-update.com", "PHISHING"),
    ("G4-08", "Combosquat", "Ngân hàng VN + từ khóa verify", "https://vietcombank-digibank-verify.com", "PHISHING"),

    # --- Group 5: Protocol Quirks, Open-Redirect & Cloud Platform Abuse (12 cases) ---
    ("G5-01", "Open-Redirect", "Lợi dụng Google Redirect dẫn sang trang lừa đảo", "https://www.google.com/url?q=http://evil-phish-login.xyz/auth", "PHISHING"),
    ("G5-02", "Backslash", "Đánh lừa bộ parse bằng dấu gạch chéo ngược \\", "https://www.google.com\\evil-stealer.xyz/login", "PHISHING"),
    ("G5-03", "Zip-TLD", "Đuôi tên miền .zip + dấu @ + ⁄ (Bobby Rauch)", "https://drive.google.com/file/d/1uh\u2044@invoice-2026.zip", "PHISHING"),
    ("G5-04", "Zip-TLD", "Tên miền độc lập đuôi .zip giả file đính kèm", "https://baocao-taichinh-2026.zip", "PHISHING"),
    ("G5-05", "At-Trick", "Đánh lừa phần Authority trước dấu @", "https://www.vietcombank.com.vn@secure-auth-vn.xyz/login", "PHISHING"),
    ("G5-06", "Cloud-Abuse", "Lạm dụng GitHub Pages github.io (KHÔNG được whitelist!)", "https://xwebhostapp.github.io/freehost//#eyJ2ZXJpZnkiOiJwaGlzaCJ9", "PHISHING"),
    ("G5-07", "Cloud-Abuse", "Lạm dụng Google Forms thu thập mật khẩu", "https://docs.google.com/forms/d/e/1FAIpQLSe9988/viewform?usp=sf_link", "PHISHING"),
    ("G5-08", "Cloud-Abuse", "Lạm dụng Cloudflare Workers AiTM", "https://microsoft-sso-portal.auth-9x2a.workers.dev/login", "PHISHING"),
    ("G5-09", "Cloud-Abuse", "Lạm dụng Cloudflare Pages", "https://netflix-billing-verify.pages.dev/account", "PHISHING"),
    ("G5-10", "Cloud-Abuse", "Lạm dụng Google Firebase Hosting", "https://google-workspace-drive-share.firebaseapp.com/auth", "PHISHING"),
    ("G5-11", "Dangerous-URI", "Giao thức thực thi mã javascript:", "javascript:alert(document.cookie)", "PHISHING"),
    ("G5-12", "Dangerous-URI", "Giao thức nhúng trang giả data:text/html", "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", "PHISHING"),

    # --- Group 6: Classical Lexical, IP, Port, Injection & Boundary (6 cases) ---
    ("G6-01", "Lexical-IP", "IPv4 nội bộ + login/verify", "http://192.168.1.1/secure-login/verify-account.php?id=9981", "PHISHING"),
    ("G6-02", "Lexical-IPv6", "IPv6 trực tiếp kèm verify.php", "http://[2001:db8:85a3::8a2e:370:7334]/bank/verify.php", "PHISHING"),
    ("G6-03", "Lexical-Port", "Port lạ :8080 + signin", "http://login-apple-id.servehttp.com:8080/signin", "PHISHING"),
    ("G6-04", "Injection", "Payload Reflected XSS trong URL", "https://github.com/<script>alert(1)</script>", "PHISHING"),
    ("G6-05", "Injection", "Payload SQL Injection trên domain tin cậy", "https://www.google.com/login?user=admin' OR '1'='1'--", "PHISHING"),
    ("G6-06", "Boundary", "URL siêu dài 4000 ký tự", "https://evil.example.com/" + ("a" * 3970), "PHISHING"),
]


def run_ood_and_api_benchmark() -> dict:
    tmp_db = Path(tempfile.gettempdir()) / "_phd_eval_cache.db"
    for p in (tmp_db, Path(str(tmp_db) + "-wal"), Path(str(tmp_db) + "-shm")):
        if p.exists():
            try:
                p.unlink()
            except OSError:
                pass
    app_mod.history_store = app_mod.ScanHistoryStore(tmp_db)
    client = TestClient(app_mod.app)

    results = []
    raw_correct = 0
    hybrid_correct = 0
    latencies_ms = []

    for cid, grp, desc, url, expected in OOD_TEST_CASES:
        app_mod.rate_limiter._hits.clear()
        # Raw ML baseline (without pre-normalization or Layer 1 guard)
        raw_p, _ = app_mod.engine.analyze(url)
        raw_verdict = "PHISHING" if raw_p >= 0.50 else "LEGITIMATE"
        # Note: for G2-10 (vnexpress unlisted deep link), true ground truth in real world is LEGITIMATE
        real_world_truth = "LEGITIMATE" if cid == "G2-10" else expected
        if raw_verdict == real_world_truth:
            raw_correct += 1

        t0 = time.perf_counter()
        resp = client.post("/api/check", json={"url": url, "reanalyze": True})
        lat_ms = (time.perf_counter() - t0) * 1000
        latencies_ms.append(lat_ms)
        data = resp.json()
        hyb_verdict = data.get("verdict")
        if hyb_verdict == real_world_truth:
            hybrid_correct += 1

        results.append({
            "id": cid,
            "group": grp,
            "description": desc,
            "url": url[:90],
            "real_truth": real_world_truth,
            "raw_ml_prob": round(raw_p, 4),
            "raw_ml_verdict": raw_verdict,
            "hybrid_verdict": hyb_verdict,
            "reason_1": (data.get("reasons") or [""])[0],
            "latency_ms": round(lat_ms, 2),
            "hybrid_matches_truth": hyb_verdict == real_world_truth,
        })

    for p in (tmp_db, Path(str(tmp_db) + "-wal"), Path(str(tmp_db) + "-shm")):
        if p.exists():
            try:
                p.unlink()
            except OSError:
                pass

    return {
        "total_ood_cases": len(OOD_TEST_CASES),
        "raw_ml_realworld_correct": raw_correct,
        "hybrid_realworld_correct": hybrid_correct,
        "avg_api_latency_ms": round(float(np.mean(latencies_ms)), 2),
        "p95_api_latency_ms": round(float(np.percentile(latencies_ms, 95)), 2),
        "cases": results,
    }


def main():
    res_10k = run_10k_benchmark()
    print("2) Running 56-case Adversarial & Real-World OOD Suite...", flush=True)
    res_ood = run_ood_and_api_benchmark()

    summary = {"benchmark_10k": res_10k, "benchmark_ood": res_ood}
    out_file = ROOT_DIR / "tests" / "phd_benchmark_results.json"
    out_file.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    r = res_10k["raw_ml_10k"]
    h = res_10k["hybrid_web_10k"]
    print("\n=== 10,000 HELD-OUT URL BENCHMARK ===")
    print(f"Raw ML Only     : {r['correct']}/10000 ({r['accuracy_pct']}%) | TP={r['tp_phish_caught']}/{r['phish_total']} (FN={r['fn_phish_missed']}) | TN={r['tn_legit_ok']}/{r['legit_total']} (FP={r['fp_legit_false_alarm']}) | F1={r['f1_phish_pct']}% | {r['batch_seconds']}s")
    print(f"Optimized Demo  : {h['correct']}/10000 ({h['accuracy_pct']}%) | TP={h['tp_phish_caught']}/{h['phish_total']} (FN={h['fn_phish_missed']}) | TN={h['tn_legit_ok']}/{h['legit_total']} (FP={h['fp_legit_false_alarm']}) | F1={h['f1_phish_pct']}% | {h['batch_seconds']}s")
    print("\n=== 56 REAL-WORLD ADVERSARIAL & OOD CASES ===")
    print(f"Raw ML Only (CELL 20) : {res_ood['raw_ml_realworld_correct']}/{res_ood['total_ood_cases']} ({res_ood['raw_ml_realworld_correct']/res_ood['total_ood_cases']*100:.1f}%)")
    print(f"Optimized Web Demo    : {res_ood['hybrid_realworld_correct']}/{res_ood['total_ood_cases']} ({res_ood['hybrid_realworld_correct']/res_ood['total_ood_cases']*100:.1f}%)")
    print(f"Single-Request API Latency: avg={res_ood['avg_api_latency_ms']} ms | p95={res_ood['p95_api_latency_ms']} ms")


if __name__ == "__main__":
    main()
