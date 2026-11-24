# Machine Learning in URL Detection — PhishGuard (Nhóm 6)

Đồ án môn học **Học máy cho bảo mật** — Trường Đại học Công Thương TP.HCM (HUIT)  
**GVHD:** Hoàng Quốc Việt  

---

## 🔗 Tài nguyên & Liên kết dự án

| Thành phần | Liên kết |
|---|---|
| **Dataset (Kaggle)** | https://www.kaggle.com/datasets/ndarvind/phiusiil-phishing-url-dataset |
| **Google Drive (Dữ liệu & Model)** | https://drive.google.com/drive/u/1/folders/1uh-qkfegs4C7mHjJRMV7WXnLds2AVOvU |
| **Google Colab Notebook** | https://colab.research.google.com/drive/1FES0v_ukQRNdw4bNZ7Bi8VvQHlxh6P3t?usp=sharing |
| **Slide thuyết trình (Canva)** | https://www.canva.com/design/DAHbPfWDpJA/-l8L6TY_B7c5B5_CVv8_8Q/edit |

---

## 🛡️ Kiến trúc hệ thống Demo (Defense-in-Depth)

Ứng dụng web kết hợp **bảo mật nhiều lớp** mà **không cần train lại mô hình** đã huấn luyện:

1. **Layer 0 — SHA-256 Threat Cache & Audit Log (`security_store.py`)**
   - Chuẩn hóa URL và băm bằng **SHA-256** (cơ chế tương tự VirusTotal URL ID) lưu vào SQLite (`threat_cache.db`).
   - Không lưu query string thô chứa thông tin nhạy cảm vào bảng audit log.
   - Tích hợp **Sliding-Window Rate Limiter** (40 lượt/phút/IP) để chống dò ranh giới mô hình.
2. **Layer 1 — IDN Homograph & Unicode Guard (`homograph_guard.py`)**
   - Giải mã **IDNA 2 chiều** (`xn--...` ↔ Unicode) để bắt cả URL Unicode thô lẫn Punycode.
   - Phát hiện ký tự **Hy Lạp / Cyrillic**, trộn nhiều bảng chữ cái (**Mixed-Script**), ký tự tàng hình (**Zero-Width**), và giả mạo thương hiệu (**Brand Spoofing**).
   - Tách riêng cảnh báo **HIGH** (Mixed-Script / giả mạo brand) và **NOTICE** (Pure IDN hợp lệ) để hạn chế False Positive.
3. **Layer 2 — Machine Learning Engine (`url_features.py` + `phishing_url_model.pkl`)**
   - Mô hình **Random Forest (300 trees)** huấn luyện trên bộ **PhiUSIIL** (235,370 URL sau làm sạch) với đúng **27 lexical features**.
   - Kết quả thực nghiệm trên tập Test (35,306 URL): **Accuracy 99,51% · Precision 99,66% · Recall 99,20% · F1-Phishing 99,43% · ROC-AUC 99,72%**.
4. **Tách quyền End-User vs SOC Analyst (`app.py` + `static/index.html`)**
   - **End-User Mode (mặc định)**: Chỉ trả về kết luận an toàn (`SAFE / SUSPICIOUS / PHISHING`), lời khuyên và `SHA-256` hash — **ẩn hoàn toàn** 27 features và xác suất ở server để chống **Adversarial Evasion**.
   - **SOC Analyst Mode (khóa xác thực Server-side, sai 3 lần khóa 60s)**: Mở khóa Character X-Ray, thanh kéo `Threshold`, giải phẫu URL, 27 features, quét hàng loạt (Batch/CSV) và Threat Intel Audit Log.

---

## 📁 Cấu trúc thư mục

```text
phishing_url_demo/
├── app.py                              # FastAPI backend (End-User & SOC APIs)
├── homograph_guard.py                  # Lớp kiểm tra IDN Homograph / Hy Lạp / Cyrillic / Punycode
├── security_store.py                   # SHA-256 Threat Cache (SQLite), Rate Limiter, SOC Auth
├── url_features.py                     # Trích xuất đúng 27 lexical features
├── static/
│   └── index.html                      # Giao diện Web Dark Cyber
├── notebooks/
│   └── Copy_of_hocmay_hoanchinh.ipynb  # Notebook huấn luyện & đánh giá trên Colab
├── phishing_url_model.pkl              # (Tải từ Google Drive nếu chưa có trong repo)
├── model_features.json                 # (Tải từ Google Drive nếu chưa có trong repo)
├── requirements.txt
└── README.md
```

---

## 🚀 Hướng dẫn cài đặt & chạy Demo

1. **Đảm bảo có đủ file model từ Google Drive** (tại thư mục gốc dự án):
   - `phishing_url_model.pkl`
   - `model_features.json`
2. **Cài đặt thư viện**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Chạy Web App**:
   ```bash
   python app.py
   ```
   Mở trình duyệt tại: `http://127.0.0.1:8000`
4. **Mở khóa SOC Analyst Mode**:
   - Mã mặc định cho demo: `SOC-NHOM6-2026` (có thể đổi bằng biến môi trường `SOC_ACCESS_KEY`).

---

## 👥 Thành viên Nhóm 6

1. Nguyễn Văn Thiên Phúc — `2033230230`
2. Nguyễn Văn Khanh — `2033222040`
3. Nguyễn Minh Vũ — `2033230328`
4. Võ Thị Thùy Trang — `2033230303`
5. Trần Thị Thảo Vy — `2033230334`
