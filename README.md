# Machine Learning in URL Detection — URL Security Checker (Nhóm 6)

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

![Giao diện URL Security Checker](./docs/demo_screenshot.png)

---

## 🛡️ Tính năng hệ thống Demo

- **Phát hiện Phishing kết hợp ngầm**:
  - Chuẩn hóa URL theo RFC 3986 và kiểm tra **IDN Homograph 2 chiều (`idna`)**: phát hiện giả mạo ký tự Latin bằng bảng chữ **Hy Lạp / Cyrillic**, ký tự tàng hình **Zero-Width**, Punycode `xn--`, và giao thức URI nguy hiểm (`javascript:`, `data:`).
  - Mô hình **Random Forest (27 lexical features)** huấn luyện trên bộ **PhiUSIIL** (`phishing_url_model.pkl` đi kèm sẵn trong repo — không cần train lại).
- **Nhận định phân tích an toàn (Chống lách luật)**:
  - Nêu rõ dấu hiệu rủi ro cho người dùng (tô sáng ký tự giả mạo trên tên miền, hiển thị Punycode thực tế, IP trực tiếp, thiếu HTTPS...) nhưng **ẩn hoàn toàn** kiến trúc mô hình, trọng số, danh sách 27 features và ngưỡng quyết định ở phía server; tắt `/docs` & `/openapi.json` kèm giới hạn tốc độ quét ngầm.
- **Lưu trữ & Tra cứu ngược `SHA-256` kiểu VirusTotal**:
  - Mỗi URL sau khi kiểm tra được băm `SHA-256` lưu vào cơ sở dữ liệu lịch sử (`threat_cache.db`, tự động che tham số nhạy cảm `?[...]`).
  - Cho phép **dán ngược mã `SHA-256` vào ô tìm kiếm** hoặc chọn từ danh sách lịch sử để xem lại báo cáo kèm nút **Phân tích lại**.
- **Bộ kiểm thử tự động 44/44 PASS**: Xem chi tiết tại [docs/qa_test_report.md](./docs/qa_test_report.md) và [tests/run_qa_suite.py](./tests/run_qa_suite.py).

---

## 📁 Cấu trúc thư mục

```text
.
├── app.py                              # FastAPI server (URL check, SHA-256 lookup & history)
├── homograph_guard.py                  # Kiểm tra IDN Homograph / Hy Lạp / Cyrillic / Punycode
├── security_store.py                   # Lưu trữ lịch sử SHA-256 (SQLite) & Rate Limiter
├── url_features.py                     # Trích xuất 27 lexical features
├── phishing_url_model.pkl              # Mô hình Random Forest đã huấn luyện
├── model_features.json                 # Metadata thứ tự 27 features
├── static/
│   └── index.html                      # Giao diện Web URL Security Checker
├── tests/
│   ├── run_qa_suite.py                 # Bộ 44 test cases tự động (URL + Bảo mật)
│   └── qa_results.json                 # Kết quả chạy kiểm thử
├── docs/
│   ├── qa_test_report.md               # Báo cáo kiểm thử chi tiết
│   └── demo_screenshot.png             # Ảnh chụp giao diện thực tế
├── notebooks/
│   └── Copy_of_hocmay_hoanchinh.ipynb  # Notebook huấn luyện & đánh giá trên Colab
├── requirements.txt
└── README.md
```

---

## 🚀 Hướng dẫn cài đặt & chạy nhanh

```bash
pip install -r requirements.txt
python app.py
```

- Mở trình duyệt tại: `http://127.0.0.1:8000`
- Chạy bộ kiểm thử tự động: `python tests/run_qa_suite.py`

---

## 👥 Thành viên Nhóm 6

1. Nguyễn Văn Thiên Phúc — `2033230230`
2. Nguyễn Văn Khanh — `2033222040`
3. Nguyễn Minh Vũ — `2033230328`
4. Võ Thị Thùy Trang — `2033230303`
5. Trần Thị Thảo Vy — `2033230334`
