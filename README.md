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

## 🛡️ Tính năng hệ thống & Kết quả Thực nghiệm

- **Phát hiện Phishing đa tầng chạy ngầm**:
  - Chuẩn hóa URL theo RFC 3986 và kiểm tra **IDN Homograph 2 chiều (`idna`) + UTS #39 Skeleton**: phát hiện giả mạo ký tự Latin bằng bảng chữ **Hy Lạp (`α`, `ο`), Cyrillic, phiên âm IPA (`ɑ`), chữ số La Mã (`ⅼ`), Latin có dấu (`ạ`)**, ký tự tàng hình **Zero-Width (`U+200B`)**, Punycode `xn--`, bẫy thị giác ASCII trên mọi subdomain (`m.paypaI.com`, `m.rnicrosoft.com`, `g00gle.com`), **Open-Redirect** mã hóa nhiều lớp, **Backslash `\`**, đuôi `.zip/.mov` và giao thức nguy hiểm (`javascript:`, `data:`).
  - Mô hình **Random Forest (27 lexical features)** huấn luyện trên bộ **PhiUSIIL** (`phishing_url_model.pkl` đi kèm sẵn trong repo — tối ưu suy luận mảng `numpy.float32`, không cần train lại).
- **Nhận định phân tích an toàn (Chống dò mô hình / Anti-Evasion)**:
  - Nêu rõ dấu hiệu rủi ro bằng ngôn ngữ dễ hiểu, tô đỏ đúng ký tự giả mạo trên tên miền và hiển thị Punycode/ASCII gốc nhưng **ẩn hoàn toàn** kiến trúc mô hình, trọng số, danh sách 27 features và ngưỡng quyết định ở phía server.
  - Tắt `/docs`, `/redoc`, `/openapi.json` (`HTTP 404`), trang bị đầy đủ **HTTP Security Headers** (`CSP`, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`) và bộ giới hạn tốc độ LRU chống tràn bộ nhớ.
- **Lưu trữ & Tra cứu ngược `SHA-256` chống đụng độ kiểu VirusTotal**:
  - Lưu lịch sử quét trên **SQLite WAL** bằng khóa băm `SHA-256` chống đầu độc cache (tách biệt tuyệt đối URL sạch với biến thể chèn `Zero-Width`, `@`, `\`, hoặc chữ `'I'` hoa giả mạo; tự động ẩn tham số nhạy cảm `?[...]` và token đường dẫn entropy cao).
  - Hỗ trợ **dán ngược mã `SHA-256` vào ô tìm kiếm** hoặc chọn từ bảng lịch sử để mở lại báo cáo kèm nút **Phân tích lại**.
- **Kiểm chứng thực nghiệm độc lập**:
  - **10.000 URL Held-Out Test (PhiUSIIL)**: Bắt đúng **9.957 / 10.000 URL (`99,57%`)**, `F1 = 99,495%` — xem [docs/phd_evaluation_report.md](./docs/phd_evaluation_report.md).
  - **56 Kịch bản Thực chiến & OOD**: Đạt **55 / 56 (`98,2%`)**, tăng `+42,8` điểm phần trăm so với mô hình thô (`55,4%`).
  - **Bộ kiểm thử QA & Red-Team tự động**: **56 / 56 PASS (`100%`)** — xem [docs/qa_test_report.md](./docs/qa_test_report.md).

---

## 📁 Cấu trúc thư mục

```text
.
├── app.py                              # FastAPI server (URL check, SHA-256 lookup, CSP headers)
├── homograph_guard.py                  # Kiểm tra IDN Homograph, IPA, eTLD+1 Typosquat & 10-gate Context
├── security_store.py                   # Lưu trữ SHA-256 chống đụng độ (SQLite WAL) & LRU Rate Limiter
├── url_features.py                     # Trích xuất 27 lexical features
├── phishing_url_model.pkl              # Mô hình Random Forest đã huấn luyện (scikit-learn 1.6.1)
├── model_features.json                 # Metadata thứ tự 27 features
├── static/
│   └── index.html                      # Giao diện Web URL Security Checker
├── tests/
│   ├── run_qa_suite.py                 # Bộ 56 test cases tự động (48 URL + 8 Security/Red-Team)
│   ├── benchmark_10k_and_ood.py        # Benchmark 10.000 URL Held-Out + 56 ca OOD thực chiến
│   ├── check_live_demo.py              # Script kiểm tra nhanh server đang chạy tại 127.0.0.1:8000
│   ├── qa_results.json                 # Kết quả chạy kiểm thử QA
│   └── phd_benchmark_results.json      # Số liệu thực nghiệm 10.000 URL & OOD
├── docs/
│   ├── phd_evaluation_report.md        # Báo cáo đánh giá thực nghiệm & phân tích giới hạn khoa học
│   ├── qa_test_report.md               # Báo cáo kiểm thử QA & Red-Team chi tiết
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
- Chạy bộ kiểm thử QA & Red-Team (56 cases): `python tests/run_qa_suite.py`
- Chạy kiểm tra trực tiếp server live: `python tests/check_live_demo.py`

---

## 👥 Thành viên Nhóm 6

1. Nguyễn Văn Thiên Phúc — `2033230230`
2. Nguyễn Văn Khanh — `2033222040`
3. Nguyễn Minh Vũ — `2033230328`
4. Võ Thị Thùy Trang — `2033230303`
5. Trần Thị Thảo Vy — `2033230334`
