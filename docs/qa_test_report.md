# Báo cáo Kiểm thử Toàn diện QA & Red-Team — URL Security Checker

**Dự án:** Machine Learning in URL Detection (Nhóm 6 — HUIT)  
**Cơ chế lõi chạy ngầm ở Server:** Chuẩn hóa RFC 3986 + 2-Way IDNA/IPA/eTLD+1 Guard + Collision-Free SHA-256 SQLite WAL + `Random Forest` (`phishing_url_model.pkl`, **không train lại**)  
**Tổng kết kiểm thử:** **56 / 56 Automated Cases PASS (100%)** (`48/48` URL & Red-Team Cases + `8/8` Security, Anti-Cache-Poisoning & Header Cases)

> [!IMPORTANT]
> **Cân bằng giữa Giải thích Thuyết phục & Chống Vượt Rào (Anti-Evasion):**
> - **Nhận định phân tích an toàn**: Chỉ rõ bản chất mối đe dọa (tô đỏ đúng ký tự giả mạo như `'α'` trong `cloudflαre.com`, chữ `'I'` hoa trong `www.paypaI.com`, chữ IPA `'ɑ'` trong `exɑmple.org`, hiển thị Punycode/ASCII gốc, cảnh báo Open-Redirect, Backslash `\`, IP trực tiếp, thiếu HTTPS...) nhưng **ẩn kín 100%** tên mô hình (`Random Forest`), danh sách `27 features`, xác suất `predict_proba` và ngưỡng quyết định.
> - **Lưu trữ `SHA-256` chống đầu độc bộ nhớ đệm (Anti-Cache-Poisoning)**: Cơ chế `build_collision_free_cache_key` đảm bảo các URL tấn công chèn ký tự ẩn (`goo\u200bgle.com`), `@` (`google.com@evil.xyz`), `\` (`google.com\evil.xyz`) hay chữ `'I'` hoa (`paypaI.com`) sinh mã `SHA-256` hoàn toàn tách biệt — **không bao giờ ghi đè làm hỏng kết quả của tên miền sạch gốc (`https://www.google.com`)**.

![Giao diện tra cứu mã SHA-256 kiểu VirusTotal & tô sáng chữ α Hy Lạp giả mạo cloudflare.com](./demo_screenshot.png)

---

## 1. Kiểm thử Bảo mật, Chống Đầu độc Cache & HTTP Headers (8/8 PASS)

| ID | Kịch bản kiểm thử bảo mật | Kỳ vọng | Kết quả thực tế | Trạng thái |
|---|---|---|---|---|
| `TC-S01` | Dò tài liệu API tự động (`/docs`, `/openapi.json`) | Tắt hoàn toàn (`HTTP 404`) | `/docs=404`, `/openapi.json=404` | **PASS** |
| `TC-S02` | Soi HTML & JSON phản hồi tìm từ khóa lộ mô hình (`random forest`, `27 features`, `layer`, `threshold`, `phiusiil`, `sklearn`, `predict_proba`) | Không lộ bất kỳ từ khóa nào (`[]`) | `Leaked=[]` | **PASS** |
| `TC-S03` | **Luồng VirusTotal**: Quét mới `cloudflαre.com` → Lưu `SHA-256` → Dán mã `SHA-256` tra cứu ngược → Bấm `Phân tích lại` | Lưu mới (`from_cache=False`), tra bằng hash trả đúng bản ghi (`from_cache=True`) | Khớp mã băm, nêu rõ giả mạo `cloudflare.com` | **PASS** |
| `TC-S04` | Ẩn dữ liệu nhạy cảm trong Lịch sử với `?token=SECRET_XYZ_999` và đường dẫn chứa token entropy cao | Tự động che thành `[...]` và `?[...]`, không lưu lộ token trong SQLite | `QueryLeaked=False`, `PathTokenLeaked=False` | **PASS** |
| `TC-S05` | Tra cứu mã `SHA-256` chưa tồn tại & gửi chuỗi rỗng | Trả `404` (chưa có bản ghi) và `400` (lỗi nhập liệu chung) | `UnknownHash=404`, `Blank=400` | **PASS** |
| `TC-S06` | Giới hạn tốc độ quét tự động (`60 req/phút` LRU chống tràn RAM) tách riêng khỏi `/api/history` | Chặn `HTTP 429` ở req thứ 61 trên `/api/check` nhưng `/api/history` vẫn trả `200` | `Req 61=429`, `History=200` | **PASS** |
| `TC-S07` | **Chống đầu độc Cache `SHA-256` & Giữ nguyên chữ `'I'` hoa đỏ** | Sau khi quét `goo\u200bgle.com`, `@`, `\`, tra lại `google.com` từ cache vẫn `LEGITIMATE`; `paypaI.com` tô đỏ đúng chữ `'I'` | `4/4` mã băm độc lập, `google_cached=LEGITIMATE`, `flagged=['I']` | **PASS** |
| `TC-S08` | Kiểm tra đầy đủ **HTTP Security Headers** | Có `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` | Đủ 4 nhóm header chuẩn bảo mật | **PASS** |

---

## 2. Tổng hợp 48 Test Cases Phân loại URL & Red-Team Bypasses (48/48 PASS)

- **Nhóm 1 — URL Hợp lệ & Biến thể Nhập liệu Người dùng (`8/8 PASS`)**:
  - `https://www.google.com`, `https://www.cloudflare.com/`, `https://www.vietcombank.com.vn`, `https://www.uni-mainz.de`, `www.microsoft.com` (gõ tắt thiếu scheme trên tên miền xác thực), `HTTPS://WWW.GITHUB.COM/` (chữ HOA + `/`), `https://www.wikipedia.org/#top`, `https://www.voicefmradio.co.uk`.
- **Nhóm 2 — Đường dẫn sâu & Đối chiếu Giới hạn Tập dữ liệu (`3/3 PASS`)**:
  - `https://github.com/scikit-learn/scikit-learn` (`LEGITIMATE`), `https://www.google.com/search?q=machine+learning&hl=vi` (`LEGITIMATE`), và `https://vnexpress.net/ai-bao-mat-2026-4819203.html` (ghi nhận trung thực hiện tượng *Shortcut Learning* trên tên miền ngoài whitelist).
- **Nhóm 3 — Phishing Cổ điển, Che giấu Lexical & Domain Lạ Không Scheme (`12/12 PASS`)**:
  - Bắt trọn IPv4 nội bộ/công khai, IPv6, cổng `:8080`, đánh lừa `@`, `//`, mã hóa `%xx`, subdomain ngẫu nhiên trên `pages.dev`/`github.io`, root phishing ngắn có HTTPS (`https://secure-vietcombank-login.com`), và tên miền lừa đảo gõ tắt không có scheme (`www.seedjfly.top`).
- **Nhóm 4 — IDN Homograph, Ký tự Phiên âm IPA & Typosquatting Đa Subdomain (`13/13 PASS`)**:
  - Bắt trọn chữ Hy Lạp (`cloudflαre.com`, `gοοgle.com`, `vietcοmbank.com.vn`), Cyrillic (`раураӏ.com`, `аррӏе.com`), Punycode chữ thường/HOA (`xn--ggle-0nda.com`, `XN--80AK6AA92E.COM`), Zero-Width `U+200B`, ký tự phiên âm quốc tế IPA `ɑ` (`exɑmple.org`), giả mạo qua subdomain di động (`https://m.paypaI.com/signin`, `https://m.rnicrosoft.com/auth`), và ví điện tử 4 ký tự Việt Nam (`https://m0mo.vn`).
- **Nhóm 5 — Giao thức Độc hại, Injection & Red-Team Bypasses (`12/12 PASS`)**:
  - Chặn `javascript:`, `data:text/html`, chèn tab điều khiển `java\tscript:alert(1)`, Open-Redirect mã hóa 2 lớp (`?continueUrl=https%253A%252F%252Fevil.xyz`), lách đường dẫn bằng dot-segment (`docs.google.com/./forms/...`), cổng lạ `:8443` trên `.edu.vn`, subdomain `.edu.vn` bị chiếm quyền dựng trang `login.php`, XSS/SQLi, port `:99999`, IPv6 lỗi cú pháp và URL biên `4.000` ký tự.

---

## 3. Cách Chạy Lại Bộ Kiểm Thử

- Script kiểm thử tự động: [run_qa_suite.py](../tests/run_qa_suite.py)
- Kết quả JSON chi tiết: [qa_results.json](../tests/qa_results.json)
- Lệnh thực thi:
  ```powershell
  cd C:\Users\Khanh\.gemini\antigravity\scratch\phishing_url_demo
  .\.venv\Scripts\python.exe tests\run_qa_suite.py
  ```
