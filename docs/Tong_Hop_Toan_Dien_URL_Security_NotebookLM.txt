# TÀI LIỆU TỔNG HỢP TOÀN DIỆN ĐỒ ÁN: PHÁT HIỆN ĐƯỜNG DẪN LỪA ĐẢO (PHISHING URL DETECTION) & HỆ THỐNG WEB DEMO "URL SECURITY"

## 1. Thông tin chung về Đồ án & Nhóm thực hiện
- **Tên đề tài**: *Machine Learning in URL Detection* — Nghiên cứu, huấn luyện mô hình Học máy phát hiện liên kết lừa đảo (Phishing URL) và xây dựng hệ thống kiểm thực thực chiến **URL Security**.
- **Môn học**: Học máy cho bảo mật (*Machine Learning for Security*).
- **Trường**: Trường Đại học Công Thương TP.HCM (HUIT).
- **Giảng viên hướng dẫn (GVHD)**: ThS. Hoàng Quốc Việt.
- **Nhóm thực hiện — Nhóm 6**:
  1. Nguyễn Văn Thiên Phúc — MSSV: `2033230230`
  2. Nguyễn Văn Khanh — MSSV: `2033222040`
  3. Nguyễn Minh Vũ — MSSV: `2033230328`
  4. Võ Thị Thùy Trang — MSSV: `2033230303`
  5. Trần Thị Thảo Vy — MSSV: `2033230334`
- **Hệ sinh thái tài nguyên dự án**:
  - Mã nguồn & Web Demo GitHub: https://github.com/Kenbachkhoa1234/Machine_Learning
  - Bộ dữ liệu gốc (PhiUSIIL Phishing URL Dataset trên Kaggle): https://www.kaggle.com/datasets/ndarvind/phiusiil-phishing-url-dataset
  - Google Colab Notebook huấn luyện: https://colab.research.google.com/drive/1FES0v_ukQRNdw4bNZ7Bi8VvQHlxh6P3t?usp=sharing
  - Thư mục lưu trữ Dữ liệu & Mô hình (`phishing_url_model.pkl`): https://drive.google.com/drive/u/1/folders/1uh-qkfegs4C7mHjJRMV7WXnLds2AVOvU

---

## 2. Đặt vấn đề & Mục tiêu Nghiên cứu
Tấn công lừa đảo trực tuyến (Phishing) hiện là cửa ngõ phổ biến nhất dẫn tới đánh cắp tài khoản ngân hàng, mã xác thực OTP, phiên đăng nhập doanh nghiệp (SSO/OAuth) và phát tán mã độc. Các phương pháp danh sách đen (Blacklist) truyền thống luôn đi chậm một bước trước hàng chục nghìn tên miền lừa đảo mới sinh ra mỗi ngày và chỉ tồn tại vài giờ.

Học máy dựa trên đặc trưng hình thái chuỗi đường dẫn (*Lexical URL Detection*) có ưu thế vượt trội:
1. **Tốc độ phản hồi tính bằng mili-giây** (không cần tải trang web độc hại về máy người dùng, tránh rủi ro kích hoạt mã độc *drive-by download*).
2. **Độc lập với dịch vụ bên thứ ba** (không phụ thuộc truy vấn WHOIS chậm chạp hay nội dung HTML bị che giấu sau CAPTCHA).

Tuy nhiên, đồ án này đặt ra một câu hỏi thực tiễn sâu sắc hơn một bài tập huấn luyện thông thường:
> **"Tại sao một mô hình Học máy đạt độ chính xác tới 99,57% trên tập kiểm thử chuẩn vẫn có thể thất bại nặng nề khi đưa vào môi trường Web thực tế — vừa báo nhầm đường dẫn hợp lệ, vừa bỏ lọt các cuộc tấn công giả mạo ký tự tinh vi? Và làm thế nào để giải quyết triệt để mà không đánh mất tốc độ lẫn độ chính xác gốc?"**

---

## 3. Dữ liệu Huấn luyện, 27 Đặc trưng Hình thái & Mô hình Lõi

### 3.1. Xử lý bộ dữ liệu PhiUSIIL và Chống rò rỉ dữ liệu (Zero Data Leakage)
- Bộ dữ liệu gốc **PhiUSIIL Phishing URL Dataset** gồm `235.795` mẫu.
- Sau bước làm sạch giá trị rỗng, chuẩn hóa kiểu dữ liệu và loại bỏ các chuỗi URL trùng lặp hoàn toàn, tập dữ liệu sạch còn **`235.370` URL duy nhất**:
  - Lớp hợp lệ (`Legitimate`, nhãn gốc `1`): **`134.850` URL** (`57,29%`).
  - Lớp lừa đảo (`Phishing`, nhãn gốc `0`): **`100.520` URL** (`42,71%`).
- **Quy ước đánh giá chuẩn bảo mật**: Trong bài toán an ninh mạng, lớp cần săn tìm là `Phishing` (`label = 0`), nên mọi chỉ số Precision, Recall, F1-Score đều được tính với lớp dương tính là Phishing (`pos_label = 0`).
- **Chia tách dữ liệu độc lập**: Dữ liệu sạch được chia phân tầng (`stratify`, `random_state = 42`) theo tỷ lệ chuẩn **`70% Train` (`164.759` URL) / `15% Validation` (`35.305` URL) / `15% Held-Out Test` (`35.306` URL)**. Tập Test hoàn toàn bị cô lập trong suốt quá trình chọn mô hình.

### 3.2. Hệ thống 27 Đặc trưng Hình thái Chuỗi (27 Lexical Features)
Thay vì dùng các cột đặc trưng HTML có sẵn trong file CSV (vốn đòi hỏi phải tải trang đích khi chạy thực tế), nhóm tự thiết kế mô-đun trích xuất trực tiếp **27 đặc trưng thuần chuỗi URL** (`url_features.py`), chia làm 4 cụm:
1. **Cụm kích thước & phân vùng cấu trúc**: Độ dài toàn URL (`url_length`), độ dài tên miền (`hostname_length`), độ dài đường dẫn (`path_length`), độ dài tham số truy vấn (`query_length`), số lượng nhãn tên miền phụ (`subdomain_count`), độ dài nhãn dài nhất.
2. **Cụm đếm ký tự đặc biệt & dấu phân tách**: Số dấu chấm (`.`), dấu gạch ngang (`-`), gạch dưới (`_`), gạch chéo (`/` — `num_slashes`), dấu hỏi (`?`), dấu bằng (`=`), dấu và (`&`), chữ số, chữ cái.
3. **Cụm tỷ lệ thống kê & Độ hỗn loạn thông tin**: Entropy Shannon của chuỗi URL và tên miền (đo mức độ ngẫu nhiên kiểu chuỗi băm tự sinh `b4e921f0...`), tỷ lệ chữ số trên độ dài URL, tỷ lệ chữ in hoa.
4. **Cụm tín hiệu ngữ nghĩa & giao thức rủi ro**: Có giao thức mã hóa HTTPS (`has_https`), dùng trực tiếp địa chỉ IPv4/IPv6 thay vì tên miền (`has_ip`), chứa ký tự `@` đánh lừa vùng định danh (`has_at`), chứa `//` chuyển hướng lồng trong đường dẫn (`has_double_slash_path`), cổng phi chuẩn, và số lượng từ khóa nhạy cảm thường gặp ở trang thu thập mật khẩu (`login`, `verify`, `secure`, `account`, `update`, `signin`, `bank`... — `suspicious_word_count`).

### 3.3. Lựa chọn Mô hình Random Forest (`phishing_url_model.pkl`)
Qua đối sánh thực nghiệm nhiều họ thuật toán (Logistic Regression, Decision Tree, Random Forest, Gradient Boosting / MLP), mô hình **Random Forest gồm 300 cây quyết định (`n_estimators = 300`, `scikit-learn 1.6.1`)** cho sự cân bằng tốt nhất giữa độ chính xác (`99,57%`), khả năng kháng nhiễu phi tuyến tính giữa các đặc trưng đếm/tỷ lệ và tốc độ suy luận tức thì trên CPU mà không cần GPU.

---

## 4. Phát hiện Đột phá từ Kiểm toán Dữ liệu: Hiện tượng "Học Đường Tắt" (*Dataset Shortcut Learning*)

Khi nhóm không dừng lại ở con số `99,57%` trên Colab mà tiến hành kiểm toán phân phối sâu trên toàn bộ `235.370` dòng dữ liệu và thử nghiệm thực chiến trên Web, nhóm phát hiện ra nguyên nhân gốc rễ khiến các mô hình học máy tĩnh bị đánh lừa ngoài đời thực:

1. **Thiên lệch cấu trúc trong tập dữ liệu PhiUSIIL**:
   - Toàn bộ **`100%` trong số `134.850` URL sạch (`Legitimate`)** của bộ PhiUSIIL đều chỉ là trang chủ gốc bắt đầu bằng `https://www.`, hoàn toàn **không có đường dẫn con (`path == ""`)** và có độ dài tối đa chỉ `58` ký tự!
   - Trong khi đó, các mẫu `Phishing` được thu thập từ PhishTank/OpenPhish lại chứa đầy đủ đường dẫn sâu (`/login/verify.php?...`) hoặc dùng `http://`.
2. **Hệ quả Toán học trên Rừng ngẫu nhiên**:
   - Phân tích trọng số đặc trưng (Feature Importance) chỉ ra tới **`71,95%` tổng độ quan trọng Gini** của cả 27 biến bị dồn vào đúng 3 biến cấu trúc:
     - `has_https`: **`43,45%`**
     - `num_slashes` (số dấu `/`): **`16,11%`**
     - `path_length` (độ dài phần đường dẫn): **`12,39%`**
3. **Hai hệ lụy nghiêm trọng khi triển khai thực tế**:
   - **Hệ lụy 1 — Báo động giả hàng loạt (False Positive)**: Người dùng chỉ cần copy trang chủ ngân hàng từ thanh địa chỉ Chrome bị dính thêm 1 dấu `/` ở cuối (`https://vietcombank.com.vn/`), gõ tắt thiếu `https://` (`www.microsoft.com`), mở kho mã nguồn `https://github.com/elastic/ember` hay đăng nhập qua cổng doanh nghiệp SSO/OAuth dài hơn 100 ký tự — mô hình gốc lập tức phán **`100% Phishing`**!
   - **Hệ lụy 2 — Bỏ lọt tấn công giả mạo tinh vi (False Negative)**: Ngược lại, kẻ tấn công chỉ cần mua chứng chỉ SSL miễn phí (`https://`) cho một tên miền giả mạo ký tự đồng hình ngắn gọn như `https://www.аррӏе.com` (chữ Kirin), `https://www.cloudflαre.com` (chữ Hy Lạp), `https://www.paypaI.com` (chữ `I` hoa giả chữ `l` thường), hoặc `https://www.goo​gle.com` (chèn ký tự tàng hình Zero-Width `U+200B`) — mô hình gốc chấm xác suất lừa đảo bằng **`0,00` đến `0,02`** (cho qua hoàn toàn!).

> **Kết luận quan trọng**: Việc huấn luyện lại (retrain) mô hình trên cùng bộ dữ liệu PhiUSIIL không thể giải quyết được hai lỗi này. Giải pháp đúng đắn về mặt kỹ thuật bảo mật là giữ nguyên mô hình lõi `phishing_url_model.pkl` (đã tối ưu trên miền đặc trưng hình thái cổ điển) và thiết kế **Kiến trúc Phòng thủ Đa tầng** bao bọc xung quanh mô hình.

---

## 5. Kiến trúc Hệ thống "URL Security" & Phương pháp Giải quyết Đa tầng

Hệ thống Web Demo được xây dựng trên nền tảng **FastAPI + NumPy Inference Engine + SQLite WAL**, xử lý mỗi truy vấn qua **4 tầng liên hoàn**:

### Tầng 1: Khử nhiễu Giao thức & Chuẩn hóa RFC 3986 Có Điều kiện (`homograph_guard.py`)
- **Chặn giao thức thực thi mã độc**: Loại bỏ toàn bộ ký tự điều khiển và khoảng trắng ASCII ẩn (`[\x00-\x20]`) trước khi xét tiền tố để chặn đứng cả biến thể lách luật `java\tscript:alert(1)` hay `data:text/html;base64,...`.
- **Chuẩn hóa dấu `/` và giao thức có điều kiện (Bài học từ thực nghiệm 10.000 URL)**:
  - Hạ chữ thường cho `scheme` và `hostname`; lược bỏ `#anchor` điều hướng nội trang ngắn vô hại (`#top`).
  - *Chi tiết đắt giá*: Ở lần thử nghiệm đầu tiên, việc tự động cắt dấu `/` cuối trên *mọi* tên miền đã làm số ca bỏ lọt Phishing trên tập 10.000 URL tăng từ `30` lên `543` (độ chính xác tụt xuống `94,45%`), bởi hàng trăm trang lừa đảo dựng trên `*.web.app/`, `*.firebaseapp.com/` có dấu `/` cuối làm tín hiệu nhận diện. Nhóm đã sửa lại bằng quy tắc: **chỉ chuẩn hóa dấu `/` gốc và tự động gắn `https://` mặc định cho các tên miền chính thống đã xác thực**, còn tên miền lạ gõ tắt (như `www.seedjfly.top`) phải giữ nguyên `has_https = 0`. Độ chính xác lập tức phục hồi về mức đỉnh **`9.957 / 10.000 (99,57%)`**.

### Tầng 2: Giải mã IDNA 2 chiều, Khung xương UTS #39 & Tách `eTLD+1` Bắt Bẫy Thị giác
- **IDNA 2 chiều (`Unicode <-> Punycode`)**: Dù kẻ tấn công gửi tên miền hiển thị tiếng Hy Lạp/Kirin (`cloudflαre.com`) hay gửi chuỗi mã hóa thô (`xn--pypal-4ve.secure-update.click`, kể cả viết hoa `XN--80AK6AA92E.COM`), hệ thống đều giải mã hai chiều để kiểm tra đối xứng.
- **Ánh xạ Khung xương Thị giác (UTS #39 Skeleton)**: Chuyển đổi hơn 60 ký tự đồng hình thuộc bảng chữ **Hy Lạp** (`α, ο, ν, ρ...`), **Kirin/Cyrillic** (`а, е, і, о, р, с, х, ӏ...`), **Phiên âm Quốc tế IPA** (`ɑ, ɡ, ɪ...`), **Chữ số La Mã** (`ⅼ` U+217C, `Ⅰ`) và **Latin mở rộng có dấu** (`ạ`) về khung xương ASCII gốc để phát hiện hành vi trộn bảng mã hoặc mạo danh thương hiệu lớn, đồng thời xuất mảng tọa độ `char_xray` giúp giao diện **tô đỏ chính xác từng ký tự giả mạo**.
- **Phát hiện Ký tự Tàng hình (`Zero-Width`)**: Bắt ngay các mã ẩn `U+200B`, `U+200C`, `U+200D`, `U+FEFF` chèn giữa tên miền (`goo​gle.com`).
- **Trích xuất Tên miền Đăng ký Gốc (`eTLD+1`) chống Typosquatting đa Subdomain**:
  - Hỗ trợ hậu tố công cộng nhiều phần (`.com.vn`, `.edu.vn`, `.gov.vn`, `.co.uk`...) để lấy đúng nhãn thương hiệu gốc bất kể kẻ tấn công gắn thêm subdomain phụ như `m.paypaI.com` hay `login.rnicrosoft.com`.
  - Bắt trọn các phép thế thị giác thuần ASCII: chữ `'I'` hoa giả chữ `'l'` thường (`paypaI.com`), ghép `'rn'` giả `'m'` (`rnicrosoft.com`), `'vv'` giả `'w'` (`vvhatsapp.com`), số `'0'` giả `'o'` (`vietc0mbank.com`, `g00gle.com`), số `'1'` giả `'l'` (`paypa1.com`), cùng khoảng cách chỉnh sửa **Damerau-Levenshtein = 1** (`cloudflaure.com`, `googel.com`, `m0mo.vn`).

### Tầng 3: 10 Cổng Kiểm định Ngữ cảnh Chính thống & Same-Domain OAuth Redirect
Để khắc phục lỗi báo động giả trên đường dẫn sâu mà **không tạo lỗ hổng cho kẻ tấn công lợi dụng nền tảng lớn**, một đường dẫn chỉ được công nhận ngữ cảnh chính thống khi vượt qua đồng thời **10 cổng kiểm tra nghiêm ngặt**:
1. Giao thức bắt buộc là `https` (không chấp nhận `http://` tường minh).
2. Cổng kết nối chỉ được là mặc định hoặc `443` (chặn các dịch vụ lạ chạy trên `:8080`, `:8443`).
3. Không có dấu hiệu Homograph hay Typosquatting (`homograph_risk == "NONE"`).
4. Không chứa gạch chéo ngược `\` trong vùng định danh (`https://google.com\evil.xyz`).
5. Không chứa ký tự `@` đánh lừa quyền sở hữu (`https://vietcombank.com.vn@evil.xyz`) hoặc `//` lồng trong đường dẫn.
6. Không chứa mẫu tấn công XSS / SQL Injection sau khi giải mã URL nhiều lớp.
7. **Loại trừ cứng toàn bộ nền tảng lưu trữ nội dung người dùng (UGC / Free Cloud Hosting)**: `github.io`, `gist.github.com`, `githubusercontent.com`, `pages.dev`, `workers.dev`, `firebaseapp.com`, `web.app`, `my.canva.site`, `sites.google.com`, `forms.gle`, `vercel.app`, `netlify.app`, `ngrok-free.app`... **không bao giờ** được tự động tin cậy!
8. **Chặn đường dẫn chia sẻ công khai nhạy cảm**: Chuẩn hóa `posixpath.normpath` kết hợp giải mã nhiều vòng `_multi_unquote` (chống trò lách `/./forms` hoặc `/%66orms`) để chặn các prefix `/forms`, `/url`, `/redirect`, `/d/e`, `/uc` trên Google Docs/Drive.
9. **Chống chiếm quyền Subdomain Giáo dục / Hành chính (`.edu.vn`, `.gov.vn`)**: Nếu đường dẫn trên `.edu.vn` xuất hiện từ khóa thu thập tài khoản (`login`, `signin`, `verify`, `password`, `webmail-auth`...), hệ thống hủy quyền ưu tiên và chuyển cho mô hình ML phán xử.
10. **Phân biệt Chuyển hướng OAuth Nội bộ (Same-Domain OAuth Redirect) với Open-Redirect Độc hại**:
    - Với các tham số `redirect_uri=`, `continueUrl=`, `url=`, `q=`, `next=` (giải mã tối đa 3 lớp `%253A%252F%252F`), nếu đích chuyển hướng trỏ ra một tên miền bên ngoài (`https://www.google.com/url?q=http://evil.xyz`) → **Chặn ngay là `PHISHING`**.
    - Nhưng nếu cả trang nguồn và trang đích trong `redirect_uri` đều dùng `https://` và thuộc **cùng một tên miền gốc chính thức đã qua kiểm định** (ví dụ luồng đăng nhập AWS thật: `signin.aws.amazon.com` chuyển hướng về `console.aws.amazon.com`) → **Cho phép hợp lệ (`LEGITIMATE`)!**

### Tầng 4: Động cơ Suy luận NumPy Tốc độ cao & Lưu trữ `SHA-256` Chống Đầu độc Cache
- **Tối ưu suy luận nhanh gấp 3,3 lần (`app.py`)**: Chuyển từ `pandas.DataFrame` sang mảng `numpy.float32` tiền cấp phát và tắt chi phí tạo luồng thừa (`n_jobs = 1`) cho từng request HTTP đơn lẻ, kéo độ trễ trung bình từ `94,24 ms` xuống chỉ còn **`~28 – 45 ms / request`** (khi quét hàng loạt 10.000 URL thì bật `n_jobs = -1` đạt tốc độ **`> 2.050 URL / giây`**).
- **Lưu trữ & Tra cứu ngược `SHA-256` kiểu VirusTotal (`security_store.py`)**:
  - Mỗi kết quả quét được lưu vào cơ sở dữ liệu **SQLite chế độ WAL (`Write-Ahead Logging`)** với khóa chính là mã băm `SHA-256`.
  - **Chống đầu độc bộ nhớ đệm (*Anti-Cache-Poisoning*)**: Hàm `build_collision_free_cache_key` đảm bảo các URL gài ký tự tàng hình (`goo​gle.com`), `@`, `\` hay chữ `'I'` hoa giả mạo sinh ra mã `SHA-256` hoàn toàn độc lập — tuyệt đối không ghi đè làm hỏng kết quả của trang `https://www.google.com` thật.
  - **Bảo vệ quyền riêng tư**: Tự động che mọi tham số truy vấn nhạy cảm (`?token=SECRET...` → `?[...]`) và chuỗi khóa ngẫu nhiên entropy cao trên đường dẫn trước khi ghi xuống đĩa.
  - Người dùng có thể bấm nút **Copy** mã `SHA-256` và dán ngược chuỗi 64 ký tự hex vào ô tìm kiếm để mở lại tức thì bản ghi đã lưu hoặc bấm **Phân tích lại**.

---

## 6. Kiểm thực Chi tiết qua 4 Nhóm Kịch bản URL Đối kháng (Trọng tâm Thuyết minh Video)

Để chứng minh năng lực thực tế một cách trực quan nhất, hệ thống được thử lửa qua **4 nhóm kịch bản URL đối kháng đặc trưng**:

### Nhóm 1: URL Hợp lệ Sạch rõ (White / Legitimate Chuẩn) — Đạt `100% LEGITIMATE`
- **Các mẫu tiêu biểu**:
  - `https://vietcombank.com.vn/`
  - `https://techcombank.com/`
  - `https://portal.office.com/`
  - `https://www.google.com/search?q=ml`
  - `https://github.com/elastic/ember`
- **Điểm đáng chú ý**: Cả 5 mẫu này nếu đưa vào mô hình gốc trên Colab đều bị báo nhầm `100% Phishing` chỉ vì có dấu `/` cuối hoặc có đường dẫn con. Nhờ Tầng 1 (chuẩn hóa RFC 3986 có điều kiện) và Tầng 3 (kiểm định ngữ cảnh), hệ thống nhận diện chính xác **5/5 là `LEGITIMATE`**.

### Nhóm 2: URL Lừa đảo Bẩn rõ (Black / Phishing Kinh điển) — Bắt trúng `100% PHISHING`
- **Các mẫu tiêu biểu**:
  - `http://192.168.1.9/vietcombank/login/verify-account.php?ref=9918273645123456` (Dùng IP trực tiếp + HTTP + từ khóa nhạy cảm).
  - `http://xn--pypal-4ve.secure-update.click/signin/account/confirm?u=victim01&step=2` (Ẩn ký tự Kirin dưới chuỗi Punycode `xn--pypal-4ve`).
  - `http://secure-vietcombank.verify-account.xyz/login?id=8821&session=9a8f7e6d5c4b3a21` (Nhồi nhiều subdomain giả thương hiệu trên đuôi `.xyz`).
  - `http://login-verify.paypal-support.top/auth/confirm/index.php?token=7712998123`
- **Cách hệ thống phản hồi**: Chặn đứng 100%, đồng thời dịch ngược chuỗi `xn--pypal-4ve` thành ký tự `'а'` bảng mã Kirin (Cyrillic) để giải thích rõ ràng trên màn hình cho người dùng phổ thông hiểu ngay mối nguy hiểm.

### Nhóm 3: Bẫy Phishing nhưng Dễ bị Nhầm là Legit (Chống Lọt Lưới / Anti-False-Negative) — Bắt sống `100% (0% Lọt lưới)`
Đây là nhóm tấn công nguy hiểm nhất ngoài đời thực: có ổ khóa `https://`, tên miền rất ngắn, không có dấu gạch ngang hay từ khóa nhạy cảm, hoặc núp bóng ngay trên hạ tầng thật của Google/Cloudflare:
- `https://www.cloudflαre.com/` → **Bắt sống `PHISHING`**: Tô đỏ đúng chữ `'α'` Hy Lạp và hiển thị tên miền thực tế `www.xn--cloudflre-wxg.com`.
- `https://www.аррӏе.com` → **Bắt sống `PHISHING`**: Dù mô hình ML gốc bị lừa chấm `0,01` (an toàn), bộ lọc Skeleton phát hiện tên miền viết 100% bằng chữ Kirin mạo danh `apple.com`.
- `https://www.paypaI.com` & `https://m.paypaI.com/signin` → **Bắt sống `PHISHING`**: Giữ nguyên chữ `'I'` hoa tô đỏ trên giao diện, chỉ rõ thủ đoạn thay chữ `'l'` thường bằng chữ `'I'` hoa kể cả dưới subdomain `m.`.
- `https://paypa1.com/home` & `https://vietc0mbank.com/web` → **Bắt sống `PHISHING`**: Bắt lỗi thay chữ bằng số tương tự thị giác (`1 → l`, `0 → o`).
- `https://www.goo​gle.com` → **Bắt sống `PHISHING`**: Phát hiện ký tự tàng hình Zero-Width `U+200B` (và đảm bảo không gây đầu độc cache cho trang `google.com` thật).
- `https://docs.google.com/forms/d/e/1FAIpQLSfFake/viewform` & `https://vcb-portal.pages.dev/check` & `https://bit.ly/3xK9mPq` → **Bắt sống `PHISHING`**: Nhờ quy tắc không bao giờ tin cậy mù quáng vào biểu mẫu công cộng `/forms`, nền tảng hosting miễn phí `pages.dev` hay dịch vụ rút gọn link ẩn đích đến.

### Nhóm 4: Bẫy Legit Phức tạp Dễ bị Nhầm là Phishing (Chống Báo Nhầm / Enterprise SSO & OAuth)
Các đường dẫn đăng nhập doanh nghiệp (Single Sign-On / OAuth 2.0) luôn rất dài (`> 100` ký tự), nhiều dấu gạch ngang, nhiều subdomain và chứa hàng loạt từ khóa `login`, `oauth`, `authorize`, `redirect_uri`:
- **Xử lý chuẩn xác các cổng SSO / Cloud thật thành `LEGITIMATE`**:
  - `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=00000003-0000-0ff1-ce00&response_type=code` → **`LEGITIMATE`** (Cổng xác thực Microsoft Entra ID thật).
  - `https://us-east-1.signin.aws.amazon.com/oauth?Action=login&redirect_uri=https%3A%2F%2Fconsole.aws.amazon.com%2F` → **`LEGITIMATE`** (Nhờ thuật toán kiểm định **Same-Domain OAuth Redirect** xác nhận đích chuyển hướng `console.aws.amazon.com` nằm cùng hệ sinh thái chính chủ `amazon.com`).
  - `https://eu-west-2.console.cloud-platform.google.com/iam-admin/serviceaccounts/update?project=prod-sec-01` → **`LEGITIMATE`**.
- **Đồng thời bóc trần chuẩn xác tên miền giả mạo trà trộn trong câu hỏi**:
  - `https://my-account.sso.vietcombank-digital.com.vn/auth/verify?state=eyJhbGciOiJIUzI1NiJ9&lang=vi` → **Chặn đúng là `PHISHING`!** Lý do: Vietcombank thật chỉ sở hữu `vietcombank.com.vn`, còn cái tên `vietcombank-digital.com.vn` chính là thủ đoạn **Combosquatting** (ghép tên thương hiệu với từ khóa `-digital`)!

---

## 7. Bảo mật Hệ thống Chống Vượt Rào (*Anti-Evasion* & Web Hardening)

Một sai lầm phổ biến của các trang demo học máy là phơi bày toàn bộ xác suất dự đoán (`predict_proba = 0.512`), danh sách 27 đặc trưng và ngưỡng cắt (`threshold = 0.50`) ra JSON API. Kẻ tấn công chỉ cần viết kịch bản thử sai vài trăm lần (*Oracle Probing*) là tìm ra cách thêm bớt ký tự để kéo điểm xuống `0.49` vượt qua bộ lọc.

Hệ thống **URL Security** khắc phục triệt để theo chuẩn thực chiến:
1. **Giải thích An toàn (*Safe Explainability*)**: Chỉ trả về nhận định ngôn ngữ tự nhiên về dấu hiệu rủi ro (ký tự giả mạo, Punycode, IP trần, thiếu HTTPS, Open-Redirect...), ẩn tuyệt đối tên mô hình (`Random Forest`), trọng số, danh sách biến và điểm xác suất nội bộ ở phía máy chủ.
2. **Đóng bề mặt dò quét API**: Tắt hoàn toàn `/docs`, `/redoc`, `/openapi.json` (`HTTP 404`).
3. **HTTP Security Headers đầy đủ**: Gắn `Content-Security-Policy` chặt chẽ, `X-Frame-Options: DENY` chống nhúng Clickjacking, `X-Content-Type-Options: nosniff` và `Referrer-Policy: no-referrer`.
4. **Giới hạn tốc độ chống cào dữ liệu & chống tràn bộ nhớ**: Bộ `SlidingWindowRateLimiter` cấu trúc **Bounded LRU** giới hạn `60 lượt kiểm tra / phút / IP` (tách riêng khỏi API tải lịch sử để giao diện hoạt động mượt mà), tự động thu hồi bộ nhớ IP hết hạn.

---

## 8. Tổng hợp Kết quả Thực nghiệm Định lượng

| Hạng mục Kiểm chứng Thực nghiệm | Quy mô | Bản ML Gốc (`Colab`) | Hệ thống `URL Security` Đã Tối Ưu | Ý nghĩa Khoa học & Thực tiễn |
|---|---:|---:|---:|---|
| **1. Tập Test Độc lập (PhiUSIIL Held-Out)** | `10.000` URL | `9.957 / 10.000` (`99,57%`) | **`9.957 / 10.000` (`99,57%`)** | Giữ trọn độ chính xác đỉnh cao; giảm báo nhầm `FP` từ `13` xuống `12` (`FPR = 0,209%`), `F1 = 99,495%` |
| **2. Bộ Stress-Test OOD & Tấn công Thực chiến** | `56` kịch bản | `31 / 56` (`55,4%`) | **`55 / 56` (`98,2%`)** | **Tăng `+42,8` điểm phần trăm** khả năng phòng thủ ngoài đời thực! |
| **3. Bộ Kiểm thử Tự động QA, Red-Team & Bảo mật** | `58` test cases | Không có | **`58 / 58 PASS` (`100%`)** | Gồm `50/50` ca URL/OAuth/Red-Team + `8/8` ca chống lộ ML, chống đầu độc Cache & CSP Headers |
| **4. Tốc độ Xử lý & Phản hồi** | Đơn lẻ & Hàng loạt | `~94,2 ms` / URL đơn | **`~30 – 45 ms` / URL đơn** (`> 2.050` URL/giây ở chế độ batch) | Nhanh gấp `> 2 – 3 lần` trên từng truy vấn người dùng |

---

## 9. Nhìn nhận Trung thực Giới hạn Khoa học & Hướng Phát triển Tiếp theo

Nhóm giữ tinh thần trung thực học thuật khi chỉ rõ những giới hạn cố hữu của phương pháp **chỉ phân tích tĩnh chuỗi URL (Static Lexical & Hostname Analysis)** mà không truy cập mạng:
1. **Đường dẫn sâu trên các tên miền hợp pháp chưa nằm trong tập định danh chính thức**: Ví dụ một bài báo dài có nhiều chữ số định danh như `https://vnexpress.net/ai-bao-mat-2026-4819203.html` hoặc cổng nội bộ riêng của một công ty nhỏ (`example-corp.co.uk/identity/confirm-signin?...`) vẫn bị mô hình Random Forest cảnh báo thận trọng là `PHISHING` do hiệu ứng *Shortcut Learning* từ bộ huấn luyện gốc. Nhóm chủ động **không hardcode tràn lan** mọi trang báo để giữ tính khách quan của thực nghiệm.
2. **Tên miền lừa đảo mới đăng ký có cấu trúc từ điển hoàn toàn sạch**: Nếu kẻ tấn công mua một tên miền mới hoàn toàn không mạo danh thương hiệu quen thuộc (ví dụ `https://happy-garden-coffee.com`), cài HTTPS chuẩn và đặt nội dung lừa đảo ngay ở trang chủ gốc không có đường dẫn con, thì chỉ nhìn chuỗi ký tự URL là chưa đủ cơ sở kết luận.

**Định hướng mở rộng trong nghiên cứu tiếp theo**:
- **Về mặt dữ liệu huấn luyện**: Kết hợp huấn luyện đa nguồn (Cross-Dataset Training) cùng các bộ dữ liệu có chứa đường dẫn sâu hợp pháp như **ISCX-URL-2016**, **PhishStorm** hoặc thu thập đường dẫn con từ bảng xếp hạng **Tranco Top Domains** để triệt tiêu tận gốc hiện tượng *Shortcut Learning* theo độ dài đường dẫn.
- **Về mặt kiến trúc hệ thống**: Bổ sung tầng kiểm tra siêu dữ liệu mạng nhẹ (*Lightweight Network Metadata*) gồm tuổi tên miền qua giao thức **RDAP/WHOIS** (tên miền vừa đăng ký dưới 7 ngày có rủi ro rất cao) và thông tin nhà cấp phát chứng chỉ số **TLS / Certificate Transparency Logs** mà vẫn không cần tải mã thực thi của trang đích.
