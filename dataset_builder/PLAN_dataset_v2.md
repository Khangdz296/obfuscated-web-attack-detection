# Kế hoạch xây dựng lại Dataset Obfuscation (v2)

> Tài liệu này tự chứa đầy đủ ngữ cảnh. Paste vào một phiên làm việc mới là đủ để tiếp tục,
> không cần đọc lại lịch sử hội thoại trước.

---

## 0. Ngữ cảnh dự án

**Đề tài NCKH:** Phát hiện tấn công web SQL Injection và XSS bằng mô hình
character-level CNN-LSTM. Mục tiêu nghiên cứu là **so sánh kiến trúc**:
CNN-LSTM tuần tự (`Embedding → CNN → Pool → CNN → Pool → LSTM → Dense`)
so với CNN-LSTM song song (`Embedding → [CNN ∥ LSTM] → Concat → Dense`).

**Thư mục gốc:** `c:\Users\MKhang\Desktop\WebAppModel`

| Đường dẫn | Vai trò |
|---|---|
| `generate_obfu_dataset.py` | Generator dataset obfuscation (nằm **ngoài** repo git) |
| `obfuscated-web-attack-detection/` | Repo git chính (remote: `github.com/Khangdz296/obfuscated-web-attack-detection`) |
| `obfuscated-web-attack-detection/DataSet/obfu_http_dataset_full.csv` | Dataset obfuscation v1, 100.001 dòng |
| `obfuscated-web-attack-detection/DataSet/csic_database.csv` | CSIC 2010, 61.065 dòng |
| `obfuscated-web-attack-detection/DataSet/SQLInjection_XSS_MixDataset.1.0.0.csv` | Kaggle payload-only, 156.636 dòng |
| `obfuscated-web-attack-detection/preprocessing/preprocess_data.py` | Nạp + làm sạch + chia tập dùng chung |
| `obfuscated-web-attack-detection/cnn_lstm/CNN_LSTM.py` | Script train chính |
| `obfuscated-web-attack-detection/dataset_builder/` | Thư mục mới, chứa quality gate + hằng số cứu hộ |

**Vai trò dataset obfuscation:** vừa là **nguồn train** (train riêng một model trên nó),
vừa là **tập test chéo** (model train trên Kaggle/CSIC được đánh giá trên nó và ngược lại).
Đây là điểm quan trọng — nó không chỉ là tập test.

**Chính sách tiền xử lý bất di bất dịch:** không URL-decode, không HTML-unescape,
không lowercase, chỉ chuẩn hoá khoảng trắng. Mục đích là giữ nguyên dấu vết obfuscation
(`%27`, `%3C`, `&#x...;`, comment SQL, chữ hoa/thường lẫn lộn) cho model học.

**Phạm vi hiện tại:** chỉ tập trung CNN-LSTM. Tạm bỏ qua `cnn_only/`, `lstm_only/`,
`cnn_lstm_parallel/`, và toàn bộ phần `webapp/`.

---

## 1. Phần việc ĐÃ HOÀN THÀNH (đừng làm lại)

### 1.1. Sửa trong `preprocessing/preprocess_data.py`

| Thay đổi | Chi tiết |
|---|---|
| Đường dẫn dataset | Thêm `DATA_DIR = PROJECT_ROOT / "DataSet"`; `KAGGLE_PATH`, `CSIC_PATH`, `OBFU_PATH` trỏ vào đó. `OBFU_PATH` giờ là `obfu_http_dataset_full.csv` |
| `to_binary_label()` | Thêm `"anomalous"` vào `attack_words`, thêm `"none"` vào `normal_words` |
| `serialize_http_request()` | Thêm tham số `user_agent` và trường `[USER_AGENT]` vào chuỗi đầu ra |
| `serialize_obfu_http_row()` | **Hàm mới.** Serialize một dòng CSIC-style, giữ cả cookie lẫn User-Agent |
| `load_obfu_http()` | **Hàm mới.** Đọc CSV schema mới (`method`/`url`/`classification`). Tham số `drop_second_order_triggers=True` loại 3.706 dòng trigger |
| `split_dataset_by_column()` | **Hàm mới.** Dùng cột `split` có sẵn thay vì chia lại |
| `load_clean_datasets()` | Key `"obfuscation"` → `"obfu_http"`, gọi `load_obfu_http()` |
| `split_all_datasets()` | Tự phát hiện dataset có cột `split` và ưu tiên dùng nó |

Hàm `load_obfuscation()` cũ (đọc `.xlsx`) **vẫn còn nguyên**, không xoá.

### 1.2. Sửa trong `cnn_lstm/CNN_LSTM.py`

| Thay đổi | Chi tiết |
|---|---|
| Đường dẫn | Lấy trực tiếp từ `prep.KAGGLE_PATH` / `prep.CSIC_PATH` / `prep.OBFU_PATH` |
| `MAX_LEN` | `1024` → `768` (p99 của chuỗi serialize là 590, max 1595; 768 chỉ cắt 0,26%) |
| Vòng đánh giá | Chạy trên cả `test` **và** `test_heldout`; nhãn kết quả là `<source>:test_heldout` |
| Lấy mẫu nhanh | `--obfu-sample-size` lấy mẫu **trong từng split** bằng `groupby("split").sample(frac=...)` để giữ thiết kế held-out |

> **Bẫy đã gặp:** dùng `groupby(...).apply(...)` trong pandas 3.0 sẽ **mất cột nhóm** (`split`),
> khiến pipeline âm thầm quay về chia ngẫu nhiên. Phải dùng `groupby(...).sample(...)`.

### 1.3. File mới trong `dataset_builder/`

- **`recovered_constants.py`** — toàn bộ hằng số trích từ bytecode của generator
  (59 seed, 30 User-Agent, 12 host, kho từ vựng benign, các tỉ lệ). Bản backup phòng khi
  mất file gốc lần nữa.
- **`quality_gate.py`** — script kiểm định 7 tiêu chí, thoát mã lỗi nếu không đạt.
  Chạy: `python dataset_builder/quality_gate.py`

### 1.4. Đã kiểm chứng chạy được

Lệnh smoke test đã chạy thành công end-to-end:

```bash
python cnn_lstm/CNN_LSTM.py --sample-size 4000 --obfu-sample-size 6000 \
    --epochs 1 --train-sources obfu_http --output-dir <thư mục tạm>
```

Kết quả (1 epoch, 6% dữ liệu — chỉ để xác nhận máy móc chạy, **không có ý nghĩa khoa học**):

| Train → Test | Accuracy | Attack recall |
|---|---|---|
| obfu_http → obfu_http | 87,9% | 94,1% |
| obfu_http → obfu_http:test_heldout | 84,3% | 84,3% |
| obfu_http → kaggle | 69,1% | 56,1% |
| obfu_http → csic | 36,8% | 41,8% |

---

## 2. Kết quả đo được trên dataset v1 (số liệu nền)

> Đây là bằng chứng thực nghiệm dẫn tới toàn bộ kế hoạch bên dưới.
> Một phiên làm việc mới sẽ **không** có các số này nếu không đọc mục này.

### 2.1. Thành phần

- 100.001 dòng: 50.000 `normal` + 50.001 `anomalous` (25.000 SQLi + 25.001 XSS)
- Split hiện tại: train 62.609 / val 13.413 / test 13.427 / test_heldout 10.552
- `test_heldout` có **0 dòng normal** → chỉ đo được recall, accuracy bằng đúng recall
- Chiều dài chuỗi sau serialize: mean 341, p50 337, p95 460, p99 590, max 1595

### 2.2. Đa dạng seed — vấn đề gốc

Đếm trực tiếp trong generator:

| Kho | Số seed |
|---|---|
| `SQLI_BASE` | 20 |
| `SQLI_TIME` | 10 |
| `SQLI_STORED` | 6 |
| `XSS_SCRIPT` / `XSS_EVENT` / `XSS_SVG` / `XSS_OTHER` / `XSS_BLIND` / `XSS_STORED` | 4 / 8 / 4 / 4 / 4 / 4 |
| **Tổng seed duy nhất** | **59** (34 SQLi + 25 XSS) |

- 50.001 dòng attack / 59 seed = **847 dòng mỗi seed**
- Dataset **cũ** (`obfuscation_dataset.xlsx`, đã bỏ) là 177 seed / 150.000 dòng = **847 dòng mỗi seed**
- → **Tỉ lệ lặp y hệt nhau. Vấn đề gốc chưa hề được sửa.**
- **100%** seed xuất hiện trong `test` cũng có trong `train`

### 2.3. Baseline tầm thường phá được dataset

Hồi quy logistic trên TF-IDF char n-gram (2–4), không hiểu SQL/HTML gì cả:

| Tập | Accuracy | Attack recall |
|---|---|---|
| `test` | **99,96%** | 100,00% |
| `test_heldout` | **100,00%** | 100,00% |

Một luật thủ công 7 từ khoá (`'`, `<`, ` or `, `--`, `script`, `select`, `alert`)
đạt 89,78% trên `test` và 98,38% trên `test_heldout`.

### 2.4. Thí nghiệm phân tách nguyên nhân (QUAN TRỌNG)

**Thí nghiệm A — gỡ confound mã hoá:** lấy chính dataset đó, URL-encode payload tấn công
cho giống hệt benign rồi đo lại baseline.

| | Accuracy |
|---|---|
| Payload thô (hiện tại) | 99,96% |
| Payload đã encode | 99,93% |
| **Chênh lệch** | **−0,02 điểm** |

→ **Confound mã hoá KHÔNG phải nguyên nhân chính.** Đừng dồn công sức vào đây.
Lý do: encode xong payload biến thành chuỗi dày đặc `%XX`, chỉ đổi shortcut này lấy shortcut khác.

**Thí nghiệm B — ghi nhớ seed:** dùng 6.095 dòng `plain` (45 seed), chia hai kiểu.

| Cách chia | Accuracy | Recall |
|---|---|---|
| Random split (seed có ở cả hai bên) | 100,00% | 100,00% |
| Unseen-seed holdout (test dùng seed chưa thấy) | 97,77% | **91,43%** |

→ **Đa dạng seed MỚI là nguyên nhân chính.** Khoảng cách 8,6 điểm recall là phần model ăn gian.

### 2.5. Các lối tắt và rò rỉ khác

| Vấn đề | Số đo |
|---|---|
| `method=DELETE` | 2.786 dòng, **100% normal** |
| `content_type=multipart/form-data` | 3.798 dòng, **100% normal** |
| Benign có dấu nháy `'` thô | **0,00%** (attack: 34,40%) |
| Benign có khoảng trắng thô trong URL | **0,00%** (attack: 19,55%) |
| Payload trùng canonical với Kaggle | **16,2%** (7.487/46.295 dòng) |
| Seed xuất hiện nguyên văn trong Kaggle | **19/59** |
| Dòng trigger second-order (không mang payload) | **3.706** |
| Chữ ký `(url\|content)` riêng biệt của attack | 16.752 / 50.001 dòng |

Nguyên nhân benign 0% ký tự thô: generator gọi `quote()` cho mọi giá trị benign
(`q={quote(term)}`, `username={quote(user)}`) nhưng chèn payload tấn công **thô**
(`url=f"{base}?{p}={payload}"`). "Hard negative" `o'brien` mà datasheet quảng cáo bị
biến thành `o%27brien` → vô hiệu ở mức ký tự.

### 2.6. Lỗi tính đúng đắn của payload

| Kỹ thuật | Ví dụ sinh ra | Vấn đề |
|---|---|---|
| `char_encoding` | `1CHAR(32)+CHAR(65)+CHAR(78)+...` | Thiếu toán tử nối, SQL không chạy |
| `hex_encoding` | `0x29204f5220281'='1` | Hex lẻ byte, phần đuôi vẫn thô |

### 2.7. Quality gate: 0/7

```
[FAIL] held-out set has both classes    : attack-only
[FAIL] rows per seed family             : 1042 rows/seed over 48 seeds (target ≤50)
[FAIL] seed overlap train -> test       : 100.0%
[FAIL] no single header predicts label  : 'method' at 0.500 (limit 0.35)
[FAIL] benign has raw special chars     : 0.00% (attack 34.40%)
[FAIL] not trivially separable          : 100.00% (limit 95%)
[FAIL] payloads distinct from Kaggle    : 16.2% (limit 5%)
```

---

## 3. Nguyên tắc thiết kế v2

> **Dataset không cần to hay giống thật. Nó cần xếp hạng được model.**
> Đề tài hỏi "kiến trúc nào chống obfuscation tốt hơn". Nếu hồi quy logistic đã đạt 100%,
> không kiến trúc nào có chỗ để tỏ ra tốt hơn kiến trúc nào.

Ba tiêu chí nghiệm thu:

1. Baseline hồi quy logistic char n-gram ≤ **95%** trên mọi tập test
2. Số dòng trên mỗi seed ≤ **50**
3. Quality gate đạt **7/7**

---

## 4. Kế hoạch thực hiện

### GIAI ĐOẠN A — Sửa generator trên 59 seed hiện có

> Làm trước phần seed. Lý do: sinh lại và đo ngay sẽ biết chính xác các con số dịch
> chuyển bao nhiêu khi *chưa* đụng tới seed, từ đó biết kho seed cần lớn cỡ nào.
> Làm ngược lại thì phải soạn 1.000 seed trong mù mờ.

File cần sửa: `c:\Users\MKhang\Desktop\WebAppModel\generate_obfu_dataset.py`

#### A1. Chia tập hai chiều (thay `assign_splits`, dòng 666)

Logic hiện tại: hold-out ~15% **tổ hợp kỹ thuật** → `test_heldout`; phần còn lại chia
70/15/15 phân tầng theo `(attack_category, difficulty_level)`. Dòng benign nằm trong
phân tầng với `attack_category="none"`. Vì `test_heldout` chỉ nhận dòng có
`technique_count > 0` nên nó **không bao giờ có benign**.

Thiết kế mới — chia seed thành hai kho rời nhau và tổ hợp kỹ thuật thành hai bộ rời nhau:

- `POOL_A` = 80% seed (dùng cho train/val/test), `POOL_B` = 20% seed (chỉ dùng cho test)
- `SET_1` = 85% tổ hợp kỹ thuật, `SET_2` = 15% tổ hợp (chỉ dùng cho test)
- Phân chia POOL phải **phân tầng theo `attack_category`** để SQLi/XSS không lệch

Sáu tập kết quả:

| Split | Seed | Tổ hợp | Đo cái gì |
|---|---|---|---|
| `train` | A | SET_1 | — |
| `val` | A | SET_1 | Chọn siêu tham số |
| `test` | A | SET_1 | Hiệu năng trong phân phối |
| `test_unseen_technique` | A | SET_2 | Tổng quát sang **cách mã hoá mới** |
| `test_unseen_seed` | B | SET_1 | Tổng quát sang **payload mới** |
| `test_unseen_both` | B | SET_2 | Trường hợp khó nhất |

**Bắt buộc:** cả bốn tập test đều phải có dòng benign, trích từ một kho benign riêng
không dùng để train. Tỉ lệ normal/anomalous trong mỗi tập test nên xấp xỉ nhau
để so sánh được.

Ghi chú thực hiện: cần gắn `seed_id` (hoặc chuỗi seed gốc) vào từng dòng attack ngay
lúc sinh, vì `assign_splits` hiện không biết dòng nào đến từ seed nào. Thêm cột
`seed_id` vào `COLUMNS` — đây cũng là cột giúp `preprocess_data.py` chia nhóm sau này.

#### A2. Xoá lối tắt

**`inject_context()` (khoảng dòng 488):**
- Thêm `DELETE` và `PATCH` vào tập method của attack (hiện attack chỉ dùng GET/POST/PUT/PATCH,
  và `DELETE` chỉ xuất hiện ở benign `benign_cart` → 100% normal)
- Thêm một nhánh `multipart_field`: chèn payload vào body multipart, dùng
  `content_type=multipart/form-data; boundary=...` giống hệt `benign_upload()`

**Chính sách mã hoá độc lập với nhãn:** hiện benign luôn `quote()`, attack luôn thô.
Thay bằng một hàm chung, ví dụ:

```python
def maybe_encode(value: str, rng) -> str:
    """Encode with the same probability for both classes."""
    return quote(value, safe="") if rng.random() < ENCODE_RATIO else value
```

Áp cho **cả** giá trị benign lẫn payload attack, cùng một `ENCODE_RATIO` (đề xuất 0.5).
Không phải "luôn encode" — thực tế attacker dùng curl/Burp vẫn gửi thô; điều cần là
tỉ lệ giống nhau ở hai lớp.

**Hard negative thật trong `gen_benign()` (các hàm `benign_*`, dòng 134–240):**
- Tên có dấu nháy để **thô** trong JSON body: `{"name": "o'brien"}`
- Nội dung bình luận chứa `<` `>` thô: `"3 < 5 and 7 > 2"`, `"<3 this product"`
- Câu tìm kiếm chứa từ khoá SQL: `"select the best laptop"`, `"drop shipping guide"`,
  `"union station hotel"`, `"order by date"`, `"insert coin arcade"`
- Đoạn code/config hợp lệ trong body: `"SELECT * FROM docs"` trong một trường ghi chú kỹ thuật

Mục tiêu: kéo tỉ lệ benign có ký tự đặc biệt thô từ 0% lên **ít nhất 15–20%**.

#### A3. Sửa payload sai cú pháp

- **`t_sqli_char()` (dòng 352):** phải sinh ra chuỗi CHAR() hợp lệ thay cho một literal
  chuỗi, ví dụ `'abc'` → `CHAR(97)+CHAR(98)+CHAR(99)` (MSSQL) hoặc
  `CONCAT(CHAR(97),CHAR(98),CHAR(99))` (MySQL). Không được nối trực tiếp vào số như
  `1CHAR(32)`.
- **`t_sqli_hex()` (dòng 344):** hex phải chẵn byte và thay đúng trọn vẹn một literal.
  Kiểm tra: `0x` + số ký tự hex chẵn, và `bytes.fromhex()` phải parse được.

#### A4. Tách dòng trigger second-order

Trong `gen_sqli()` (dòng 555) và `gen_xss()` (dòng 587), phần `if is_second:` sinh ra
một cặp `[store, trig]`. Dòng `trig` mang nhãn `anomalous` nhưng **không chứa payload**
(ví dụ `GET /admin/reviews?uid=1267`) — không thể học được từ một request đơn lẻ.

Ghi các dòng này ra **file riêng** (`obfu_http_dataset_second_order.csv`) thay vì trộn
vào dataset chính. Chúng vẫn có giá trị cho phần phân tích tương quan qua
`linked_request_id`, nhưng không nên nằm trong train/test.

> `preprocess_data.py::load_obfu_http()` đã có `drop_second_order_triggers=True` nên
> pipeline hiện tại vẫn an toàn kể cả khi chưa tách file.

#### A5. Sinh lại và đo

```bash
cd c:\Users\MKhang\Desktop\WebAppModel
python generate_obfu_dataset.py --scale pilot    # ~2k dòng, review nhanh
python generate_obfu_dataset.py --scale full     # 100k dòng
```

Chuyển file kết quả vào `obfuscated-web-attack-detection/DataSet/`, rồi:

```bash
cd obfuscated-web-attack-detection
python dataset_builder/quality_gate.py --dataset DataSet/obfu_http_dataset_v2.csv
```

**Ghi lại con số baseline hồi quy logistic.** Đây là thứ quyết định kho seed cần lớn cỡ nào:

- Nếu baseline tụt xuống ≤ 95% → kho seed hiện tại có thể đủ, chuyển thẳng sang Giai đoạn C
- Nếu vẫn > 95% → cần Giai đoạn B, và mức chênh cho biết cần bao nhiêu seed

---

### GIAI ĐOẠN B — Mở rộng kho seed

Đây là việc chiếm phần lớn công sức, nhưng **chia được cho nhiều người** vì bản chất là
soạn danh sách payload.

#### B1. Mục tiêu số lượng

| Loại | Hiện tại | Mục tiêu |
|---|---|---|
| SQLi | 34 | ~500 |
| XSS | 25 | ~400 |
| **Tổng** | **59** | **~900–1.000** |

Phép tính: 1.000 seed × 50 dòng/seed = 50.000 dòng attack. **Không cần tăng kích thước
dataset** — chỉ đổi 847 dòng/seed thành 50 dòng/seed.

#### B2. Phân bố SQLi (~500 seed)

Ma trận *kỹ thuật × hệ quản trị*. Hiện `SQLI_BASE` gần như toàn MySQL.

| Kỹ thuật | Ghi chú |
|---|---|
| union_based | Nhiều số cột khác nhau, có/không `NULL` padding |
| boolean_blind | `AND 1=1` / `AND 1=2`, `SUBSTRING`, `ASCII`, `LIKE` |
| error_based | `extractvalue`, `updatexml`, `CONVERT`, `CAST`, `XMLType` |
| time_blind | `SLEEP`, `BENCHMARK`, `WAITFOR DELAY`, `pg_sleep`, `DBMS_PIPE.RECEIVE_MESSAGE` |
| stacked_queries | `; DROP`, `; EXEC`, `; INSERT` |
| out_of_band | `LOAD_FILE`, `INTO OUTFILE`, `UTL_HTTP`, DNS exfil |
| second_order | Giá trị lưu vào DB rồi kích hoạt sau |
| auth_bypass | `admin'--`, `' OR '1'='1`, biến thể dấu nháy đôi/ngoặc |

Hệ quản trị cần phủ: **MySQL, MSSQL, PostgreSQL, Oracle, SQLite**.

#### B3. Phân bố XSS (~400 seed)

| Kỹ thuật | Ghi chú |
|---|---|
| script_tag | `<script>` với nhiều sink khác nhau |
| event_handler | Ma trận **thẻ × sự kiện**: `img/svg/body/input/details/video/audio/marquee/iframe` × `onerror/onload/onfocus/ontoggle/onstart/onpageshow/onanimationstart/onmouseover` — riêng ô này đã cho hàng trăm biến thể |
| svg_namespace | `<svg>`, `<svg/onload>`, `<svg><script>` |
| uri_scheme | `javascript:`, `data:text/html;base64,`, `vbscript:` |
| tag_breakout | `"><script>`, `'-alert(1)-'`, thoát khỏi thuộc tính |
| dom_sink | `innerHTML`, `document.write`, `eval`, `location.hash` |
| polyglot | Payload chạy được ở nhiều ngữ cảnh |

#### B4. Nguồn payload

- **OWASP Cheat Sheet Series** — XSS Filter Evasion, SQL Injection Prevention
- **PayloadsAllTheThings** (GitHub: `swisskyrepo/PayloadsAllTheThings`)
- **SecLists** (GitHub: `danielmiessler/SecLists`) — thư mục `Fuzzing/`

#### B5. Bước lọc BẮT BUỘC — khử trùng với Kaggle

19/59 seed hiện tại xuất hiện **nguyên văn** trong Kaggle, dẫn tới 16,2% dòng attack
bị trùng. Vì obfu được đánh giá chéo với Kaggle, đây là rò rỉ trực tiếp.

```python
def canonical(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())

kaggle_canon = set(pd.read_csv(KAGGLE)["Sentence"].dropna().map(canonical))
seeds = [s for s in seeds if canonical(s) not in kaggle_canon]
```

Mục tiêu: đưa tỉ lệ trùng xuống **dưới 5%**.

#### B6. Tổ chức file

Tách kho seed khỏi generator để dễ chia việc và review:

```
dataset_builder/
    seeds_sqli.py     # SQLI_SEEDS = [{"payload":..., "category":..., "dbms":...}, ...]
    seeds_xss.py      # XSS_SEEDS  = [{"payload":..., "category":...}, ...]
```

Mỗi seed nên có metadata `category` (và `dbms` cho SQLi) để `attack_category` trong
dataset chi tiết hơn mức `sqli`/`xss` hiện tại — cho phép phân tích theo loại tấn công.

---

### GIAI ĐOẠN C — Sinh, kiểm định, huấn luyện

#### C1. Sinh và kiểm định

```bash
python generate_obfu_dataset.py --scale full
python dataset_builder/quality_gate.py --dataset DataSet/obfu_http_dataset_v2.csv
```

**Không train cho tới khi đạt 7/7.** Nếu còn tiêu chí trượt, quay lại giai đoạn tương ứng.

#### C2. Cập nhật `preprocess_data.py`

`split_dataset_by_column()` hiện chỉ nhận bốn tên `train/val/test/test_heldout`.
Cần mở rộng cho ba tập test mới:

```python
for name in ("train", "val", "test",
             "test_unseen_technique", "test_unseen_seed", "test_unseen_both"):
```

Và `CNN_LSTM.py` trong vòng đánh giá, đổi
`for split_name in ("test", "test_heldout")` thành danh sách đầy đủ (hoặc lấy động
mọi key bắt đầu bằng `test`).

#### C3. Huấn luyện

```bash
python cnn_lstm/CNN_LSTM.py --train-sources obfu_http --epochs 30
```

Sau đó chạy thêm cho kiến trúc song song để so sánh. Lưu ý báo cáo cũ đã tự ghi nhận
rằng so sánh tuần tự ↔ song song **chưa công bằng** vì baseline chưa rerun cùng pipeline.
Lần này phải chạy cả hai với **cùng dataset, cùng tokenizer, cùng split, cùng threshold**.

#### C4. Bảng kết quả cần có trong báo cáo

| Tập test | CNN-LSTM tuần tự | CNN-LSTM song song |
|---|---|---|
| `test` (trong phân phối) | | |
| `test_unseen_technique` | | |
| `test_unseen_seed` | | |
| `test_unseen_both` | | |
| **Baseline LogReg char n-gram** | | |

Luận điểm nghiên cứu chuyển từ *"đạt 99,8% recall"* (yếu, dễ bị hỏi "sao biết không phải
học thuộc?") sang *"kiến trúc X suy giảm chậm hơn kiến trúc Y khi gặp payload chưa từng thấy"*
— có bằng chứng, có cơ chế, khó bắt bẻ.

**Nên đưa dòng baseline LogReg vào báo cáo.** Đây là thông lệ tốt và chặn trước
câu hỏi của phản biện về việc dataset có quá dễ hay không.

---

## 5. Những điều KHÔNG nên làm

| Việc | Lý do |
|---|---|
| Dồn công sức vào confound mã hoá | Thí nghiệm A đo được chỉ **−0,02 điểm**. Vẫn nên sửa cho đúng thực tế, nhưng không kỳ vọng đổi kết quả |
| Tăng số dòng dataset | 100k dòng đã quá đủ. Vấn đề là **đa dạng seed**, không phải số lượng |
| Gộp Kaggle + CSIC + obfu thành một tập rồi chia lại | Ba nguồn có mật độ họ payload khác nhau hoàn toàn (kaggle 1,0 dòng/họ; csic 5,1; obfu 847). Một giao thức chia duy nhất không thể đúng cho cả ba. Giữ thiết kế train riêng + đánh giá chéo hiện tại |
| Dùng `random_stratified_row` cho CSIC | Rò rỉ **82,7%** (csic có 5,1 dòng mỗi họ). Phải dùng `family_group` |
| Sửa `to_binary_label` bằng cách bỏ nhánh fallback numeric | CSIC dùng nhãn 0/1 dạng số, vẫn cần nhánh đó |
| Bỏ webapp ra khỏi phạm vi rồi quên | `webapp/app.py` gửi chuỗi thô, không bọc HTTP envelope → sai lệch train/serve. Đã thống nhất tạm gác, nhưng phải xử lý trước khi demo |

---

## 6. Checklist nghiệm thu

- [ ] `python dataset_builder/quality_gate.py` đạt **7/7**
- [ ] Baseline LogReg char n-gram ≤ **95%** trên mọi tập test
- [ ] Số dòng mỗi seed ≤ **50**
- [ ] Trùng canonical với Kaggle < **5%**
- [ ] Cả bốn tập test đều chứa dòng benign
- [ ] Không tổ hợp kỹ thuật nào của `SET_2` xuất hiện trong `train`
- [ ] Không seed nào của `POOL_B` xuất hiện trong `train`
- [ ] Benign chứa ký tự đặc biệt thô ở mức ≥ **15%**
- [ ] `DELETE` và `multipart/form-data` xuất hiện ở **cả hai lớp**
- [ ] `bytes.fromhex()` parse được mọi chuỗi `hex_encoding` sinh ra
- [ ] Dòng trigger second-order nằm ở file riêng
- [ ] Sinh lại được 100% với seed cố định (`SEED=1337`)
- [ ] Train cả hai kiến trúc với **cùng** dataset/tokenizer/split/threshold

---

## 7. Lệnh hay dùng

```bash
# Thư mục gốc
cd c:\Users\MKhang\Desktop\WebAppModel

# Sinh dataset
python generate_obfu_dataset.py --scale pilot
python generate_obfu_dataset.py --scale full

# Kiểm định
cd obfuscated-web-attack-detection
python dataset_builder/quality_gate.py
python dataset_builder/quality_gate.py --dataset DataSet/<file>.csv

# Smoke test nhanh (vài phút)
python cnn_lstm/CNN_LSTM.py --sample-size 4000 --obfu-sample-size 6000 \
    --epochs 1 --train-sources obfu_http

# Train thật
python cnn_lstm/CNN_LSTM.py --train-sources obfu_http --epochs 30

# Kiểm tra nhanh nhãn có đúng không
python -c "import sys; sys.path.insert(0,'.'); from preprocessing import preprocess_data as prep; \
df = prep.clean(prep.load_obfu_http(prep.OBFU_PATH), deduplicate=True, drop_label_conflicts=False); \
print(df.label.value_counts().to_dict())"
```

---

## 8. Ghi chú kỹ thuật cần nhớ

- Môi trường: Python 3.11.9, pandas 3.0.3, scikit-learn 1.9.0, TensorFlow 2.17.1, Windows
- `pandas 3.0`: `groupby(...).apply(...)` **loại bỏ cột nhóm**. Dùng `groupby(...).sample(...)`
  hoặc chỉ định rõ cột khi cần giữ
- `SEED = 1337` trong generator, `RANDOM_STATE = 42` trong pipeline train
- Repo git nằm ở `obfuscated-web-attack-detection/`, **không phải** ở `WebAppModel/`.
  File `generate_obfu_dataset.py` nằm ngoài repo nên **không được version control** —
  nên đưa nó vào repo để khỏi mất lần nữa (đã từng bị xoá, phải cứu từ `__pycache__`)
- `.gitignore` của repo loại trừ `*.csv` và `*.xlsx` → dataset không lên git
