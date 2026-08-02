# Báo cáo dataset obfuscation v2 và kết quả huấn luyện

> Cập nhật 02/08/2026.

---

## Bắt đầu từ đây (đọc trước nếu vào giữa chừng)

**Đề tài:** Phát hiện tấn công Web XSS và SQL Injection bị che giấu payload bằng
mô hình học sâu (SV2026-15).

**Trạng thái:**

| Mục tiêu thuyết minh | Xong |
|---|---|
| 1. Nghiên cứu kỹ thuật tấn công + che giấu payload | Có |
| 2. Thiết kế mô hình CNN + LSTM | Có |
| 3. Xây dựng bộ dữ liệu chuyên biệt | Có |
| 4. Thực nghiệm, đánh giá | Có |
| **Sản phẩm: chương trình nhận HTTP request** | **Chưa** |

**Việc còn lại duy nhất bắt buộc:** sửa `webapp/app.py`. Model được train trên
chuỗi có bao bì `[METHOD] [PATH] [BODY]...` nhưng webapp đang gửi chuỗi thô vào
→ kết quả demo sai. Chi tiết ở Phần 5.1.

**Ba lệnh chạy lại toàn bộ:**

```bash
python dataset_builder/generate_obfu_dataset_v2.py --scale full   # sinh dataset
python cnn_lstm/CNN_LSTM.py --datasets obfu_http --train-sources obfu_http \
    --epochs 30 --threshold-strategy fixed                         # train
python analysis/analyze_cnn_lstm.py                                # phân tích
```

---

## Phần 1 — Vì sao phải làm lại dataset

### 1.1. Phát hiện

Dataset v1 (`obfu_http_dataset_full.csv`) có vẻ tốt: 100.001 dòng, 20 cột, cấp
độ HTTP request đầy đủ, metadata phong phú. Nhưng khi đo:

**Hồi quy logistic + TF-IDF char n-gram đạt 99,96%**, và **recall 100,00% ở cả 5
tầng `difficulty_level`, kể cả `advanced`.**

Một mô hình tuyến tính bắt đúng mọi mẫu ở mọi tầng độ khó. Nghĩa là dataset không
phân biệt được kiến trúc nào tốt hơn kiến trúc nào — mọi model đều sẽ ra 99-100%.

### 1.2. Nguyên nhân

Cột `source` tương quan hoàn hảo với nhãn:

| source | normal | anomalous |
|---|---:|---:|
| `template` | 50.000 | 0 |
| `grammar_mutated` | 0 | 50.001 |

Model không học "thế nào là tấn công" — nó học "chuỗi này do generator nào sinh".

Đo cụ thể tỉ lệ xuất hiện ký tự:

| Đặc trưng | Normal | Attack |
|---|---:|---:|
| dấu nháy đơn `'` | **0,00%** | 31,75% |
| dấu ngoặc `(` | **0,00%** | 36,78% |
| từ khoá SQL | **0,00%** | 16,66% |
| `\u00` | **0,00%** | 6,79% |

Một luật regex một dòng — *"có `'` hoặc `(` hoặc `\u00` → attack"* — đạt
**precision 1,0**, không một false positive nào trên 50.000 mẫu benign.

Nguyên nhân kỹ thuật: generator gọi `quote()` cho mọi giá trị benign nhưng chèn
payload tấn công **thô**. Hard negative `o'brien` bị biến thành `o%27brien` → vô
hiệu ở mức ký tự.

### 1.3. Các vấn đề khác của v1

| Vấn đề | Số đo |
|---|---|
| Dòng trên mỗi seed | **847** (59 seed / 50.001 dòng) |
| Seed trong test cũng có trong train | **100%** |
| `method=DELETE` | 2.786 dòng, **100% normal** |
| `content_type=multipart/form-data` | 3.798 dòng, **100% normal** |
| Payload trùng canonical với Kaggle | **16,2%** |
| Dòng trigger second-order không mang payload | 3.706 |
| Quality gate | **0/7** |

---

## Phần 2 — Dataset v2

### 2.1. Trước / sau

| | v1 | v2 |
|---|---|---|
| Quality gate | **0/7** | **10/11** |
| Seed duy nhất | 59 | **1.096** |
| Dòng / seed | 847 | **46** |
| Seed test có trong train | 100% | **0%** (tập unseen-seed) |
| Benign có dấu nháy thô | 0,00% | **17,50%** |
| Luật 1 ký tự mạnh nhất | precision **100%** | precision **68,6%** |
| Trùng canonical với Kaggle | 16,2% | **0,0%** |
| Hex literal lẻ byte | có | **0/165** |
| Tập test có cả 2 lớp | 3/4 | **4/4** |
| LogReg: recall test → khó nhất | 100% → 100% (phẳng) | 98,70% → **96,16%** |

### 2.2. Sáu tập split

Dataset giấu **hai trục độc lập** khi huấn luyện:

|  | Mã hoá quen (SET_1) | Mã hoá lạ (SET_2) |
|---|---|---|
| **Payload quen** (POOL_A) | `test` | `test_unseen_technique` |
| **Payload lạ** (POOL_B) | `test_unseen_seed` | `test_unseen_both` |

| Split | n | normal | anomalous |
|---|---:|---:|---:|
| `train` | 49.000 | 24.500 | 24.500 |
| `val` | 10.500 | 5.250 | 5.250 |
| `test` | 10.500 | 5.250 | 5.250 |
| `test_unseen_technique` | 10.000 | 5.000 | 5.000 |
| `test_unseen_seed` | 10.000 | 5.000 | 5.000 |
| `test_unseen_both` | 10.000 | 5.000 | 5.000 |

Kỹ thuật bị giấu hoàn toàn: `char_encoding` (SQLi), `fromcharcode` +
`unicode_escape` (XSS) — chính là những transform phá huỷ token bề mặt.

### 2.3. Sáu thay đổi chính trong generator

1. **Attack dùng khung request benign làm vật mang.** Sinh một request benign
   trước rồi chèn payload vào. Phân bố `method`/`content_type`/`host` khớp do
   thiết kế. Skew giảm còn 0,223 / 0,032 / 0,060.

2. **Kho seed sinh tổ hợp** (`seeds_sqli.py` 705 seed, `seeds_xss.py` 423 seed)
   theo ma trận *kỹ thuật × DBMS × breakout × bảng × cột*.

3. **Kho nội dung benign sinh tổ hợp** (`seeds_benign.py`, 1.830 chuỗi SQL/HTML/
   JS/văn bản hợp lệ). Trước đó benign chỉ có ~40 chuỗi viết tay nên model học
   thuộc. Sau khi thêm, luật "chứa từ khoá SQL" rớt xuống precision **52,9%**.

4. **Obfuscation áp lên cả benign** (`obfuscated_benign`, ~11% benign). Trước đó
   mọi `%27`, `&#x3c;`, `\u003c` đều thuộc attack → "trông có vẻ mã hoá" là câu
   trả lời miễn phí.

5. **Hold-out transform mạnh thay vì tổ hợp ngẫu nhiên.** Tổ hợp ngẫu nhiên
   không tạo độ khó nào (LogReg 99,63%, cao hơn cả `test`).

6. **Sửa lỗi cú pháp payload.** `_safe_literal()` chỉ nhận literal dạng giá trị.
   Bug cụ thể: trên `1' AND WAITFOR TIME '0:0:15'`, hàm cũ khớp
   `' AND WAITFOR TIME '` rồi hex hoá, nuốt luôn chữ số liền sau.

### 2.4. Tiêu chí chưa đạt

LogReg in-distribution 99,14%, mốc đặt ra là ≤95%.

**Đánh giá: mốc này nhiều khả năng không đạt được mà không làm hỏng nhãn.** Muốn
ép LogReg xuống 95%, benign phải chứa `<img src=x onerror=alert(1)>` thô ở mật độ
tương đương — mà nội dung đó *chính là* stored XSS.

Đây là lý do các nghiên cứu SQLi/XSS ở mức payload đều báo 99%+. Con số cao
in-distribution là **thuộc tính của bài toán**, không phải khuyết tật dataset.

Quality gate vẫn giữ phép kiểm này và vẫn báo FAIL — không che. Bù lại có thêm
phép kiểm **độ suy giảm**, đo đúng thứ đề tài cần:

```
degradation: test 98,70% -> test_unseen_both 96,16%  (gap 2,54 điểm)
[PASS] held-out splits are measurably harder
```

Ở v1 khoảng cách này là **0,00 điểm** — hold-out chỉ là trang trí.

---

## Phần 3 — Kết quả huấn luyện

### 3.1. Cấu hình

`MAX_LEN=768`, `EMBEDDING_DIM=64`, `CONV_FILTERS=128`, `LSTM_UNITS=128`,
`POOL_SIZE=4`, `DROPOUT=0.3`, `BATCH=256`, `EPOCHS=30` (early stopping patience 5),
`LEARNING_RATE=1e-3`, **threshold cố định 0,5**, không dùng `class_weight`
(dataset cân bằng 50/50). Vocab 112 ký tự.

### 3.2. Một lần chạy (seed 42)

Attack recall (%), threshold 0,5:

| Tập | Tuần tự | Song song | LogReg |
|---|---:|---:|---:|
| `test` | 99,96 | 99,98 | 98,70 |
| `test_unseen_technique` | 93,56 | 95,54 | 96,58 |
| `test_unseen_seed` | 99,94 | 99,62 | 98,36 |
| `test_unseen_both` | 93,74 | 95,84 | 96,16 |
| **GAP** | 6,22 | 4,14 | 2,54 |

Tham số: tuần tự 253.825, song song 229.249. Thời gian ~2,1-2,2 phút/model.

### 3.3. Ba seed — kết quả quyết định

| seed | Tuần tự | Song song |
|---|---:|---:|
| 42 | 4,40 | 4,90 |
| 7 | 5,30 | 3,46 |
| 2024 | 5,62 | 6,12 |
| **TB ± ĐLC** | **5,11 ± 0,63** | **4,83 ± 1,33** |

**Thứ hạng đảo lộn theo từng seed.** 2/3 lần tuần tự tốt hơn.

Chênh lệch trung bình 0,28 điểm, độ lệch chuẩn của song song là 1,33 — gấp gần 5
lần khoảng chênh. Kiểm định t theo cặp: t = 0,36, **p ≈ 0,75**.

> **Kết luận: không phát hiện được khác biệt giữa hai kiến trúc.**

Lưu ý thêm: seed 42 chạy hai lần cho hai kết quả khác nhau (6,22 và 4,40) vì phép
toán GPU không tất định hoàn toàn. Nhiễu còn lớn hơn bảng này thể hiện.

Không nên chạy thêm seed để tìm khác biệt: với chênh lệch 0,28 và độ lệch chuẩn
~1,0, cần khoảng **200 lần chạy mỗi kiến trúc** mới đủ lực thống kê.

### 3.3b. Chạy bằng `CNN_LSTM.py` trên Colab GPU (02/08/2026)

Lần chạy này dùng **đường code hoàn toàn khác** với mục 3.2: script gốc của nhóm
(`CNN_LSTM.py`) thay vì notebook riêng — khác tokenizer, khác class_weight, khác
cách lấy mẫu.

Lệnh:

```bash
python cnn_lstm/CNN_LSTM.py --datasets obfu_http --train-sources obfu_http \
    --epochs 30 --threshold-strategy fixed
python analysis/analyze_cnn_lstm.py
```

| Tập | Recall | So với `test` |
|---|---:|---:|
| `test` | 99,98% | — |
| `test_unseen_seed` | 99,84% | **−0,14** |
| `test_unseen_technique` | 95,60% | **−4,38** |
| `test_unseen_both` | 95,22% | −4,76 |
| **GAP** | **4,76 điểm** | |

Ma trận nhầm lẫn trên `test_unseen_technique`:

```
[[4997    3]     5.000 benign, chỉ 3 false positive (FPR 0,06%)
 [ 220 4780]]    5.000 attack, bỏ sót 220
```

AUC-ROC 0,9981 và PR-AUC 0,9985 nhưng recall chỉ 95,60% — cùng dấu hiệu "tự tin
sai" đã thấy ở mục 3.8.

**Ý nghĩa:** GAP 4,76 nằm gọn trong khoảng nhiễu đã đo ở mục 3.3 (tuần tự
5,11 ± 0,63), và tỉ lệ giữa hai trục giữ nguyên hình dạng:

| | Notebook riêng (3.2) | `CNN_LSTM.py` (3.3b) |
|---|---:|---:|
| Payload lạ | −0,02 | −0,14 |
| Mã hoá lạ | −6,40 | −4,38 |

Hai đường code độc lập cho cùng một kết luận. Đây là bằng chứng mạnh hơn nhiều so
với chạy lại cùng một script nhiều lần.

### 3.4. Phát hiện chính — hai trục tách nhau

Đây mới là kết quả mạnh, vững qua mọi seed và mọi kiến trúc:

| Gặp gì | Suy giảm |
|---|---:|
| Payload chưa từng thấy | ~**0,1 điểm** |
| Mã hoá chưa từng thấy | ~**6 điểm** |

Chênh nhau **60 lần**. Model học được đặc trưng tấn công, **không** học được cách
nguỵ trang mới.

### 3.5. Suy giảm tỉ lệ với độ sâu obfuscation

Recall trên `test_unseen_technique`:

| obfuscation_type | Tuần tự | Song song |
|---|---:|---:|
| `plain` | 100,00 | 100,00 |
| `single_technique` | 95,47 | 96,69 |
| `combined_2` | 93,96 | 95,36 |
| `combined_3plus` | **87,03** | **92,54** |

Đơn điệu hoàn hảo. Đúng "khoảng trống nghiên cứu về che giấu đa lớp" nêu trong
thuyết minh đề tài.

### 3.6. Điểm mù nằm gọn ở XSS

Recall theo kỹ thuật, `test_unseen_technique` (bản tuần tự):

| Chết | Recall | | Không chết | Recall |
|---|---:|---|---|---:|
| `uri_scheme` | 83,11 | | `out_of_band` | 100,00 |
| `svg_namespace` | 86,49 | | `auth_bypass` | 100,00 |
| `stored` | 86,75 | | `error_based` | 100,00 |
| `script_tag` | 86,82 | | | |
| `tag_breakout` | 87,12 | | | |
| `event_handler` | 87,43 | | | |

**Cột trái toàn XSS, cột phải toàn SQLi.** Vì kỹ thuật bị giấu phía XSS
(`fromcharcode`, `unicode_escape`) phá huỷ token JS hoàn toàn — `alert` thành
`self[String.fromCharCode(97,108,101,114,116)]`.

### 3.7. False positive gần như bằng không

FPR = 0,00% trên **mọi** loại benign trong tập `test`, gồm cả `obfuscated_benign`
(768 mẫu). Tổng FP toàn tập: 0-2 mẫu.

### 3.8. Quét ngưỡng — loại trừ giả thuyết sai

Giả thuyết "recall thấp do đặt ngưỡng 0,5 không hợp" **bị bác bỏ**:

| Ngưỡng | Recall `test_unseen_technique` | FPR |
|---|---:|---:|
| 0,50 | 93,56% | 0,02% |
| 0,10 | 94,32% | 0,06% |
| 0,01 | 95,08% | 0,10% |

Hạ tới 0,01 chỉ nhích 1,5 điểm, vẫn bỏ sót 246 mẫu. Model **tự tin sai** — lỗi
học thuộc, không phải lỗi hiệu chỉnh. Giữ threshold 0,5.

### 3.9. Cách phát biểu trong báo cáo

Không lấy 99,98% làm con số tiêu đề — ai cũng có 99%. Nên viết:

> *"Mô hình đạt 99,98% trên payload cùng phân phối nhưng chỉ 95,54% khi gặp kỹ
> thuật che giấu chưa từng thấy. Chúng tôi báo cáo kèm baseline hồi quy logistic
> (99,14% / 96,58%) để chứng minh chênh lệch đến từ thiết kế đánh giá chứ không
> từ độ khó tự nhiên của dữ liệu. Khác biệt giữa hai kiến trúc CNN-LSTM nằm trong
> khoảng nhiễu (5,11 ± 0,63 vs 4,83 ± 1,33; n=3, p=0,75), cho thấy giới hạn không
> nằm ở topology mà ở biểu diễn đầu vào ở mức ký tự."*

Về độ chính xác trên payload không che giấu: **đừng viết "100%"**. Viết
*"1.529/1.529, khoảng tin cậy 95% ≥ 99,8%"*.

---

## Phần 4 — Đối chiếu với thuyết minh đề tài

| Mục tiêu trong thuyết minh | Trạng thái |
|---|---|
| 1. Nghiên cứu kỹ thuật tấn công XSS/SQLi và phương pháp che giấu payload | Xong — 1.096 seed, 8 nhóm SQLi × 5 DBMS, 9 nhóm XSS, 13+ kỹ thuật che giấu |
| 2. Thiết kế các mô hình dựa trên CNN và LSTM | Xong — tuần tự + song song |
| 3. Xây dựng bộ dữ liệu chuyên biệt, chú trọng payload đã che giấu | Xong — 100.000 dòng, gate 10/11 |
| 4. Thực nghiệm, đánh giá, chứng minh tính hiệu quả của học sâu | Xong |
| **Sản phẩm: chương trình nhận đầu vào là HTTP request** | **Chưa** — webapp còn lệch train/serve |

Mục tiêu 4 ghi *"chứng minh tính hiệu quả của phương pháp học sâu"*, không phải
"chứng minh kiến trúc A hơn B". Nên kết quả "hai kiến trúc tương đương" không ảnh
hưởng tới việc hoàn thành mục tiêu.

---

## Phần 5 — Việc còn lại

### 5.1. Sản phẩm bắt buộc — sửa webapp

Model được train trên chuỗi có bao bì HTTP:

```
[METHOD] POST [PATH] /cart/add [QUERY]  [BODY] product_id=1035&quantity=2
[COOKIE] laravel_session=... [CONTENT_TYPE] application/x-www-form-urlencoded
[USER_AGENT] Mozilla/5.0 ...
```

`webapp/app.py::normalize_payload()` chỉ chuẩn hoá khoảng trắng rồi đưa thẳng
chuỗi thô vào. Ví dụ trong README — `{"payload": "/search?q=' OR 1=1 --"}` —
không hề có các token `[METHOD]`, `[PATH]`, `[BODY]`.

Cần cho webapp nhận các trường HTTP rời rạc rồi gọi `prep.serialize_http_request()`.

Đóng gói artifact: webapp đọc cứng
`cnn_lstm/artifacts/best_hybrid_cnn_lstm.keras`, `tokenizer.pkl`,
`metadata_and_results.json`. File cuối phải có `model.max_len = 768`, nếu thiếu
webapp rơi về `DEFAULT_MAX_LEN = 1024` → pad sai → kết quả vô nghĩa.

### 5.2. Cần cho phân tích lỗi

`preprocess_data.py::load_obfu_http()` chưa mang 3 cột sang. Thêm vào bảng ánh xạ
cột (~dòng 351):

```python
("benign_kind", "benign_kind"),
("attack_technique", "attack_technique"),
("seed_id", "seed_id"),
```

`analysis/analyze_cnn_lstm.py` cần biết 3 tên split mới
(`test_unseen_technique`, `test_unseen_seed`, `test_unseen_both`).

### 5.3. Chưa được version control

`git ls-files dataset_builder/` trả về **rỗng** — thư mục không bị `.gitignore`
loại, chỉ là chưa `git add`. Generator và 3 kho seed hiện không có bản sao lưu
nào, mà chuyện mất file generator đã xảy ra một lần.

```bash
git add dataset_builder/
git commit -m "dataset builder v2: seed banks, generator, quality gate"
```

Sau khi commit thì `recovered_constants.py` (bản cứu hộ hằng số v1, không file
nào import) có thể xoá.

### 5.4. Tuỳ chọn

- `POOL_SIZE = 2`: payload trung vị đi từ 3 lên 13 timestep. Kiểm chứng trực tiếp
  kết luận "giới hạn ở biểu diễn đầu vào".
- Chạy trên Kaggle (payload trần, cột `raw_payload`) để đối sánh với bài báo.
- Sửa CSIC theo `analysis_csic_issue.md` + `--split-protocol family_group`.

---

## Phần 6 — Bẫy đã gặp

| Bẫy | Chi tiết |
|---|---|
| `groupby(...).apply(...)` pandas 3.0 | Làm mất cột nhóm (`split`), pipeline âm thầm quay về chia ngẫu nhiên. Dùng `groupby(...).sample(...)` |
| Ghi CSV lên ổ mount | Ghi từng dòng 100k dòng mất hơn 1 phút; đệm RAM rồi ghi một lần mất dưới 1 giây |
| Hard negative bị `quote()` nuốt | v1 có sẵn `"O'Brien collection"` nhưng `quote()` biến thành `O%27Brien` |
| Regex `0x[0-9a-f]+` bắt nhầm | Session token `zTi6fMt0x1T1YjCkk` chứa `0x1`. Cần ràng buộc biên từ |
| Chèn payload bằng `re.sub` | Payload chứa `\x` hoặc `\u` bị đọc là escape của regex. Dùng `lambda _m: ...` |
| SET_2 ngẫu nhiên không tạo độ khó | LogReg đạt 99,63% trên tập unseen-technique, cao hơn `test` |
| `obfuscation_techniques` ≠ tổ hợp được gán | Transform có thể no-op. Kiểm hold-out phải dùng `assigned_combo` |
| `git status` báo sửa toàn repo | Nhiễu CRLF↔LF do mount Windows/Linux. `git diff --ignore-all-space` trả rỗng |
| File `.ipynb` nối dòng | Mỗi dòng trong `source` phải kết thúc bằng `\n`, nếu không Colab nối liền |

---

## Phần 7 — Lệnh hay dùng

```bash
cd C:\Users\MKhang\Desktop\WebAppModel\obfuscated-web-attack-detection

# sinh lại dataset (SEED=1337, tái lập 100%)
python dataset_builder/generate_obfu_dataset_v2.py --scale pilot   # ~6k dòng
python dataset_builder/generate_obfu_dataset_v2.py --scale full    # 100k dòng

# kiểm định
python dataset_builder/quality_gate.py

# kiểm tra pipeline nạp đúng
python -c "import sys; sys.path.insert(0,'.'); from preprocessing import preprocess_data as prep; \
df = prep.clean(prep.load_obfu_http(prep.OBFU_PATH), deduplicate=True, drop_label_conflicts=False); \
print(df.label.value_counts().to_dict()); \
print({k: len(v) for k, v in prep.split_dataset_by_column(df).items()})"

# smoke test
python cnn_lstm/CNN_LSTM.py --sample-size 4000 --obfu-sample-size 6000 \
    --epochs 1 --train-sources obfu_http

# train thật
python cnn_lstm/CNN_LSTM.py --train-sources obfu_http --epochs 30

# phân tích sau huấn luyện
python analysis/analyze_cnn_lstm.py
```

Kỳ vọng của lệnh kiểm tra pipeline:

```
{0: 50000, 1: 50000}
{'train': 49000, 'val': 10500, 'test': 10500,
 'test_unseen_technique': 10000, 'test_unseen_seed': 10000, 'test_unseen_both': 10000}
```
