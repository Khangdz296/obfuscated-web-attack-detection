# Báo Cáo Pipeline Phát Hiện Tấn Công Web Bằng Hybrid 1D-CNN + LSTM

## 1. Tổng Quan Đề Tài

Đề tài hướng đến bài toán phát hiện tấn công web trên HTTP payload/request, tập trung vào hai nhóm tấn công phổ biến:

- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)

Bài toán được mô hình hóa thành phân loại nhị phân:

| Nhãn | Ý nghĩa |
|---:|---|
| 0 | Normal |
| 1 | Attack |

Định hướng chính của đề tài không chỉ là đạt accuracy cao trên tập dữ liệu thông thường, mà là đánh giá khả năng phát hiện payload bị làm rối (obfuscation). Vì vậy, pipeline được thiết kế theo hướng **char-level no-decoding**, tức là giữ nguyên các dấu vết mã hóa và biến thể cú pháp trong payload.

Tài liệu tham khảo chính là bài báo *Securing web applications against XSS and SQLi attacks using a novel deep learning approach* trên Scientific Reports: https://www.nature.com/articles/s41598-023-48845-4. Bài báo sử dụng hướng CNN-LSTM để phát hiện SQLi/XSS, nhưng có xu hướng decode và chuẩn hóa payload trước khi đưa vào mô hình. Đề tài này kế thừa ý tưởng hybrid CNN-LSTM, đồng thời điều chỉnh pipeline tiền xử lý theo hướng giữ nguyên dấu vết obfuscation.

## 2. Nguồn Dữ Liệu

Hệ thống sử dụng 3 nguồn dữ liệu:

| File | Vai trò |
|---|---|
| `SQLInjection_XSS_MixDataset.1.0.0.csv` | Tập payload SQLi/XSS/Normal |
| `csic_database.csv` | Tập HTTP request CSIC 2010 |
| `obfuscation_dataset_full.xlsx` | Tập obfuscation tự tạo của nhóm |

Sau khi tiền xử lý và loại trùng, dữ liệu gốc gồm Kaggle + CSIC có:

| Tập | Số mẫu | Normal | Attack |
|---|---:|---:|---:|
| Base clean | 177,277 | 63,324 | 113,953 |
| Train | 127,638 | 45,593 | 82,045 |
| Validation | 14,183 | 5,066 | 9,117 |
| Test | 35,456 | 12,665 | 22,791 |
| Obfuscated test | 150,000 | 0 | 150,000 |

Tập `obfuscated_test` được tách riêng và không dùng để huấn luyện. Tập này dùng để đánh giá khả năng chống obfuscation của mô hình.

Thống kê độ dài payload của tập gốc:

| Chỉ số | Giá trị |
|---|---:|
| Mean | 333.36 ký tự |
| Median | 251 ký tự |
| p90 | 784 ký tự |
| p95 | 883 ký tự |
| p99 | 975 ký tự |
| Max | 8,493 ký tự |

Từ đó, `MAX_LEN = 1024` được chọn vì lớn hơn p99, giữ được phần lớn payload nhưng vẫn không quá dài để huấn luyện.

## 3. Tiền Xử Lý Dữ Liệu

### 3.1. Chuẩn Hóa Schema

Mỗi dataset ban đầu có cấu trúc khác nhau, nên được đưa về schema chung:

| Cột | Ý nghĩa |
|---|---|
| `payload` | Chuỗi request/payload đầu vào |
| `label` | 0 = Normal, 1 = Attack |
| `source` | Nguồn dữ liệu |
| `attack_type` | Loại tấn công: SQLi/XSS/mixed |
| `obfuscation_type` | Kỹ thuật làm rối |
| `pattern_category` | Nhóm pattern tấn công |
| `difficulty_level` | Mức độ khó của mẫu obfuscation |

Với Kaggle dataset:

```python
payload = Sentence
label = max(SQLInjection, XSS)
```

Với CSIC:

```python
payload = content + " " + URL
label = classification
```

Với tập obfuscation:

```python
payload = obfuscated_input
label = sqli/xss -> 1
```

### 3.2. Chính Sách No-Decoding

Pipeline không thực hiện:

- Không URL decode
- Không HTML unescape
- Không lowercase

Lý do: các chuỗi như `%27`, `%3C`, `&#x27;`, `%2527`, `SeLeCt`, `<sCrIpT>` không phải nhiễu thông thường. Chúng là dấu vết của kỹ thuật né tránh WAF/parser.

Ví dụ:

```text
' OR 1=1--
%27%20OR%201%3D1--
%2527%2520OR%25201%253D1--
```

Nếu decode quá sớm, mô hình có thể mất thông tin rằng attacker đang sử dụng URL encoding hoặc double encoding. Vì vậy, đề tài giữ nguyên payload ở mức ký tự để mô hình tự học pattern mã hóa liên quan đến obfuscation.

### 3.3. Chuẩn Hóa Whitespace

Bước duy nhất can thiệp vào payload là chuẩn hóa khoảng trắng:

```python
re.sub(r"\s+", " ", payload).strip()
```

Mục đích:

- Giảm nhiễu do khoảng trắng thừa.
- Giảm độ dài không cần thiết.
- Vẫn giữ lại các ký hiệu có ý nghĩa bảo mật như `%20`, `%0A`, `%0D`, `/**/`.

### 3.4. Loại Bỏ Mẫu Rỗng Và Trùng Lặp

Sau chuẩn hóa, pipeline loại:

- Payload rỗng.
- Mẫu trùng theo cặp `payload + label`.

Bước này giúp giảm học vẹt và giảm nguy cơ một payload giống nhau xuất hiện ở cả train và test.

### 3.5. Chia Train / Validation / Test

Dữ liệu gốc được chia có `stratify=label` để giữ tỷ lệ Normal/Attack tương đối ổn định giữa các tập:

```text
base_df -> train_val_df + test_df
train_val_df -> train_df + val_df
```

Vai trò:

| Tập | Vai trò |
|---|---|
| Train | Fit tokenizer và train model |
| Validation | Theo dõi `val_loss`, EarlyStopping, ModelCheckpoint |
| Test | Đánh giá hiệu năng cuối cùng trên dữ liệu thông thường |
| Obfuscated test | Đánh giá robustness trước payload bị làm rối |

## 4. Tokenization, Padding Và Embedding

### 4.1. Vì Sao Cần Tokenization?

Neural network không xử lý trực tiếp chuỗi ký tự. Vì vậy payload cần được biến thành dãy số.

Ví dụ:

```text
%27%20OR
```

có thể thành:

```text
[5, 12, 18, 5, 12, 9, 31, 22]
```

Pipeline dùng char-level tokenizer:

```python
Tokenizer(
    char_level=True,
    lower=False,
    filters="",
    oov_token="<OOV>"
)
```

Lý do dùng char-level:

- SQLi/XSS phụ thuộc mạnh vào ký tự đặc biệt: `'`, `"`, `<`, `>`, `/`, `=`, `%`, `;`, `-`.
- Các pattern tấn công có thể rất ngắn: `%27`, `1=1`, `--`, `<sc`, `/**/`.
- Word-level tokenizer dễ mất hoặc xử lý kém các chuỗi mã hóa và ký tự đặc biệt.

Tokenizer chỉ fit trên `train.csv`:

```python
tokenizer.fit_on_texts(train_df["payload"])
```

Không fit trên validation/test/obfuscated test để tránh data leakage.

### 4.2. Padding

Payload có độ dài khác nhau, nhưng model cần input cùng kích thước. Vì vậy tất cả sequences được pad/cắt về:

```text
MAX_LEN = 1024
```

Dùng:

```python
padding="post"
truncating="post"
```

Kết quả input vào model có shape:

```text
(batch_size, 1024)
```

### 4.3. Embedding

Token ID chỉ là mã số, chưa có ý nghĩa vector. Lớp Embedding học biểu diễn vector cho từng ký tự:

```python
Embedding(input_dim=vocab_size, output_dim=64)
```

Shape biến đổi:

```text
(batch_size, 1024) -> (batch_size, 1024, 64)
```

Mỗi ký tự được biểu diễn bằng vector 64 chiều. Embedding giúp mô hình học mối quan hệ giữa các ký tự, ví dụ các ký tự trong encoding `%`, `2`, `7`, `3`, `C` hoặc các ký tự trong XSS `<`, `/`, `>`.

## 5. Mô Hình Đầu Tiên: Hybrid 1D-CNN + LSTM

### 5.1. Kiến Trúc

Mô hình chính trong `CNN_LSTM.py`:

```text
Input
-> Embedding
-> Conv1D(kernel=3, filters=128)
-> MaxPooling1D(pool=4)
-> Conv1D(kernel=5, filters=128)
-> MaxPooling1D(pool=4)
-> LSTM(128)
-> Dense(64)
-> Dropout(0.3)
-> Dense(1, sigmoid)
```

### 5.2. Luồng Shape

| Bước | Shape |
|---|---|
| Token IDs | `(batch_size, 1024)` |
| Embedding | `(batch_size, 1024, 64)` |
| Conv1D k=3 | `(batch_size, 1024, 128)` |
| Pool 1 | `(batch_size, 256, 128)` |
| Conv1D k=5 | `(batch_size, 256, 128)` |
| Pool 2 | `(batch_size, 64, 128)` |
| LSTM | `(batch_size, 128)` |
| Sigmoid | `(batch_size, 1)` |

Đầu ra của CNN sau pooling được đưa làm đầu vào cho LSTM. CNN trích xuất đặc trưng cục bộ, LSTM học quan hệ tuần tự trên chuỗi đặc trưng đã được nén.

### 5.3. Vai Trò Của Từng Khối

**Conv1D kernel 3** bắt pattern ngắn:

```text
%27
OR 
1=1
<sc
```

**Conv1D kernel 5** bắt pattern dài hơn:

```text
UNION
alert
script
SELECT
```

**MaxPooling1D** nén chuỗi:

```text
1024 -> 256 -> 64
```

Nếu đưa thẳng 1024 timestep vào LSTM sẽ rất chậm. Pooling giúp giảm chi phí tính toán nhưng vẫn giữ trục thời gian.

**LSTM** học quan hệ dài hơn:

```text
UNION ... SELECT ... FROM
<script ... alert ... </script>
```

**Sigmoid** xuất xác suất tấn công. Mặc định:

```text
probability >= 0.5 -> Attack
```

### 5.4. Vì Sao Đưa Đầu Ra CNN Vào LSTM?

Trong mô hình này, CNN và LSTM không hoạt động độc lập. CNN đóng vai trò trích xuất đặc trưng cục bộ trước, sau đó đầu ra của CNN được đưa vào LSTM để học quan hệ tuần tự.

Luồng xử lý có thể hiểu như sau:

```text
Payload gốc
-> dãy token ký tự
-> vector embedding từng ký tự
-> CNN phát hiện các mảnh đáng ngờ
-> pooling nén chuỗi nhưng vẫn giữ thứ tự tương đối
-> LSTM đọc chuỗi đặc trưng đã nén
-> Dense/Sigmoid phân loại Normal hoặc Attack
```

Ví dụ với payload SQLi:

```text
%27%20UNION%20SELECT%20username,password%20FROM%20users--
```

CNN có thể học các pattern cục bộ như:

```text
%27
UNION
SELECT
FROM
--
```

Tuy nhiên, chỉ biết từng mảnh riêng lẻ chưa đủ. Một từ như `SELECT` có thể xuất hiện trong nhiều ngữ cảnh khác nhau. LSTM giúp mô hình học rằng các mảnh này xuất hiện theo một trình tự đáng ngờ:

```text
UNION -> SELECT -> FROM
```

Với XSS:

```text
<sCrIpT>alert(1)</sCrIpT>
```

CNN có thể phát hiện:

```text
<sC
CrI
alert
</
```

LSTM tiếp tục học quan hệ ngữ cảnh giữa các mảnh này, ví dụ một thẻ script mở, lời gọi hàm JavaScript và thẻ đóng.

Điểm quan trọng là CNN sau pooling vẫn giữ dạng chuỗi:

```text
(batch_size, 64, 128)
```

Trong đó:

- `64` là số bước thời gian còn lại sau khi nén từ 1024 ký tự.
- `128` là số đặc trưng do CNN học được tại mỗi bước.

LSTM nhận đúng tensor này làm đầu vào:

```text
LSTM input = (batch_size, timesteps, features)
           = (batch_size, 64, 128)
```

Do đó, có thể nói chính xác rằng:

> Đầu ra của khối CNN sau MaxPooling là đầu vào của LSTM. CNN trích xuất và nén đặc trưng, còn LSTM học quan hệ tuần tự giữa các đặc trưng đó.

### 5.5. Vì Sao Không Dùng GlobalMaxPooling Trước LSTM?

Một lựa chọn khác thường gặp là dùng `GlobalMaxPooling1D`. Tuy nhiên, trong mô hình CNN-LSTM, không nên dùng GlobalMaxPooling trước LSTM.

Nếu dùng:

```text
Conv1D -> GlobalMaxPooling1D -> LSTM
```

thì `GlobalMaxPooling1D` sẽ ép toàn bộ chuỗi thành một vector:

```text
(batch_size, timesteps, features)
-> (batch_size, features)
```

Khi đó trục thời gian bị mất, LSTM không còn chuỗi để đọc. Nói cách khác, LSTM sẽ không còn nhiều ý nghĩa.

Vì vậy mô hình sử dụng `MaxPooling1D` cục bộ:

```text
1024 -> 256 -> 64
```

Cách này giúp:

- Giảm độ dài chuỗi để LSTM chạy nhanh hơn.
- Vẫn giữ thứ tự tương đối của các pattern.
- Cho phép LSTM học quan hệ giữa các đặc trưng cục bộ do CNN trích xuất.

Đây là điểm khác biệt quan trọng giữa CNN-only và CNN-LSTM. CNN-only có thể dùng GlobalMaxPooling để lấy pattern mạnh nhất ở bất kỳ vị trí nào, còn CNN-LSTM cần giữ lại trục thời gian để học ngữ cảnh.

## 6. Kết Quả Mô Hình Đầu Tiên

Mô hình được EarlyStopping tại epoch 14 và khôi phục trọng số tốt nhất từ epoch 9.

### 6.1. Kết Quả Trên Normal Test

| Metric | Giá trị |
|---|---:|
| Accuracy | 99.42% |
| AUC-ROC | 99.96% |
| Normal Precision | 98.67% |
| Normal Recall | 99.72% |
| Normal F1 | 99.19% |
| Attack Precision | 99.85% |
| Attack Recall | 99.25% |
| Attack F1 | 99.55% |

Confusion matrix:

```text
[[12630    35]
 [  170 22621]]
```

Diễn giải:

- 12,630 Normal được phân loại đúng.
- 35 Normal bị báo nhầm thành Attack.
- 170 Attack bị bỏ sót.
- 22,621 Attack được phát hiện đúng.

### 6.2. Kết Quả Trên Obfuscated Test

| Metric | Giá trị |
|---|---:|
| Attack Recall | 99.54% |
| Attack F1 | 99.77% |
| Số mẫu obfuscated | 150,000 |
| Phát hiện đúng | 149,311 |
| Bỏ sót | 689 |

Confusion matrix:

```text
[[     0      0]
 [   689 149311]]
```

Tập obfuscation chỉ gồm mẫu Attack, nên nên trình bày bằng Attack Recall/Detection Rate thay vì accuracy. False Negative Rate:

```text
689 / 150000 = 0.46%
```

## 7. Phân Tích Threshold

Mô hình mặc định dùng threshold 0.5. Tuy nhiên trong bài toán bảo mật, có thể ưu tiên giảm false negative. Vì vậy, đã thử các threshold từ 0.1 đến 0.9.

### 7.1. Threshold Trên Normal Test

| Threshold | Normal Recall | Attack Recall | False Positive | False Negative |
|---:|---:|---:|---:|---:|
| 0.1 | 99.43% | 99.42% | 72 | 132 |
| 0.3 | 99.65% | 99.31% | 44 | 157 |
| 0.5 | 99.72% | 99.25% | 35 | 170 |
| 0.7 | 99.79% | 99.19% | 27 | 185 |
| 0.9 | 99.83% | 99.07% | 21 | 212 |

Giảm threshold từ 0.5 xuống 0.1:

- False negative trên normal test giảm từ 170 xuống 132.
- False positive tăng từ 35 lên 72.
- Attack Recall tăng từ 99.25% lên 99.42%.

### 7.2. Threshold Trên Obfuscated Test

| Threshold | Attack Recall | Bỏ sót |
|---:|---:|---:|
| 0.1 | 99.76% | 367 |
| 0.3 | 99.64% | 534 |
| 0.5 | 99.54% | 689 |
| 0.7 | 99.43% | 859 |
| 0.9 | 99.26% | 1,112 |

Threshold 0.1 cho chế độ security-oriented giúp giảm số mẫu obfuscated bị bỏ sót từ 689 xuống 367. Đổi lại, false positive trên normal test tăng. Trong bối cảnh WAF/NIDS, đây là trade-off có thể chấp nhận nếu ưu tiên giảm tấn công lọt qua hệ thống.

## 8. Phân Tích Theo Loại Obfuscation

Kết quả theo `obfuscation_type` cho thấy phần lớn kỹ thuật obfuscation được phát hiện rất tốt. Tuy nhiên, nhóm `mixed_case` là nhóm yếu nhất:

| Obfuscation type | Samples | Detected | Missed | Recall |
|---|---:|---:|---:|---:|
| mixed_case | 17,046 | 16,500 | 546 | 96.80% |
| noise_injection | 13,657 | 13,620 | 37 | 99.73% |
| unicode_encoding | 16,949 | 16,913 | 36 | 99.79% |
| html_entity_encoding+mixed_case | 1,276 | 1,264 | 12 | 99.06% |
| mixed_case+noise_injection | 1,556 | 1,546 | 10 | 99.36% |

Theo attack type:

| Attack type | Samples | Detected | Missed | Recall |
|---|---:|---:|---:|---:|
| SQLi | 75,000 | 74,561 | 439 | 99.41% |
| XSS | 75,000 | 74,750 | 250 | 99.67% |

Theo difficulty:

| Difficulty | Samples | Detected | Missed | Recall |
|---|---:|---:|---:|---:|
| Easy | 13,756 | 13,447 | 309 | 97.75% |
| Medium | 58,789 | 58,471 | 318 | 99.46% |
| Hard | 77,455 | 77,393 | 62 | 99.92% |

Kết quả này có vẻ ngược trực giác vì nhóm hard lại cao hơn easy. Lý do có thể là các mẫu hard chứa nhiều dấu vết rõ ràng như encoding/noise/comment, trong khi một số mẫu easy mixed-case ngắn hoặc ít ký tự đặc biệt nên dễ bị xem như benign.

## 9. Thử Nghiệm Cải Tiến Mô Hình

Sau khi có kết quả model đầu tiên, một mô hình cải tiến được thử nghiệm trong `experiments/cnn_bilstm/train_cnn_bilstm.py`.

### 9.1. Kiến Trúc Cải Tiến

```text
Input
-> Embedding
-> SpatialDropout1D
-> Conv1D + BatchNormalization + ReLU
-> MaxPooling1D
-> Conv1D + BatchNormalization + ReLU
-> MaxPooling1D
-> Bidirectional LSTM
-> Dense + BatchNormalization + ReLU
-> Dropout
-> Sigmoid
```

Các thay đổi:

| Thành phần | Mục đích |
|---|---|
| SpatialDropout1D | Giảm overfitting trên embedding sequence |
| BatchNormalization | Ổn định huấn luyện sau Conv/Dense |
| Bidirectional LSTM | Đọc chuỗi đặc trưng theo cả hai hướng |
| Threshold tuning | Chọn ngưỡng theo validation để giảm false negative |

Mô hình cải tiến có khoảng 221k parameters, thấp hơn model gốc khoảng 253k parameters, nhưng thời gian train mỗi epoch lại cao hơn do Bidirectional LSTM và BatchNormalization.

### 9.2. Kết Quả Mô Hình Cải Tiến

Mô hình cải tiến EarlyStopping tại epoch 15 và khôi phục trọng số tốt nhất từ epoch 10.

**Normal test, threshold 0.5**

```text
[[12647    18]
 [  166 22625]]
```

| Metric | Giá trị |
|---|---:|
| Accuracy | 99.48% |
| Normal Recall | 99.86% |
| Attack Recall | 99.27% |
| Attack F1 | 99.60% |

**Normal test, threshold 0.1**

```text
[[12591    74]
 [  120 22671]]
```

| Metric | Giá trị |
|---|---:|
| Accuracy | 99.45% |
| Normal Recall | 99.42% |
| Attack Recall | 99.47% |
| Attack F1 | 99.57% |

**Obfuscated test, threshold 0.5**

```text
[[     0      0]
 [  2615 147385]]
```

| Metric | Giá trị |
|---|---:|
| Attack Recall | 98.26% |
| Missed | 2,615 |

**Obfuscated test, threshold 0.1**

```text
[[     0      0]
 [   955 149045]]
```

| Metric | Giá trị |
|---|---:|
| Attack Recall | 99.36% |
| Missed | 955 |

## 10. So Sánh Model Gốc Và Model Cải Tiến

| Mô hình | Threshold | Normal Test Accuracy | Test Attack Recall | Obfuscated Recall | Obfuscated Missed | Thời gian/epoch |
|---|---:|---:|---:|---:|---:|---:|
| CNN-LSTM gốc | 0.5 | 99.42% | 99.25% | 99.54% | 689 | ~309s |
| CNN-LSTM gốc | 0.1 | gần tương đương | 99.42% | 99.76% | 367 | không train lại |
| Improved CNN-BiLSTM | 0.5 | 99.48% | 99.27% | 98.26% | 2,615 | ~560s |
| Improved CNN-BiLSTM | 0.1 | 99.45% | 99.47% | 99.36% | 955 | ~560s |

Nhận xét:

- Mô hình cải tiến nhỉnh hơn nhẹ trên normal test, đặc biệt giảm false positive và false negative ở threshold 0.5.
- Tuy nhiên, mô hình cải tiến kém hơn trên obfuscated test.
- Mô hình cải tiến train chậm hơn gần gấp đôi.
- Mục tiêu của đề tài là robustness trước obfuscation, nên mô hình gốc phù hợp hơn.

## 11. Kết Luận Lựa Chọn Mô Hình

Mô hình được chọn làm model chính là:

```text
Embedding -> Conv1D(k=3) -> MaxPooling -> Conv1D(k=5) -> MaxPooling -> LSTM -> Dense -> Sigmoid
```

Lý do:

1. Đạt kết quả rất cao trên normal test: accuracy 99.42%, AUC-ROC 99.96%.
2. Đạt robustness cao trên obfuscated test: Attack Recall 99.54% với threshold 0.5.
3. Khi dùng threshold 0.1 cho chế độ security, obfuscated recall tăng lên 99.76%.
4. Train nhanh hơn mô hình cải tiến.
5. Mô hình đơn giản hơn, dễ giải thích hơn, phù hợp với báo cáo nghiên cứu.

Có thể trình bày hai chế độ vận hành:

| Chế độ | Threshold | Mục tiêu |
|---|---:|---|
| Balanced mode | 0.5 | Cân bằng precision/recall |
| Security mode | 0.1 | Ưu tiên giảm false negative |

## 12. Đóng Góp Chính Của Đề Tài

Đề tài không tuyên bố phát minh kiến trúc CNN-LSTM hoàn toàn mới. Đóng góp nằm ở pipeline và đánh giá:

1. Áp dụng char-level no-decoding để bảo toàn dấu vết obfuscation.
2. Dùng CNN để trích xuất pattern cục bộ và LSTM để học ngữ cảnh chuỗi.
3. Tách riêng tập obfuscation 150,000 mẫu để đánh giá robustness.
4. Phân tích threshold để tối ưu theo hướng giảm false negative trong bảo mật.
5. Thử nghiệm mô hình cải tiến và chứng minh mô hình đơn giản ban đầu phù hợp hơn với mục tiêu chống obfuscation.

## 13. Hướng Phát Triển

Một số hướng tiếp theo:

- Phân tích sâu các false negative trong `false_negatives_obfuscated_test.csv`.
- Tăng cường dữ liệu cho nhóm yếu `mixed_case`.
- Thử baseline CNN-only, LSTM-only, TF-IDF + SVM/Logistic Regression.
- Thử obfuscation-aware augmentation: đưa một phần nhỏ obfuscation vào train và giữ phần còn lại làm holdout.
- Đánh giá thêm False Positive Rate trên lưu lượng HTTP thực tế.

## 14. Kết Luận Chung

Pipeline char-level no-decoding kết hợp Hybrid 1D-CNN + LSTM cho kết quả tốt trên cả tập kiểm thử thông thường và tập obfuscation tự tạo. Kết quả cho thấy việc giữ nguyên encoding, case variation và các dấu vết làm rối giúp mô hình học được pattern tấn công ở dạng gần với môi trường thực tế. Thử nghiệm cải tiến bằng SpatialDropout, BatchNormalization và Bidirectional LSTM cho thấy mô hình phức tạp hơn không nhất thiết tốt hơn về robustness. Do đó, mô hình CNN-LSTM gốc kết hợp threshold tuning là lựa chọn phù hợp nhất cho mục tiêu của đề tài.
