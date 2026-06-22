# BÁO CÁO TỔNG HỢP DỰ ÁN

## PHÁT HIỆN TẤN CÔNG WEB SQL INJECTION VÀ XSS BẰNG MÔ HÌNH CHARACTER-LEVEL CNN-LSTM

---

## 1. Tóm tắt

Dự án xây dựng hệ thống phân loại HTTP request/payload thành hai lớp: **Normal (0)** và **Attack (1)**. Lớp Attack hợp nhất SQL Injection (SQLi) và Cross-Site Scripting (XSS). Trọng tâm của nghiên cứu là khả năng nhận diện payload đã bị che giấu bằng URL encoding, HTML entity, Unicode encoding, thay đổi chữ hoa/thường, chèn comment, khoảng trắng hoặc ký tự nhiễu.

Hệ thống sử dụng biểu diễn ở cấp ký tự. Pipeline chính không giải mã URL/HTML, không chuyển chữ thường và chỉ chuẩn hóa khoảng trắng. Cách xử lý này giữ lại dấu vết của kỹ thuật che giấu để mô hình có thể học trực tiếp. Tokenizer chỉ được fit trên tập train nhằm hạn chế rò rỉ dữ liệu.

Mô hình đề xuất chính là **CNN-LSTM nối tiếp**: CNN trích xuất các mẫu ký tự cục bộ, sau đó LSTM phân tích chuỗi đặc trưng đã được CNN nén. Nghiên cứu cũng thực hiện các baseline và biến thể gồm CNN-only, CNN-LSTM Sequence Pooling, CNN-BiLSTM, CNN-LSTM song song và LSTM-only.

Trên tập test thông thường, CNN-LSTM chính đạt Accuracy **99,4218%**, ROC-AUC **99,9566%** và Attack Recall **99,2541%**. Trên 150.000 payload obfuscation được giữ riêng hoàn toàn khỏi quá trình huấn luyện, mô hình phát hiện đúng **149.311** mẫu, tương ứng Attack Recall **99,5407%**. Tuy nhiên, CNN-only đạt recall obfuscation cao hơn (**99,6740%**) với số tham số thấp hơn. Vì vậy, kết quả không chứng minh rằng mô hình lai luôn vượt CNN; nó cho thấy dữ liệu hiện tại chứa nhiều tín hiệu cục bộ mà CNN có thể khai thác rất hiệu quả.

---

## 2. Bài toán và mục tiêu nghiên cứu

### 2.1. Bài toán

Đầu vào là chuỗi chứa URL, nội dung request hoặc payload. Đầu ra là xác suất chuỗi thuộc lớp Attack:

\[
\hat{y} = P(y=1 \mid x)
\]

Với ngưỡng quyết định \(t\):

\[
\text{label} =
\begin{cases}
1, & \hat{y} \ge t \\
0, & \hat{y} < t
\end{cases}
\]

### 2.2. Mục tiêu

1. Xây dựng pipeline thống nhất cho dữ liệu SQLi, XSS và request bình thường.
2. Hạn chế data leakage khi chia dữ liệu và xây dựng vocabulary.
3. Đánh giá khả năng tổng quát trên payload thông thường và payload obfuscation chưa dùng để train.
4. So sánh CNN, LSTM và nhiều cách kết hợp CNN-LSTM.
5. Triển khai mô hình đã huấn luyện thành webapp phục vụ thử nghiệm inference.

### 2.3. Câu hỏi nghiên cứu

- Character-level learning có nhận diện được payload bị biến đổi ở cấp ký tự hay không?
- LSTM có tạo lợi thế rõ ràng so với CNN-only trên bộ dữ liệu hiện tại hay không?
- Cách lấy trạng thái cuối của LSTM, sequence pooling, BiLSTM hoặc ghép hai nhánh song song ảnh hưởng thế nào tới kết quả?
- Mô hình nào phù hợp nhất cho nghiên cứu và mô hình nào phù hợp nhất cho triển khai nhẹ?

---

## 3. Đóng góp và phạm vi mới của dự án

CNN-LSTM không phải kiến trúc hoàn toàn mới. Điểm đóng góp của dự án nằm ở **thiết kế pipeline và giao thức đánh giá**, cụ thể:

1. Giữ nguyên dấu vết obfuscation bằng chính sách no-decoding, case-sensitive.
2. Xây dựng tập 150.000 payload obfuscation để đánh giá robustness độc lập.
3. Thực hiện ablation có kiểm soát giữa CNN-only và các biến thể CNN-LSTM dùng chung dữ liệu, tokenizer, seed và cách chia tập.
4. Phân tích đồng thời false positive, false negative, Attack Recall, AUC và chi phí mô hình thay vì chỉ báo cáo Accuracy.
5. Đóng gói model, tokenizer và metadata để tái sử dụng nhất quán trong Flask webapp.

Không nên tuyên bố dự án vượt một công trình khác chỉ dựa trên Accuracy nếu dữ liệu, cách chia tập, preprocessing hoặc giao thức đánh giá khác nhau.

---

## 4. Dữ liệu

### 4.1. Nguồn dữ liệu

| Nguồn | Vai trò |
|---|---|
| `SQLInjection_XSS_MixDataset.1.0.0.csv` | Payload Normal, SQLi và XSS |
| `csic_database.csv` | HTTP request từ CSIC 2010 |
| `obfuscation_dataset_full.xlsx` | 150.000 payload Attack đã được obfuscate |

SQLi và XSS được hợp nhất thành lớp Attack vì mục tiêu hiện tại là phát hiện request nguy hiểm ở tầng WAF/NIDS, chưa phải phân loại chi tiết loại tấn công.

### 4.2. Dữ liệu dùng cho nhóm thí nghiệm có kiểm soát

Sau làm sạch, hai tập cơ sở có **177.277** mẫu:

| Tập | Số mẫu | Normal | Attack |
|---|---:|---:|---:|
| Train | 127.638 | 45.593 | 82.045 |
| Validation | 14.183 | 5.066 | 9.117 |
| Test thông thường | 35.456 | 12.665 | 22.791 |
| Obfuscation test | 150.000 | 0 | 150.000 |

Tỉ lệ tương ứng xấp xỉ 72% train, 8% validation và 20% test. Việc chia tập sử dụng `stratify` và seed 42.

### 4.3. Ý nghĩa và giới hạn của tập obfuscation

Tập obfuscation chỉ chứa lớp Attack. Vì vậy:

- Chỉ số phù hợp nhất là **Attack Recall** hoặc số false negative.
- Không thể tính ROC-AUC do không có lớp Normal.
- Precision bằng 1 trong báo cáo sklearn không có nghĩa mô hình không tạo false positive, vì tập này không chứa mẫu Normal để đo false positive.
- Accuracy trên tập này về số học bằng Attack Recall, nhưng gọi là recall sẽ đúng bản chất hơn.

---

## 5. Pipeline tiền xử lý chung

### 5.1. Chuẩn hóa nhãn và trường dữ liệu

- Kaggle: đổi `Sentence` thành `payload`; nhãn Attack là giá trị lớn nhất của hai cột `SQLInjection` và `XSS`.
- CSIC: ghép `content` và `URL` thành payload; lấy `classification` làm nhãn.
- Mọi nhãn được đưa về `0 = Normal`, `1 = Attack`.
- Payload rỗng bị loại; dữ liệu trùng được xử lý trước khi chia tập.

### 5.2. Chính sách no-decoding

Hàm chuẩn hóa chỉ thu gọn chuỗi whitespace liên tiếp và loại khoảng trắng ở hai đầu:

```python
re.sub(r"\s+", " ", payload).strip()
```

Pipeline chủ động:

- không URL decode `%27`, `%20`, `%3C`;
- không HTML unescape `&#x...;`;
- không lowercase;
- không loại dấu nháy, dấu `<`, `>`, `%`, `/`, `=` hoặc comment SQL.

Lợi ích là bảo toàn bằng chứng tấn công. Đổi lại, vocabulary lớn hơn và mô hình phải tự học quan hệ giữa nhiều biểu diễn tương đương.

### 5.3. Chia tập trước khi fit tokenizer

Tokenizer được cấu hình:

```python
Tokenizer(
    char_level=True,
    lower=False,
    filters="",
    oov_token="<OOV>"
)
```

Tokenizer chỉ fit trên payload của tập train. Validation, test và obfuscation test chỉ được transform. Đây là bước quan trọng để vocabulary không học trước ký tự từ tập đánh giá.

### 5.4. Vector hóa và padding

Mỗi ký tự được ánh xạ thành một token ID. Chuỗi được pad/cắt về `MAX_LEN = 1024`:

- `padding="post"`: thêm token 0 ở cuối;
- `truncating="post"`: cắt phần cuối nếu vượt 1024 ký tự.

P99 của tập cơ sở khoảng 975 ký tự, do đó 1024 giữ được gần như toàn bộ phần quan trọng của đa số request.

### 5.5. Embedding

Embedding không phải bước tiền xử lý cố định mà là lớp đầu tiên được học cùng mô hình. Với vocabulary 191 và embedding dimension 64, mỗi token ký tự được ánh xạ thành vector 64 chiều:

\[
(B, 1024) \rightarrow (B, 1024, 64)
\]

Embedding cho phép mô hình học các ký tự có vai trò tương tự thay vì xem token ID như giá trị số liên tục.

### 5.6. Mất cân bằng lớp

Class weight được tính từ tập train:

- Normal: khoảng 1,3998;
- Attack: khoảng 0,7779.

Lỗi trên lớp Normal ít mẫu hơn được gán trọng số lớn hơn trong binary cross-entropy.

---

## 6. Mô hình chính: CNN-LSTM nối tiếp

### 6.1. Kiến trúc

```text
Token IDs (1024)
    -> Embedding(64)
    -> Conv1D(128, kernel=3, ReLU)
    -> MaxPooling1D(pool=4)
    -> Conv1D(128, kernel=5, ReLU)
    -> MaxPooling1D(pool=4)
    -> LSTM(128)
    -> Dense(64, ReLU)
    -> Dropout(0.3)
    -> Dense(1, Sigmoid)
```

Luồng shape chính:

```text
(B, 1024) -> (B, 1024, 64)
          -> (B, 1024, 128)
          -> (B, 256, 128)
          -> (B, 256, 128)
          -> (B, 64, 128)
          -> (B, 128)
          -> (B, 64)
          -> (B, 1)
```

Mô hình có khoảng **258.881 tham số**.

### 6.2. Cách hoạt động

Conv1D quét các cửa sổ ký tự để phát hiện mẫu ngắn như `%27`, `<sc`, `or+`, dấu nháy, comment hoặc chuỗi từ khóa. Max pooling giảm độ dài từ 1024 xuống 64 timestep, nhờ đó LSTM không phải xử lý toàn bộ chuỗi gốc.

LSTM nhận **đầu ra của CNN**, không nhận trực tiếp token embedding. Nó kết hợp các đặc trưng cục bộ theo thứ tự để tạo vector ngữ cảnh 128 chiều. Dense và sigmoid chuyển vector này thành xác suất Attack.

### 6.3. Huấn luyện

- Loss: binary cross-entropy.
- Optimizer: Adam.
- Batch size: 128.
- Tối đa: 50 epoch.
- Early stopping: theo dõi validation loss, patience 5.
- Model checkpoint: lưu model có validation loss tốt nhất.
- Seed: 42.

---

## 7. Các baseline và biến thể

### 7.1. CNN-only

CNN-only dùng đúng pipeline của mô hình chính, nhưng thay LSTM bằng `GlobalMaxPooling1D`:

```text
Embedding -> Conv -> Pool -> Conv -> Pool
          -> GlobalMaxPooling -> Dense -> Sigmoid
```

Mục đích là kiểm tra LSTM có thực sự tạo thêm giá trị hay CNN đã đủ mạnh. Mô hình có **127.297 tham số**, chạy 12 epoch với trung bình khoảng **404 giây/epoch** trong lần đo đã lưu.

### 7.2. CNN-LSTM Sequence Pooling

Biến thể này đặt `return_sequences=True` cho LSTM, sau đó dùng Global Max Pooling trên toàn bộ chuỗi đầu ra:

```text
CNN -> LSTM(return_sequences=True)
    -> GlobalMaxPooling1D -> Dense -> Sigmoid
```

Mục tiêu là tránh phụ thuộc hoàn toàn vào trạng thái LSTM cuối. Mô hình có **258.881 tham số**, chạy 10 epoch với trung bình khoảng **635 giây/epoch**.

### 7.3. CNN-BiLSTM

Biến thể cải tiến bổ sung Spatial Dropout, Batch Normalization và Bidirectional LSTM:

```text
Embedding -> SpatialDropout
          -> Conv + BN + ReLU -> Pool
          -> Conv + BN + ReLU -> Pool
          -> Bidirectional LSTM(64)
          -> Dense + BN + ReLU -> Dropout -> Sigmoid
```

Mô hình có khoảng **227.073 tham số**. Ngoài ngưỡng mặc định 0,5, thí nghiệm chọn ngưỡng 0,1 trên validation với ràng buộc Normal Recall tối thiểu 0,99.

### 7.4. CNN-LSTM song song của thành viên khác

Đây là biến thể trong `cnn_lstm_parallel/cnn_lstm_parallel_experiment.ipynb`. Khác với mô hình nối tiếp, đầu ra CNN không được đưa vào LSTM; hai nhánh nhận chung đầu ra Embedding rồi học hai loại biểu diễn độc lập:

```text
                    -> CNN blocks -> GlobalMaxPool --┐
Embedding -------------------------------------------+-> Concatenate -> Dense -> Sigmoid
                    -> LSTM(32) -> LSTM(16) ---------┘
```

Pipeline loại 30 payload có nhãn mâu thuẫn và các payload trùng, còn **177.217 mẫu** gồm 63.294 Normal và 113.923 Attack. Dữ liệu được stratified split theo tỉ lệ 72/8/20:

| Tập | Số mẫu |
|---|---:|
| Train | 127.596 |
| Validation | 14.177 |
| Test | 35.444 |

Tokenizer character-level chỉ fit trên train, vocabulary có 187 token và `MAX_LEN = 512`. Khoảng p95 độ dài payload là 883 ký tự, vì vậy giới hạn 512 vẫn cắt một phần đáng kể request dài và cần được xem là hạn chế của biến thể này.

#### Tìm hyperparameter bằng Random Search

Thay vì giữ một cấu hình cố định, notebook thử ngẫu nhiên 6 cấu hình. Mỗi trial dùng 35% tập train để giảm thời gian tìm kiếm, tối đa 8 epoch, Early Stopping theo `val_auc`; validation và test không được dùng để cập nhật trọng số. Sau đó, cấu hình có `val_auc` tốt nhất được dựng lại và huấn luyện trên toàn bộ train.

| Trial | Best epoch | Best val AUC | Embedding | CNN filters | LSTM | Dense | Learning rate | Batch |
|---:|---:|---:|---:|---|---|---:|---:|---:|
| 3 | 4 | **99,2770%** | 32 | 128-128-64 | 32-16 | 64 | 0,0005 | 128 |
| 5 | 7 | 99,1675% | 32 | 128-128-64 | 32-16 | 32 | 0,0005 | 128 |
| 6 | 3 | 99,0829% | 32 | 64-64-32 | 32-16 | 32 | 0,0005 | 128 |
| 1 | 4 | 98,9428% | 64 | 64-64-32 | 64-32 | 32 | 0,0005 | 128 |
| 2 | 1 | 87,1073% | 64 | 128-64-32 | 32-16 | 64 | 0,001 | 256 |
| 4 | 1 | 67,9453% | 64 | 128-128-64 | 32-16 | 32 | 0,001 | 256 |

Cấu hình thắng dùng Embedding 32, CNN filters 128-128-64 với kernel 3-4-5, CNN dropout 0,3, LSTM 32-16, LSTM dropout 0,2, Dense 64, L2 bằng 0,0005, learning rate 0,0005 và batch size 128. Mô hình cuối có **143.329 tham số**, trong đó 142.561 tham số trainable.

Ngưỡng quyết định không giữ ở 0,5 mà được chọn bằng F1 trên validation:

```text
BEST_THRESHOLD = 0,740835
Validation Precision = 99,72%
Validation Recall    = 98,20%
Validation F1        = 98,96%
```

Trên test thông thường, checkpoint tốt nhất cùng threshold 0,740835 đạt Accuracy 98,6514%, ROC-AUC 99,6396%, PR-AUC 99,8240% và Attack Recall 98,1742%. Confusion matrix tương ứng có 62 false positive và 416 false negative.

Tập obfuscation 150.000 mẫu được đánh giá độc lập bằng cùng checkpoint, tokenizer, `MAX_LEN` và threshold 0,740835. Mô hình phát hiện 149.354 mẫu và bỏ sót 646 mẫu, tương ứng Attack Recall **99,5693%** và Attack F1 **99,7842%**. Vì tập này không có Normal, ROC-AUC không được tính và precision bằng 1 không phản ánh khả năng kiểm soát false positive.

Trong 646 false negative obfuscation, `mixed_case` chiếm 567 mẫu, tương đương 87,77% tổng số bỏ sót. Recall của riêng nhóm này là 96,6737%, thấp rõ rệt so với `unicode_encoding` (99,8761%) và `noise_injection` (99,8682%). Điều này cho thấy biến đổi chữ hoa/thường là điểm yếu nổi bật của mô hình song song dù pipeline chủ động giữ nguyên case.

Giao thức đánh giá cuối đã thống nhất hoàn toàn: validation, test thông thường và obfuscation test đều nạp `best_cnn_lstm_model.keras` và sử dụng cùng threshold 0,740835 lưu trong `preprocessing_config.json`.

Một số mô tả cũ ghi BiLSTM, nhưng code thực nghiệm sử dụng hai LSTM một chiều 32 và 16 units.

### 7.5. LSTM-only

Baseline LSTM-only được cài đặt bằng PyTorch Lightning, theo kiến trúc character-level:

```text
Embedding(64) -> Dropout -> LSTM(128, 2 layers)
              -> Dense(64) -> Dropout -> Sigmoid logit
```

Mô hình có khoảng **251 nghìn tham số** (embedding 12,0K, LSTM 231K và classifier 8,3K). `pack_padded_sequence` được dùng để LSTM chỉ xử lý phần ký tự thực, không học trên phần padding.

Pipeline sử dụng đúng hai tập `SQLInjection_XSS_MixDataset.1.0.0.csv` và `csic_database.csv`, đồng nhất với CNN-LSTM về nguồn dữ liệu và tiền xử lý: giữ nguyên chữ hoa/thường và encoding, chỉ gộp khoảng trắng liên tiếp rồi `strip()`. Sau khi bỏ payload rỗng, xóa payload trùng và loại 30 payload có nhãn mâu thuẫn, dữ liệu còn **177.217 mẫu** (63.294 Normal, 113.923 Attack). Dữ liệu được stratified split thành **72% train, 8% validation và 20% test**; vocabulary ký tự chỉ fit trên train và `MAX_LEN` được chọn từ p95 của train, giới hạn tối đa 512.

Trên tập test gồm 35.444 mẫu, mô hình đạt các kết quả sau:

| Ngưỡng | Accuracy | Attack Precision | Attack Recall | Attack F1 | ROC-AUC | PR-AUC | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 0,50 | 98,6655% | 99,7813% | 98,1391% | 98,9534% | 99,5833% | 99,8006% | 49 | 424 |
| 0,18 (chọn trên validation) | **98,7191%** | 99,7239% | **98,2796%** | **98,9965%** | 99,5833% | 99,8006% | 62 | **392** |

Ngưỡng 0,18 tăng Attack Recall và giảm 32 false negative so với ngưỡng 0,5, nhưng tăng false positive từ 49 lên 62. Ngưỡng này được chọn trên validation, không dùng test để tuning.

Trên tập obfuscation ngoài tập, file gốc có 150.000 payload Attack. Một payload trùng hệt với dữ liệu cơ sở được loại trước khi đánh giá, còn **149.999** mẫu. Ở ngưỡng 0,18, LSTM-only phát hiện **148.738** mẫu và bỏ sót **1.261** mẫu, tương ứng **Attack Recall 99,1593%**; xác suất Attack trung bình là 97,7182%. Vì tập này không có Normal, chỉ số này được diễn giải là khả năng phát hiện Attack trên dữ liệu obfuscation, không phải accuracy/precision tổng quát.

---

## 8. Kết quả thực nghiệm

### 8.1. Nhóm dùng chung pipeline - ngưỡng 0,5

| Mô hình | Accuracy test | ROC-AUC | Attack Recall | Attack F1 | FP | FN | Recall obfuscation | Bỏ sót obfuscation |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| CNN-only | 99,4105% | 99,9528% | 99,2234% | 99,5400% | 32 | 177 | **99,6740%** | **489** |
| CNN-LSTM nối tiếp | 99,4218% | 99,9566% | 99,2541% | 99,5489% | 35 | 170 | 99,5407% | 689 |
| CNN-LSTM Sequence Pool | **99,4641%** | **99,9587%** | **99,3726%** | **99,5823%** | 47 | **143** | 99,3300% | 1.005 |
| CNN-BiLSTM | 99,4810% | Không lưu | 99,2716% | **99,5950%** | **18** | 166 | 98,2567% | 2.615 |

CNN-BiLSTM không lưu ROC-AUC test trong metadata hiện tại, vì vậy không điền giá trị suy đoán.

### 8.2. CNN-BiLSTM tại ngưỡng 0,1

| Chỉ số | Kết quả |
|---|---:|
| Accuracy test | 99,4529% |
| Attack Recall | 99,4735% |
| Attack F1 | 99,5740% |
| False positive | 74 |
| False negative | 120 |
| Recall obfuscation | 99,3633% |
| Obfuscation bị bỏ sót | 955 |

Hạ ngưỡng làm giảm false negative trên test thường nhưng tăng false positive. Trên obfuscation, ngưỡng 0,1 tốt hơn 0,5 nhưng vẫn chưa vượt CNN-only hoặc CNN-LSTM chính. So sánh ngưỡng chỉ công bằng khi mọi mô hình đều được tuning theo cùng một quy tắc validation.

### 8.3. Các baseline bổ sung

| Mô hình | Giao thức | Accuracy | Attack Precision | Attack Recall | Attack F1 | ROC-AUC | FP | FN | Recall obfuscation | Bỏ sót obfuscation |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| CNN-LSTM song song, threshold 0,740835 | Random Search 6 trial; cùng checkpoint/threshold cho hai test | 98,6514% | 99,7236% | 98,1742% | 98,9429% | 99,6396% | 62 | 416 | **99,5693%** | **646** |
| LSTM-only, threshold 0,5 | Hai CSV cơ sở, no-decoding, split 72/8/20 | 98,6655% | 99,7813% | 98,1391% | 98,9534% | 99,5833% | 49 | 424 | - | - |
| LSTM-only, threshold 0,18 | Ngưỡng chọn trên validation; obfuscation tách ngoài train | **98,7191%** | 99,7239% | **98,2796%** | **98,9965%** | 99,5833% | 62 | **392** | **99,1593%** | **1.261** |

CNN-LSTM song song hiện đã dùng split 72/8/20, no-decoding, tokenizer fit trên train và tập obfuscation tách ngoài quá trình train. Tuy nhiên, nó vẫn là baseline độc lập so với nhóm ở mục 8.1 vì dùng `MAX_LEN=512`, cách khử trùng lặp, kiến trúc, Random Search và quy tắc threshold khác. LSTM-only cũng khác framework, regularization và lịch huấn luyện; do đó bảng này hỗ trợ so sánh thực nghiệm nhưng chưa phải ablation tuyệt đối.

---

## 9. Phân tích kết quả

### 9.1. CNN-only mạnh hơn dự kiến

CNN-only có kết quả test thường gần như tương đương CNN-LSTM, đồng thời có recall obfuscation cao nhất và chỉ khoảng một nửa số tham số. Điều này cho thấy nhiều tín hiệu trong dữ liệu hiện tại là pattern cục bộ mạnh. SQLi/XSS thường chứa token đặc trưng như dấu nháy, thẻ HTML, keyword, comment hoặc encoding marker; Global Max Pooling chỉ cần xác định pattern xuất hiện ở đâu đó trong chuỗi.

Kết quả này không phải thất bại. Đây là một phát hiện thực nghiệm có giá trị: **độ phức tạp tuần tự chưa tạo lợi ích rõ ràng trên phân phối dữ liệu hiện tại**.

### 9.2. CNN-LSTM nối tiếp tạo cải thiện nhỏ trên test thường

So với CNN-only, CNN-LSTM tăng Accuracy từ 99,4105% lên 99,4218% (tăng 0,0113 điểm phần trăm), tăng Attack Recall từ 99,2234% lên 99,2541% (tăng 0,0307 điểm phần trăm) và giảm false negative từ 177 xuống 170. ROC-AUC và Attack F1 cũng nhỉnh hơn lần lượt khoảng 0,0038 và 0,0089 điểm phần trăm. Đổi lại, false positive tăng từ 32 lên 35.

Trên tập obfuscation, CNN-only tốt hơn: recall cao hơn 0,1333 điểm phần trăm và bỏ sót 489 mẫu thay vì 689 mẫu, tức ít hơn 200 false negative. Vì vậy, có thể kết luận **CNN-LSTM nhỉnh nhẹ về chất lượng phân loại trên tập test thông thường**, còn **CNN-only nhỉnh hơn về độ bền obfuscation và hiệu quả tài nguyên**. Mức chênh lệch giữa hai mô hình vẫn nhỏ, chưa đủ để khẳng định LSTM vượt trội nếu chưa chạy nhiều seed và kiểm định thống kê.

Nếu đánh giá tổng thể theo mục tiêu nghiên cứu gồm hiệu năng test thông thường, khả năng mô hình hóa cả đặc trưng cục bộ lẫn quan hệ tuần tự, độ bền obfuscation ở mức cao và mức độ hoàn thiện của pipeline triển khai, CNN-LSTM là lựa chọn cân bằng phù hợp. Nếu ưu tiên tuyệt đối recall obfuscation, tốc độ và kích thước mô hình, CNN-only phù hợp hơn.

### 9.3. Sequence Pooling tối ưu test thường nhưng giảm robustness

Sequence Pooling đạt Accuracy, AUC và Attack Recall tốt nhất trong nhóm ba mô hình CNN/CNN-LSTM trực tiếp. Đổi lại, nó bỏ sót 1.005 payload obfuscation, cao hơn CNN-only và mô hình chính. Mô hình có thể đang tối ưu tốt phân phối test cơ sở nhưng khái quát kém hơn sang một số kiểu obfuscation.

### 9.4. BiLSTM phụ thuộc mạnh vào threshold

BiLSTM tạo precision rất cao ở threshold 0,5 nhưng recall obfuscation thấp. Hạ threshold cải thiện recall, song tăng false positive. Điều này nhấn mạnh rằng lựa chọn threshold là một phần của thiết kế hệ thống an ninh, không phải chi tiết phụ sau huấn luyện.

### 9.5. Mức độ công bằng khi so sánh baseline

CNN-LSTM song song và LSTM-only đều đã dùng hai nguồn dữ liệu cơ sở, quy tắc no-decoding, split 72/8/20 và tập obfuscation tách ngoài train. Điều này làm phép so sánh có ý nghĩa hơn phiên bản cũ. Tuy nhiên, CNN-LSTM song song dùng `MAX_LEN=512`, Random Search và threshold tối ưu F1; nhóm mô hình chính dùng `MAX_LEN=1024` và giao thức huấn luyện khác, còn LSTM-only dùng PyTorch Lightning. Callback, regularization, snapshot checkpoint và framework vẫn là biến nhiễu. Muốn ablation tuyệt đối cần giữ cố định toàn bộ các yếu tố này ngoài kiến trúc.

### 9.6. Ý nghĩa kết quả của CNN-LSTM song song

Random Search cho thấy cấu hình có learning rate 0,0005 và batch size 128 ổn định hơn rõ rệt hai trial dùng learning rate 0,001 và batch size 256. Hai trial sau chỉ đạt best validation AUC lần lượt 87,1073% và 67,9453%, trong khi bốn cấu hình dùng learning rate 0,0005 đều đạt từ 98,9428% đến 99,2770%. Với số trial còn ít, chưa thể tách riêng tác động của learning rate và batch size, nhưng kết quả cho thấy cấu hình huấn luyện mạnh hơn không đồng nghĩa hội tụ tốt hơn.

Cấu hình thắng dùng Embedding 32 thay vì 64. Điều này gợi ý vocabulary 187 ký tự không cần không gian embedding quá lớn trong thí nghiệm hiện tại. Nhánh CNN 128-128-64 tạo biểu diễn cục bộ mạnh, còn nhánh LSTM 32-16 tương đối nhỏ; toàn mô hình chỉ có 143.329 tham số nhưng đạt ROC-AUC test 99,6396%.

Trên test thông thường, CNN-LSTM song song gần tương đương LSTM-only dùng threshold tối ưu: Accuracy thấp hơn 0,0677 điểm phần trăm và Attack Recall thấp hơn 0,1054 điểm phần trăm. Trên obfuscation, mô hình song song đạt Recall 99,5693%, cao hơn LSTM-only 0,4100 điểm phần trăm và giảm số bỏ sót từ 1.261 xuống 646. Kết quả này ủng hộ giả thuyết rằng nhánh CNN song song bổ sung khả năng nhận diện các dấu hiệu ký tự cục bộ mà LSTM-only dễ bỏ qua.

Tuy nhiên, 567/646 false negative của mô hình song song thuộc nhóm `mixed_case`, tương đương 87,77% tổng số bỏ sót. Đây là điểm yếu tập trung, không phải suy giảm đồng đều trên mọi kỹ thuật obfuscation. Các hướng cải thiện nên ưu tiên augmentation thay đổi chữ hoa/thường, case-invariant auxiliary features hoặc đánh giá thêm mô hình vừa giữ case vừa có nhánh chuẩn hóa lowercase.

---

## 10. Lựa chọn mô hình

### 10.1. Mô hình nghiên cứu chính và webapp

Dự án tiếp tục chọn **CNN-LSTM nối tiếp** trong `cnn_lstm/CNN_LSTM.py` làm mô hình nghiên cứu chính và model phục vụ webapp. Quyết định này dựa trên nhiều tiêu chí thay vì chỉ chọn giá trị lớn nhất của một metric:

1. Kiến trúc bám sát giả thuyết nghiên cứu: CNN học dấu hiệu cục bộ, LSTM kết hợp theo ngữ cảnh.
2. Trên test thông thường, mô hình nhỉnh nhẹ hơn CNN-only về Accuracy, ROC-AUC, Attack Recall, Attack F1 và số false negative.
3. Trên obfuscation, recall 99,5407% vẫn ở mức cao dù thấp hơn CNN-only 0,1333 điểm phần trăm.
4. Mô hình giữ trục thời gian sau local pooling, phù hợp mục tiêu phân tích payload bị chèn nhiễu hoặc tách rời các dấu hiệu tấn công.
5. Pipeline, tokenizer, metadata và webapp đã được tích hợp hoàn chỉnh, bảo đảm khả năng tái sử dụng kết quả huấn luyện.

Theo bộ tiêu chí trên, CNN-LSTM được xem là mô hình **cân bằng và phù hợp nhất với mục tiêu nghiên cứu tổng thể**, chứ không phải mô hình vượt trội tuyệt đối ở mọi phép đo. CNN-only vẫn tốt hơn về recall obfuscation, số tham số và tiềm năng tốc độ inference.

### 10.2. Mô hình khuyến nghị cho triển khai nhẹ

Nếu ưu tiên tốc độ, kích thước và recall obfuscation trên dữ liệu hiện tại, **CNN-only là lựa chọn Pareto tốt hơn**:

- 127.297 tham số so với 258.881;
- recall obfuscation cao nhất;
- Accuracy test chỉ thấp hơn mô hình chính khoảng 0,0113 điểm phần trăm;
- dễ tối ưu inference hơn do không có phép tính tuần tự của LSTM.

Do đó, báo cáo đề xuất giữ hai hướng:

- CNN-LSTM: mô hình nghiên cứu và prototype chính;
- CNN-only: baseline mạnh và ứng viên edge/real-time.

---

## 11. Webapp inference

Webapp Flask nằm trong `webapp/` và tải:

```text
cnn_lstm/artifacts/best_hybrid_cnn_lstm.keras
cnn_lstm/artifacts/tokenizer.pkl
cnn_lstm/artifacts/metadata_and_results.json
```

Luồng xử lý:

```text
Người dùng nhập payload
    -> Flask nhận JSON
    -> chuẩn hóa whitespace
    -> tokenizer char-level
    -> pad/truncate về max_len từ metadata
    -> model.predict
    -> áp dụng threshold
    -> trả xác suất Attack/Normal
```

API chính:

- `GET /`: giao diện thử nghiệm;
- `GET /api/health`: kiểm tra model, tokenizer và runtime;
- `POST /api/predict`: dự đoán một payload.

Webapp hiện là sản phẩm minh họa nghiên cứu, chưa phải WAF production. Bản production cần bổ sung authentication, rate limiting, logging an toàn, giới hạn kích thước request, kiểm thử tải, xử lý đồng thời và cơ chế cập nhật model.

---

## 12. Cấu trúc dự án

```text
NCKH_sp/
|-- cnn_lstm/                         # mô hình nghiên cứu chính
|   |-- CNN_LSTM.py
|   |-- CNN_LSTM.ipynb
|   `-- artifacts/
|-- cnn_only/                         # baseline CNN
|-- lstm_only/                        # baseline LSTM độc lập
|-- cnn_lstm_parallel/                # baseline song song độc lập
|-- experiments/
|   |-- cnn_bilstm/
|   `-- cnn_lstm_sequence_pool/
|-- preprocessing/
|-- analysis/
|-- reports/
|-- webapp/
|-- SQLInjection_XSS_MixDataset.1.0.0.csv
|-- csic_database.csv
`-- obfuscation_dataset_full.xlsx
```

Dataset và artifact sinh cục bộ được `.gitignore`; repository chỉ lưu code, notebook, báo cáo và webapp.

---

## 13. Hạn chế

1. Tập obfuscation chỉ có lớp Attack nên không đo được false positive hoặc AUC trên miền obfuscation.
2. Các biến thể obfuscation có thể được sinh từ số lượng pattern gốc hạn chế; cần family-holdout để tránh đánh giá quá lạc quan giữa các biến thể gần giống nhau.
3. Phần lớn thí nghiệm mới chạy một seed; chưa có trung bình, độ lệch chuẩn hoặc kiểm định ý nghĩa thống kê.
4. Chưa benchmark latency, throughput, RAM và kích thước model trên cùng phần cứng.
5. LSTM-only vẫn dùng framework, regularization và lịch huấn luyện khác nhóm Keras, nên chưa phải ablation kiến trúc tuyệt đối.
6. Threshold chưa được tuning thống nhất cho mọi mô hình.
7. `truncating="post"` có thể bỏ dấu hiệu tấn công nằm cuối request dài.
8. Kết quả cao trên benchmark không bảo đảm chống được zero-day hoặc traffic production thay đổi theo thời gian.

---

## 14. Hướng phát triển

1. Xây dựng split theo family/base payload cho dữ liệu obfuscation.
2. Bổ sung benign request có encoding, ký tự đặc biệt và nội dung dài để đo false positive thực tế.
3. Chạy mỗi kiến trúc với ít nhất 3-5 seed và báo cáo khoảng tin cậy.
4. Chạy LSTM-only và các mô hình Keras với cùng hyperparameter/callback để ablation kiến trúc chặt chẽ hơn.
5. Tuning threshold trên validation theo chi phí FN/FP đã định trước.
6. Đo latency, throughput và RAM cho CNN-only và CNN-LSTM.
7. Thử masking padding, attention nhẹ hoặc pooling có mask.
8. Phân tích false negative theo loại obfuscation và độ dài.
9. Đánh giá cross-dataset và dữ liệu thu thập mới ngoài benchmark.
10. Bổ sung cơ chế giám sát drift và tái huấn luyện cho hệ thống triển khai.

---

## 15. Kết luận

Dự án đã xây dựng hoàn chỉnh pipeline character-level phát hiện SQLi/XSS, huấn luyện nhiều kiến trúc và triển khai mô hình chính thành webapp. CNN-LSTM nối tiếp đạt hiệu năng cao trên cả test thông thường và tập obfuscation độc lập. Tuy nhiên, CNN-only cho thấy hiệu năng robustness tốt hơn với chi phí thấp hơn, còn Sequence Pooling đạt kết quả tốt nhất trên test cơ sở nhưng yếu hơn trên obfuscation.

Kết luận khoa học quan trọng nhất không phải “CNN-LSTM luôn tốt nhất”, mà là: **trên bộ dữ liệu hiện tại, đặc trưng cục bộ đủ mạnh để CNN-only cạnh tranh hoặc vượt mô hình lai; lợi ích của LSTM chỉ xuất hiện ở mức nhỏ và cần được kiểm chứng thêm bằng split theo family, nhiều seed và benchmark production**.

Mô hình CNN-LSTM vẫn được giữ làm mô hình nghiên cứu chính vì phù hợp mục tiêu ban đầu và đã tích hợp đầy đủ vào hệ thống. CNN-only được đề xuất như lựa chọn triển khai nhẹ và là baseline bắt buộc trong mọi kết luận tiếp theo.

---

## Phụ lục A. Nguồn số liệu

Số liệu nhóm thí nghiệm chung được lấy trực tiếp từ:

```text
cnn_lstm/artifacts/metadata_and_results.json
cnn_only/artifacts/metadata_and_results.json
experiments/cnn_lstm_sequence_pool/artifacts/metadata_and_results.json
experiments/cnn_bilstm/artifacts/metadata_and_results.json
```

Số liệu baseline độc lập được lấy từ output đã lưu trong:

```text
cnn_lstm_parallel/cnn_lstm_parallel_experiment.ipynb
cnn_lstm_parallel/artifacts/random_search_results.csv
cnn_lstm_parallel/artifacts/preprocessing_config.json
cnn_lstm_parallel/artifacts/obfuscation_evaluation.json
cnn_lstm_parallel/artifacts/obfuscation_results_by_type.csv
lstm_only/lstm_only_experiment.ipynb
lstm_only_baseline_colab (2).ipynb
```

## Phụ lục B. Lệnh chạy chính

Huấn luyện mô hình chính:

```powershell
python cnn_lstm/CNN_LSTM.py
```

Smoke test:

```powershell
python cnn_lstm/CNN_LSTM.py --sample-size 3000 --obfu-sample-size 1000 --epochs 3
```

Chạy webapp:

```powershell
cd webapp
python app.py
```

