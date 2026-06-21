# Báo Cáo So Sánh Và Lựa Chọn Mô Hình Phát Hiện SQLi/XSS

## 1. Mục Tiêu Báo Cáo

Báo cáo này tổng hợp các kiến trúc đã thử nghiệm trong đề tài phát hiện SQL Injection (SQLi) và Cross-Site Scripting (XSS), từ đó đánh giá mô hình phù hợp nhất theo các tiêu chí:

- Hiệu quả trên tập kiểm thử thông thường.
- Khả năng phát hiện payload bị obfuscation.
- Số lượng tấn công bị bỏ sót (False Negative).
- Số lượng truy cập bình thường bị cảnh báo nhầm (False Positive).
- Độ phức tạp và số lượng tham số.
- Khả năng triển khai trong hệ thống WAF/NIDS thời gian thực.

Mục tiêu không phải là chứng minh mô hình phức tạp nhất luôn tốt nhất. Thí nghiệm được sử dụng để trả lời câu hỏi:

> Trong bài toán phát hiện SQLi/XSS ở cấp ký tự với pipeline no-decoding, thành phần LSTM có tạo ra lợi ích đủ lớn so với CNN-only hay không?

## 2. Thiết Kế Thí Nghiệm Chung

### 2.1. Nguồn dữ liệu

Các mô hình sử dụng chung ba nguồn:

| Nguồn | Vai trò |
|---|---|
| `SQLInjection_XSS_MixDataset.1.0.0.csv` | Payload SQLi, XSS và Normal |
| `csic_database.csv` | HTTP request từ CSIC 2010 |
| `obfuscation_dataset_full.xlsx` | Tập obfuscation tự xây dựng |

Sau khi làm sạch và loại trùng:

| Tập | Số mẫu | Normal | Attack |
|---|---:|---:|---:|
| Train | 127,638 | 45,593 | 82,045 |
| Validation | 14,183 | 5,066 | 9,117 |
| Normal test | 35,456 | 12,665 | 22,791 |
| Obfuscated test | 150,000 | 0 | 150,000 |

Tập obfuscation không được đưa vào quá trình huấn luyện của các kết quả chính trong báo cáo này. Vì vậy, kết quả trên tập đó phản ánh khả năng **zero-shot obfuscation detection**.

### 2.2. Tiền xử lý chung

Tất cả mô hình sử dụng cùng pipeline:

- Không URL decode.
- Không HTML unescape.
- Không lowercase.
- Chỉ chuẩn hóa whitespace.
- Xóa payload rỗng và mẫu trùng.
- Tokenizer ở cấp ký tự (`char_level=True`).
- Tokenizer chỉ fit trên tập train.
- `MAX_LEN = 1024`.
- `padding="post"`, `truncating="post"`.
- Embedding 64 chiều.
- Class weight cân bằng theo phân phối nhãn train.
- Adam với learning rate `1e-3`.
- Binary cross-entropy.
- EarlyStopping và ModelCheckpoint theo `val_loss`.
- Threshold mặc định là 0.5, trừ khi ghi rõ.

Việc giữ nguyên preprocessing, dữ liệu và seed giúp kết quả giữa các kiến trúc có thể đối chiếu tương đối công bằng.

## 3. Các Mô Hình Đã Thử

### 3.1. CNN-only

Kiến trúc:

```text
Input
-> Embedding(64)
-> Conv1D(128, kernel=3)
-> MaxPooling1D(4)
-> Conv1D(128, kernel=5)
-> MaxPooling1D(4)
-> GlobalMaxPooling1D
-> Dense(64)
-> Dropout(0.3)
-> Sigmoid
```

CNN-only tìm các pattern ký tự cục bộ, ví dụ `%27`, `1=1`, `UNION`, `<script`, `javascript:`, `/**/`. `GlobalMaxPooling1D` giữ kích hoạt mạnh nhất của mỗi feature map tại bất kỳ vị trí nào trong payload.

Số tham số: **127,297**.

### 3.2. CNN-LSTM sử dụng final state

Kiến trúc ban đầu:

```text
Input
-> Embedding(64)
-> Conv1D(128, kernel=3)
-> MaxPooling1D(4)
-> Conv1D(128, kernel=5)
-> MaxPooling1D(4)
-> LSTM(128)
-> Dense(64)
-> Dropout(0.3)
-> Sigmoid
```

CNN trích xuất đặc trưng cục bộ và nén chuỗi từ 1024 xuống 64 timestep. LSTM nhận tensor `(batch, 64, 128)` và trả hidden state cuối cùng để phân loại.

Số tham số với vocabulary đầy đủ: **258,881**.

### 3.3. CNN-LSTM sequence pooling

Kiến trúc:

```text
CNN
-> LSTM(128, return_sequences=True)
-> GlobalMaxPooling1D
-> Dense
-> Sigmoid
```

Biến thể này không chỉ sử dụng hidden state cuối. LSTM trả toàn bộ 64 hidden states, sau đó GlobalMaxPooling lấy tín hiệu ngữ cảnh mạnh nhất. Mục tiêu là giảm ảnh hưởng của các timestep sinh từ post-padding.

Số tham số: **258,881**.

### 3.4. CNN-BiLSTM cải tiến

Kiến trúc:

```text
Embedding
-> SpatialDropout1D
-> Conv1D + BatchNormalization + ReLU
-> MaxPooling
-> Conv1D + BatchNormalization + ReLU
-> MaxPooling
-> Bidirectional LSTM
-> Dense + BatchNormalization + ReLU
-> Dropout
-> Sigmoid
```

Mục tiêu là tăng regularization, ổn định huấn luyện và học ngữ cảnh theo cả hai chiều. Mô hình được đánh giá với threshold 0.5 và threshold tối ưu 0.1.

Số tham số xấp xỉ: **227,073**.

## 4. Kết Quả Trên Normal Test

### 4.1. So sánh tại threshold 0.5

| Mô hình | Accuracy | AUC-ROC | Attack Precision | Attack Recall | Attack F1 | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|
| CNN-only | 99.4105% | 99.9528% | 99.8587% | 99.2234% | 99.5400% | 32 | 177 |
| CNN-LSTM final state | 99.4218% | 99.9566% | 99.8455% | 99.2541% | 99.5489% | 35 | 170 |
| CNN-LSTM sequence pool | **99.4641%** | **99.9587%** | 99.7929% | **99.3726%** | **99.5823%** | 47 | **143** |
| CNN-BiLSTM | **99.4810%** | N/A | **99.9205%** | 99.2716% | **99.5950%** | **18** | 166 |

### 4.2. Nhận xét

CNN-LSTM final state chỉ cải thiện rất nhẹ so với CNN-only:

- Accuracy tăng khoảng 0.0113 điểm phần trăm.
- False Negative giảm từ 177 xuống 170, tức phát hiện thêm 7 tấn công.
- False Positive tăng từ 32 lên 35.

CNN-LSTM sequence pool đạt Attack Recall tốt nhất trong nhóm threshold 0.5 và giảm FN xuống 143. Tuy nhiên, FP tăng lên 47.

CNN-BiLSTM đạt accuracy cao nhất và FP thấp nhất ở threshold 0.5, nhưng không có lợi thế tương ứng trên tập obfuscation.

Nhìn chung, cả bốn mô hình đều đạt trên 99.4% accuracy. Chênh lệch trên normal test nhỏ, nên không thể lựa chọn mô hình chỉ dựa trên accuracy.

## 5. Kết Quả Trên Obfuscated Test

Tập obfuscation chỉ chứa lớp Attack. Vì vậy, chỉ số phù hợp là Attack Recall/Detection Rate và số False Negative. Không sử dụng accuracy này để suy luận về khả năng phân biệt Normal/Attack.

| Mô hình | Threshold | Obfuscated Recall | Số phát hiện đúng | Số bỏ sót |
|---|---:|---:|---:|---:|
| CNN-only | 0.5 | **99.6740%** | **149,511** | **489** |
| CNN-LSTM final state | 0.5 | 99.5407% | 149,311 | 689 |
| CNN-LSTM sequence pool | 0.5 | 99.3300% | 148,995 | 1,005 |
| CNN-BiLSTM | 0.5 | 98.2567% | 147,385 | 2,615 |
| CNN-BiLSTM tuned | 0.1 | 99.3633% | 149,045 | 955 |

CNN-only đạt kết quả tốt nhất trên obfuscation zero-shot. Điều này cho thấy các dấu hiệu cục bộ ở cấp ký tự có tính phân biệt rất mạnh. Việc thêm LSTM không làm tăng robustness trên tập obfuscation hiện tại.

## 6. Phân Tích Threshold

Với CNN-LSTM final state, giảm threshold từ 0.5 xuống 0.1 cho kết quả:

| Chỉ số | Threshold 0.5 | Threshold 0.1 |
|---|---:|---:|
| Normal-test Attack Recall | 99.2541% | 99.4208% |
| Normal-test False Negative | 170 | 132 |
| Normal-test False Positive | 35 | 72 |
| Obfuscated Recall | 99.5407% | 99.7553% |
| Obfuscated Missed | 689 | 367 |

Threshold thấp hơn làm giảm bỏ sót nhưng tăng cảnh báo nhầm. Đây là trade-off phù hợp để xây dựng hai chế độ:

- Balanced mode: threshold 0.5.
- Security mode: threshold 0.1.

Tuy nhiên, chưa nên so CNN-LSTM threshold 0.1 với CNN-only threshold 0.5 để khẳng định mô hình nào tốt hơn. CNN-only cũng cần được threshold tuning trên cùng validation set để so sánh công bằng.

## 7. Vì Sao CNN-only Mạnh?

### 7.1. Đặc trưng dữ liệu phù hợp với CNN

Payload SQLi/XSS chứa nhiều dấu hiệu cục bộ:

```text
%27
UNION
SELECT
1=1
--
<script
javascript:
onerror
&#x
/**/
```

GlobalMaxPooling chỉ cần một filter kích hoạt mạnh tại bất kỳ vị trí nào. Với nhiều payload, việc phát hiện sự hiện diện của pattern đã đủ để phân loại.

### 7.2. Ảnh hưởng của post-padding đối với LSTM

Độ dài trung vị:

- Dữ liệu gốc: khoảng 251 ký tự.
- Obfuscation: khoảng 63 ký tự.

Trong khi đó input luôn được pad tới 1024 ký tự. Sau hai lần pooling, payload obfuscation ngắn có thể chỉ còn khoảng 4 timestep chứa tín hiệu thật và nhiều timestep sinh từ padding.

CNN-only dùng GlobalMaxPooling nên vẫn giữ activation mạnh. CNN-LSTM final state tiếp tục đọc các timestep phía sau, nên tín hiệu đầu chuỗi có thể bị suy giảm. Sequence pooling giúp trên normal test nhưng vẫn không vượt CNN-only trên obfuscation, cho thấy vấn đề không chỉ nằm ở final state.

### 7.3. LSTM không mặc nhiên cải thiện CNN

LSTM có khả năng học quan hệ tuần tự, nhưng chỉ hữu ích khi nhãn phụ thuộc đáng kể vào thứ tự và ngữ cảnh dài. Nếu local pattern đã đủ mạnh, LSTM có thể tăng chi phí mà không tạo lợi ích tương ứng.

## 8. Audit Dataset Và Giới Hạn Đánh Giá

### 8.1. Overlap train-test

Audit cho thấy nhóm normal test chưa có canonical fingerprint trong train vẫn đạt khoảng 99.43% accuracy với CNN-only. Nhóm đã thấy canonical đạt khoảng 99.25%. Vì vậy kết quả cao không chủ yếu đến từ overlap.

### 8.2. Shortcut độ dài

Model Logistic Regression chỉ dùng độ dài payload đạt:

- Test accuracy: 61.07%.
- Test AUC: 65.15%.
- Obfuscated recall: 83.70%.

Độ dài có đóng góp vào dự đoán, nhưng không thể giải thích kết quả trên 99% của CNN.

### 8.3. Giới hạn tập obfuscation

Tập obfuscation có 150,000 biến thể nhưng được sinh từ 177 original pattern, tương ứng khoảng 149 canonical family sau khi gom các pattern tương đương. Tập này chỉ chứa Attack.

Do đó:

- Không đo được false positive trên obfuscation.
- 150,000 dòng không tương đương 150,000 tình huống độc lập.
- Cần báo cáo thêm kết quả theo original family.
- Cần family-holdout test để đánh giá tổng quát hóa chặt hơn.

### 8.4. Payload xung đột nhãn

Có 7 payload giống hệt xuất hiện ở các split nhưng mang nhãn trái ngược. Nguyên nhân là deduplicate theo `payload + label`, nên cùng payload khác nhãn vẫn được giữ. Đây là label noise cần xử lý trong phiên bản dữ liệu cuối.

## 9. Thí Nghiệm Obfuscation-Aware Family Holdout

Đã xây dựng script `obfu_family_experiment.py` để thực hiện thiết kế:

```text
Canonical obfuscation families
├── 70% family -> train augmentation
├── 15% family -> validation
└── 15% family -> holdout test hoàn toàn chưa thấy
```

Mỗi family train/validation được giới hạn số biến thể để tránh lớp Attack áp đảo. CNN-only và CNN-LSTM có thể chạy với đúng cùng split bằng tùy chọn `--model`.

Hiện mới hoàn thành smoke test để kiểm tra pipeline. Kết quả smoke test không được đưa vào bảng kết quả chính. Cần chạy full cả hai model trước khi kết luận liệu việc học obfuscation có giúp LSTM phát huy lợi thế hay không.

## 10. Lựa Chọn Mô Hình Theo Mục Tiêu

### 10.1. Triển khai WAF/NIDS thời gian thực

**Khuyến nghị: CNN-only.**

Lý do:

- Chỉ khoảng một nửa số tham số của CNN-LSTM.
- Accuracy và Attack Recall trên normal test gần tương đương.
- Zero-shot obfuscated recall cao nhất.
- Kiến trúc đơn giản, dễ tối ưu inference.
- Phù hợp với bản chất pattern cục bộ của dữ liệu hiện tại.

### 10.2. Ưu tiên giảm False Negative trên normal traffic

**Khuyến nghị: CNN-LSTM sequence pool hoặc CNN-BiLSTM với threshold phù hợp.**

Sequence pool giảm FN xuống 143 tại threshold 0.5. CNN-BiLSTM threshold 0.1 giảm FN xuống 120 nhưng tăng FP lên 74. Hai phương án này phù hợp khi bỏ sót Attack nguy hiểm hơn chi phí cảnh báo nhầm.

### 10.3. Mô hình nghiên cứu chính nếu giữ định hướng CNN-LSTM

**Khuyến nghị: CNN-LSTM final state làm baseline hybrid chính.**

Lý do:

- Đúng với kiến trúc đề xuất ban đầu.
- Kết quả tái lập hoàn toàn qua hai lần chạy với cùng seed.
- Nhỉnh nhẹ CNN-only trên normal test.
- Đơn giản và nhanh hơn các biến thể BiLSTM/sequence pooling.

Tuy nhiên báo cáo phải trình bày trung thực rằng lợi ích của LSTM trên dữ liệu hiện tại là nhỏ.

## 11. Kết Luận Cuối Cùng

Nếu chọn mô hình theo hiệu quả tổng thể trên dữ liệu hiện tại, **CNN-only là lựa chọn phù hợp nhất**. Mô hình đạt hiệu năng gần như CNN-LSTM trên normal test, tốt nhất trên obfuscation zero-shot và có số tham số thấp hơn đáng kể.

CNN-LSTM không thất bại. Thí nghiệm cho thấy thành phần LSTM cải thiện nhẹ khả năng phát hiện Attack trên normal test, đặc biệt khi dùng sequence pooling, nhưng lợi ích chưa đủ lớn để bù chi phí tính toán và sự suy giảm trên obfuscated test.

Kết luận nghiên cứu phù hợp là:

> Trong pipeline char-level no-decoding, các đặc trưng ký tự cục bộ đóng vai trò chủ đạo đối với bộ dữ liệu hiện tại. CNN-only đã đạt hiệu quả rất cao và có robustness tốt trước obfuscation. LSTM chỉ tạo cải thiện nhỏ trên tập kiểm thử thông thường, cho thấy việc bổ sung mô hình tuần tự cần được quyết định dựa trên đặc điểm dữ liệu và mục tiêu triển khai, không nên mặc định rằng mô hình lai luôn tốt hơn.

## 12. Công Việc Cần Hoàn Thành Trước Khi Chốt Báo Cáo

1. Chạy full `obfu_family_experiment.py` cho cả CNN-only và CNN-LSTM.
2. Chạy LSTM-only để hoàn thiện ablation study.
3. Threshold tuning CNN-only trên validation set.
4. Đo latency inference và throughput trong cùng điều kiện.
5. Loại hoặc xử lý 7 payload xung đột nhãn.
6. Nếu cần kiểm định thống kê, dùng McNemar test trên dự đoán paired của normal test.
7. Bổ sung benign encoded payload để đánh giá false positive trong điều kiện obfuscation-like.
