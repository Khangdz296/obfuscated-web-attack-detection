# BÁO CÁO TỔNG HỢP DỰ ÁN

## Phát hiện tấn công web SQL Injection và XSS bằng mô hình character-level CNN-LSTM song song

---

## 1. Tóm tắt

Dự án xây dựng hệ thống phân loại payload/request web thành hai lớp:

- **Normal (0)**: request/payload bình thường.
- **Attack (1)**: payload tấn công, bao gồm SQL Injection và Cross-Site Scripting.

Thí nghiệm hiện tại tập trung vào notebook:

```text
cnn_lstm_parallel/cnn_lstm_parallel_experiment.ipynb
```

Notebook này dùng pipeline tiền xử lý từ:

```text
preprocessing/preprocess_data.py
```

Phần tiền xử lý không giải mã URL, không HTML unescape, không chuyển chữ thường và chỉ chuẩn hóa khoảng trắng. Cách làm này giữ lại dấu vết obfuscation như `%27`, `%3C`, `&#x...;`, comment SQL, ký tự nhiễu hoặc thay đổi chữ hoa/thường.

Mô hình chính trong notebook là **CNN-LSTM song song**:

```text
Shared Embedding
    -> CNN branch
    -> LSTM branch
    -> Concatenate
    -> Dense
    -> Sigmoid
```

Kết quả mới nhất của mô hình song song:

| Tập đánh giá | Accuracy | AUC-ROC | Attack Recall | Attack F1 | False Negative |
|---|---:|---:|---:|---:|---:|
| Test thông thường | 98,3356% | 99,8871% | 97,8433% | 98,6933% | 452 |
| Obfuscation test | 99,8013% | Không áp dụng | 99,8013% | 99,9006% | 298 |

Trên tập obfuscation gồm 150.000 payload Attack, mô hình phát hiện đúng **149.702** mẫu và bỏ sót **298** mẫu.

So với artifact CNN-LSTM tuần tự hiện có, mô hình song song cho recall obfuscation cao hơn nhưng kết quả test thông thường thấp hơn. Tuy nhiên, artifact tuần tự hiện có không dùng đúng cùng số mẫu sau làm sạch với notebook song song hiện tại, nên phần so sánh chỉ nên xem là tham chiếu nếu chưa rerun lại baseline tuần tự cùng pipeline.

---

## 2. Bài toán và mục tiêu

### 2.1. Bài toán

Với đầu vào là chuỗi payload/request \(x\), mô hình dự đoán xác suất chuỗi đó là tấn công:

\[
\hat{y} = P(y=1 \mid x)
\]

Notebook hiện tại dùng ngưỡng quyết định cố định:

```text
threshold = 0.5
```

Quy tắc phân loại:

\[
\text{label} =
\begin{cases}
1, & \hat{y} \ge 0.5 \\
0, & \hat{y} < 0.5
\end{cases}
\]

### 2.2. Mục tiêu

1. Dùng lại các hàm tiền xử lý có sẵn trong `preprocessing/preprocess_data.py`.
2. Giữ chính sách character-level, no-decoding và case-sensitive.
3. Chia dữ liệu train/validation/test theo seed cố định để dễ tái lập.
4. Xây dựng mô hình CNN-LSTM song song với bộ siêu tham số tương ứng với `cnn_lstm/CNN_LSTM.py`.
5. Đánh giá trên test thông thường và tập obfuscation độc lập.
6. So sánh kết quả với artifact CNN-LSTM tuần tự hiện có.

---

## 3. Dữ liệu

### 3.1. Nguồn dữ liệu

| Nguồn | Vai trò |
|---|---|
| `SQLInjection_XSS_MixDataset.1.0.0.csv` | Payload Normal, SQLi và XSS |
| `csic_database.csv` | HTTP request từ CSIC 2010 |
| `obfuscation_dataset_full.xlsx` | 150.000 payload Attack đã được obfuscate |

SQLi và XSS được hợp nhất thành lớp **Attack (1)** vì mục tiêu của thí nghiệm là phát hiện request nguy hiểm, chưa phân loại chi tiết loại tấn công.

### 3.2. Dữ liệu sau làm sạch

Notebook hiện tại gọi:

```python
prep.load_kaggle(...)
prep.load_csic(...)
prep.load_obfuscation(...)
prep.clean(...)
prep.summarize(...)
```

Kết quả sau làm sạch trên tập cơ sở:

| Nguồn | Số mẫu |
|---|---:|
| Kaggle SQLi/XSS | 151.662 |
| CSIC 2010 | 11.456 |
| Tổng base clean | 163.118 |

Phân bố nhãn của tập base clean:

| Nhãn | Số mẫu |
|---|---:|
| Normal (0) | 58.327 |
| Attack (1) | 104.791 |

### 3.3. Chia tập

Notebook dùng `train_test_split` với `stratify` và `SEED = 42`.

| Tập | Số mẫu | Normal | Attack |
|---|---:|---:|---:|
| Train | 117.444 | 41.995 | 75.449 |
| Validation | 13.050 | 4.666 | 8.384 |
| Test thông thường | 32.624 | 11.666 | 20.958 |
| Obfuscation test | 150.000 | 0 | 150.000 |

Tỉ lệ tương ứng là khoảng **72% train / 8% validation / 20% test**.

### 3.4. Đặc điểm độ dài payload

| Tập | Mean | Median | P90 | P95 | P99 | Max |
|---|---:|---:|---:|---:|---:|---:|
| Base clean | 338,50 | 233 | 798 | 891 | 977 | 8.493 |
| Train | 338,71 | 234 | 799 | 891 | 977 | 8.493 |
| Validation | 340,23 | 235 | 797 | 891 | 979 | 3.478 |
| Test | 337,03 | 229 | 795 | 892 | 979 | 3.477 |
| Obfuscation | 130,12 | 63 | 279 | 445 | 996 | 6.853 |

Notebook dùng:

```text
MAX_LEN = 1024
```

Vì P99 của tập base clean khoảng 977 ký tự, độ dài 1024 giữ được phần lớn nội dung quan trọng của đa số request.

---

## 4. Pipeline tiền xử lý

### 4.1. Chính sách tiền xử lý

Pipeline hiện tại:

- không URL decode;
- không HTML unescape;
- không lowercase;
- chỉ chuẩn hóa whitespace;
- loại bỏ payload rỗng;
- xử lý trùng lặp và xung đột nhãn thông qua `prep.clean`.

Chính sách này phù hợp với bài toán phát hiện payload obfuscated vì các dấu hiệu như `%3C`, `%27`, comment, khoảng trắng bất thường hoặc chữ hoa/thường hỗn hợp vẫn được giữ lại cho mô hình học.

### 4.2. Tokenizer

`preprocess_data.py` hiện chưa có hàm tokenizer/vectorization, nên notebook định nghĩa phần này trực tiếp trong notebook.

Cấu hình tokenizer:

```python
Tokenizer(
    char_level=True,
    lower=False,
    filters="",
    oov_token="<OOV>"
)
```

Tokenizer chỉ được fit trên `train_df["payload"]`. Validation, test và obfuscation test chỉ được transform, giúp hạn chế rò rỉ dữ liệu từ tập đánh giá vào vocabulary.

### 4.3. Vector hóa

Mỗi payload được chuyển thành chuỗi token ID rồi pad/cắt về 1024 ký tự:

```python
pad_sequences(
    tokenizer.texts_to_sequences(payloads),
    maxlen=1024,
    padding="post",
    truncating="post"
)
```

---

## 5. Kiến trúc mô hình CNN-LSTM song song

### 5.1. Tổng quan

Mô hình hiện tại có tên:

```text
Parallel_1D_CNN_LSTM_Web_Attack_Detector
```

Số tham số:

```text
233.601
```

Topology:

```text
Input token IDs (1024)
    -> Embedding(64)
        -> CNN branch:
            Conv1D(128, kernel=3)
            MaxPooling1D(pool=4)
            Conv1D(128, kernel=5)
            MaxPooling1D(pool=4)
            GlobalMaxPooling1D
        -> LSTM branch:
            LSTM(128)
    -> Concatenate
    -> Dense(64, ReLU)
    -> Dropout(0.3)
    -> Dense(1, Sigmoid)
```

### 5.2. Ý nghĩa từng nhánh

Nhánh CNN học các mẫu cục bộ trong payload, ví dụ:

- ký tự đặc biệt như `'`, `"`, `<`, `>`, `%`, `/`, `=`;
- chuỗi ngắn như `%27`, `%3C`, `or+`, `<sc`;
- dấu hiệu comment hoặc nối chuỗi trong SQLi/XSS.

Nhánh LSTM đọc trực tiếp chuỗi embedding để học quan hệ theo thứ tự trên toàn chuỗi.

Hai vector đặc trưng được nối bằng `Concatenate`, sau đó Dense và Sigmoid tạo xác suất Attack.

### 5.3. Khác biệt với CNN-LSTM tuần tự

CNN-LSTM tuần tự trong `cnn_lstm/CNN_LSTM.py` có luồng:

```text
Embedding -> CNN -> Pooling -> CNN -> Pooling -> LSTM -> Dense -> Sigmoid
```

Trong mô hình song song hiện tại:

```text
Embedding -> [CNN branch || LSTM branch] -> Concatenate -> Dense -> Sigmoid
```

Vì vậy:

- CNN branch giữ cấu hình Conv/Pool tương tự baseline tuần tự.
- LSTM branch giữ `LSTM(128)` nhưng nhận trực tiếp embedding, không nhận đầu ra đã nén bởi CNN.
- `GlobalMaxPooling1D` được thêm vào nhánh CNN để biến chuỗi đặc trưng CNN thành vector có thể concatenate với vector LSTM.

---

## 6. Cấu hình huấn luyện

| Thành phần | Giá trị |
|---|---:|
| Seed | 42 |
| MAX_LEN | 1024 |
| Embedding dimension | 64 |
| Batch size | 128 |
| Epoch tối đa | 50 |
| Optimizer | Adam |
| Learning rate | 0,001 |
| Loss | Binary cross-entropy |
| EarlyStopping monitor | `val_loss` |
| EarlyStopping patience | 5 |
| ModelCheckpoint monitor | `val_loss` |
| Decision threshold | 0,5 |

Class weight được tính từ tập train:

| Lớp | Class weight |
|---|---:|
| Normal (0) | 1,3983 |
| Attack (1) | 0,7783 |

Training dừng sau 13 epoch trong lần chạy hiện tại. Một số chỉ số cuối training:

| Chỉ số | Giá trị cuối |
|---|---:|
| Train accuracy | 99,0106% |
| Train AUC | 99,9602% |
| Train loss | 0,0209 |
| Validation accuracy | 98,2376% |
| Validation AUC | 99,8492% |
| Validation loss | 0,0427 |

---

## 7. Kết quả đánh giá mô hình song song

### 7.1. Test thông thường

Confusion matrix:

| | Dự đoán Normal | Dự đoán Attack |
|---|---:|---:|
| Thực tế Normal | 11.575 | 91 |
| Thực tế Attack | 452 | 20.506 |

Chỉ số chính:

| Metric | Giá trị |
|---|---:|
| Accuracy | 98,3356% |
| AUC-ROC | 99,8871% |
| Normal Precision | 96,2418% |
| Normal Recall | 99,2200% |
| Normal F1 | 97,7082% |
| Attack Precision | 99,5582% |
| Attack Recall | 97,8433% |
| Attack F1 | 98,6933% |
| False Positive | 91 |
| False Negative | 452 |

Ý nghĩa bảo mật: mô hình bỏ sót 452 payload Attack trên 20.958 mẫu Attack trong tập test thông thường. Đây là nhóm lỗi cần ưu tiên phân tích nếu mục tiêu triển khai là giảm false negative.

### 7.2. Obfuscation test

Tập obfuscation có 150.000 mẫu và toàn bộ đều là Attack.

Confusion matrix:

| | Dự đoán Normal | Dự đoán Attack |
|---|---:|---:|
| Thực tế Normal | 0 | 0 |
| Thực tế Attack | 298 | 149.702 |

Chỉ số chính:

| Metric | Giá trị |
|---|---:|
| Attack Recall | 99,8013% |
| Attack F1 | 99,9006% |
| Phát hiện đúng | 149.702 |
| Bỏ sót | 298 |

Vì tập này không có mẫu Normal, Accuracy về mặt số học bằng Attack Recall. Precision bằng 1,0 trong báo cáo sklearn không nên được hiểu là mô hình không tạo false positive, vì tập này không chứa mẫu Normal để đo false positive.

---

## 8. So sánh với CNN-LSTM tuần tự hiện có

Notebook mục 6 đọc baseline từ:

```text
cnn_lstm/artifacts/metadata_and_results.json
```

Kết quả so sánh theo artifact hiện có:

| Mô hình | Params | Test Accuracy | Test AUC | Test Attack Recall | Test Attack F1 | Obfuscation Recall | Obfuscation F1 | Obfuscation FN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| CNN-LSTM tuần tự | khoảng 258.881 | 99,4218% | 99,9566% | 99,2541% | 99,5489% | 99,5407% | 99,7698% | 689 |
| CNN-LSTM song song | 233.601 | 98,3356% | 99,8871% | 97,8433% | 98,6933% | 99,8013% | 99,9006% | 298 |

Nhận xét:

1. Trên test thông thường, CNN-LSTM tuần tự tốt hơn ở Accuracy, AUC, Attack Recall và Attack F1.
2. Trên obfuscation test, CNN-LSTM song song bỏ sót ít hơn: **298** so với **689**.
3. Mô hình song song có ít tham số hơn: **233.601** so với khoảng **258.881**.
4. So sánh này chưa phải so sánh tuyệt đối công bằng nếu baseline tuần tự chưa được rerun bằng đúng pipeline hiện tại, vì artifact baseline đang có số mẫu base clean khác notebook song song.

Kết luận thận trọng: mô hình song song hiện cho kết quả rất mạnh trên tập obfuscation, nhưng trên test thông thường vẫn kém mô hình tuần tự theo artifact hiện có. Để kết luận chắc chắn topology nào tốt hơn, cần chạy lại cả hai mô hình với cùng tập dữ liệu sau làm sạch, cùng tokenizer, cùng split và cùng threshold 0,5.

---

## 9. Artifact hợp lệ của notebook hiện tại

Notebook `cnn_lstm_parallel_experiment.ipynb` hiện tạo các file output sau trong:

```text
cnn_lstm_parallel/artifacts/
```

| File | Vai trò |
|---|---|
| `best_parallel_cnn_lstm.keras` | Checkpoint tốt nhất theo `val_loss` |
| `last_parallel_cnn_lstm.keras` | Model sau epoch cuối |
| `tokenizer.pkl` | Tokenizer character-level fit trên train |
| `metadata_and_results.json` | Metadata preprocessing, cấu hình model, history và kết quả đánh giá |

Các file output cũ từ pipeline trước như Random Search, checkpoint tên cũ hoặc báo cáo obfuscation tách riêng không còn thuộc notebook hiện tại.

---

## 10. Kết luận

Thí nghiệm hiện tại đã xây dựng được pipeline CNN-LSTM song song, dùng lại tiền xử lý từ `preprocessing/preprocess_data.py`, giữ tokenizer character-level và dùng bộ siêu tham số gần với `CNN_LSTM.py`.

Kết quả nổi bật nhất là khả năng phát hiện payload obfuscated: mô hình song song đạt **99,8013% Attack Recall** và chỉ bỏ sót **298/150.000** mẫu. Tuy nhiên, trên test thông thường mô hình tuần tự hiện vẫn tốt hơn theo artifact sẵn có.

Do đó, kết luận hợp lý ở trạng thái hiện tại là:

- CNN-LSTM song song là một biến thể có khả năng chống obfuscation tốt.
- CNN-LSTM tuần tự vẫn mạnh hơn trên test thông thường theo artifact baseline hiện có.
- Cần rerun baseline tuần tự bằng đúng pipeline hiện tại nếu muốn so sánh công bằng tuyệt đối.

