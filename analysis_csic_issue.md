# Phân tích vấn đề hiệu suất thấp trên tập CSIC

## Tóm tắt vấn đề
Model CNN+LSTM của bạn có hiệu suất thấp trên tập CSIC mặc dù đã thử nghiệm nhiều lần. Sau khi phân tích code và dữ liệu, tôi đã phát hiện **5 vấn đề chính** gây ra hiệu suất kém.

---

## Vấn đề 1: Sự khác biệt lớn về đặc trưng giữa CSIC và Kaggle

### Phân tích
- **Kaggle dataset**: Chỉ chứa payload thuần túy (SQLi/XSS patterns)
  ```
  """ or pg_sleep ( __TIME__ ) --
  admin' or 1 = 1#
  ```

- **CSIC dataset**: Chứa **FULL HTTP request** với nhiều metadata
  ```
  Method: GET
  User-Agent: Mozilla/5.0...
  Cookie: JSESSIONID=...
  URL: http://localhost:8080/tienda1/publico/anadir.jsp?id=3&nombre=Vino+Rioja...
  Content-Type: application/x-www-form-urlencoded
  ```

### Tác động
Code preprocessing của bạn (`preprocess_data.py`) thực hiện:

1. **Kaggle**: Wrap payload đơn giản vào HTTP envelope giả định
   ```python
   def wrap_payload_as_request(payload):
       # Tạo HTTP wrapper với template cố định
       method, path = stable_choice(...)  # POST/GET ngẫu nhiên
       return f"[METHOD] POST [PATH] /submit [BODY] input={payload}"
   ```

2. **CSIC**: Giữ nguyên toàn bộ HTTP request thật
   ```python
   def serialize_csic_row(row):
       return f"[METHOD] {method} [PATH] {path} [QUERY] {query} [BODY] {body} [COOKIE] {cookie} [CONTENT_TYPE] {content_type}"
   ```

**Kết quả**: 
- CSIC samples dài gấp 3-5 lần Kaggle (có User-Agent, Cookie, headers...)
- Model học từ Kaggle (payload ngắn) không generalize tốt sang CSIC (request dài với nhiều noise)
- Payload attack thật sự bị "chìm" trong metadata không liên quan

---

## Vấn đề 2: Imbalanced data không được xử lý đúng cách

### Phân tích dữ liệu
```
CSIC:  36,000 Normal vs 25,065 Attacks (ratio 1.44:1)
Kaggle: Tương đối balanced
```

### Vấn đề trong code
```python
class_weights = compute_class_weight(
    class_weight="balanced",
    classes=np.unique(y_train),
    y=y_train,
)
```

**Class weights chỉ điều chỉnh loss, KHÔNG giải quyết vấn đề**:
- Model vẫn thấy nhiều Normal hơn trong training
- Validation threshold tuning ưu tiên Normal (vì chiếm đa số)
- Khi test trên CSIC, model thiên về predict Normal → **Recall thấp cho Attacks**

---

## Vấn đề 3: Tokenizer bị overfitting với training data

### Code hiện tại
```python
def build_tokenizer(train_payloads: pd.Series) -> Tokenizer:
    tokenizer = Tokenizer(
        char_level=True,
        lower=False,           # Giữ nguyên case
        filters="",            # Không filter ký tự nào
        oov_token="<OOV>",
    )
    tokenizer.fit_on_texts(train_payloads)
    return tokenizer
```

### Vấn đề
1. **Nếu train trên Kaggle + CSIC combined**:
   - Kaggle chiếm đa số (156K vs 61K)
   - Tokenizer học vocabulary thiên về Kaggle patterns
   - CSIC-specific chars (trong headers, cookies) bị map sang `<OOV>`

2. **Nếu train riêng từng dataset** (theo code `CNN_LSTM.py` line 271-302):
   - Mỗi model có tokenizer riêng
   - Nhưng vẫn gặp vấn đề #1: CSIC model học từ full HTTP request, không tập trung vào attack payload

---

## Vấn đề 4: MAX_LEN = 1024 không phù hợp với CSIC

### Phân tích độ dài
```python
# Từ preprocess_data.py line 328-340
lengths = df["payload"].str.len()
summary = {
    "mean": lengths.mean(),
    "p90": lengths.quantile(0.90),
    "p95": lengths.quantile(0.95),
    "p99": lengths.quantile(0.99),
}
```

**Dự đoán**:
- Kaggle: mean ~50-100 chars (chỉ có payload)
- CSIC: mean ~300-500 chars (full HTTP request)
- CSIC p99: có thể >1024 chars

**Vấn đề**:
- Nếu CSIC request >1024: bị truncate → mất payload attack ở cuối
- Nếu CSIC request <1024: padding quá nhiều → model học noise

---

## Vấn đề 5: Model architecture không phù hợp với CSIC structure

### Code model hiện tại
```python
model.add(Embedding(vocab_size, embedding_dim=64))
model.add(Conv1D(filters=128, kernel_size=3, padding="same"))
model.add(MaxPooling1D(pool_size=4))
model.add(Conv1D(filters=128, kernel_size=5, padding="same"))
model.add(MaxPooling1D(pool_size=4))
model.add(LSTM(128, return_sequences=True))
model.add(GlobalMaxPooling1D())
```

**Vấn đề**:
1. **Pooling quá aggressive**: `MaxPooling(4) → MaxPooling(4)` = giảm 16x length
   - Input 1024 → sau 2 pools = 64 tokens
   - Nếu payload attack chỉ chiếm 50 chars trong 500 chars request → bị pool mất

2. **LSTM không đủ capacity**: 128 units cho sequence length 64
   - Với CSIC, phải học nhiều context: headers + path + query + body
   - 128 units không đủ để capture long-range dependencies

3. **GlobalMaxPooling sau LSTM**: Chỉ lấy max value từ 128 LSTM outputs
   - Mất thông tin sequential quan trọng
   - Payload attack ở giữa request có thể bị bỏ qua

---

## Giải pháp đề xuất

### 1. Tách riêng preprocessing cho từng dataset
```python
# Cho Kaggle: Wrap payload đơn giản
def preprocess_kaggle(payload):
    return f"[PAYLOAD] {normalize_payload(payload)}"

# Cho CSIC: Chỉ extract query + body, bỏ headers noise
def preprocess_csic(row):
    path, query = split_csic_url(row['URL'])
    body = row.get('content', '')
    return f"[PATH] {path} [QUERY] {query} [BODY] {body}"
    # BỎ: User-Agent, Cookie, headers không liên quan
```

### 2. Cải thiện handling imbalanced data
```python
# Thay vì chỉ dùng class_weight, thêm:

# a) Oversample minority class (attacks)
from imblearn.over_sampling import SMOTE, ADASYN
X_train, y_train = SMOTE(random_state=42).fit_resample(X_train, y_train)

# b) Hoặc undersample majority class
from imblearn.under_sampling import RandomUnderSampler
X_train, y_train = RandomUnderSampler(random_state=42).fit_resample(X_train, y_train)

# c) Điều chỉnh threshold về phía bảo vệ (security-first)
# Thay vì optimize F1, optimize recall với min_precision constraint
def choose_security_threshold(y_val, val_prob, min_precision=0.95):
    # Chọn threshold sao cho: precision >= 0.95 và maximize recall
    pass
```

### 3. Tối ưu tokenizer
```python
# Thêm common HTTP tokens vào vocabulary
SPECIAL_TOKENS = ['<PAD>', '<OOV>', '<START>', '<END>']
HTTP_TOKENS = ['GET', 'POST', 'PUT', 'DELETE', 'HTTP', '1.1', 'Host:', 'Cookie:', ...]

# Hoặc: Dùng BPE tokenizer thay vì char-level
from tokenizers import ByteLevelBPETokenizer
tokenizer = ByteLevelBPETokenizer()
tokenizer.train_from_iterator(train_payloads, vocab_size=5000)
```

### 4. Điều chỉnh MAX_LEN dựa trên phân tích data
```python
# Chạy trước để xác định:
python -c "
import pandas as pd
from preprocessing.preprocess_data import load_csic, clean
df = clean(load_csic('csic_database.csv'))
lengths = df['payload'].str.len()
print(f'Mean: {lengths.mean():.0f}')
print(f'P90: {lengths.quantile(0.90):.0f}')
print(f'P95: {lengths.quantile(0.95):.0f}')
print(f'P99: {lengths.quantile(0.99):.0f}')
print(f'Max: {lengths.max()}')
"

# Sau đó set MAX_LEN = p95 hoặc p99
# VD: Nếu p95=800 → MAX_LEN=1024 OK
#     Nếu p99=1500 → tăng MAX_LEN=2048
```

### 5. Cải thiện model architecture
```python
# Option A: Giảm pooling, tăng LSTM capacity
model.add(Embedding(vocab_size, 64))
model.add(SpatialDropout1D(0.2))

model.add(Conv1D(128, 3, activation='relu'))
model.add(MaxPooling1D(2))  # Chỉ giảm 2x thay vì 4x

model.add(Conv1D(128, 5, activation='relu'))
model.add(MaxPooling1D(2))  # Chỉ giảm 2x

model.add(Bidirectional(LSTM(256, return_sequences=True)))  # Tăng 128→256
model.add(GlobalMaxPooling1D())
model.add(Dense(128, activation='relu'))
model.add(Dropout(0.5))
model.add(Dense(1, activation='sigmoid'))

# Option B: Multi-head attention thay vì LSTM
from tensorflow.keras.layers import MultiHeadAttention, LayerNormalization

model.add(Embedding(vocab_size, 128))
model.add(MultiHeadAttention(num_heads=8, key_dim=16))
model.add(LayerNormalization())
model.add(GlobalAveragePooling1D())  # Thay GlobalMaxPooling
model.add(Dense(1, activation='sigmoid'))
```

---

## Action plan ưu tiên

### Bước 1: Validate giả thuyết (1 giờ)
```bash
# Chạy script phân tích:
python -c "
from preprocessing.preprocess_data import *
import pandas as pd

# Load và analyze
kaggle = clean(load_kaggle('SQLInjection_XSS_MixDataset.1.0.0.csv'))
csic = clean(load_csic('csic_database.csv'))

print('=== KAGGLE ===')
print(summarize(kaggle))

print('\n=== CSIC ===')
print(summarize(csic))

# So sánh độ dài
print('\n=== LENGTH COMPARISON ===')
print(f'Kaggle mean: {kaggle[\"payload\"].str.len().mean():.0f}')
print(f'CSIC mean: {csic[\"payload\"].str.len().mean():.0f}')
print(f'CSIC / Kaggle ratio: {csic[\"payload\"].str.len().mean() / kaggle[\"payload\"].str.len().mean():.2f}x')
"
```

### Bước 2: Quick fix - Simplify CSIC preprocessing (2 giờ)
Sửa `preprocess_data.py`:
```python
def serialize_csic_row_simplified(row: pd.Series) -> tuple[str, str, str]:
    """KHÔNG lấy User-Agent, Cookie, headers - chỉ lấy payload"""
    path, query = split_csic_url(row.get("URL", ""))
    body = normalize_payload(row.get("content", ""))
    
    # Chỉ giữ method + path + query + body
    model_input = serialize_http_request(
        method=row.get("Method", ""),
        path=path,
        query=query,
        body=body,
        cookie="",              # BỎ cookie
        content_type="",        # BỎ content-type
    )
    raw_payload = " ".join(value for value in (query, body) if value)
    split_group = canonical_csic_family(row.get("Method", ""), path, query, body)
    return model_input, raw_payload, split_group
```

### Bước 3: Retrain và đánh giá (3 giờ)
```bash
python cnn_lstm/CNN_LSTM.py --train-sources csic --epochs 30
```

### Bước 4: Nếu vẫn thấp, thử option B (4 giờ)
- Implement SMOTE/undersampling
- Tăng LSTM units 128→256
- Thử Attention mechanism

---

## Kết luận

**Nguyên nhân chính**: CSIC dataset có cấu trúc khác hoàn toàn so với Kaggle (full HTTP request vs pure payload), nhưng preprocessing code đang xử lý không phù hợp, khiến model học nhiều noise không liên quan và không focus vào attack patterns.

**Giải pháp tức thì**: Đơn giản hóa CSIC preprocessing - chỉ giữ path/query/body, bỏ headers.

**Giải pháp dài hạn**: Train 2 models riêng biệt cho 2 loại input khác nhau, hoặc dùng multi-task learning với 2 input branches.
