# Experiments

Thư mục này chứa các biến thể phát triển từ mô hình chính `cnn_lstm/CNN_LSTM.py`.

- `cnn_bilstm/`: thay LSTM một chiều bằng Bidirectional LSTM và bổ sung regularization.
- `cnn_lstm_sequence_pool/`: giữ chuỗi đầu ra LSTM rồi dùng Global Max Pooling thay vì chỉ lấy trạng thái cuối.

Mỗi thí nghiệm sử dụng pipeline dữ liệu của mô hình chính và lưu kết quả trong thư mục `artifacts/` riêng.
