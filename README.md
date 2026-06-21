# CNN-LSTM Web Attack Detector

This project contains a char-level Hybrid 1D-CNN + LSTM model for web attack detection and a Flask web app for interactive inference.

The workflow has two stages:

1. Train and evaluate the CNN-LSTM model with `cnn_lstm/CNN_LSTM.py`.
2. Run the Flask web app in `webapp/` to classify user input with the trained model.

## Project Structure

```text
.
+-- cnn_lstm/
|   +-- CNN_LSTM.py
|   +-- CNN_LSTM.ipynb
|   +-- artifacts/                  # generated locally, ignored by git
|       +-- best_hybrid_cnn_lstm.keras
|       +-- tokenizer.pkl
|       +-- metadata_and_results.json
|       +-- processed_data/
+-- webapp/
|   +-- app.py                      # Flask backend
|   +-- requirements.txt
|   +-- templates/
|   |   +-- index.html
|   +-- static/
|       +-- app.js
|       +-- styles.css
+-- SQLInjection_XSS_MixDataset.1.0.0.csv
+-- csic_database.csv
+-- obfuscation_dataset_full.xlsx
```

## Requirements

Use Python 3.10-3.12. A virtual environment is recommended.

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate        # Linux/macOS/WSL
# .venv\Scripts\activate         # Windows PowerShell
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r webapp/requirements.txt
```

## Stage 1: Train And Evaluate The CNN-LSTM Model

Download the datasets from Google Drive:

```text
https://drive.google.com/drive/folders/1xzM_3EEYn79TUXTqee_HPub4hQcLaAJ8?usp=drive_link
```

After downloading, place these files in the repository root:

```text
SQLInjection_XSS_MixDataset.1.0.0.csv
csic_database.csv
obfuscation_dataset_full.xlsx
```

Run training from the repository root:

```bash
python cnn_lstm/CNN_LSTM.py
```

For a quick smoke test on a small sample:

```bash
python cnn_lstm/CNN_LSTM.py --sample-size 3000 --obfu-sample-size 1000 --epochs 3
```

The script will:

- load and clean the Kaggle SQLi/XSS dataset and CSIC dataset;
- keep obfuscation evidence by only normalizing redundant whitespace;
- split the base dataset into train, validation, and test sets;
- keep the custom obfuscation dataset as a separate robustness test set;
- fit the char-level tokenizer on the train split only;
- train the Hybrid CNN-LSTM model;
- evaluate the model on the normal test set and the obfuscated test set.

After training, generated outputs are saved in:

```text
cnn_lstm/artifacts/
```

Important files:

```text
cnn_lstm/artifacts/best_hybrid_cnn_lstm.keras
cnn_lstm/artifacts/tokenizer.pkl
cnn_lstm/artifacts/metadata_and_results.json
cnn_lstm/artifacts/processed_data/
```

`metadata_and_results.json` contains the overall training/evaluation summary, including:

- dataset split summaries;
- model configuration;
- training history;
- normal test metrics;
- obfuscated test metrics;
- confusion matrices;
- classification reports.

`cnn_lstm/artifacts/` is ignored by git because it contains generated models and outputs.

## Stage 2: Run The Flask Web App

The web app requires these files from Stage 1:

```text
cnn_lstm/artifacts/best_hybrid_cnn_lstm.keras
cnn_lstm/artifacts/tokenizer.pkl
cnn_lstm/artifacts/metadata_and_results.json
```

Start the Flask app:

```bash
cd webapp
python app.py
```

Open:

```text
http://127.0.0.1:8000
```

The web flow is:

```text
User input -> Flask backend -> tokenizer -> CNN-LSTM model -> prediction result -> frontend
```

## Health Check

Open:

```text
http://127.0.0.1:8000/api/health
```

Expected important fields:

```json
{
  "model_exists": true,
  "tokenizer_exists": true,
  "runtime": {
    "tensorflow_importable": true,
    "flask_importable": true
  }
}
```

If `model_exists` or `tokenizer_exists` is `false`, run Stage 1 first or copy the generated artifacts into `cnn_lstm/artifacts/`.

## Prediction API

Endpoint:

```text
POST /api/predict
```

Example request:

```json
{
  "payload": "/search?q=' OR 1=1 --",
  "threshold": 0.5
}
```

Example response:

```json
{
  "ok": true,
  "result": {
    "label": 1,
    "class_name": "Attack",
    "attack_probability": 0.98,
    "normal_probability": 0.02,
    "threshold": 0.5
  }
}
```

## Notes

- The backend uses the same preprocessing policy as `CNN_LSTM.py`: preserve payload evidence and normalize only redundant whitespace.
- The tokenizer is loaded from `cnn_lstm/artifacts/tokenizer.pkl`.
- The model is loaded from `cnn_lstm/artifacts/best_hybrid_cnn_lstm.keras` with `compile=False` for inference.
