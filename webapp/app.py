"""
Flask inference app for the trained Hybrid CNN-LSTM detector.

Run:
    python app.py

Then open:
    http://127.0.0.1:8000
"""

import json
import pickle
import re
import sys
from functools import lru_cache
from importlib.util import find_spec
from pathlib import Path

from flask import Flask, jsonify, render_template, request


BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
ARTIFACTS_DIR = PROJECT_ROOT / "cnn_lstm" / "artifacts"
MODEL_PATH = ARTIFACTS_DIR / "best_hybrid_cnn_lstm.keras"
TOKENIZER_PATH = ARTIFACTS_DIR / "tokenizer.pkl"
METADATA_PATH = ARTIFACTS_DIR / "metadata_and_results.json"
DEFAULT_MAX_LEN = 1024
DEFAULT_THRESHOLD = 0.5
HOST = "127.0.0.1"
PORT = 8000

app = Flask(__name__)


def normalize_payload(value: object) -> str:
    """Match CNN_LSTM.py preprocessing: preserve evidence, normalize whitespace only."""
    if not isinstance(value, str):
        return ""
    return re.sub(r"\s+", " ", value).strip()


def load_metadata() -> dict:
    if not METADATA_PATH.exists():
        return {}
    with METADATA_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def get_runtime_status() -> dict:
    return {
        "python_executable": sys.executable,
        "python_version": sys.version,
        "tensorflow_importable": find_spec("tensorflow") is not None,
        "keras_importable": find_spec("keras") is not None,
        "flask_importable": find_spec("flask") is not None,
    }


@lru_cache(maxsize=1)
def load_inference_assets():
    """Load TensorFlow model and tokenizer once, on the first prediction request."""
    missing = [str(path) for path in (MODEL_PATH, TOKENIZER_PATH) if not path.exists()]
    if missing:
        raise FileNotFoundError("Missing required artifact(s): " + ", ".join(missing))

    try:
        import tensorflow as tf
    except ImportError as exc:
        runtime = get_runtime_status()
        raise RuntimeError(
            "TensorFlow is not installed or is broken in this Python environment. "
            "Run: python -m pip install -r requirements.txt. "
            f"Current Python: {runtime['python_executable']}"
        ) from exc

    try:
        from tensorflow.keras.preprocessing.sequence import pad_sequences
    except ImportError:
        try:
            from keras.preprocessing.sequence import pad_sequences
        except ImportError as exc:
            runtime = get_runtime_status()
            raise RuntimeError(
                "TensorFlow is importable, but pad_sequences could not be imported "
                "from tensorflow.keras or keras. Run: "
                "python -m pip install --upgrade tensorflow keras. "
                f"Current Python: {runtime['python_executable']}"
            ) from exc

    with TOKENIZER_PATH.open("rb") as file:
        tokenizer = pickle.load(file)

    model = tf.keras.models.load_model(MODEL_PATH, compile=False)
    metadata = load_metadata()
    max_len = int(metadata.get("model", {}).get("max_len", DEFAULT_MAX_LEN))
    return model, tokenizer, pad_sequences, max_len


def predict_payload(payload: str, threshold: float = DEFAULT_THRESHOLD) -> dict:
    cleaned = normalize_payload(payload)
    if not cleaned:
        raise ValueError("Payload is empty after whitespace normalization.")

    model, tokenizer, pad_sequences, max_len = load_inference_assets()
    sequence = tokenizer.texts_to_sequences([cleaned])
    vector = pad_sequences(sequence, maxlen=max_len, padding="post", truncating="post")
    probability = float(model.predict(vector, verbose=0).flatten()[0])
    label = 1 if probability >= threshold else 0

    return {
        "label": label,
        "class_name": "Attack" if label else "Normal",
        "attack_probability": probability,
        "normal_probability": 1.0 - probability,
        "threshold": threshold,
        "normalized_payload": cleaned,
        "input_length": len(cleaned),
        "max_len": max_len,
        "truncated": len(cleaned) > max_len,
    }


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/health")
def health():
    return jsonify(
        {
            "ok": True,
            "model_exists": MODEL_PATH.exists(),
            "tokenizer_exists": TOKENIZER_PATH.exists(),
            "model_path": str(MODEL_PATH),
            "tokenizer_path": str(TOKENIZER_PATH),
            "runtime": get_runtime_status(),
        }
    )


@app.post("/api/predict")
def predict():
    try:
        payload = request.get_json(silent=True) or {}
        text = payload.get("payload", "")
        threshold = float(payload.get("threshold", DEFAULT_THRESHOLD))
        if not 0 <= threshold <= 1:
            raise ValueError("Threshold must be between 0 and 1.")

        result = predict_payload(text, threshold)
        return jsonify({"ok": True, "result": result})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


if __name__ == "__main__":
    print(f"Serving CNN-LSTM detector at http://{HOST}:{PORT}")
    print(f"Model    : {MODEL_PATH}")
    print(f"Tokenizer: {TOKENIZER_PATH}")
    app.run(host=HOST, port=PORT, debug=False)
