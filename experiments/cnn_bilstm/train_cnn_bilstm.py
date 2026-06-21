"""
Experimental improved pipeline.

This file is separate from CNN_LSTM.py so the original result is preserved.

Changes compared with CNN_LSTM.py:
- Adds SpatialDropout1D after Embedding to regularize character embeddings.
- Uses Conv1D -> BatchNormalization -> ReLU blocks for more stable training.
- Uses Bidirectional LSTM so context can be read from both directions.
- Tunes the decision threshold on validation data to reduce false negatives.

Run a quick experiment:
py -c "import runpy, sys; sys.argv=['train_cnn_bilstm.py','--sample-size','30000','--obfu-sample-size','10000','--epochs','8']; runpy.run_path('train_cnn_bilstm.py', run_name='__main__')"
"""

import argparse
import json
import pickle
import sys
from pathlib import Path

import numpy as np
import tensorflow as tf
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support
from sklearn.utils.class_weight import compute_class_weight
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
from tensorflow.keras.layers import (
    Activation,
    BatchNormalization,
    Bidirectional,
    Conv1D,
    Dense,
    Dropout,
    Embedding,
    Input,
    LSTM,
    MaxPooling1D,
    SpatialDropout1D,
)
from tensorflow.keras.models import Sequential
from tensorflow.keras.optimizers import Adam

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "cnn_lstm"))

from CNN_LSTM import (
    CSIC_PATH,
    EMBEDDING_DIM,
    KAGGLE_PATH,
    MAX_LEN,
    OBFUSCATION_PATH,
    SEED,
    build_datasets,
    build_tokenizer,
    save_processed_csvs,
    set_seed,
    vectorize,
)


OUTPUT_DIR = str(Path(__file__).resolve().parent / "artifacts")


def conv_bn_relu(filters: int, kernel_size: int, name: str) -> list:
    return [
        Conv1D(filters=filters, kernel_size=kernel_size, padding="same", use_bias=False, name=f"{name}_conv"),
        BatchNormalization(name=f"{name}_bn"),
        Activation("relu", name=f"{name}_relu"),
    ]


def build_improved_model(vocab_size: int, max_len: int, embedding_dim: int) -> Sequential:
    model = Sequential(name="Improved_CNN_BiLSTM_Web_Attack_Detector")
    model.add(Input(shape=(max_len,), name="payload_tokens"))
    model.add(Embedding(input_dim=vocab_size, output_dim=embedding_dim, name="char_embedding"))
    model.add(SpatialDropout1D(0.15, name="embedding_spatial_dropout"))

    for layer in conv_bn_relu(filters=128, kernel_size=3, name="conv_k3"):
        model.add(layer)
    model.add(MaxPooling1D(pool_size=4, name="pool_1"))

    for layer in conv_bn_relu(filters=128, kernel_size=5, name="conv_k5"):
        model.add(layer)
    model.add(MaxPooling1D(pool_size=4, name="pool_2"))

    model.add(Bidirectional(LSTM(64), name="bilstm_context"))
    model.add(Dense(64, use_bias=False, name="dense_classifier"))
    model.add(BatchNormalization(name="dense_bn"))
    model.add(Activation("relu", name="dense_relu"))
    model.add(Dropout(0.35, name="dropout"))
    model.add(Dense(1, activation="sigmoid", name="attack_probability"))

    model.compile(
        optimizer=Adam(learning_rate=1e-3),
        loss="binary_crossentropy",
        metrics=[
            "accuracy",
            tf.keras.metrics.AUC(name="auc"),
            tf.keras.metrics.Precision(name="precision"),
            tf.keras.metrics.Recall(name="recall"),
        ],
    )
    return model


def predict_probabilities(model: Sequential, X: np.ndarray, batch_size: int) -> np.ndarray:
    return model.predict(X, batch_size=batch_size).flatten()


def metrics_for_threshold(y_true: np.ndarray, y_prob: np.ndarray, threshold: float) -> dict:
    y_pred = (y_prob >= threshold).astype(int)
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true,
        y_pred,
        labels=[0, 1],
        zero_division=0,
    )
    return {
        "threshold": float(threshold),
        "normal_precision": float(precision[0]),
        "normal_recall": float(recall[0]),
        "normal_f1": float(f1[0]),
        "normal_support": int(support[0]),
        "attack_precision": float(precision[1]),
        "attack_recall": float(recall[1]),
        "attack_f1": float(f1[1]),
        "attack_support": int(support[1]),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist(),
    }


def choose_security_threshold(
    y_val: np.ndarray,
    val_prob: np.ndarray,
    min_normal_recall: float = 0.99,
) -> tuple[float, list[dict]]:
    thresholds = [round(x, 2) for x in np.arange(0.05, 0.96, 0.05)]
    rows = [metrics_for_threshold(y_val, val_prob, threshold) for threshold in thresholds]

    valid_rows = [row for row in rows if row["normal_recall"] >= min_normal_recall]
    if not valid_rows:
        valid_rows = rows

    best = sorted(
        valid_rows,
        key=lambda row: (row["attack_recall"], row["attack_f1"], -row["threshold"]),
        reverse=True,
    )[0]
    return best["threshold"], rows


def evaluate_with_threshold(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    threshold: float,
    title: str,
) -> dict:
    y_pred = (y_prob >= threshold).astype(int)
    result = metrics_for_threshold(y_true, y_prob, threshold) if len(np.unique(y_true)) > 1 else {
        "threshold": float(threshold),
        "attack_precision": 1.0,
        "attack_recall": float((y_pred == 1).sum() / len(y_pred)),
        "attack_f1": float(2 * ((y_pred == 1).sum() / len(y_pred)) / (1 + ((y_pred == 1).sum() / len(y_pred)))),
        "attack_support": int(len(y_true)),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist(),
    }

    print(f"\n=== {title.upper()} @ threshold={threshold:.2f} ===")
    print("Confusion matrix:")
    print(np.array(result["confusion_matrix"]))
    print("Classification report:")
    print(classification_report(y_true, y_pred, labels=sorted(np.unique(y_true)), digits=4, zero_division=0))
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Experimental improved CNN-BiLSTM pipeline.")
    parser.add_argument("--kaggle-path", default=KAGGLE_PATH)
    parser.add_argument("--csic-path", default=CSIC_PATH)
    parser.add_argument("--obfuscation-path", default=OBFUSCATION_PATH)
    parser.add_argument("--output-dir", default=OUTPUT_DIR)
    parser.add_argument("--max-len", type=int, default=MAX_LEN)
    parser.add_argument("--embedding-dim", type=int, default=EMBEDDING_DIM)
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--epochs", type=int, default=30)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--val-size", type=float, default=0.1)
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--sample-size", type=int, default=None)
    parser.add_argument("--obfu-sample-size", type=int, default=None)
    parser.add_argument("--min-normal-recall", type=float, default=0.99)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    set_seed(args.seed)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    train_df, val_df, test_df, obfuscated_df, metadata = build_datasets(args)
    save_processed_csvs(output_dir, train_df, val_df, test_df, obfuscated_df)

    tokenizer = build_tokenizer(train_df["payload"])
    vocab_size = len(tokenizer.word_index) + 1

    X_train = vectorize(tokenizer, train_df["payload"], args.max_len)
    X_val = vectorize(tokenizer, val_df["payload"], args.max_len)
    X_test = vectorize(tokenizer, test_df["payload"], args.max_len)
    X_obfu = vectorize(tokenizer, obfuscated_df["payload"], args.max_len)

    y_train = train_df["label"].to_numpy(dtype=np.int32)
    y_val = val_df["label"].to_numpy(dtype=np.int32)
    y_test = test_df["label"].to_numpy(dtype=np.int32)
    y_obfu = obfuscated_df["label"].to_numpy(dtype=np.int32)

    class_weights = compute_class_weight(
        class_weight="balanced",
        classes=np.unique(y_train),
        y=y_train,
    )
    class_weight_dict = {
        int(label): float(weight) for label, weight in zip(np.unique(y_train), class_weights)
    }

    print("=== IMPROVED EXPERIMENT DATA ===")
    print(f"Train           : {len(train_df):,}")
    print(f"Val             : {len(val_df):,}")
    print(f"Test            : {len(test_df):,}")
    print(f"Obfuscated test : {len(obfuscated_df):,}")
    print(f"Vocabulary size : {vocab_size}")
    print(f"Class weights   : {class_weight_dict}")

    model = build_improved_model(vocab_size, args.max_len, args.embedding_dim)
    model.summary()

    best_model_path = output_dir / "best_improved_cnn_bilstm.keras"
    callbacks = [
        EarlyStopping(monitor="val_loss", patience=5, restore_best_weights=True, verbose=1),
        ModelCheckpoint(filepath=str(best_model_path), monitor="val_loss", save_best_only=True, verbose=1),
    ]

    history = model.fit(
        X_train,
        y_train,
        validation_data=(X_val, y_val),
        batch_size=args.batch_size,
        epochs=args.epochs,
        callbacks=callbacks,
        class_weight=class_weight_dict,
        verbose=1,
    )

    model.save(output_dir / "last_improved_cnn_bilstm.keras")
    with (output_dir / "tokenizer.pkl").open("wb") as file:
        pickle.dump(tokenizer, file)

    val_prob = predict_probabilities(model, X_val, args.batch_size)
    test_prob = predict_probabilities(model, X_test, args.batch_size)
    obfu_prob = predict_probabilities(model, X_obfu, args.batch_size)

    tuned_threshold, threshold_rows = choose_security_threshold(
        y_val,
        val_prob,
        min_normal_recall=args.min_normal_recall,
    )
    print(f"\nSelected security threshold: {tuned_threshold:.2f}")

    test_default = evaluate_with_threshold(y_test, test_prob, 0.5, "normal test default")
    test_tuned = evaluate_with_threshold(y_test, test_prob, tuned_threshold, "normal test tuned")
    obfu_default = evaluate_with_threshold(y_obfu, obfu_prob, 0.5, "obfuscated test default")
    obfu_tuned = evaluate_with_threshold(y_obfu, obfu_prob, tuned_threshold, "obfuscated test tuned")

    metadata["improved_model"] = {
        "architecture": "Embedding -> SpatialDropout1D -> Conv1D+BN+ReLU -> Pool -> Conv1D+BN+ReLU -> Pool -> Bidirectional LSTM -> Dense+BN+ReLU -> Dropout -> Sigmoid",
        "max_len": args.max_len,
        "embedding_dim": args.embedding_dim,
        "vocab_size": vocab_size,
        "class_weight": class_weight_dict,
        "selected_threshold": tuned_threshold,
        "min_normal_recall_for_threshold": args.min_normal_recall,
        "artifacts": {
            "best_model": str(best_model_path),
            "last_model": str(output_dir / "last_improved_cnn_bilstm.keras"),
            "tokenizer": str(output_dir / "tokenizer.pkl"),
        },
    }
    metadata["threshold_search_val"] = threshold_rows
    metadata["training_history"] = {
        key: [float(value) for value in values] for key, values in history.history.items()
    }
    metadata["evaluation"] = {
        "test_default_0_5": test_default,
        "test_tuned": test_tuned,
        "obfuscated_default_0_5": obfu_default,
        "obfuscated_tuned": obfu_tuned,
    }

    with (output_dir / "metadata_and_results.json").open("w", encoding="utf-8") as file:
        json.dump(metadata, file, ensure_ascii=False, indent=2)

    print(f"\nSaved improved experiment artifacts to: {output_dir.resolve()}")


if __name__ == "__main__":
    main()
