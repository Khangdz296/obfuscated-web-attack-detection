"""CNN-only baseline using the shared preprocessing pipeline.

The data policy is owned by preprocessing/preprocess_data.py. In particular,
CSIC requests contribute raw query/body values only; URL paths and parameter
names are not used as model input.
"""

import argparse
import json
import pickle
import sys
import time
from pathlib import Path

import numpy as np
import tensorflow as tf
from sklearn.utils.class_weight import compute_class_weight
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
from tensorflow.keras.layers import (
    Conv1D,
    Dense,
    Dropout,
    Embedding,
    GlobalMaxPooling1D,
    Input,
    MaxPooling1D,
)
from tensorflow.keras.models import Sequential
from tensorflow.keras.optimizers import Adam

MODEL_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = MODEL_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cnn_lstm import CNN_LSTM as pipeline
from preprocessing import preprocess_data as prep

CSIC_PATH = pipeline.CSIC_PATH
EMBEDDING_DIM = pipeline.EMBEDDING_DIM
KAGGLE_PATH = pipeline.KAGGLE_PATH
MAX_LEN = pipeline.MAX_LEN
OBFUSCATION_PATH = pipeline.OBFUSCATION_PATH
SEED = pipeline.SEED


OUTPUT_DIR = str(MODEL_DIR / "artifacts_new_preprocessing")


def build_cnn_model(vocab_size: int, max_len: int, embedding_dim: int) -> Sequential:
    """Replace the original LSTM with GlobalMaxPooling1D for a fair ablation."""
    model = Sequential(name="CNN_Only_Web_Attack_Detector")
    model.add(Input(shape=(max_len,), name="payload_tokens"))
    model.add(Embedding(vocab_size, embedding_dim, name="char_embedding"))
    model.add(Conv1D(128, 3, padding="same", activation="relu", name="conv_k3"))
    model.add(MaxPooling1D(pool_size=4, name="pool_1"))
    model.add(Conv1D(128, 5, padding="same", activation="relu", name="conv_k5"))
    model.add(MaxPooling1D(pool_size=4, name="pool_2"))
    model.add(GlobalMaxPooling1D(name="global_max_pool"))
    model.add(Dense(64, activation="relu", name="dense_classifier"))
    model.add(Dropout(0.3, name="dropout"))
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train the CNN-only SQLi/XSS baseline.")
    parser.add_argument("--kaggle-path", default=KAGGLE_PATH)
    parser.add_argument("--csic-path", default=CSIC_PATH)
    parser.add_argument("--obfuscation-path", default=OBFUSCATION_PATH)
    parser.add_argument("--output-dir", default=OUTPUT_DIR)
    parser.add_argument("--max-len", type=int, default=MAX_LEN)
    parser.add_argument("--embedding-dim", type=int, default=EMBEDDING_DIM)
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--val-size", type=float, default=0.1)
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--sample-size", type=int, default=None)
    parser.add_argument("--obfu-sample-size", type=int, default=None)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    pipeline.set_seed(args.seed)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    train_df, val_df, test_df, obfuscated_df, metadata = pipeline.build_datasets(args)
    pipeline.save_processed_csvs(output_dir, train_df, val_df, test_df, obfuscated_df)

    tokenizer = pipeline.build_tokenizer(train_df["payload"])
    vocab_size = len(tokenizer.word_index) + 1
    X_train = pipeline.vectorize(tokenizer, train_df["payload"], args.max_len)
    X_val = pipeline.vectorize(tokenizer, val_df["payload"], args.max_len)
    X_test = pipeline.vectorize(tokenizer, test_df["payload"], args.max_len)
    X_obfu = pipeline.vectorize(tokenizer, obfuscated_df["payload"], args.max_len)
    y_train = train_df["label"].to_numpy(dtype=np.int32)
    y_val = val_df["label"].to_numpy(dtype=np.int32)
    y_test = test_df["label"].to_numpy(dtype=np.int32)
    y_obfu = obfuscated_df["label"].to_numpy(dtype=np.int32)

    classes = np.unique(y_train)
    weights = compute_class_weight("balanced", classes=classes, y=y_train)
    class_weight = {int(label): float(weight) for label, weight in zip(classes, weights)}

    print("=== CNN-ONLY EXPERIMENT ===")
    print(f"Train: {len(train_df):,} | Val: {len(val_df):,} | Test: {len(test_df):,}")
    print(f"Obfuscated test: {len(obfuscated_df):,}")
    print(f"X_train: {X_train.shape} | Vocab: {vocab_size}")
    print("Shared preprocessing:", Path(prep.__file__).resolve())
    print("CSIC policy:", metadata["preprocessing_policy"]["csic_payload_policy"])

    model = build_cnn_model(vocab_size, args.max_len, args.embedding_dim)
    model.summary()
    best_model_path = output_dir / "best_cnn_only.keras"
    callbacks = [
        EarlyStopping(monitor="val_loss", patience=5, restore_best_weights=True, verbose=1),
        ModelCheckpoint(str(best_model_path), monitor="val_loss", save_best_only=True, verbose=1),
    ]

    started = time.perf_counter()
    history = model.fit(
        X_train,
        y_train,
        validation_data=(X_val, y_val),
        batch_size=args.batch_size,
        epochs=args.epochs,
        callbacks=callbacks,
        class_weight=class_weight,
        verbose=1,
    )
    training_seconds = time.perf_counter() - started

    model.save(output_dir / "last_cnn_only.keras")
    with (output_dir / "tokenizer.pkl").open("wb") as file:
        pickle.dump(tokenizer, file)

    test_result = pipeline.evaluate_model(
        model, X_test, y_test, "CNN-only normal test", args.batch_size
    )
    obfu_result = pipeline.evaluate_model(
        model, X_obfu, y_obfu, "CNN-only obfuscated test", args.batch_size
    )
    epochs_run = len(history.history["loss"])

    metadata["cnn_only_model"] = {
        "architecture": "Embedding -> Conv1D(k3) -> Pool(4) -> Conv1D(k5) -> Pool(4) -> GlobalMaxPooling1D -> Dense -> Sigmoid",
        "max_len": args.max_len,
        "embedding_dim": args.embedding_dim,
        "vocab_size": vocab_size,
        "parameter_count": int(model.count_params()),
        "class_weight": class_weight,
        "training_seconds": float(training_seconds),
        "epochs_run": epochs_run,
        "seconds_per_epoch_average": float(training_seconds / max(epochs_run, 1)),
    }
    metadata["training_history"] = {
        key: [float(value) for value in values] for key, values in history.history.items()
    }
    metadata["evaluation"] = {
        "normal_test": test_result,
        "obfuscated_test": obfu_result,
    }
    with (output_dir / "metadata_and_results.json").open("w", encoding="utf-8") as file:
        json.dump(metadata, file, ensure_ascii=False, indent=2)

    print(f"Training time: {training_seconds:.1f}s")
    print(f"Saved artifacts to: {output_dir.resolve()}")


if __name__ == "__main__":
    main()
