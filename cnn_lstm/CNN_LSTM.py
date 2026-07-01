"""
All-in-one pipeline for char-level Hybrid 1D-CNN + LSTM web attack detection.

This file intentionally keeps preprocessing, vectorization, training, and
evaluation together so the research workflow is easy to run and explain.

Main idea:
- Preserve obfuscation evidence: no URL decode, no HTML unescape, no lowercase.
- Normalize only redundant whitespace.
- Fit tokenizer on train split only to avoid data leakage.
- Keep the custom obfuscation dataset as a separate robustness test set.
"""

import argparse
import json
import pickle
import random
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import tensorflow as tf
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
from tensorflow.keras.layers import (
    Conv1D,
    Dense,
    Dropout,
    Embedding,
    GlobalMaxPooling1D,
    Input,
    LSTM,
    MaxPooling1D,
)
from tensorflow.keras.models import Sequential
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.preprocessing.text import Tokenizer


MODEL_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = MODEL_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from preprocessing import preprocess_data as prep

KAGGLE_PATH = str(PROJECT_ROOT / "SQLInjection_XSS_MixDataset.1.0.0.csv")
CSIC_PATH = str(PROJECT_ROOT / "csic_database.csv")
OBFUSCATION_PATH = str(PROJECT_ROOT / "obfuscation_dataset_full.xlsx")
OUTPUT_DIR = str(MODEL_DIR / "artifacts")
MAX_LEN = 1024
EMBEDDING_DIM = 64
SEED = 42


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    tf.random.set_seed(seed)


def normalize_payload(value: object) -> str:
    return prep.normalize_payload(value)


def to_binary_label(series: pd.Series) -> pd.Series:
    return prep.to_binary_label(series)


def load_kaggle_dataset(path: str) -> pd.DataFrame:
    return prep.load_kaggle(path)


def load_csic_dataset(path: str) -> pd.DataFrame:
    return prep.load_csic(path)


def read_xlsx_first_sheet(path: str) -> pd.DataFrame:
    return prep.read_xlsx_first_sheet(path)


def load_obfuscation_dataset(path: str) -> pd.DataFrame:
    return prep.load_obfuscation(path)


def clean_dataset(
    df: pd.DataFrame,
    deduplicate: bool = True,
    drop_label_conflicts: bool = True,
) -> pd.DataFrame:
    return prep.clean(
        df,
        deduplicate=deduplicate,
        drop_label_conflicts=drop_label_conflicts,
    )


def summarize(df: pd.DataFrame) -> dict:
    return prep.summarize(df)


def build_datasets(args: argparse.Namespace) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame, dict]:
    base_df = pd.concat(
        [
            load_kaggle_dataset(args.kaggle_path),
            load_csic_dataset(args.csic_path),
        ],
        ignore_index=True,
    )
    base_df = clean_dataset(base_df, deduplicate=True, drop_label_conflicts=True)
    base_df = base_df.sample(frac=1, random_state=args.seed).reset_index(drop=True)

    if args.sample_size:
        base_df = base_df.sample(n=min(args.sample_size, len(base_df)), random_state=args.seed)
        base_df = base_df.reset_index(drop=True)

    train_val_df, test_df = train_test_split(
        base_df,
        test_size=args.test_size,
        random_state=args.seed,
        stratify=base_df["label"],
    )
    train_df, val_df = train_test_split(
        train_val_df,
        test_size=args.val_size,
        random_state=args.seed,
        stratify=train_val_df["label"],
    )

    obfuscated_df = clean_dataset(
        load_obfuscation_dataset(args.obfuscation_path),
        deduplicate=True,
        drop_label_conflicts=False,
    )
    if args.obfu_sample_size:
        obfuscated_df = obfuscated_df.sample(
            n=min(args.obfu_sample_size, len(obfuscated_df)),
            random_state=args.seed,
        ).reset_index(drop=True)

    metadata = {
        "preprocessing_policy": {
            "url_decode": False,
            "html_unescape": False,
            "lowercase": False,
            "whitespace_normalization_only": True,
            "csic_payload_policy": "Use raw query/body parameter values only; drop requests with no input values.",
            "drop_label_conflicts_base": True,
            "drop_label_conflicts_obfuscated_test": False,
            "tokenizer_rule": "Tokenizer is fit on train split only.",
        },
        "splits": {
            "base_clean": summarize(base_df),
            "train": summarize(train_df),
            "val": summarize(val_df),
            "test": summarize(test_df),
            "obfuscated_test": summarize(obfuscated_df),
        },
    }
    return train_df, val_df, test_df, obfuscated_df, metadata


def build_tokenizer(train_payloads: pd.Series) -> Tokenizer:
    tokenizer = Tokenizer(
        char_level=True,
        lower=False,
        filters="",
        oov_token="<OOV>",
    )
    tokenizer.fit_on_texts(train_payloads)
    return tokenizer


def vectorize(tokenizer: Tokenizer, payloads: pd.Series, max_len: int) -> np.ndarray:
    sequences = tokenizer.texts_to_sequences(payloads)
    return pad_sequences(
        sequences,
        maxlen=max_len,
        padding="post",
        truncating="post",
    )


def build_model(vocab_size: int, max_len: int, embedding_dim: int) -> Sequential:
    model = Sequential(name="Hybrid_1D_CNN_LSTM_Sequence_Pooling_Web_Attack_Detector")
    model.add(Input(shape=(max_len,), name="payload_tokens"))
    model.add(Embedding(input_dim=vocab_size, output_dim=embedding_dim, name="char_embedding"))

    model.add(Conv1D(filters=128, kernel_size=3, padding="same", activation="relu", name="conv_k3"))
    model.add(MaxPooling1D(pool_size=4, name="pool_1"))

    model.add(Conv1D(filters=128, kernel_size=5, padding="same", activation="relu", name="conv_k5"))
    model.add(MaxPooling1D(pool_size=4, name="pool_2"))

    model.add(LSTM(128, return_sequences=True, name="lstm_context_sequence"))
    model.add(GlobalMaxPooling1D(name="lstm_global_max_pool"))
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


def evaluate_model(model: Sequential, X: np.ndarray, y: np.ndarray, name: str, batch_size: int) -> dict:
    y_prob = model.predict(X, batch_size=batch_size).flatten()
    y_pred = (y_prob >= 0.5).astype(int)

    result = {
        "accuracy": float(accuracy_score(y, y_pred)),
        "auc_roc": float(roc_auc_score(y, y_prob)) if len(np.unique(y)) > 1 else None,
        "confusion_matrix": confusion_matrix(y, y_pred).tolist(),
        "classification_report": classification_report(
            y,
            y_pred,
            target_names=["Normal (0)", "Attack (1)"] if len(np.unique(y)) > 1 else None,
            digits=4,
            zero_division=0,
            output_dict=True,
        ),
    }

    print(f"\n=== {name.upper()} RESULTS ===")
    print(f"Accuracy: {result['accuracy']:.4f}")
    if result["auc_roc"] is not None:
        print(f"AUC-ROC : {result['auc_roc']:.4f}")
    print("Confusion matrix:")
    print(np.array(result["confusion_matrix"]))
    print("Classification report:")
    print(
        classification_report(
            y,
            y_pred,
            target_names=["Normal (0)", "Attack (1)"] if len(np.unique(y)) > 1 else None,
            digits=4,
            zero_division=0,
        )
    )
    return result


def save_processed_csvs(
    output_dir: Path,
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    test_df: pd.DataFrame,
    obfuscated_df: pd.DataFrame,
) -> None:
    processed_dir = output_dir / "processed_data"
    processed_dir.mkdir(parents=True, exist_ok=True)
    train_df.to_csv(processed_dir / "train.csv", index=False, encoding="utf-8")
    val_df.to_csv(processed_dir / "val.csv", index=False, encoding="utf-8")
    test_df.to_csv(processed_dir / "test.csv", index=False, encoding="utf-8")
    obfuscated_df.to_csv(processed_dir / "obfuscated_test.csv", index=False, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train and evaluate the Hybrid CNN-LSTM SQLi/XSS detector.")
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
    parser.add_argument("--sample-size", type=int, default=None, help="Optional quick-run sample size for base data.")
    parser.add_argument("--obfu-sample-size", type=int, default=None, help="Optional quick-run sample size for obfu test.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    set_seed(args.seed)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    train_df, val_df, test_df, obfuscated_df, metadata = build_datasets(args)
    save_processed_csvs(output_dir, train_df, val_df, test_df, obfuscated_df)

    print("=== DATA PREPARED ===")
    print(f"Train           : {len(train_df):,}")
    print(f"Val             : {len(val_df):,}")
    print(f"Test            : {len(test_df):,}")
    print(f"Obfuscated test : {len(obfuscated_df):,}")
    print(f"Base p99 length : {metadata['splits']['base_clean']['length']['p99']:.0f}")

    tokenizer = build_tokenizer(train_df["payload"])
    vocab_size = len(tokenizer.word_index) + 1
    print("\n=== TOKENIZER ===")
    print(f"Vocabulary size: {vocab_size}")
    print("Tokenizer was fit on train payloads only.")

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
    print("\n=== INPUT SHAPES ===")
    print(f"X_train: {X_train.shape}")
    print(f"X_val  : {X_val.shape}")
    print(f"X_test : {X_test.shape}")
    print(f"X_obfu : {X_obfu.shape}")
    print(f"Class weights: {class_weight_dict}")

    model = build_model(vocab_size, args.max_len, args.embedding_dim)
    model.summary()

    best_model_path = output_dir / "best_hybrid_cnn_lstm.keras"
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

    model.save(output_dir / "last_hybrid_cnn_lstm.keras")
    with (output_dir / "tokenizer.pkl").open("wb") as file:
        pickle.dump(tokenizer, file)

    test_result = evaluate_model(model, X_test, y_test, "normal test", args.batch_size)
    obfu_result = evaluate_model(model, X_obfu, y_obfu, "obfuscated test", args.batch_size)

    metadata["model"] = {
        "max_len": args.max_len,
        "embedding_dim": args.embedding_dim,
        "vocab_size": vocab_size,
        "architecture": "Embedding -> Conv1D(k3) -> MaxPool(4) -> Conv1D(k5) -> MaxPool(4) -> LSTM(128, return_sequences=True) -> GlobalMaxPooling1D -> Dense(64) -> Dropout -> Sigmoid",
        "architecture_note": "Sequence pooling keeps the LSTM output at every timestep and pools the strongest activation, instead of relying only on the final LSTM state.",
        "parameter_count": int(model.count_params()),
        "class_weight": class_weight_dict,
        "artifacts": {
            "best_model": str(best_model_path),
            "last_model": str(output_dir / "last_hybrid_cnn_lstm.keras"),
            "tokenizer": str(output_dir / "tokenizer.pkl"),
        },
    }
    metadata["training_history"] = {
        key: [float(value) for value in values] for key, values in history.history.items()
    }
    metadata["evaluation"] = {
        "test": test_result,
        "obfuscated_test": obfu_result,
    }

    with (output_dir / "metadata_and_results.json").open("w", encoding="utf-8") as file:
        json.dump(metadata, file, ensure_ascii=False, indent=2)

    print(f"\nSaved artifacts to: {output_dir.resolve()}")


if __name__ == "__main__":
    main()
