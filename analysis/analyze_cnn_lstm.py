"""
Post-training analysis for the saved CNN-LSTM model.

This script is intentionally separate from CNN_LSTM.py. It does not retrain and
does not modify the model. It only:
- evaluates different decision thresholds on val/test/obfuscated_test,
- reports recall by obfuscation_type / attack_type / difficulty_level,
- exports false negatives for manual inspection.
"""

import argparse
import json
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
import tensorflow as tf
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support
from tensorflow.keras.preprocessing.sequence import pad_sequences


DEFAULT_ARTIFACT_DIR = str(
    Path(__file__).resolve().parent.parent / "cnn_lstm" / "artifacts"
)
DEFAULT_MAX_LEN = 1024


def load_artifacts(artifact_dir: Path):
    model_path = artifact_dir / "best_hybrid_cnn_lstm.keras"
    tokenizer_path = artifact_dir / "tokenizer.pkl"

    model = tf.keras.models.load_model(model_path)
    with tokenizer_path.open("rb") as file:
        tokenizer = pickle.load(file)
    return model, tokenizer


def vectorize(tokenizer, payloads: pd.Series, max_len: int) -> np.ndarray:
    sequences = tokenizer.texts_to_sequences(payloads.astype(str))
    return pad_sequences(
        sequences,
        maxlen=max_len,
        padding="post",
        truncating="post",
    )


def predict_probabilities(model, tokenizer, df: pd.DataFrame, max_len: int, batch_size: int) -> np.ndarray:
    X = vectorize(tokenizer, df["payload"], max_len)
    return model.predict(X, batch_size=batch_size).flatten()


def metrics_at_threshold(y_true: np.ndarray, y_prob: np.ndarray, threshold: float) -> dict:
    y_pred = (y_prob >= threshold).astype(int)
    labels = sorted(np.unique(y_true).tolist())

    precision, recall, f1, support = precision_recall_fscore_support(
        y_true,
        y_pred,
        labels=labels,
        zero_division=0,
    )
    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist()

    result = {
        "threshold": float(threshold),
        "confusion_matrix_0_1": matrix,
        "classification_report": classification_report(
            y_true,
            y_pred,
            labels=labels,
            digits=4,
            zero_division=0,
            output_dict=True,
        ),
    }

    for label, p, r, f, s in zip(labels, precision, recall, f1, support):
        prefix = "normal" if label == 0 else "attack"
        result[f"{prefix}_precision"] = float(p)
        result[f"{prefix}_recall"] = float(r)
        result[f"{prefix}_f1"] = float(f)
        result[f"{prefix}_support"] = int(s)
    return result


def threshold_table(y_true: np.ndarray, y_prob: np.ndarray, thresholds: list[float]) -> pd.DataFrame:
    rows = []
    for threshold in thresholds:
        result = metrics_at_threshold(y_true, y_prob, threshold)
        rows.append(
            {
                "threshold": threshold,
                "normal_precision": result.get("normal_precision"),
                "normal_recall": result.get("normal_recall"),
                "normal_f1": result.get("normal_f1"),
                "attack_precision": result.get("attack_precision"),
                "attack_recall": result.get("attack_recall"),
                "attack_f1": result.get("attack_f1"),
                "confusion_matrix_0_1": json.dumps(result["confusion_matrix_0_1"]),
            }
        )
    return pd.DataFrame(rows)


def grouped_attack_recall(df: pd.DataFrame, y_prob: np.ndarray, threshold: float, group_col: str) -> pd.DataFrame:
    if group_col not in df.columns:
        return pd.DataFrame()

    work = df.copy()
    work["probability"] = y_prob
    work["predicted"] = (work["probability"] >= threshold).astype(int)
    work["is_detected"] = (work["label"].astype(int) == 1) & (work["predicted"] == 1)
    work["is_missed"] = (work["label"].astype(int) == 1) & (work["predicted"] == 0)

    grouped = (
        work.groupby(group_col, dropna=False)
        .agg(
            samples=("payload", "size"),
            detected=("is_detected", "sum"),
            missed=("is_missed", "sum"),
            avg_probability=("probability", "mean"),
        )
        .reset_index()
    )
    grouped["recall"] = grouped["detected"] / grouped["samples"].clip(lower=1)
    grouped = grouped.sort_values(["recall", "samples"], ascending=[True, False])
    return grouped


def export_false_negatives(df: pd.DataFrame, y_prob: np.ndarray, threshold: float, path: Path, limit: int) -> None:
    work = df.copy()
    work["probability"] = y_prob
    work["predicted"] = (work["probability"] >= threshold).astype(int)
    missed = work[(work["label"].astype(int) == 1) & (work["predicted"] == 0)]
    missed = missed.sort_values("probability", ascending=True).head(limit)
    missed.to_csv(path, index=False, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze saved CNN-LSTM results without retraining.")
    parser.add_argument("--artifact-dir", default=DEFAULT_ARTIFACT_DIR)
    parser.add_argument("--max-len", type=int, default=DEFAULT_MAX_LEN)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--false-negative-limit", type=int, default=1000)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    artifact_dir = Path(args.artifact_dir)
    processed_dir = artifact_dir / "processed_data"
    output_dir = artifact_dir / "analysis"
    output_dir.mkdir(parents=True, exist_ok=True)

    model, tokenizer = load_artifacts(artifact_dir)
    val_df = pd.read_csv(processed_dir / "val.csv")
    test_df = pd.read_csv(processed_dir / "test.csv")
    obfu_df = pd.read_csv(processed_dir / "obfuscated_test.csv")

    print("Predicting validation probabilities...")
    val_prob = predict_probabilities(model, tokenizer, val_df, args.max_len, args.batch_size)
    print("Predicting normal test probabilities...")
    test_prob = predict_probabilities(model, tokenizer, test_df, args.max_len, args.batch_size)
    print("Predicting obfuscated test probabilities...")
    obfu_prob = predict_probabilities(model, tokenizer, obfu_df, args.max_len, args.batch_size)

    thresholds = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
    threshold_table(val_df["label"].to_numpy(), val_prob, thresholds).to_csv(
        output_dir / "thresholds_val.csv", index=False, encoding="utf-8"
    )
    threshold_table(test_df["label"].to_numpy(), test_prob, thresholds).to_csv(
        output_dir / "thresholds_test.csv", index=False, encoding="utf-8"
    )
    threshold_table(obfu_df["label"].to_numpy(), obfu_prob, thresholds).to_csv(
        output_dir / "thresholds_obfuscated_test.csv", index=False, encoding="utf-8"
    )

    for group_col in ["obfuscation_type", "attack_type", "difficulty_level", "pattern_category"]:
        grouped = grouped_attack_recall(obfu_df, obfu_prob, args.threshold, group_col)
        if not grouped.empty:
            grouped.to_csv(output_dir / f"obfuscated_recall_by_{group_col}.csv", index=False, encoding="utf-8")

    export_false_negatives(
        test_df,
        test_prob,
        args.threshold,
        output_dir / "false_negatives_test.csv",
        args.false_negative_limit,
    )
    export_false_negatives(
        obfu_df,
        obfu_prob,
        args.threshold,
        output_dir / "false_negatives_obfuscated_test.csv",
        args.false_negative_limit,
    )

    summary = {
        "threshold": args.threshold,
        "test": metrics_at_threshold(test_df["label"].to_numpy(), test_prob, args.threshold),
        "obfuscated_test": metrics_at_threshold(obfu_df["label"].to_numpy(), obfu_prob, args.threshold),
        "outputs": {
            "thresholds_val": str(output_dir / "thresholds_val.csv"),
            "thresholds_test": str(output_dir / "thresholds_test.csv"),
            "thresholds_obfuscated_test": str(output_dir / "thresholds_obfuscated_test.csv"),
            "false_negatives_test": str(output_dir / "false_negatives_test.csv"),
            "false_negatives_obfuscated_test": str(output_dir / "false_negatives_obfuscated_test.csv"),
        },
    }
    with (output_dir / "analysis_summary.json").open("w", encoding="utf-8") as file:
        json.dump(summary, file, ensure_ascii=False, indent=2)

    print(f"Analysis saved to: {output_dir.resolve()}")


if __name__ == "__main__":
    main()
