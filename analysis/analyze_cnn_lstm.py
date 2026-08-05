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
    Path(__file__).resolve().parent.parent
    / "cnn_lstm"
    / "artifacts_cnn_lstm_by_dataset"
)
DEFAULT_MAX_LEN = 768
DEFAULT_SOURCE = "obfu_http"

# Columns worth grouping the results by. The last two only exist on the v2
# dataset; missing ones are skipped silently.
GROUP_COLUMNS = ["obfuscation_type", "attack_type", "difficulty_level",
                 "pattern_category", "attack_technique", "benign_kind"]


def resolve_model_dir(artifact_dir: Path, source: str) -> Path:
    """Find where CNN_LSTM.py actually saved the model for this source.

    Per-source runs write to artifacts/by_dataset/<source>/, while the older
    single-model layout wrote straight into artifacts/. Prefer the per-source
    directory and fall back, so both layouts keep working.
    """
    candidate = artifact_dir / "by_dataset" / source
    if (candidate / "best_hybrid_cnn_lstm.keras").exists():
        return candidate
    return artifact_dir


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


def grouped_false_positive_rate(df: pd.DataFrame, y_prob: np.ndarray,
                                threshold: float, group_col: str) -> pd.DataFrame:
    """False alarms per kind of legitimate traffic.

    grouped_attack_recall() cannot answer this: a benign group contains only
    label 0 rows, so its recall is always zero. What matters for benign traffic
    is how often the model cries wolf, broken down by the kind of legitimate
    content -- ordinary requests versus hard negatives such as obfuscated but
    harmless payloads.
    """
    if group_col not in df.columns:
        return pd.DataFrame()

    work = df.copy()
    work["probability"] = y_prob
    work["predicted"] = (work["probability"] >= threshold).astype(int)
    work = work[work["label"].astype(int) == 0]
    if work.empty:
        return pd.DataFrame()

    grouped = (
        work.groupby(group_col, dropna=False)
        .agg(samples=("payload", "size"),
             false_positives=("predicted", "sum"),
             avg_probability=("probability", "mean"))
        .reset_index()
    )
    grouped["false_positive_rate"] = (
        grouped["false_positives"] / grouped["samples"].clip(lower=1))
    return grouped.sort_values(["false_positive_rate", "samples"],
                               ascending=[False, False])


def export_false_negatives(df: pd.DataFrame, y_prob: np.ndarray, threshold: float, path: Path, limit: int) -> None:
    work = df.copy()
    work["probability"] = y_prob
    work["predicted"] = (work["probability"] >= threshold).astype(int)
    missed = work[(work["label"].astype(int) == 1) & (work["predicted"] == 0)]
    missed = missed.sort_values("probability", ascending=True).head(limit)
    missed.to_csv(path, index=False, encoding="utf-8")


def load_split_frames(artifact_dir: Path, source: str) -> dict[str, pd.DataFrame]:
    """Read whatever splits CNN_LSTM.py actually wrote for one source.

    CNN_LSTM.py writes artifacts/processed_data_by_dataset/<source>/<split>.csv.
    This script used to read artifacts/processed_data/{val,test,obfuscated_test}.csv,
    which is the legacy layout produced by build_datasets() -- a function main()
    no longer calls. Reading the directory means the three v2 generalisation
    splits are picked up automatically instead of being silently ignored.
    """
    source_dir = artifact_dir / "processed_data_by_dataset" / source
    if not source_dir.is_dir():
        raise FileNotFoundError(
            f"Không thấy {source_dir}. Chạy cnn_lstm/CNN_LSTM.py trước, "
            f"hoặc chỉ định --source cho đúng nguồn đã huấn luyện."
        )
    frames = {path.stem: pd.read_csv(path) for path in sorted(source_dir.glob("*.csv"))}
    if not frames:
        raise FileNotFoundError(f"{source_dir} rỗng.")
    return frames


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze saved CNN-LSTM results without retraining.")
    parser.add_argument("--artifact-dir", default=DEFAULT_ARTIFACT_DIR)
    parser.add_argument("--source", default=DEFAULT_SOURCE,
                        help="Dataset source directory to analyse (obfu_http, csic, kaggle).")
    parser.add_argument("--max-len", type=int, default=DEFAULT_MAX_LEN)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--false-negative-limit", type=int, default=1000)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    artifact_dir = Path(args.artifact_dir)
    output_dir = artifact_dir / "analysis" / args.source
    output_dir.mkdir(parents=True, exist_ok=True)

    model_dir = resolve_model_dir(artifact_dir, args.source)
    print(f"Loading model from: {model_dir}")
    model, tokenizer = load_artifacts(model_dir)
    frames = load_split_frames(artifact_dir, args.source)

    # Every split named test* is evaluated. On the v2 dataset that is the
    # in-distribution test plus three generalisation splits; the difference
    # between them is the result the project is after.
    analysed = ["val"] + sorted(n for n in frames if n.startswith("test"))
    analysed = [n for n in analysed if n in frames]

    thresholds = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
    probabilities: dict[str, np.ndarray] = {}
    summary_splits: dict[str, dict] = {}

    for split_name in analysed:
        frame = frames[split_name]
        print(f"Predicting {split_name} probabilities ({len(frame):,} rows)...")
        prob = predict_probabilities(model, tokenizer, frame, args.max_len, args.batch_size)
        probabilities[split_name] = prob
        truth = frame["label"].to_numpy()

        threshold_table(truth, prob, thresholds).to_csv(
            output_dir / f"thresholds_{split_name}.csv", index=False, encoding="utf-8")

        if split_name != "val":
            summary_splits[split_name] = metrics_at_threshold(truth, prob, args.threshold)

        for group_col in GROUP_COLUMNS:
            grouped = grouped_attack_recall(frame, prob, args.threshold, group_col)
            if not grouped.empty and grouped["detected"].sum() + grouped["missed"].sum() > 0:
                grouped.to_csv(output_dir / f"{split_name}_recall_by_{group_col}.csv",
                               index=False, encoding="utf-8")

        false_positives = grouped_false_positive_rate(
            frame, prob, args.threshold, "benign_kind")
        if not false_positives.empty:
            false_positives.to_csv(output_dir / f"{split_name}_false_positive_by_benign_kind.csv",
                                   index=False, encoding="utf-8")

        export_false_negatives(frame, prob, args.threshold,
                               output_dir / f"false_negatives_{split_name}.csv",
                               args.false_negative_limit)

    # The headline number: how far recall falls between the in-distribution
    # split and the hardest held-out one.
    gap = None
    if "test" in summary_splits and "test_unseen_both" in summary_splits:
        gap = round((summary_splits["test"]["attack_recall"]
                     - summary_splits["test_unseen_both"]["attack_recall"]) * 100, 2)

    print("\n=== Attack recall @ threshold", args.threshold, "===")
    for split_name, metrics in summary_splits.items():
        print(f"  {split_name:24s} {metrics['attack_recall'] * 100:6.2f}%")
    if gap is not None:
        print(f"  {'GAP (test -> unseen_both)':24s} {gap:6.2f} điểm")

    summary = {
        "source": args.source,
        "threshold": args.threshold,
        "max_len": args.max_len,
        "splits": summary_splits,
        "gap_test_to_unseen_both": gap,
        "output_dir": str(output_dir),
    }
    with (output_dir / "analysis_summary.json").open("w", encoding="utf-8") as file:
        json.dump(summary, file, ensure_ascii=False, indent=2)

    print(f"\nAnalysis saved to: {output_dir.resolve()}")


if __name__ == "__main__":
    main()
