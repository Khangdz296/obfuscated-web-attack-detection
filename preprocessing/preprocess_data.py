import argparse
import json
import re
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split


PROJECT_ROOT = Path(__file__).resolve().parent.parent
KAGGLE_PATH = str(PROJECT_ROOT / "SQLInjection_XSS_MixDataset.1.0.0.csv")
CSIC_PATH = str(PROJECT_ROOT / "csic_database.csv")
OBFU_PATH = str(PROJECT_ROOT / "obfuscation_dataset_full.xlsx")
OUTPUT_DIR = str(PROJECT_ROOT / "cnn_lstm" / "artifacts" / "processed_data")
RANDOM_STATE = 42


def normalize_payload(value: object) -> str:
    """No URL decode, no HTML unescape, no lowercase: keep obfuscation evidence."""
    if not isinstance(value, str):
        return ""
    return re.sub(r"\s+", " ", value).strip()


def to_binary_label(series: pd.Series) -> pd.Series:
    text = series.astype(str).str.strip().str.lower()
    attack_words = {"1", "true", "attack", "attacks", "malicious", "sqli", "sql", "xss"}
    normal_words = {"0", "false", "normal", "benign", "clean"}

    mapped = []
    for value in text:
        if value in attack_words:
            mapped.append(1)
        elif value in normal_words:
            mapped.append(0)
        else:
            numeric = pd.to_numeric(value, errors="coerce")
            mapped.append(1 if pd.notna(numeric) and numeric > 0 else 0)
    return pd.Series(mapped, index=series.index, dtype="int64")


def load_kaggle(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    required = {"Sentence", "SQLInjection", "XSS"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"{path} is missing columns: {sorted(missing)}")

    out = pd.DataFrame()
    out["payload"] = df["Sentence"]
    out["label"] = df[["SQLInjection", "XSS"]].max(axis=1).astype(int)
    out["source"] = "kaggle_sqli_xss"
    out["attack_type"] = "mixed"
    out["obfuscation_type"] = "original"
    out["pattern_category"] = ""
    out["difficulty_level"] = ""
    return out


def extract_form_values(payload: object) -> str:
    """Extract raw form/query values without URL-decoding obfuscation evidence."""
    if not isinstance(payload, str):
        return ""

    values = []
    for pair in payload.split("&"):
        pair = pair.strip()
        if not pair:
            continue
        if "=" in pair:
            _, value = pair.split("=", 1)
        else:
            value = pair
        if value:
            values.append(value)
    return " ".join(values)


def extract_url_query(url: object) -> str:
    if not isinstance(url, str):
        return ""

    request_url = re.sub(r"\s+HTTP/\d(?:\.\d)?\s*$", "", url.strip())
    if "?" not in request_url:
        return ""
    return request_url.split("?", 1)[1]


def extract_csic_input_values(row: pd.Series) -> str:
    body_values = extract_form_values(row.get("content", ""))
    query_values = extract_form_values(extract_url_query(row.get("URL", "")))
    return " ".join(value for value in [body_values, query_values] if value)


def load_csic(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    required = {"content", "URL", "classification"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"{path} is missing columns: {sorted(missing)}")

    out = pd.DataFrame()
    out["payload"] = df.apply(extract_csic_input_values, axis=1)
    out["label"] = to_binary_label(df["classification"])
    out["source"] = "csic_2010"
    out["attack_type"] = "mixed"
    out["obfuscation_type"] = "original"
    out["pattern_category"] = ""
    out["difficulty_level"] = ""
    return out


def read_xlsx_first_sheet(path: str) -> pd.DataFrame:
    """Read a simple XLSX table without openpyxl."""
    ns = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
    with zipfile.ZipFile(path) as workbook:
        shared_strings = []
        if "xl/sharedStrings.xml" in workbook.namelist():
            root = ET.fromstring(workbook.read("xl/sharedStrings.xml"))
            for si in root.findall(ns + "si"):
                shared_strings.append("".join(t.text or "" for t in si.iter(ns + "t")))

        sheet_root = ET.fromstring(workbook.read("xl/worksheets/sheet1.xml"))
        rows = []
        for row in sheet_root.find(ns + "sheetData").findall(ns + "row"):
            values = []
            for cell in row.findall(ns + "c"):
                value_node = cell.find(ns + "v")
                value = "" if value_node is None else value_node.text or ""
                if cell.get("t") == "s" and value:
                    value = shared_strings[int(value)]
                values.append(value)
            rows.append(values)

    if not rows:
        return pd.DataFrame()

    width = max(len(row) for row in rows)
    normalized_rows = [row + [""] * (width - len(row)) for row in rows]
    header = normalized_rows[0]
    data = normalized_rows[1:]
    return pd.DataFrame(data, columns=header)


def load_obfuscation(path: str) -> pd.DataFrame:
    if path.lower().endswith(".xlsx"):
        df = read_xlsx_first_sheet(path)
    else:
        df = pd.read_csv(path)

    required = {"obfuscated_input", "label", "obfuscation_type"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"{path} is missing columns: {sorted(missing)}")

    out = pd.DataFrame()
    out["payload"] = df["obfuscated_input"]
    out["label"] = to_binary_label(df["label"])
    out["source"] = "custom_obfuscation"
    out["attack_type"] = df["label"].astype(str).str.lower()
    out["obfuscation_type"] = df["obfuscation_type"]
    out["pattern_category"] = df["pattern_category"] if "pattern_category" in df.columns else ""
    out["difficulty_level"] = df["difficulty_level"] if "difficulty_level" in df.columns else ""
    if "original_pattern" in df.columns:
        out["original_pattern"] = df["original_pattern"]
    return out


def clean(df: pd.DataFrame, deduplicate: bool = True, drop_label_conflicts: bool = True) -> pd.DataFrame:
    cleaned = df.copy()
    cleaned["payload"] = cleaned["payload"].apply(normalize_payload)
    cleaned["label"] = to_binary_label(cleaned["label"])

    for column in ["source", "attack_type", "obfuscation_type", "pattern_category", "difficulty_level"]:
        if column not in cleaned.columns:
            cleaned[column] = ""
        cleaned[column] = cleaned[column].fillna("").astype(str)

    cleaned = cleaned[cleaned["payload"].str.len() > 0]
    if drop_label_conflicts:
        label_counts = cleaned.groupby("payload")["label"].transform("nunique")
        cleaned = cleaned[label_counts == 1]
    if deduplicate:
        cleaned = cleaned.drop_duplicates(subset=["payload", "label"])
    return cleaned.reset_index(drop=True)


def summarize(df: pd.DataFrame) -> dict:
    lengths = df["payload"].str.len()
    summary = {
        "rows": int(len(df)),
        "label_counts": {str(k): int(v) for k, v in df["label"].value_counts().sort_index().items()},
        "source_counts": {str(k): int(v) for k, v in df["source"].value_counts().items()},
        "length": {
            "mean": float(lengths.mean()) if len(df) else 0.0,
            "median": float(lengths.median()) if len(df) else 0.0,
            "p90": float(lengths.quantile(0.90)) if len(df) else 0.0,
            "p95": float(lengths.quantile(0.95)) if len(df) else 0.0,
            "p99": float(lengths.quantile(0.99)) if len(df) else 0.0,
            "max": int(lengths.max()) if len(df) else 0,
        },
    }
    if "obfuscation_type" in df.columns:
        summary["obfuscation_counts"] = {
            str(k): int(v) for k, v in df["obfuscation_type"].value_counts().head(30).items()
        }
    return summary


def save_csv(df: pd.DataFrame, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False, encoding="utf-8")


def split_dataset(
    df: pd.DataFrame,
    test_size: float,
    val_size: float,
    seed: int,
    group_column: str | None = None,
) -> dict[str, pd.DataFrame]:
    if not 0 < test_size < 1:
        raise ValueError("--test-size must be between 0 and 1.")
    if not 0 < val_size < 1:
        raise ValueError("--val-size must be between 0 and 1.")

    shuffled = df.sample(frac=1, random_state=seed).reset_index(drop=True)
    if group_column and group_column in shuffled.columns:
        return split_dataset_by_group(shuffled, test_size, val_size, seed, group_column)
    return split_dataset_by_row(shuffled, test_size, val_size, seed)


def safe_train_test_split(
    df: pd.DataFrame,
    test_size: float,
    seed: int,
    stratify_column: str = "label",
) -> tuple[pd.DataFrame, pd.DataFrame]:
    stratify = df[stratify_column] if stratify_column in df.columns else None
    try:
        return train_test_split(
            df,
            test_size=test_size,
            random_state=seed,
            stratify=stratify,
        )
    except ValueError:
        return train_test_split(df, test_size=test_size, random_state=seed)


def split_dataset_by_row(
    df: pd.DataFrame,
    test_size: float,
    val_size: float,
    seed: int,
) -> dict[str, pd.DataFrame]:
    train_val_df, test_df = safe_train_test_split(df, test_size, seed)
    train_df, val_df = safe_train_test_split(train_val_df, val_size, seed)
    return {
        "train": train_df.reset_index(drop=True),
        "val": val_df.reset_index(drop=True),
        "test": test_df.reset_index(drop=True),
    }


def split_dataset_by_group(
    df: pd.DataFrame,
    test_size: float,
    val_size: float,
    seed: int,
    group_column: str,
) -> dict[str, pd.DataFrame]:
    group_key = df[group_column].fillna("").astype(str)
    group_key = group_key.where(group_key.str.len() > 0, df["payload"])

    group_frame = (
        pd.DataFrame({"group_key": group_key, "label": df["label"]})
        .groupby("group_key", as_index=False)["label"]
        .agg(lambda values: values.mode().iloc[0])
    )
    train_val_groups, test_groups = safe_train_test_split(group_frame, test_size, seed)
    train_groups, val_groups = safe_train_test_split(train_val_groups, val_size, seed)

    train_keys = set(train_groups["group_key"])
    val_keys = set(val_groups["group_key"])
    test_keys = set(test_groups["group_key"])

    return {
        "train": df[group_key.isin(train_keys)].reset_index(drop=True),
        "val": df[group_key.isin(val_keys)].reset_index(drop=True),
        "test": df[group_key.isin(test_keys)].reset_index(drop=True),
    }


def load_clean_datasets(kaggle_path: str, csic_path: str, obfu_path: str) -> dict[str, pd.DataFrame]:
    return {
        "kaggle": clean(load_kaggle(kaggle_path), deduplicate=True, drop_label_conflicts=True),
        "csic": clean(load_csic(csic_path), deduplicate=True, drop_label_conflicts=True),
        "obfuscation": clean(
            load_obfuscation(obfu_path),
            deduplicate=True,
            drop_label_conflicts=False,
        ),
    }


def split_all_datasets(
    datasets: dict[str, pd.DataFrame],
    test_size: float,
    val_size: float,
    seed: int,
) -> dict[str, dict[str, pd.DataFrame]]:
    output = {}
    for name, frame in datasets.items():
        group_column = "original_pattern" if name == "obfuscation" else None
        output[name] = split_dataset(frame, test_size, val_size, seed, group_column=group_column)
    return output


def build_dataset_splits(
    kaggle_path: str,
    csic_path: str,
    obfu_path: str,
    test_size: float,
    val_size: float,
    seed: int,
) -> tuple[dict[str, dict[str, pd.DataFrame]], dict]:
    datasets = load_clean_datasets(kaggle_path, csic_path, obfu_path)
    dataset_splits = split_all_datasets(datasets, test_size, val_size, seed)
    metadata = {
        "preprocessing_policy": {
            "url_decode": False,
            "html_unescape": False,
            "lowercase": False,
            "whitespace_normalization_only": True,
            "deduplicate_by": ["payload", "label"],
            "csic_payload_policy": "Use raw query/body parameter values only; drop requests with no input values.",
            "obfuscation_group_split": "Use original_pattern when available so variants of the same pattern stay in one split.",
            "tokenizer_rule": "Each model fits its tokenizer on that dataset's train split only.",
        },
        "datasets": {},
    }
    for name, frame in datasets.items():
        metadata["datasets"][name] = {
            "clean": summarize(frame),
            "splits": {split_name: summarize(split_df) for split_name, split_df in dataset_splits[name].items()},
        }
    return dataset_splits, metadata


def save_dataset_splits(dataset_splits: dict[str, dict[str, pd.DataFrame]], output_dir: Path) -> None:
    for dataset_name, splits in dataset_splits.items():
        for split_name, split_df in splits.items():
            save_csv(split_df, output_dir / dataset_name / f"{split_name}.csv")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Preprocess datasets for char-level SQLi/XSS detection.")
    parser.add_argument("--kaggle-path", default=KAGGLE_PATH)
    parser.add_argument("--csic-path", default=CSIC_PATH)
    parser.add_argument("--obfu-path", default=OBFU_PATH)
    parser.add_argument("--output-dir", default=OUTPUT_DIR)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--val-size", type=float, default=0.1)
    parser.add_argument("--seed", type=int, default=RANDOM_STATE)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    dataset_splits, metadata = build_dataset_splits(
        args.kaggle_path,
        args.csic_path,
        args.obfu_path,
        args.test_size,
        args.val_size,
        args.seed,
    )
    save_dataset_splits(dataset_splits, output_dir)

    with (output_dir / "metadata.json").open("w", encoding="utf-8") as f:
        json.dump(metadata, f, ensure_ascii=False, indent=2)

    print("=== PREPROCESSING DONE ===")
    print(f"Output directory: {output_dir.resolve()}")
    for dataset_name, splits in dataset_splits.items():
        print(
            f"{dataset_name}: "
            f"train={len(splits['train']):,} | "
            f"val={len(splits['val']):,} | "
            f"test={len(splits['test']):,}"
        )


if __name__ == "__main__":
    main()
