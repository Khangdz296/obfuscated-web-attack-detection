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


def load_csic(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    required = {"content", "URL", "classification"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"{path} is missing columns: {sorted(missing)}")

    out = pd.DataFrame()
    out["payload"] = df["content"].fillna("") + " " + df["URL"].fillna("")
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


def clean(df: pd.DataFrame, deduplicate: bool = True) -> pd.DataFrame:
    cleaned = df.copy()
    cleaned["payload"] = cleaned["payload"].apply(normalize_payload)
    cleaned["label"] = to_binary_label(cleaned["label"])

    for column in ["source", "attack_type", "obfuscation_type", "pattern_category", "difficulty_level"]:
        if column not in cleaned.columns:
            cleaned[column] = ""
        cleaned[column] = cleaned[column].fillna("").astype(str)

    cleaned = cleaned[cleaned["payload"].str.len() > 0]
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

    base_df = clean(
        pd.concat(
            [
                load_kaggle(args.kaggle_path),
                load_csic(args.csic_path),
            ],
            ignore_index=True,
        ),
        deduplicate=True,
    )
    base_df = base_df.sample(frac=1, random_state=args.seed).reset_index(drop=True)

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

    obfu_df = clean(load_obfuscation(args.obfu_path), deduplicate=True)

    save_csv(base_df, output_dir / "base_clean.csv")
    save_csv(train_df, output_dir / "train.csv")
    save_csv(val_df, output_dir / "val.csv")
    save_csv(test_df, output_dir / "test.csv")
    save_csv(obfu_df, output_dir / "obfuscated_test.csv")

    metadata = {
        "preprocessing_policy": {
            "url_decode": False,
            "html_unescape": False,
            "lowercase": False,
            "whitespace_normalization_only": True,
            "deduplicate_base_by": ["payload", "label"],
            "tokenizer_rule": "Fit tokenizer on train.csv only. Do not fit on val/test/obfuscated_test.",
        },
        "splits": {
            "base_clean": summarize(base_df),
            "train": summarize(train_df),
            "val": summarize(val_df),
            "test": summarize(test_df),
            "obfuscated_test": summarize(obfu_df),
        },
    }

    with (output_dir / "metadata.json").open("w", encoding="utf-8") as f:
        json.dump(metadata, f, ensure_ascii=False, indent=2)

    print("=== PREPROCESSING DONE ===")
    print(f"Output directory: {output_dir.resolve()}")
    print(f"Train: {len(train_df):,}")
    print(f"Val: {len(val_df):,}")
    print(f"Test: {len(test_df):,}")
    print(f"Obfuscated test: {len(obfu_df):,}")


if __name__ == "__main__":
    main()
