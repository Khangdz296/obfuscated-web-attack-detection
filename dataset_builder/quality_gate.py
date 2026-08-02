"""Quality gate for the obfuscated HTTP dataset.

Run this after every regeneration. It answers one question: is the dataset hard
enough to tell a good detector from a bad one? A char n-gram logistic regression
stands in for "the dumbest possible model" -- if it already scores near-perfect,
the dataset cannot rank anything above it, so the deep model's score means
nothing.

Works on both schemas:
  v1  classification / split in {train,val,test,test_heldout}, no seed_id
  v2  adds seed_id, benign_kind, attack_technique, and four test splits

    python dataset_builder/quality_gate.py
    python dataset_builder/quality_gate.py --dataset DataSet/obfu_http_dataset_v2.csv
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, recall_score

BUILDER_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BUILDER_DIR.parent
DEFAULT_DATASET = PROJECT_ROOT / "DataSet" / "obfu_http_dataset_v2.csv"
DEFAULT_KAGGLE = PROJECT_ROOT / "DataSet" / "SQLInjection_XSS_MixDataset.1.0.0.csv"

# A dataset that fails these is not broken, but its headline number is not evidence.
MAX_TRIVIAL_ACCURACY = 0.95
MAX_ROWS_PER_SEED = 50.0
MAX_CROSS_SOURCE_OVERLAP = 0.05
MAX_SINGLE_FEATURE_SKEW = 0.35
MIN_BENIGN_RAW_SPECIAL = 0.15
MAX_RULE_PRECISION = 0.90
MIN_DEGRADATION_POINTS = 2.0

TEST_SPLITS = ("test", "test_heldout", "test_unseen_technique",
               "test_unseen_seed", "test_unseen_both")


class Report:
    def __init__(self) -> None:
        self.checks: list[tuple[str, bool, str]] = []

    def add(self, name: str, passed: bool, detail: str) -> None:
        self.checks.append((name, passed, detail))
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}: {detail}")

    def verdict(self) -> bool:
        return all(passed for _, passed, _ in self.checks)


def canonical(value: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def seed_family(payload: object) -> str:
    """Collapse per-row randomness so one seed template counts as one family."""
    text = str(payload).lower()
    text = re.sub(r"[0-9a-f]{4,}", "<id>", text)
    return re.sub(r"\d+", "<n>", text)


def load_seed_payloads() -> dict[str, str]:
    """seed_id -> original payload, for exact diversity and overlap measurement."""
    try:
        sys.path.insert(0, str(BUILDER_DIR))
        from seeds_sqli import build_sqli_seeds
        from seeds_xss import build_xss_seeds
        bank = build_sqli_seeds() + build_xss_seeds()
        return {s["seed_id"]: s["payload"] for s in bank}
    except Exception as exc:                                # pragma: no cover
        print(f"      (seed banks unavailable: {exc})")
        return {}


def benign_user_agents(df: pd.DataFrame) -> tuple[str, ...]:
    if "user_agent" not in df.columns or "classification" not in df.columns:
        return ()
    benign = df.loc[df["classification"] == "normal", "user_agent"].dropna().astype(str)
    return tuple(sorted(benign.unique(), key=len, reverse=True))


def extract_payload(row: pd.Series, known_agents: tuple[str, ...] = ()) -> str | None:
    """Fallback payload recovery for v1 rows, which carry no seed_id."""
    location = row.get("context_location")
    if not isinstance(location, str) or not location:
        return None
    try:
        if location == "query_param":
            value = str(row["url"]).split("?", 1)[1].split("=", 1)[1]
            return re.sub(r"&\w+=\d+$", "", value)
        if location == "form_field":
            value = str(row["content"]).split("=", 1)[1]
            return value[: -len("&submit=1")] if value.endswith("&submit=1") else value
        if location == "json_body":
            for key, value in json.loads(str(row["content"])).items():
                if key != "ts":
                    return str(value)
        if location == "cookie":
            return str(row["cookie"]).split("; pref=", 1)[1]
        if location == "header":
            agent = str(row["user_agent"])
            for known in known_agents:
                if agent.startswith(known + " "):
                    return agent[len(known) + 1:]
            return agent
    except (IndexError, KeyError, ValueError):
        return None
    return None


def build_surface(df: pd.DataFrame) -> pd.Series:
    columns = ["url", "content", "cookie", "user_agent"]
    present = [c for c in columns if c in df.columns]
    return df[present].fillna("").astype(str).agg(" ".join, axis=1)


def present_test_splits(df: pd.DataFrame) -> list[str]:
    if "split" not in df.columns:
        return []
    values = set(df["split"].astype(str).str.strip().str.lower())
    return [name for name in TEST_SPLITS if name in values]


# ---------------------------------------------------------------------------
def check_composition(df: pd.DataFrame, report: Report) -> None:
    print("\n1. Composition")
    print(f"      rows={len(df):,}  "
          f"classification={df['classification'].value_counts().to_dict()}")
    if "split" not in df.columns:
        return
    split = df["split"].astype(str).str.strip().str.lower()
    for name in sorted(split.unique()):
        part = df[split == name]
        labels = part["classification"].value_counts()
        print(f"      {name:24s} n={len(part):>7,} "
              f"normal={labels.get('normal', 0):>7,} "
              f"anomalous={labels.get('anomalous', 0):>7,}")

    tests = present_test_splits(df)
    single_class = [name for name in tests
                    if df.loc[split == name, "classification"].nunique() < 2]
    report.add(
        "every test split has both classes",
        not single_class,
        "all test splits contain normal and anomalous rows" if not single_class
        else f"{single_class} are attack-only, so only recall is measurable there",
    )


def check_seed_diversity(df: pd.DataFrame, report: Report) -> None:
    print("\n2. Seed diversity (the dominant driver of memorisation)")
    attacks = df[df["classification"] == "anomalous"].copy()
    if attacks.empty:
        report.add("seed diversity", False, "no attack rows")
        return

    has_seed_id = "seed_id" in df.columns and attacks["seed_id"].notna().any()
    if has_seed_id:
        seed_payloads = load_seed_payloads()
        attacks["family"] = attacks["seed_id"].map(
            lambda s: seed_family(seed_payloads.get(s, s)))
        families = attacks["family"].nunique()
        source = "seed_id column"
    else:
        agents = benign_user_agents(df)
        attacks["payload"] = attacks.apply(extract_payload, axis=1, known_agents=agents)
        usable = attacks[attacks["payload"].notna()]
        if usable.empty:
            report.add("seed diversity", False, "could not extract any payload")
            return
        attacks = usable.assign(family=usable["payload"].map(seed_family))
        plain = attacks[attacks.get("obfuscation_type", pd.Series(dtype=str)) == "plain"]
        families = plain["family"].nunique() if len(plain) else attacks["family"].nunique()
        source = "payload extraction (v1 fallback)"

    rows_per_seed = len(attacks) / max(families, 1)
    report.add(
        "rows per seed family",
        rows_per_seed <= MAX_ROWS_PER_SEED,
        f"{rows_per_seed:.0f} rows/seed over {families:,} seeds via {source} "
        f"(target <= {MAX_ROWS_PER_SEED:.0f}); {len(attacks):,} attack rows",
    )

    if "split" not in df.columns:
        return
    split = attacks["split"].astype(str).str.strip().str.lower()
    train = set(attacks.loc[split == "train", "family"])
    if not train:
        return

    unseen_ok = True
    for name in present_test_splits(df):
        test = set(attacks.loc[split == name, "family"])
        if not test:
            continue
        overlap = len(test & train) / len(test)
        expected = "must be 0%" if "unseen_seed" in name or "unseen_both" in name else "in-distribution"
        print(f"      train -> {name:24s} seed overlap {overlap * 100:5.1f}%  ({expected})")
        if ("unseen_seed" in name or "unseen_both" in name) and overlap > 0:
            unseen_ok = False

    held = [n for n in present_test_splits(df) if "unseen_seed" in n or "unseen_both" in n]
    if held:
        report.add(
            "unseen-seed splits share no seed with train",
            unseen_ok,
            "held-out seed pool is clean" if unseen_ok
            else "a held-out seed leaked into train, so those splits measure memorisation",
        )
    else:
        test = set(attacks.loc[split == "test", "family"])
        if test:
            overlap = len(test & train) / len(test)
            report.add("seed overlap train -> test", overlap < 1.0,
                       f"{overlap * 100:.1f}% of test seeds also appear in train")


def check_technique_holdout(df: pd.DataFrame, report: Report) -> None:
    print("\n3. Technique hold-out")
    if "obfuscation_techniques" not in df.columns or "split" not in df.columns:
        return
    tests = [n for n in present_test_splits(df) if "unseen_technique" in n or "unseen_both" in n]
    if not tests:
        print("      no unseen-technique split in this dataset, skipping")
        return
    attacks = df[df["classification"] == "anomalous"]
    split = attacks["split"].astype(str).str.strip().str.lower()
    # Prefer the combo that was assigned. A transform can be a no-op on a given
    # payload, so obfuscation_techniques (what actually changed) understates the
    # hold-out and reports false leaks.
    column = "assigned_combo" if "assigned_combo" in attacks.columns else "obfuscation_techniques"
    print(f"      measured on {column!r}")
    # Compare within an attack category. SQLi and XSS have separate technique
    # universes that share names, so a global comparison reports a phantom leak
    # whenever e.g. ("case_variation",) is SET_1 for one and SET_2 for the other.
    category = (attacks["attack_category"] if "attack_category" in attacks.columns
                else pd.Series("all", index=attacks.index))
    combos = attacks[column].fillna("") + "@" + category.astype(str)
    train_combos = {c for c in combos[split == "train"] if not c.startswith("@")}
    leaked = {}
    for name in tests:
        test_combos = {c for c in combos[split == name] if not c.startswith("@")}
        overlap = test_combos & train_combos
        if overlap:
            leaked[name] = sorted(overlap)[:3]
        print(f"      {name:24s} {len(test_combos):3d} combos, "
              f"{len(overlap):3d} also in train")
    report.add(
        "unseen-technique splits use combos absent from train",
        not leaked,
        "held-out combo set is clean" if not leaked
        else f"leaked combos: {leaked}",
    )


def check_shortcuts(df: pd.DataFrame, report: Report) -> None:
    print("\n4. Shortcut features (can a model cheat without reading the payload?)")
    y = (df["classification"] == "anomalous").astype(int)
    worst_name, worst_skew = "", 0.0
    for column in ["method", "content_type", "host"]:
        if column not in df.columns:
            continue
        values = df[column].fillna("<none>").astype(str).str.split(";").str[0]
        grouped = pd.DataFrame({"v": values, "y": y}).groupby("v")["y"].agg(["size", "mean"])
        grouped = grouped[grouped["size"] >= max(50, len(df) // 1000)]
        if grouped.empty:
            continue
        skew = float((grouped["mean"] - 0.5).abs().max())
        flag = "  <-- leaks the label" if skew > MAX_SINGLE_FEATURE_SKEW else ""
        print(f"      {column:14s} max |P(attack|value) - 0.5| = {skew:.3f}{flag}")
        if skew > worst_skew:
            worst_name, worst_skew = column, skew
    report.add(
        "no single header predicts the label",
        worst_skew <= MAX_SINGLE_FEATURE_SKEW,
        f"worst is {worst_name!r} at {worst_skew:.3f} (limit {MAX_SINGLE_FEATURE_SKEW})",
    )

    # The question is not "how often does a character appear" but "how well does
    # a one-character rule work". v1's benign set had 0.00% raw apostrophes, so
    # "contains ' -> attack" was right 100% of the time and the model needed to
    # learn nothing else. Precision of that rule is the quantity that matters.
    surface = build_surface(df)
    benign = surface[y == 0]
    attack = surface[y == 1]
    n_benign, n_attack = max(len(benign), 1), max(len(attack), 1)
    print(f"      {'feature':24s} {'benign':>9s} {'attack':>9s} {'rule prec':>10s}")
    precisions = {}
    for label, pattern, regex in [
        ("raw apostrophe", "'", False),
        ("raw parenthesis", "(", False),
        ("angle bracket", r"[<>]", True),
        ("SQL keyword", r"(?i)\b(select|union|drop|insert)\b", True),
        ("percent escape", r"%[0-9a-fA-F]{2}", True),
        ("html entity", r"&(#x?[0-9a-fA-F]+|lt|gt|quot);", True),
        ("backslash escape", r"\\[ux][0-9a-fA-F]{2}", True),
    ]:
        b_rate = benign.str.contains(pattern, regex=regex).mean()
        a_rate = attack.str.contains(pattern, regex=regex).mean()
        hits_b, hits_a = b_rate * n_benign, a_rate * n_attack
        precision = hits_a / (hits_a + hits_b) if (hits_a + hits_b) else 0.0
        precisions[label] = precision
        flag = "  <-- one-sided" if precision > MAX_RULE_PRECISION else ""
        print(f"      {label:24s} {b_rate * 100:8.2f}% {a_rate * 100:8.2f}% "
              f"{precision * 100:9.1f}%{flag}")

    worst_feature = max(precisions, key=precisions.get)
    report.add(
        "no single character rule separates the classes",
        precisions[worst_feature] <= MAX_RULE_PRECISION,
        f"best one-feature rule is {worst_feature!r} at {precisions[worst_feature] * 100:.1f}% "
        f"precision (limit {MAX_RULE_PRECISION * 100:.0f}%)",
    )

    apostrophe_benign = benign.str.contains("'", regex=False).mean()
    report.add(
        "benign carries raw special characters",
        apostrophe_benign >= MIN_BENIGN_RAW_SPECIAL,
        f"benign rows with a raw apostrophe = {apostrophe_benign * 100:.2f}% "
        f"(need >= {MIN_BENIGN_RAW_SPECIAL * 100:.0f}%); v1 sat at 0.00%",
    )


def check_payload_validity(df: pd.DataFrame, report: Report) -> None:
    print("\n5. Payload correctness")
    if "obfuscation_techniques" not in df.columns:
        return
    techniques = df["obfuscation_techniques"].fillna("")
    hex_rows = df[techniques.str.contains("hex_encoding")]
    if hex_rows.empty:
        print("      no hex_encoding rows, skipping")
        return
    surface = build_surface(hex_rows)
    # Require word boundaries. A random session token like "zTi6fMt0x1T1Yjk"
    # contains the substring "0x1" without being a hex literal at all.
    pattern = re.compile(r"(?<![0-9A-Za-z_])0x([0-9a-fA-F]+)(?![0-9A-Za-z_])")
    bad = 0
    total = 0
    for text in surface:
        for match in pattern.finditer(str(text)):
            total += 1
            if len(match.group(1)) % 2 != 0:
                bad += 1
    report.add(
        "hex literals are byte-aligned",
        bad == 0,
        f"{bad}/{total} hex literals have an odd digit count "
        "(an odd literal cannot be parsed by any DBMS)",
    )


def check_trivial_baseline(df: pd.DataFrame, report: Report) -> None:
    print("\n6. Trivial baseline (char 2-4 gram logistic regression)")
    if "split" not in df.columns:
        report.add("trivial baseline", False, "no split column to train on")
        return
    surface = build_surface(df)
    y = (df["classification"] == "anomalous").astype(int)
    split = df["split"].astype(str).str.strip().str.lower()

    train_mask = split == "train"
    if not train_mask.any():
        report.add("trivial baseline", False, "no train split")
        return

    vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(2, 4),
                                 max_features=30000, lowercase=False)
    X_train = vectorizer.fit_transform(surface[train_mask])
    model = LogisticRegression(max_iter=1000)
    model.fit(X_train, y[train_mask])

    worst = 0.0
    recalls: dict[str, float] = {}
    for name in present_test_splits(df):
        mask = split == name
        if not mask.any():
            continue
        predicted = model.predict(vectorizer.transform(surface[mask]))
        accuracy = accuracy_score(y[mask], predicted)
        recall = recall_score(y[mask], predicted, zero_division=0)
        recalls[name] = recall
        print(f"      {name:24s} accuracy={accuracy * 100:6.2f}%  "
              f"attack_recall={recall * 100:6.2f}%")
        worst = max(worst, accuracy)

    report.add(
        "dataset is not trivially separable",
        worst <= MAX_TRIVIAL_ACCURACY,
        f"best trivial accuracy {worst * 100:.2f}% (limit {MAX_TRIVIAL_ACCURACY * 100:.0f}%); "
        "see the note below if this fails on the in-distribution split only",
    )

    # The check above asks "is detection hard?". For an architecture comparison
    # the operative question is different: "does the dataset separate a model
    # that generalises from one that memorises?" That shows up as a drop between
    # the in-distribution split and the held-out ones. A flat profile means the
    # hold-out design is decorative, however low the absolute numbers are.
    baseline = recalls.get("test")
    unseen = {k: v for k, v in recalls.items() if k.startswith("test_unseen")}
    if baseline is not None and unseen:
        hardest, lowest = min(unseen.items(), key=lambda kv: kv[1])
        gap = (baseline - lowest) * 100
        print(f"      degradation: test {baseline * 100:.2f}% -> "
              f"{hardest} {lowest * 100:.2f}%  (gap {gap:.2f} points)")
        report.add(
            "held-out splits are measurably harder",
            gap >= MIN_DEGRADATION_POINTS,
            f"trivial-baseline recall drops {gap:.2f} points from 'test' to {hardest!r} "
            f"(need >= {MIN_DEGRADATION_POINTS:.1f}); a flat profile means the hold-out "
            "design does not bite",
        )


def check_cross_source_overlap(df: pd.DataFrame, kaggle_path: Path, report: Report) -> None:
    print("\n7. Overlap with the Kaggle source (leaks when both are used together)")
    if not kaggle_path.exists():
        print(f"      skipped, {kaggle_path.name} not found")
        return
    kaggle = pd.read_csv(kaggle_path, usecols=["Sentence"])
    kaggle_canonical = set(kaggle["Sentence"].dropna().astype(str).map(canonical))

    attacks = df[df["classification"] == "anomalous"].copy()
    if "seed_id" in df.columns and attacks["seed_id"].notna().any():
        seed_payloads = load_seed_payloads()
        payloads = attacks["seed_id"].map(seed_payloads)
    else:
        agents = benign_user_agents(df)
        payloads = attacks.apply(extract_payload, axis=1, known_agents=agents)
    usable = payloads.dropna()
    if usable.empty:
        return
    overlap = usable.map(canonical).isin(kaggle_canonical).mean()
    report.add(
        "attack payloads are distinct from Kaggle",
        overlap <= MAX_CROSS_SOURCE_OVERLAP,
        f"{overlap * 100:.1f}% of attack payloads also exist in Kaggle "
        f"(limit {MAX_CROSS_SOURCE_OVERLAP * 100:.0f}%)",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Measure whether the dataset can rank detectors.")
    parser.add_argument("--dataset", default=str(DEFAULT_DATASET))
    parser.add_argument("--kaggle", default=str(DEFAULT_KAGGLE))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    dataset_path = Path(args.dataset)
    print(f"Quality gate for: {dataset_path}")
    df = pd.read_csv(dataset_path, low_memory=False)

    report = Report()
    check_composition(df, report)
    check_seed_diversity(df, report)
    check_technique_holdout(df, report)
    check_shortcuts(df, report)
    check_payload_validity(df, report)
    check_trivial_baseline(df, report)
    check_cross_source_overlap(df, Path(args.kaggle), report)

    passed = sum(1 for _, ok, _ in report.checks if ok)
    print(f"\n{'=' * 70}")
    print(f"VERDICT: {passed}/{len(report.checks)} checks passed")
    if not report.verdict():
        print("The dataset can still be used, but a high model score on it is not evidence")
        print("of a good detector until the failing checks are addressed.")
    sys.exit(0 if report.verdict() else 1)


if __name__ == "__main__":
    main()
