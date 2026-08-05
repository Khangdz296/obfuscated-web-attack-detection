#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Manual evasion probe: payloads the generator never produced.

Why this exists
---------------
Aggregate metrics hide narrow blind spots. The dataset reports 99.98% recall on
its own test split, yet deleting a single space turns

    /login?username=admin'; select user from users--   -> 92.72% attack
    /login?username=admin';select user from users--    ->  0.65% attack

That evasion was found by typing into the web app, not by any metric. This
script automates that kind of probing: every payload here is written by hand and
checked against the seed bank, so nothing in it was ever seen during training.

Payloads are grouped by the evasion idea they test. A group where several
payloads slip through points at a technique missing from the generator's
taxonomy, which is the actionable output.

    python analysis/probe_evasion.py
    python analysis/probe_evasion.py --api http://127.0.0.1:8000/api/predict
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# ---------------------------------------------------------------------------
# Probe set. (group, payload, is_attack)
#
# Attacks are real: each one executes against a naive application. Benign
# entries are legitimate traffic that merely looks dangerous -- they check the
# opposite failure, crying wolf.
# ---------------------------------------------------------------------------
PROBES: list[tuple[str, str, bool]] = [
    # --- the evasion found by hand: delete the separator -------------------
    ("separator_removal", "/login?username=admin';select user from users--", True),
    ("separator_removal", "/item?id=1;DROP TABLE users--", True),
    ("separator_removal", "/search?q=1'OR'1'='1", True),
    ("separator_removal", "/view?id=1'AND'1'='1", True),
    ("separator_removal", "/p?id=-1'UNION SELECT 1,2,3--", True),

    # --- comment used as the separator instead of a space ------------------
    ("comment_separator", "/p?id=1/**/UNION/**/SELECT/**/NULL,NULL--", True),
    ("comment_separator", "/p?id=1/*!50000UNION*//*!50000SELECT*/1,2--", True),
    ("comment_separator", "/p?id=1'/**/OR/**/'1'='1", True),
    ("comment_separator", "/p?id=1--+-", True),

    # --- newline / tab / vertical tab as the separator ---------------------
    ("newline_separator", "/p?id=1%0AUNION%0ASELECT%0A1,2--", True),
    ("newline_separator", "/p?id=1%0BOR%0B1=1--", True),
    ("newline_separator", "/p?id=1%A0OR%A01=1--", True),

    # --- alternative operators -------------------------------------------
    ("operator_swap", "/p?id=1'||'1'='1", True),
    ("operator_swap", "/p?id=1'%26%26'1'='1", True),
    ("operator_swap", "/p?id=1 RLIKE (SELECT 1)--", True),
    ("operator_swap", "/p?id=1 XOR 1=1--", True),
    ("operator_swap", "/p?id=1'!='2'--", True),

    # --- arithmetic / scientific notation ---------------------------------
    ("numeric_trick", "/p?id=1e0UNION SELECT 1,2--", True),
    ("numeric_trick", "/p?id=1.0OR 1=1--", True),
    ("numeric_trick", "/p?id=0x31 OR 1=1--", True),

    # --- XSS: no quotes, no spaces ----------------------------------------
    ("xss_no_quote", "/s?q=<img/src=x/onerror=alert(1)>", True),
    ("xss_no_quote", "/s?q=<svg/onload=alert(1)>", True),
    ("xss_no_quote", "/s?q=<img%0Asrc=x%0Aonerror=alert(1)>", True),
    ("xss_no_quote", "/s?q=<img src=x onerror=alert`1`>", True),

    # --- XSS: rarely used HTML5 handlers ----------------------------------
    ("xss_rare_handler", "/s?q=<body onbeforescriptexecute=alert(1)>", True),
    ("xss_rare_handler", "/s?q=<dialog open onclose=alert(1)>", True),
    ("xss_rare_handler", "/s?q=<input onauxclick=alert(1)>", True),
    ("xss_rare_handler", "/s?q=<div onpointerrawupdate=alert(1)>", True),
    ("xss_rare_handler", "/s?q=<video onloadedmetadata=alert(1) src=x>", True),

    # --- XSS: escaping out of an existing attribute -----------------------
    ("xss_breakout", "/s?q=x\" autofocus onfocus=alert(1) x=\"", True),
    ("xss_breakout", "/s?q=x'-alert(1)-'", True),
    ("xss_breakout", "/s?q=</script><script>alert(1)</script>", True),
    ("xss_breakout", "/s?q=\"><svg onload=alert(1)>", True),

    # --- XSS: DOM sinks ---------------------------------------------------
    ("xss_dom", "/page#<img src=x onerror=alert(1)>", True),
    ("xss_dom", "/s?q=javascript:eval('ale'+'rt(1)')", True),
    ("xss_dom", "/s?q=<iframe srcdoc=\"&lt;script&gt;alert(1)&lt;/script&gt;\">", True),

    # --- path traversal / command injection (outside the taxonomy) --------
    ("other_attack", "/download?file=../../../../etc/passwd", True),
    ("other_attack", "/ping?host=127.0.0.1;cat /etc/passwd", True),
    ("other_attack", "/api?tpl={{7*7}}", True),

    # --- benign that looks dangerous --------------------------------------
    ("benign_hard", "/search?q=O'Brien and sons", False),
    ("benign_hard", "/search?q=select the best laptop under 500", False),
    ("benign_hard", "/api/v1/notes?text=SELECT name FROM products WHERE id = ?", False),
    ("benign_hard", "/comment?body=3 < 5 and 7 > 2, right?", False),
    ("benign_hard", "/article?body=<p>Xin chào <b>bạn</b></p>", False),
    ("benign_hard", "/upload?file=report(final)_v2.xlsx", False),
    ("benign_hard", "/search?q=union station hotel booking", False),
    ("benign_hard", "/js?src=var s=String.fromCharCode(72,101);console.log(s);", False),
    ("benign_hard", "/note?t=we use --strict mode in the compiler", False),
    ("benign_hard", "/comment?body=don't forget the &lt;br&gt; tag", False),

    # --- plainly benign ----------------------------------------------------
    ("benign_plain", "/products?category=electronics&page=3&limit=20", False),
    ("benign_plain", "/api/v1/orders/48213", False),
    ("benign_plain", "/login", False),
    ("benign_plain", "/cart/add?product_id=8320&quantity=2", False),
    ("benign_plain", "/search?q=running%20shoes%20size%2042", False),
]


def check_unseen() -> None:
    """Confirm no probe was copied from the seed bank."""
    try:
        sys.path.insert(0, str(PROJECT_ROOT / "dataset_builder"))
        from seeds_sqli import build_sqli_seeds
        from seeds_xss import build_xss_seeds
    except ImportError:
        print("  (không import được kho seed, bỏ qua kiểm tra trùng lặp)")
        return

    import re

    def canonical(text: str) -> str:
        return re.sub(r"[^a-z0-9]", "", text.lower())

    seeds = {canonical(s["payload"]) for s in build_sqli_seeds() + build_xss_seeds()}
    overlaps = [p for _, p, is_attack in PROBES
                if is_attack and canonical(p.split("?", 1)[-1]) in seeds]
    if overlaps:
        print(f"  CẢNH BÁO: {len(overlaps)} probe trùng kho seed: {overlaps[:3]}")
    else:
        attacks = sum(1 for _, _, a in PROBES if a)
        print(f"  {attacks} payload tấn công, không cái nào có trong kho seed.")


def to_envelope(raw: str) -> str:
    """Wrap a raw URL/payload the way training data was wrapped."""
    from preprocessing import preprocess_data as prep

    path, _, query = raw.partition("?")
    return prep.serialize_http_request(method="GET", path=path, query=query)


def predict_local(payloads: list[str], artifact_dir: Path, source: str,
                  max_len: int, threshold: float) -> list[float]:
    import pickle

    import numpy as np
    import tensorflow as tf
    from tensorflow.keras.preprocessing.sequence import pad_sequences

    model_dir = artifact_dir / "by_dataset" / source
    if not (model_dir / "best_hybrid_cnn_lstm.keras").exists():
        model_dir = artifact_dir
    model = tf.keras.models.load_model(model_dir / "best_hybrid_cnn_lstm.keras",
                                       compile=False)
    with (model_dir / "tokenizer.pkl").open("rb") as handle:
        tokenizer = pickle.load(handle)

    texts = [to_envelope(p) for p in payloads]
    vectors = pad_sequences(tokenizer.texts_to_sequences(texts),
                            maxlen=max_len, padding="post", truncating="post")
    return model.predict(vectors, batch_size=64, verbose=0).ravel().tolist()


def predict_api(payloads: list[str], api: str, threshold: float) -> list[float]:
    import urllib.request

    out = []
    for payload in payloads:
        body = json.dumps({"payload": payload, "threshold": threshold}).encode()
        request = urllib.request.Request(
            api, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=20) as response:
            data = json.loads(response.read())
        out.append(float(data["result"]["attack_probability"]))
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Probe the detector with unseen payloads.")
    parser.add_argument("--artifact-dir",
                        default=str(
                            PROJECT_ROOT / "cnn_lstm" / "artifacts_cnn_lstm_by_dataset"
                        ))
    parser.add_argument("--source", default="obfu_http")
    parser.add_argument("--max-len", type=int, default=768)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--api", default=None,
                        help="Gọi webapp thay vì nạp model trực tiếp.")
    parser.add_argument("--out", default=None, help="Ghi kết quả ra CSV.")
    args = parser.parse_args()

    print("Kiểm tra probe có trùng kho seed không:")
    check_unseen()
    print()

    payloads = [p for _, p, _ in PROBES]
    if args.api:
        print(f"Gọi API: {args.api}")
        probabilities = predict_api(payloads, args.api, args.threshold)
    else:
        probabilities = predict_local(payloads, Path(args.artifact_dir),
                                      args.source, args.max_len, args.threshold)

    import pandas as pd

    frame = pd.DataFrame({
        "group": [g for g, _, _ in PROBES],
        "payload": payloads,
        "is_attack": [a for _, _, a in PROBES],
        "attack_prob": [round(p, 4) for p in probabilities],
    })
    frame["predicted"] = frame["attack_prob"] >= args.threshold
    frame["correct"] = frame["predicted"] == frame["is_attack"]

    print("=" * 78)
    print("KẾT QUẢ THEO NHÓM")
    print("=" * 78)
    summary = (frame.groupby("group")
               .agg(n=("correct", "size"), dung=("correct", "sum"),
                    prob_tb=("attack_prob", "mean"))
               .assign(ty_le=lambda d: (d["dung"] / d["n"] * 100).round(1))
               .sort_values("ty_le"))
    print(summary.to_string())

    missed = frame[(~frame["correct"]) & (frame["is_attack"])]
    print(f"\n{'=' * 78}\nTẤN CÔNG BỊ BỎ SÓT ({len(missed)}/{int(frame.is_attack.sum())})")
    print("=" * 78)
    for _, row in missed.sort_values("attack_prob").iterrows():
        print(f"  {row.attack_prob:6.2%}  [{row.group:18s}] {row.payload[:70]}")

    false_alarms = frame[(~frame["correct"]) & (~frame["is_attack"])]
    print(f"\n{'=' * 78}\nBÁO ĐỘNG GIẢ ({len(false_alarms)}/{int((~frame.is_attack).sum())})")
    print("=" * 78)
    for _, row in false_alarms.sort_values("attack_prob", ascending=False).iterrows():
        print(f"  {row.attack_prob:6.2%}  [{row.group:18s}] {row.payload[:70]}")

    attack_recall = frame[frame.is_attack]["correct"].mean() * 100
    benign_ok = frame[~frame.is_attack]["correct"].mean() * 100
    print(f"\n{'=' * 78}")
    print(f"Recall trên payload chưa từng thấy : {attack_recall:.1f}%")
    print(f"Đúng trên benign                   : {benign_ok:.1f}%")
    print("So sánh: recall trên tập test của chính dataset là 99,98%")

    if args.out:
        frame.to_csv(args.out, index=False, encoding="utf-8")
        print(f"\nĐã ghi: {args.out}")


if __name__ == "__main__":
    main()
