#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Obfuscated SQLi/XSS HTTP dataset generator, version 2.

What changed from v1 and why
----------------------------
v1 scored 0/7 on the quality gate. A char n-gram logistic regression reached
99.96% on it, which means the dataset could not rank one architecture above
another -- the whole point of the research question. Five root causes, five
fixes:

1. 59 seeds over 50k attack rows (847 rows/seed), and 100% of test seeds also
   appeared in train.
   -> seed banks in seeds_sqli.py / seeds_xss.py (~1100 lexically distinct
      seeds), plus a seed_id column and a POOL_A / POOL_B holdout.

2. Attack rows were built by their own code path, so method, content_type and
   host leaked the label (DELETE was 100% benign, multipart was 100% benign).
   -> attacks are now built by generating a benign request first and injecting
      the payload into it. Structural distributions are identical by
      construction, not by tuning.

3. Benign values went through quote(), attack payloads did not. Raw apostrophe
   was 0.00% benign / 34.40% attack -- a perfect one-sided rule.
   -> maybe_encode() applies the same encoding probability to both classes, and
      a hard-negative flow deliberately puts raw quotes, angle brackets and SQL
      words into legitimate traffic.

4. test_heldout contained no benign rows, so only recall was measurable.
   -> four test splits, every one of them containing both classes.

5. char_encoding and hex_encoding rewrote text that was not a string literal,
   producing SQL that cannot parse.
   -> literal detection is restricted to word-like content and the result is
      validated.

Usage
-----
    python dataset_builder/generate_obfu_dataset_v2.py --scale pilot
    python dataset_builder/generate_obfu_dataset_v2.py --scale full
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import itertools
import json
import random
import re
import string
import uuid
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import quote

from seeds_benign import build_benign_banks
from seeds_sqli import build_sqli_seeds
from seeds_xss import build_xss_seeds

# Legitimate SQL / markup / JavaScript / prose, generated with the same kind of
# vocabulary matrix as the attack seeds. Without this the benign class is a few
# dozen fixed strings and a char n-gram model simply memorises them.
BENIGN_BANKS = build_benign_banks(SEED := 1337)

BUILDER_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BUILDER_DIR.parent
KAGGLE_PATH = PROJECT_ROOT / "DataSet" / "SQLInjection_XSS_MixDataset.1.0.0.csv"

# Same probability for both classes, so encoding cannot predict the label.
ENCODE_RATIO = 0.50
PLAIN_RATIO = 0.12
SECOND_ORDER_RATIO = 0.08
TIME_RATIO = 0.10
HARD_NEGATIVE_RATIO = 0.55

POOL_B_FRACTION = 0.20   # seeds reserved for unseen-seed tests
SET_2_FRACTION = 0.15    # technique combos reserved for unseen-technique tests

rnd = random.Random(SEED)

# ---------------------------------------------------------------------------
# request vocabulary
# ---------------------------------------------------------------------------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 OPR/112.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 12; moto g power) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/125.0.0.0 Mobile/15E148 Safari/604.1",
    "PostmanRuntime/7.37.3", "curl/8.5.0", "python-requests/2.31.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "okhttp/4.12.0", "Java/17.0.10",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Linux; Android 14; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/124.0.0.0",
]

HOSTS = [
    "shop.northwind-mart.com", "www.northwind-mart.com", "api.northwind-mart.com",
    "admin.northwind-mart.com", "store.acme-retail.io", "app.bluewave-shop.net",
    "www.bluewave-shop.net", "api.bluewave-shop.net", "portal.citymart.vn",
    "shop.citymart.vn", "checkout.acme-retail.io", "m.northwind-mart.com",
]

FIRST_NAMES = ["john", "mary", "david", "linh", "huy", "anna", "peter", "trang",
    "minh", "sara", "james", "olivia", "khang", "tuan", "emma", "daniel", "ngoc",
    "liam", "noah", "mia", "an", "binh", "chi", "dung", "giang", "ha", "khanh",
    "lan", "nam", "phuong", "quan", "son", "thao", "vy"]
LAST_NAMES = ["smith", "nguyen", "tran", "le", "pham", "brown", "wilson", "garcia",
    "vo", "do", "hoang", "bui", "dang", "ngo", "duong", "ly", "kim", "chen",
    "patel", "khan"]
SEARCH_TERMS = ["cheap laptop", "best headphones 2026", "gaming mouse",
    "office chair ergonomic", "usb c hub", "4k monitor", "wireless earbuds",
    "standing desk white", "mechanical keyboard brown switch", "iphone case clear",
    "running shoes size 42", "yoga mat non slip", "coffee grinder", "áo thun nam",
    "giày thể thao", "bàn phím cơ", "tai nghe bluetooth"]
CATEGORIES = ["electronics", "accessories", "home-office", "sports", "books",
    "fashion", "toys", "garden"]


def rand_hex(n: int) -> str:
    return "".join(rnd.choice("0123456789abcdef") for _ in range(n))


def rand_alnum(n: int) -> str:
    return "".join(rnd.choice(string.ascii_letters + string.digits) for _ in range(n))


def make_cookie(role: str | None = None, with_cart: bool = False) -> str:
    parts = []
    style = rnd.choice(["JSESSIONID", "PHPSESSID", "connect.sid", "sessionid",
                        "laravel_session"])
    if style == "JSESSIONID":
        parts.append(f"JSESSIONID={rand_hex(32).upper()}")
    elif style == "PHPSESSID":
        parts.append(f"PHPSESSID={rand_alnum(26)}")
    elif style == "connect.sid":
        parts.append(f"connect.sid=s%3A{rand_alnum(24)}.{rand_alnum(27)}")
    elif style == "sessionid":
        parts.append(f"sessionid={rand_alnum(32)}")
    else:
        parts.append(f"laravel_session={rand_alnum(40)}")
    if rnd.random() < 0.6:
        parts.append(f"csrftoken={rand_alnum(rnd.choice([32, 40]))}")
    if with_cart and rnd.random() < 0.7:
        parts.append(f"cart_id={rand_hex(16)}")
    if role:
        parts.append(f"role={role}")
    if rnd.random() < 0.4:
        parts.append(f"locale={rnd.choice(['en-US', 'vi-VN', 'en-GB', 'ja-JP'])}")
    rnd.shuffle(parts)
    return "; ".join(parts)


def maybe_encode(value: str) -> str:
    """Transport encoding applied with identical probability to both classes.

    v1 called quote() on every benign value and on no attack payload, which
    made "contains a raw apostrophe" a perfect attack detector. The point here
    is not that encoding is realistic -- it is that its probability must not
    depend on the label.
    """
    return quote(value, safe="") if rnd.random() < ENCODE_RATIO else value


def wire_hash(method: str, host: str, url: str, content: str,
              cookie: str = "", ua: str = "") -> str:
    return hashlib.sha1(
        f"{method}|{host}|{url}|{content}|{cookie}|{ua}".encode("utf-8", "replace")
    ).hexdigest()


def blank_row() -> dict:
    return {
        "request_id": str(uuid.UUID(int=rnd.getrandbits(128))),
        "method": "", "url": "", "host": "", "user_agent": "", "cookie": "",
        "content_type": "", "content": "", "classification": "",
        "attack_category": "", "attack_technique": "", "dbms": "",
        "seed_id": "", "context_location": "", "obfuscation_techniques": "",
        "assigned_combo": "", "obfuscation_type": "", "technique_count": 0,
        "difficulty_level": "", "is_second_order": False, "is_time_based": False,
        "linked_request_id": "", "benign_kind": "", "benign_obfuscation": "",
        "source": "", "split": "",
    }


# ---------------------------------------------------------------------------
# BENIGN: ordinary flows
# ---------------------------------------------------------------------------
def benign_login() -> dict:
    host = rnd.choice([h for h in HOSTS if not h.startswith("api.")])
    if rnd.random() < 0.35:
        return dict(method="GET", host=host, url="/login", content_type="", content="")
    # Real user data is full of apostrophes. v1 URL-encoded every one of them,
    # which is how "contains a raw quote" became a perfect attack signal.
    if rnd.random() < 0.55:
        user = rnd.choice(APOSTROPHE_NAMES)
    else:
        user = f"{rnd.choice(FIRST_NAMES)}.{rnd.choice(LAST_NAMES)}"
    body = (f"username={maybe_encode(user)}"
            f"&password={maybe_encode(rand_alnum(rnd.randint(8, 16)))}"
            f"&remember={rnd.choice(['on', 'off', 'true'])}")
    return dict(method="POST", host=host, url="/login",
                content_type="application/x-www-form-urlencoded", content=body)


def benign_search() -> dict:
    host = rnd.choice([h for h in HOSTS if not h.startswith("admin.")])
    params = [f"q={maybe_encode(rnd.choice(SEARCH_TERMS))}"]
    if rnd.random() < 0.6:
        params.append(f"category={rnd.choice(CATEGORIES)}")
    if rnd.random() < 0.5:
        params.append(f"sort={rnd.choice(['price_asc', 'price_desc', 'relevance', 'newest'])}")
    if rnd.random() < 0.5:
        params.append(f"page={rnd.randint(1, 25)}")
    rnd.shuffle(params)
    return dict(method="GET", host=host, url="/search?" + "&".join(params),
                content_type="", content="")


def benign_rest_api() -> dict:
    host = rnd.choice([h for h in HOSTS if h.startswith("api.")] or HOSTS)
    method = rnd.choice(["GET", "POST", "PUT", "PATCH", "DELETE"])
    resource = rnd.choice(["users", "orders", "products", "reviews", "addresses",
                           "payments", "wishlists"])
    rid = rnd.randint(1, 99999)
    if method in ("GET", "DELETE"):
        return dict(method=method, host=host, url=f"/api/v1/{resource}/{rid}",
                    content_type="", content="")
    url = f"/api/v1/{resource}" + (f"/{rid}" if method in ("PUT", "PATCH") else "")
    name = (rnd.choice(APOSTROPHE_NAMES) if rnd.random() < 0.55
            else f"{rnd.choice(FIRST_NAMES)} {rnd.choice(LAST_NAMES)}")
    payload = {
        "name": name,
        "email": f"{rnd.choice(FIRST_NAMES)}@example.com",
        "quantity": rnd.randint(1, 10),
        "note": rnd.choice(["", "gift wrap please", "leave at door",
                            "it's for a gift", "don't ring the bell",
                            rnd.choice(BENIGN_BANKS["text"])]),
    }
    keys = list(payload)
    rnd.shuffle(keys)
    return dict(method=method, host=host, url=url, content_type="application/json",
                content=json.dumps({k: payload[k] for k in keys}, ensure_ascii=False))


def benign_cart() -> dict:
    host = rnd.choice([h for h in HOSTS if not h.startswith("admin.")])
    action = rnd.choice(["add", "update", "remove", "view", "checkout"])
    if action == "add":
        body = (f"product_id={rnd.randint(1000, 9999)}&quantity={rnd.randint(1, 5)}"
                f"&variant={rnd.choice(['s', 'm', 'l', 'xl', 'default'])}")
        return dict(method="POST", host=host, url="/cart/add",
                    content_type="application/x-www-form-urlencoded", content=body)
    if action == "update":
        return dict(method="PUT", host=host, url="/cart/update",
                    content_type="application/json",
                    content=json.dumps({"item_id": rnd.randint(1, 50),
                                        "quantity": rnd.randint(1, 9)}))
    if action == "remove":
        return dict(method="DELETE", host=host, url=f"/cart/item/{rnd.randint(1, 50)}",
                    content_type="", content="")
    if action == "checkout":
        body = (f"payment={rnd.choice(['card', 'paypal', 'cod', 'applepay'])}"
                f"&address_id={rnd.randint(1, 20)}"
                f"&coupon={rnd.choice(['', 'SAVE10', 'FREESHIP', 'WELCOME'])}")
        return dict(method="POST", host=host, url="/checkout",
                    content_type="application/x-www-form-urlencoded", content=body)
    return dict(method="GET", host=host, url="/cart", content_type="", content="")


def benign_pagination() -> dict:
    host = rnd.choice(HOSTS)
    category = rnd.choice(CATEGORIES)
    if rnd.random() < 0.5:
        url = (f"/products?category={category}&page={rnd.randint(1, 100)}"
               f"&limit={rnd.choice([10, 20, 25, 50])}")
    else:
        url = (f"/products?category={category}&offset={rnd.randint(0, 2000)}"
               f"&limit={rnd.choice([10, 20, 25, 50])}")
    return dict(method="GET", host=host, url=url, content_type="", content="")


def benign_upload() -> dict:
    host = rnd.choice(HOSTS)
    boundary = "----WebKitFormBoundary" + rand_alnum(16)
    fname = (rnd.choice(["invoice", "photo", "avatar", "report", "resume", "receipt"])
             + rnd.choice([".pdf", ".png", ".jpg", ".docx", ".csv"]))
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
            f"filename=\"{fname}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            f"<binary {rnd.randint(1000, 900000)} bytes>\r\n--{boundary}--")
    return dict(method="POST", host=host, url="/upload",
                content_type=f"multipart/form-data; boundary={boundary}", content=body)


def benign_admin() -> dict:
    host = rnd.choice([h for h in HOSTS if h.startswith("admin.")] or HOSTS)
    endpoint = rnd.choice(["/admin/users", "/admin/orders", "/admin/settings",
                           "/admin/reports", "/admin/inventory"])
    if rnd.random() < 0.5:
        return dict(method="GET", host=host, url=endpoint + f"?page={rnd.randint(1, 10)}",
                    content_type="", content="", _role="admin")
    body = (f"csrf_token={rand_alnum(40)}"
            f"&action={rnd.choice(['update', 'disable', 'enable', 'export'])}"
            f"&target_id={rnd.randint(1, 999)}")
    return dict(method="POST", host=host, url=endpoint,
                content_type="application/x-www-form-urlencoded", content=body,
                _role="admin")


# ---------------------------------------------------------------------------
# BENIGN: hard negatives
# ---------------------------------------------------------------------------
# Legitimate traffic that shares surface features with attacks. Without these
# the model never has to look past a single character.
APOSTROPHE_NAMES = ["o'brien", "d'angelo", "o'neill", "d'souza", "o'connor",
    "l'estrange", "dell'acqua", "o'hara", "d'artagnan", "o'sullivan"]

SQL_WORD_QUERIES = [
    "select the best laptop for students", "union station hotel booking",
    "order by date not price", "drop shipping guide 2026",
    "insert coin arcade machine", "delete duplicate photos app",
    "where to buy cheap monitors", "update my shipping address",
    "table and chair set", "having trouble with checkout",
    "group by category filter", "join our newsletter",
    "create table saw stand", "alter ego t-shirt", "exec chef knife set",
    "truncate hedge trimmer", "grant park picnic blanket",
    "count to ten toy", "declare independence poster",
]

ANGLE_TEXTS = [
    "3 < 5 and 7 > 2", "<3 this product", "price < 500 please",
    "size M <-> L", "rating >4 stars only", "a<b<c ordering",
    "temperature <0 degrees", "if x>y then swap", "use <br> for line break",
    "the <b> tag is bold", "compare 10>9", "arrow -> right",
]

HTML_CONTENT = BENIGN_BANKS["html"]
JS_SNIPPETS = BENIGN_BANKS["js"]
SQL_IN_NOTES = BENIGN_BANKS["sql"]


ESCAPED_DISCUSSION = BENIGN_BANKS["text"]

# Anything legitimate is fair game for the obfuscation pipeline: encoding a
# search term or a product description does not make it an attack.
BENIGN_OBFUSCATABLE = (BENIGN_BANKS["text"] + BENIGN_BANKS["html"]
                       + BENIGN_BANKS["sql"] + SEARCH_TERMS
                       + ["o'brien & sons ltd", "3 < 5 and 7 > 2",
                          "price (final) = 250", "user's manual v2",
                          "50% off today", "invoice (Q1) 2026"])


def obfuscate_benign_value(value: str) -> tuple[str, str]:
    """Run legitimate content through the *same* obfuscation transforms.

    This is the fix for the deepest shortcut in v1: every %XX, &#x3c; and \\u003c
    in the dataset belonged to an attack, so "looks encoded" was a free answer.
    Encoding a search term does not make it malicious, and once both classes
    carry the same artefacts the label has to come from what the payload does.
    """
    techniques = rnd.sample(
        ["case_variation", "html_entity", "js_encoding", "unicode_escape",
         "url_encoding", "whitespace_variation", "comment_html"],
        k=rnd.randint(1, 2))
    applied = []
    text = value
    for technique in techniques:
        if technique == "case_variation":
            text, ok = t_xss_case(text)
        elif technique == "html_entity":
            text, ok = t_xss_html_entity(text)
        elif technique == "js_encoding":
            text, ok = t_xss_js_hex(text)
        elif technique == "unicode_escape":
            text, ok = t_xss_unicode(text)
        elif technique == "url_encoding":
            text, ok = t_sqli_urlencode(text)
        elif technique == "whitespace_variation":
            text, ok = t_xss_whitespace(text)
        else:
            text, ok = (text.replace(" ", "/**/", 1), " " in text)
        if ok:
            applied.append(technique)
    return text, "|".join(sorted(applied))


def benign_hard_negative() -> dict:
    """Legitimate requests carrying attack-shaped surface features."""
    kind = rnd.choices(
        ["apostrophe_name", "sql_word_search", "angle_text", "html_content",
         "js_snippet", "sql_in_note", "double_encoded", "math_expression",
         "path_special", "quoted_json", "obfuscated_benign", "escaped_discussion"],
        weights=[0.14, 0.09, 0.09, 0.07, 0.04, 0.07, 0.03, 0.04,
                 0.04, 0.09, 0.20, 0.10],
        k=1)[0]
    host = rnd.choice(HOSTS)

    if kind == "obfuscated_benign":
        value, applied = obfuscate_benign_value(rnd.choice(BENIGN_OBFUSCATABLE))
        carrier = rnd.random()
        if carrier < 0.45:
            row = dict(method="GET", host=host, url=f"/search?q={value}&page={rnd.randint(1, 9)}",
                       content_type="", content="")
        elif carrier < 0.75:
            row = dict(method="POST", host=host, url="/feedback",
                       content_type="application/x-www-form-urlencoded",
                       content=f"comment={value}&rating={rnd.randint(1, 5)}")
        else:
            row = dict(method=rnd.choice(["POST", "PUT"]), host=host,
                       url="/api/v1/articles", content_type="application/json",
                       content=json.dumps({"title": value, "draft": True},
                                          ensure_ascii=False))
        row["_hard_kind"] = kind
        row["_benign_obfuscation"] = applied
        return row

    if kind == "escaped_discussion":
        text = rnd.choice(ESCAPED_DISCUSSION)
        if rnd.random() < 0.5:
            row = dict(method="POST", host=host, url="/api/v1/comments",
                       content_type="application/json",
                       content=json.dumps({"body": text, "thread": rnd.randint(1, 999)},
                                          ensure_ascii=False))
        else:
            row = dict(method="POST", host=host, url="/feedback",
                       content_type="application/x-www-form-urlencoded",
                       content=f"comment={maybe_encode(text)}&rating={rnd.randint(1, 5)}")
        row["_hard_kind"] = kind
        return row

    if kind == "apostrophe_name":
        name = rnd.choice(APOSTROPHE_NAMES)
        if rnd.random() < 0.5:
            body = json.dumps({"name": name, "city": rnd.choice(["Ha Noi", "Da Nang"])},
                              ensure_ascii=False)
            row = dict(method=rnd.choice(["POST", "PUT", "PATCH"]), host=host,
                       url="/api/v1/users", content_type="application/json", content=body)
        else:
            body = f"last_name={maybe_encode(name)}&first_name={rnd.choice(FIRST_NAMES)}"
            row = dict(method="POST", host=host, url="/profile/update",
                       content_type="application/x-www-form-urlencoded", content=body)

    elif kind == "sql_word_search":
        term = rnd.choice(SQL_WORD_QUERIES)
        row = dict(method="GET", host=host,
                   url=f"/search?q={maybe_encode(term)}&page={rnd.randint(1, 9)}",
                   content_type="", content="")

    elif kind == "angle_text":
        text = rnd.choice(ANGLE_TEXTS)
        body = f"comment={maybe_encode(text)}&rating={rnd.randint(1, 5)}"
        row = dict(method="POST", host=host, url="/feedback",
                   content_type="application/x-www-form-urlencoded", content=body)

    elif kind == "html_content":
        body = json.dumps({"body": rnd.choice(HTML_CONTENT),
                           "status": rnd.choice(["draft", "published"])},
                          ensure_ascii=False)
        row = dict(method=rnd.choice(["POST", "PUT"]), host=host,
                   url="/api/v1/articles", content_type="application/json", content=body)

    elif kind == "js_snippet":
        boundary = "----WebKitFormBoundary" + rand_alnum(16)
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
                f"filename=\"bundle.min.js\"\r\nContent-Type: application/javascript"
                f"\r\n\r\n{rnd.choice(JS_SNIPPETS)}\r\n--{boundary}--")
        row = dict(method="POST", host=host, url="/upload",
                   content_type=f"multipart/form-data; boundary={boundary}", content=body)

    elif kind == "sql_in_note":
        body = json.dumps({"note": rnd.choice(SQL_IN_NOTES),
                           "ticket": rnd.randint(100, 9999)}, ensure_ascii=False)
        row = dict(method="POST", host=host, url="/api/v1/tickets",
                   content_type="application/json", content=body)

    elif kind == "double_encoded":
        raw = rnd.choice(["<hello>", "a&b", "50% off", "c++ book", "r&d team"])
        row = dict(method="GET", host=host,
                   url=f"/search?q={quote(quote(raw, safe=''), safe='')}",
                   content_type="", content="")

    elif kind == "math_expression":
        expr = rnd.choice(["(a+b)*c > 100", "x = (y-1)/2", "total=(price*qty)+tax",
                           "f(x) = x^2 + 1", "avg(scores) >= 7.5"])
        body = f"formula={maybe_encode(expr)}&sheet={rnd.randint(1, 9)}"
        row = dict(method="POST", host=host, url="/api/v1/reports",
                   content_type="application/x-www-form-urlencoded", content=body)

    elif kind == "path_special":
        fname = rnd.choice(["ID-2024_(final).pdf", "report(v2).xlsx",
                            "photo's-album.zip", "notes[draft].txt",
                            "q1&q2-summary.csv"])
        row = dict(method=rnd.choice(["GET", "DELETE"]), host=host,
                   url=f"/api/v1/files/{maybe_encode(fname)}",
                   content_type="", content="")

    else:  # quoted_json
        body = json.dumps({
            "quote": rnd.choice(["it's fine", "don't worry", "we're open",
                                 "can't ship yet", "that's all"]),
            "author": f"{rnd.choice(FIRST_NAMES)} {rnd.choice(LAST_NAMES)}",
        }, ensure_ascii=False)
        row = dict(method="POST", host=host, url="/api/v1/reviews",
                   content_type="application/json", content=body)

    row["_hard_kind"] = kind
    return row


BENIGN_FLOWS = [benign_login, benign_search, benign_rest_api, benign_cart,
                benign_pagination, benign_upload, benign_admin]
BENIGN_WEIGHTS = [0.16, 0.20, 0.18, 0.18, 0.12, 0.06, 0.10]


def gen_benign_shape() -> dict:
    """One benign request shape, used directly or as an injection carrier."""
    if rnd.random() < HARD_NEGATIVE_RATIO:
        shape = benign_hard_negative()
        shape.setdefault("_role", None)
        return shape
    flow = rnd.choices(BENIGN_FLOWS, weights=BENIGN_WEIGHTS, k=1)[0]
    shape = flow()
    shape["_hard_kind"] = ""
    shape["_is_cart"] = flow is benign_cart
    return shape


def gen_benign() -> dict:
    shape = gen_benign_shape()
    row = blank_row()
    row.update(
        method=shape["method"], host=shape["host"], url=shape["url"],
        content_type=shape.get("content_type", ""), content=shape.get("content", ""),
        user_agent=rnd.choice(USER_AGENTS),
        cookie=make_cookie(role=shape.get("_role"), with_cart=shape.get("_is_cart", False)),
        classification="normal", attack_category="none",
        benign_kind=shape.get("_hard_kind") or "ordinary",
        benign_obfuscation=shape.get("_benign_obfuscation", ""),
        source="template",
    )
    return row


# ---------------------------------------------------------------------------
# OBFUSCATION TRANSFORMS
# ---------------------------------------------------------------------------
# A literal we are allowed to re-encode.
#
# v1 matched the first '...' pair in the string. On `') OR ('1'='1` that grabs
# `) OR (` -- the text *between* two literals, not a literal -- and rewriting it
# produces SQL no parser accepts. Restricting to value-like content (no spaces,
# no SQL words) is what keeps the rewritten payload executable.
SAFE_LITERAL = re.compile(r"'([A-Za-z0-9_@.\-]{1,32})'")

RESERVED_WORDS = {
    "or", "and", "not", "select", "union", "from", "where", "null", "true",
    "false", "like", "between", "exists", "waitfor", "delay", "sleep", "time",
    "order", "by", "group", "having", "insert", "update", "delete", "drop",
    "exec", "all", "distinct", "in", "is", "as", "on",
}


def _safe_literal(text: str):
    """First quoted literal that is a plain value and safe to rewrite in place."""
    for match in SAFE_LITERAL.finditer(text):
        content = match.group(1)
        if not content.strip():
            continue
        if content.lower() in RESERVED_WORDS:
            continue
        # A hex literal absorbs an adjacent hex digit, and a CHAR() expression
        # glued onto an identifier changes its meaning. Require a clean boundary.
        after = text[match.end():match.end() + 1]
        if after and (after.isalnum() or after == "_"):
            continue
        before = text[max(0, match.start() - 1):match.start()]
        if before and (before.isalnum() or before == "_"):
            continue
        return match
    return None


def t_sqli_hex(text: str, dbms: str = "mysql"):
    """Replace one string literal with an even-length hex literal."""
    match = _safe_literal(text)
    if not match:
        return text, False
    literal = match.group(1)
    if not literal.isascii():
        return text, False
    encoded = literal.encode()
    hex_body = encoded.hex()
    if len(hex_body) % 2 != 0:           # cannot happen, but the gate checks it
        return text, False
    try:
        bytes.fromhex(hex_body)
    except ValueError:
        return text, False
    if dbms == "oracle":
        replacement = f"utl_raw.cast_to_varchar2('{hex_body.upper()}')"
    elif dbms == "postgres":
        replacement = f"decode('{hex_body}','hex')"
    else:
        replacement = "0x" + hex_body
    return text[:match.start()] + replacement + text[match.end():], True


CONCAT_STYLE = {
    "mysql": ("CONCAT(", ",", ")", "CHAR"),
    "mssql": ("", "+", "", "CHAR"),
    "postgres": ("", "||", "", "CHR"),
    "oracle": ("", "||", "", "CHR"),
    "sqlite": ("", "||", "", "CHAR"),
    "generic": ("CONCAT(", ",", ")", "CHAR"),
}


def t_sqli_char(text: str, dbms: str = "mysql"):
    """Replace one string literal with a CHAR()/CHR() expression.

    v1 emitted `1CHAR(32)+CHAR(65)` -- a bare CHAR list glued onto a number with
    no operator, and always MSSQL's `+` regardless of dialect.
    """
    match = _safe_literal(text)
    if not match:
        return text, False
    literal = match.group(1)
    if not literal.isascii() or len(literal) > 24:
        return text, False
    prefix, joiner, suffix, fn = CONCAT_STYLE.get(dbms, CONCAT_STYLE["generic"])
    parts = joiner.join(f"{fn}({ord(c)})" for c in literal)
    replacement = f"{prefix}{parts}{suffix}"
    return text[:match.start()] + replacement + text[match.end():], True


def t_sqli_case(text: str):
    out, changed = [], False
    for ch in text:
        if ch.isalpha() and rnd.random() < 0.55:
            flipped = ch.upper() if ch.islower() else ch.lower()
            if flipped != ch:
                changed = True
            out.append(flipped)
        else:
            out.append(ch)
    return "".join(out), changed


def t_sqli_comment(text: str):
    changed = False
    for keyword in ["UNION", "SELECT", "FROM", "WHERE", "ORDER", "AND", "SLEEP"]:
        def repl(match):
            nonlocal changed
            changed = True
            word = match.group(0)
            middle = len(word) // 2
            return word[:middle] + rnd.choice(["/**/", "/*!*/", "/*x*/"]) + word[middle:]
        text = re.sub(keyword, repl, text, flags=re.IGNORECASE, count=1)
    if " " in text and rnd.random() < 0.5:
        text = text.replace(" ", "/**/", rnd.randint(1, 3))
        changed = True
    return text, changed


WS_TOKENS = ["%09", "%0a", "%0c", "%0d", "%20", "+", "%a0", "\t"]


def t_sqli_whitespace(text: str):
    if " " not in text:
        return text, False
    out, changed = [], False
    for ch in text:
        if ch == " " and rnd.random() < 0.85:
            out.append(rnd.choice(WS_TOKENS))
            changed = True
        else:
            out.append(ch)
    return "".join(out), changed


URL_SAFE_SKIP = set(string.ascii_letters + string.digits + "-_.~")


def t_sqli_urlencode(text: str, double: bool = False):
    out, index, changed = [], 0, False
    while index < len(text):
        ch = text[index]
        if (ch == "%" and index + 2 < len(text)
                and text[index + 1] in string.hexdigits
                and text[index + 2] in string.hexdigits):
            if double:
                out.append("%25")
                changed = True
                index += 1
                continue
            out.append(text[index:index + 3])
            index += 3
            continue
        if ch not in URL_SAFE_SKIP:
            encoded = "%%%02X" % ord(ch) if ord(ch) < 256 else quote(ch)
            if double:
                encoded = "%25" + encoded[1:]
            out.append(encoded)
            changed = True
        else:
            out.append(ch)
        index += 1
    return "".join(out), changed


KEYWORD_SWAPS = [
    (r"\bOR\b", ["||", "or", "Or"]),
    (r"\bAND\b", ["&&", "and", "AnD"]),
    (r"\bUNION\b", ["UNION ALL", "UNION DISTINCT"]),
    (r"=", ["=", " LIKE ", " BETWEEN "]),
    (r"\bSELECT\b", ["SELECT", "SELECT DISTINCT"]),
]


def t_sqli_keyword_swap(text: str):
    """Swap operators and keywords for equivalents a naive filter will miss."""
    changed = False
    for pattern, options in KEYWORD_SWAPS:
        if rnd.random() < 0.5:
            continue
        replacement = rnd.choice(options)
        new_text, count = re.subn(pattern, lambda _m: replacement, text,
                                  count=1, flags=re.IGNORECASE)
        if count and new_text != text:
            text, changed = new_text, True
    return text, changed


SQLI_PIPELINE = ["char_encoding", "hex_encoding", "keyword_swap",
                 "comment_injection", "case_variation", "whitespace_variation",
                 "url_encoding"]
SQLI_TECHNIQUES = ["url_encoding", "hex_encoding", "comment_injection",
                   "case_variation", "whitespace_variation", "char_encoding",
                   "keyword_swap"]
SQLI_MUTEX = [{"hex_encoding", "char_encoding"}]


def apply_sqli(payload: str, chosen: set, dbms: str):
    applied, text = [], payload
    double = "url_encoding" in chosen and rnd.random() < 0.4
    for technique in SQLI_PIPELINE:
        if technique not in chosen:
            continue
        if technique == "char_encoding":
            text, ok = t_sqli_char(text, dbms)
        elif technique == "hex_encoding":
            text, ok = t_sqli_hex(text, dbms)
        elif technique == "keyword_swap":
            text, ok = t_sqli_keyword_swap(text)
        elif technique == "comment_injection":
            text, ok = t_sqli_comment(text)
        elif technique == "case_variation":
            text, ok = t_sqli_case(text)
        elif technique == "whitespace_variation":
            text, ok = t_sqli_whitespace(text)
        else:
            text, ok = t_sqli_urlencode(text, double=double)
        if ok:
            applied.append("double_url_encoding"
                           if (technique == "url_encoding" and double) else technique)
    return text, sorted(applied)


def t_xss_case(text: str):
    out, changed = [], False
    for ch in text:
        if ch.isalpha() and rnd.random() < 0.5:
            flipped = ch.upper() if ch.islower() else ch.lower()
            if flipped != ch:
                changed = True
            out.append(flipped)
        else:
            out.append(ch)
    return "".join(out), changed


def t_xss_html_entity(text: str):
    mapping = {"<": ["&lt;", "&#60;", "&#x3c;"], ">": ["&gt;", "&#62;", "&#x3e;"],
               "\"": ["&quot;", "&#34;"], "'": ["&#39;", "&#x27;"],
               "/": ["&#47;", "&#x2f;"]}
    out, changed = [], False
    for ch in text:
        if ch in mapping and rnd.random() < 0.8:
            out.append(rnd.choice(mapping[ch]))
            changed = True
        else:
            out.append(ch)
    return "".join(out), changed


def t_xss_js_hex(text: str):
    out, changed = [], False
    for ch in text:
        if ch in "<>()/'\";=" and rnd.random() < 0.8:
            out.append("\\x%02x" % ord(ch))
            changed = True
        else:
            out.append(ch)
    return "".join(out), changed


def t_xss_unicode(text: str):
    out, changed = [], False
    for ch in text:
        if ch in "<>()/'\";=" and rnd.random() < 0.8:
            out.append("\\u%04x" % ord(ch))
            changed = True
        else:
            out.append(ch)
    return "".join(out), changed


def t_xss_double_url(text: str):
    return quote(text, safe="").replace("%", "%25"), True


XSS_WS_TOKENS = ["\t", "\n", "\r", "\x0c", "/", "%09", "%0a", "%20"]


def t_xss_whitespace(text: str):
    """Separators inside a tag: a browser accepts tab, newline and even `/`."""
    if " " not in text:
        return text, False
    out, changed = [], False
    for ch in text:
        if ch == " " and rnd.random() < 0.7:
            out.append(rnd.choice(XSS_WS_TOKENS))
            changed = True
        else:
            out.append(ch)
    return "".join(out), changed


def t_xss_comment(text: str):
    """HTML/JS comments wedged into places a signature would look at."""
    changed = False
    if "<" in text and rnd.random() < 0.6:
        index = text.index("<") + 1
        text = text[:index] + rnd.choice(["", ""]) + text[index:]
    for token in ("alert", "document", "fetch", "eval", "script"):
        if token in text and rnd.random() < 0.6:
            middle = len(token) // 2
            text = text.replace(token, token[:middle] + "/**/" + token[middle:], 1)
            changed = True
            break
    if not changed and ">" in text:
        text = text.replace(">", "<!---->>", 1)
        changed = True
    return text, changed


def t_xss_quote_swap(text: str):
    """Backtick or bare attribute values instead of the expected quoting."""
    changed = False
    if '="' in text and rnd.random() < 0.7:
        text = text.replace('="', "=`", 1)
        if '"' in text:
            text = text.replace('"', "`", 1)
        changed = True
    elif "='" in text and rnd.random() < 0.7:
        text = text.replace("='", "=`", 1)
        if "'" in text:
            text = text.replace("'", "`", 1)
        changed = True
    elif "(" in text and ")" in text and rnd.random() < 0.5:
        text = re.sub(r"\((\d+)\)", lambda m: "`" + m.group(1) + "`", text, count=1)
        changed = True
    return text, changed


def t_xss_fromcharcode(text: str):
    """Rebuild the sink call from character codes."""
    for token in ("alert", "confirm", "prompt", "eval"):
        if token in text:
            codes = ",".join(str(ord(c)) for c in token)
            replacement = f"self[String.fromCharCode({codes})]"
            return text.replace(token, replacement, 1), True
    if "src=" in text:
        return text.replace("src=", "SRC=", 1), False
    return text, False


XSS_ENCODERS = ["html_entity", "js_encoding", "unicode_escape", "double_encoding"]
XSS_TECHNIQUES = ["case_variation", "whitespace_variation", "comment_injection",
                  "quote_swap", "fromcharcode"] + XSS_ENCODERS
XSS_PIPELINE = ["fromcharcode", "quote_swap", "comment_injection",
                "case_variation", "whitespace_variation"]


def apply_xss(payload: str, chosen: set):
    applied, text = [], payload
    for technique in XSS_PIPELINE:
        if technique not in chosen:
            continue
        if technique == "fromcharcode":
            text, ok = t_xss_fromcharcode(text)
        elif technique == "quote_swap":
            text, ok = t_xss_quote_swap(text)
        elif technique == "comment_injection":
            text, ok = t_xss_comment(text)
        elif technique == "case_variation":
            text, ok = t_xss_case(text)
        else:
            text, ok = t_xss_whitespace(text)
        if ok:
            applied.append(technique)
    for technique in XSS_ENCODERS:
        if technique in chosen:
            if technique == "html_entity":
                text, ok = t_xss_html_entity(text)
            elif technique == "js_encoding":
                text, ok = t_xss_js_hex(text)
            elif technique == "unicode_escape":
                text, ok = t_xss_unicode(text)
            else:
                text, ok = t_xss_double_url(text)
            if ok:
                applied.append(technique)
            break
    return text, sorted(applied)


# ---------------------------------------------------------------------------
# technique combo universe -- enumerated up front, then split into SET_1/SET_2
# ---------------------------------------------------------------------------
def enumerate_combos(techniques: list[str], mutex: list[set], max_n: int = 3):
    combos = []
    for n in range(1, max_n + 1):
        for combo in itertools.combinations(sorted(techniques), n):
            combo_set = set(combo)
            if any(len(group & combo_set) > 1 for group in mutex):
                continue
            combos.append(tuple(sorted(combo)))
    return combos


# Techniques the model never sees during training.
#
# A random combo hold-out produced no measurable difficulty: a lexical model
# keys on tokens like `alert` or `--` that survive most transforms, so an unseen
# *combination* of familiar transforms is no harder than a familiar one. Holding
# out the transforms that actually destroy those tokens -- character-code
# rewriting and unicode escaping -- is what makes the split mean something.
HELDOUT_TECHNIQUES = {
    "sqli": {"char_encoding"},
    "xss": {"fromcharcode", "unicode_escape"},
}


def split_combos_by_technique(combos: list[tuple], heldout: set):
    """SET_1 avoids the held-out transforms entirely; SET_2 always uses one."""
    set_1 = {c for c in combos if not (set(c) & heldout)}
    set_2 = {c for c in combos if set(c) & heldout}
    return set_1, set_2


# ---------------------------------------------------------------------------
# INJECTION: attacks reuse a benign request as carrier
# ---------------------------------------------------------------------------
def _inject_query(shape: dict, payload: str) -> tuple[dict, str] | None:
    url = shape["url"]
    if "?" not in url:
        return None
    base, query = url.split("?", 1)
    pairs = [p.split("=", 1) for p in query.split("&") if "=" in p]
    if not pairs:
        return None
    index = rnd.randrange(len(pairs))
    pairs[index][1] = payload
    shape["url"] = base + "?" + "&".join(f"{k}={v}" for k, v in pairs)
    return shape, "query_param"


def _inject_form(shape: dict, payload: str) -> tuple[dict, str] | None:
    content = shape.get("content", "")
    if "urlencoded" not in shape.get("content_type", "") or "=" not in content:
        return None
    pairs = [p.split("=", 1) for p in content.split("&") if "=" in p]
    if not pairs:
        return None
    index = rnd.randrange(len(pairs))
    pairs[index][1] = payload
    shape["content"] = "&".join(f"{k}={v}" for k, v in pairs)
    return shape, "form_field"


def _inject_json(shape: dict, payload: str) -> tuple[dict, str] | None:
    if "json" not in shape.get("content_type", ""):
        return None
    try:
        data = json.loads(shape["content"])
    except (ValueError, KeyError):
        return None
    keys = [k for k, v in data.items() if isinstance(v, str)]
    if not keys:
        return None
    data[rnd.choice(keys)] = payload
    shape["content"] = json.dumps(data, ensure_ascii=False)
    return shape, "json_body"


def _inject_multipart(shape: dict, payload: str) -> tuple[dict, str] | None:
    if "multipart" not in shape.get("content_type", ""):
        return None
    content = shape["content"]
    if 'filename="' not in content:
        return None
    # lambda replacement: a payload containing \x or \u would otherwise be read
    # as a regex escape sequence
    shape["content"] = re.sub(r'filename="[^"]*"',
                              lambda _m: f'filename="{payload}"', content, count=1)
    return shape, "multipart_field"


def _inject_path(shape: dict, payload: str) -> tuple[dict, str]:
    base = shape["url"].split("?", 1)[0].rstrip("/")
    suffix = shape["url"][len(shape["url"].split("?", 1)[0]):]
    shape["url"] = f"{base}/{payload}{suffix}"
    return shape, "path_segment"


def _inject_cookie(shape: dict, payload: str) -> tuple[dict, str]:
    shape["_cookie_extra"] = payload
    return shape, "cookie"


def _inject_header(shape: dict, payload: str) -> tuple[dict, str]:
    shape["_ua_override"] = payload
    return shape, "header"


def inject_into_benign(payload: str) -> tuple[dict, str]:
    """Build an attack row on top of a real benign request skeleton.

    This is the fix for the structural shortcuts: because the carrier comes from
    the same generator that produces benign traffic, method / content_type /
    host distributions match by construction.
    """
    for _ in range(12):
        shape = gen_benign_shape()
        candidates = [_inject_query, _inject_form, _inject_json, _inject_multipart]
        rnd.shuffle(candidates)
        weights_roll = rnd.random()
        if weights_roll < 0.10:
            return _inject_cookie(shape, payload)
        if weights_roll < 0.18:
            return _inject_header(shape, payload)
        if weights_roll < 0.26:
            return _inject_path(shape, payload)
        for injector in candidates:
            result = injector(shape, payload)
            if result is not None:
                return result
    shape = gen_benign_shape()
    return _inject_path(shape, payload)


def build_attack_row(seed: dict, payload: str, applied: list[str],
                     is_time: bool, is_second: bool,
                     linked_id: str = "") -> dict:
    shape, location = inject_into_benign(payload)
    row = blank_row()
    cookie = make_cookie(role=shape.get("_role"), with_cart=shape.get("_is_cart", False))
    if shape.get("_cookie_extra"):
        cookie = cookie + f"; pref={shape['_cookie_extra']}"
    user_agent = shape.get("_ua_override") or rnd.choice(USER_AGENTS)
    row.update(
        method=shape["method"], url=shape["url"], host=shape["host"],
        user_agent=user_agent, cookie=cookie,
        content_type=shape.get("content_type", ""), content=shape.get("content", ""),
        classification="anomalous",
        attack_category="sqli" if seed["seed_id"].startswith("sqli") else "xss",
        attack_technique=seed["category"], dbms=seed.get("dbms", ""),
        seed_id=seed["seed_id"], context_location=location,
        is_time_based=is_time, is_second_order=is_second,
        linked_request_id=linked_id, benign_kind="", source="grammar_mutated",
    )
    return finalize_labels(row, applied)


def finalize_labels(row: dict, techniques: list[str]) -> dict:
    count = len(techniques)
    row["obfuscation_techniques"] = "|".join(techniques)
    row["technique_count"] = count
    row["obfuscation_type"] = ("plain" if count == 0 else
                               "single_technique" if count == 1 else
                               "combined_2" if count == 2 else "combined_3plus")
    if row["is_second_order"] or row["is_time_based"]:
        row["difficulty_level"] = "advanced"
    else:
        row["difficulty_level"] = ("baseline" if count == 0 else
                                   "low" if count == 1 else
                                   "medium" if count == 2 else "high")
    return row


def make_trigger_row(store_row: dict) -> dict:
    """The later request that fires a stored payload. Carries no payload itself."""
    row = blank_row()
    endpoints = (["/admin/users", "/profile/view", "/account/orders", "/moderation/queue"]
                 if store_row["attack_category"] == "sqli" else
                 ["/comments/thread", "/profile/view", "/admin/reviews", "/feed"])
    row.update(
        method="GET", host=store_row["host"],
        url=rnd.choice(endpoints) + f"?id={rnd.randint(1, 9999)}",
        user_agent=rnd.choice(USER_AGENTS),
        cookie=make_cookie(role=rnd.choice([None, "admin"])),
        content_type="", content="", classification="anomalous",
        attack_category=store_row["attack_category"],
        attack_technique="second_order_trigger", seed_id=store_row["seed_id"],
        context_location="", obfuscation_techniques="", obfuscation_type="plain",
        technique_count=0, difficulty_level="advanced", is_second_order=True,
        is_time_based=False, linked_request_id=store_row["linked_request_id"],
        benign_kind="", source="grammar_mutated", split="second_order_trigger",
    )
    return row


# ---------------------------------------------------------------------------
# seed bank preparation
# ---------------------------------------------------------------------------
def canonical(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def load_seed_banks(verbose: bool = True) -> list[dict]:
    """Load both banks and drop anything that already exists in Kaggle.

    The obfuscation set is evaluated cross-source against Kaggle, so a seed
    present in both is a direct train/test leak.
    """
    seeds = build_sqli_seeds(SEED) + build_xss_seeds(SEED)
    if KAGGLE_PATH.exists():
        try:
            import pandas as pd
            kaggle = pd.read_csv(KAGGLE_PATH, usecols=["Sentence"])
            known = set(kaggle["Sentence"].dropna().astype(str).map(canonical))
        except Exception as exc:                      # pragma: no cover
            print(f"  ! could not read Kaggle for dedup: {exc}")
            known = set()
        before = len(seeds)
        seeds = [s for s in seeds if canonical(s["payload"]) not in known]
        if verbose:
            print(f"  seed bank: {before} -> {len(seeds)} after Kaggle dedup "
                  f"({before - len(seeds)} removed)")
    elif verbose:
        print(f"  ! Kaggle file not found at {KAGGLE_PATH}, skipping dedup")
    return seeds


def seed_family(payload: str) -> str:
    """Collapse per-seed numbering the way the quality gate does.

    `' OR 1=1--` and `' OR 3=3--` are different seed_ids but the same skeleton.
    Splitting on seed_id alone lets a skeleton appear on both sides of the
    hold-out, which is a real, if mild, leak -- so the pools are cut on family.
    """
    text = str(payload).lower()
    text = re.sub(r"[0-9a-f]{4,}", "<id>", text)
    return re.sub(r"\d+", "<n>", text)


def partition_seeds(seeds: list[dict], rng: random.Random):
    """POOL_A trains, POOL_B is only ever seen at test time.

    Whole families move together and the cut is stratified by attack category,
    so SQLi and XSS are held out in the same proportion.
    """
    by_category = defaultdict(lambda: defaultdict(list))
    for seed in seeds:
        category = seed["seed_id"].split("_")[0]
        by_category[category][seed_family(seed["payload"])].append(seed)

    pool_a, pool_b = [], []
    for families in by_category.values():
        keys = sorted(families)
        rng.shuffle(keys)
        cut = int(round(POOL_B_FRACTION * len(keys)))
        for key in keys[:cut]:
            pool_b.extend(families[key])
        for key in keys[cut:]:
            pool_a.extend(families[key])
    return pool_a, pool_b


# ---------------------------------------------------------------------------
# attack row generation for one (seed pool, combo set, split) cell
# ---------------------------------------------------------------------------
def generate_attacks(seeds: list[dict], combos: list[tuple], n_rows: int,
                     allow_plain: bool, split_name: str,
                     seen: set, triggers: list) -> list[dict]:
    """Round-robin over seeds so every seed is represented, never oversampled."""
    rows: list[dict] = []
    if not seeds:
        return rows
    order = list(seeds)
    rnd.shuffle(order)
    combo_list = [tuple(c) for c in combos] or [()]
    position = 0
    attempts = 0
    max_attempts = n_rows * 12

    # guarantee one plain row per seed, so the seed-diversity check sees them all
    if allow_plain:
        for seed in order:
            if len(rows) >= n_rows:
                break
            row = _one_attack(seed, (), split_name, seen, triggers)
            if row:
                rows.append(row)

    while len(rows) < n_rows and attempts < max_attempts:
        attempts += 1
        seed = order[position % len(order)]
        position += 1
        if allow_plain and rnd.random() < PLAIN_RATIO:
            combo = ()
        else:
            combo = rnd.choice(combo_list)
        row = _one_attack(seed, combo, split_name, seen, triggers)
        if row:
            rows.append(row)
    return rows


def _one_attack(seed: dict, combo: tuple, split_name: str,
                seen: set, triggers: list) -> dict | None:
    is_sqli = seed["seed_id"].startswith("sqli")
    base = seed["payload"]
    if "{id}" in base:
        base = base.replace("{id}", rand_hex(6))

    # Both flags are properties of the seed itself, never random noise, so the
    # label always matches what the payload actually does.
    is_time = seed["category"] in ("time_blind", "blind")
    is_second = seed["category"] in ("second_order", "stored")

    combo_set = set(combo)
    if is_sqli:
        allowed = combo_set & set(SQLI_TECHNIQUES)
        payload, applied = apply_sqli(base, allowed, seed.get("dbms", "mysql"))
    else:
        allowed = combo_set & set(XSS_TECHNIQUES)
        payload, applied = apply_xss(base, allowed)

    # transport encoding, same probability for both classes; skip when the
    # payload already carries a URL-encoding technique
    if not any(t in applied for t in ("url_encoding", "double_url_encoding",
                                      "double_encoding")):
        payload = maybe_encode(payload)

    linked_id = str(uuid.UUID(int=rnd.getrandbits(128))) if is_second else ""
    row = build_attack_row(seed, payload, applied, is_time, is_second, linked_id)
    row["split"] = split_name
    # The combo that was *drawn* from SET_1 / SET_2, as opposed to the techniques
    # that ended up changing the text. A transform can be a no-op on a given
    # payload, so the applied list is not a reliable record of the hold-out.
    row["assigned_combo"] = "|".join(sorted(combo))

    digest = wire_hash(row["method"], row["host"], row["url"], row["content"],
                       row["cookie"], row["user_agent"])
    if digest in seen:
        return None
    seen.add(digest)

    if is_second:
        triggers.append(make_trigger_row(row))
    return row


# ---------------------------------------------------------------------------
# BUILD
# ---------------------------------------------------------------------------
SPLIT_PLAN = [
    # name,                    pool,  combo set, share of attack rows
    ("train",                  "A", "SET_1", 0.490),
    ("val",                    "A", "SET_1", 0.105),
    ("test",                   "A", "SET_1", 0.105),
    ("test_unseen_technique",  "A", "SET_2", 0.100),
    ("test_unseen_seed",       "B", "SET_1", 0.100),
    ("test_unseen_both",       "B", "SET_2", 0.100),
]


def build(n_benign: int, n_attack: int, verbose: bool = True):
    rng = random.Random(SEED)
    seeds = load_seed_banks(verbose)
    pool_a, pool_b = partition_seeds(seeds, rng)
    if verbose:
        print(f"  seed pools: POOL_A={len(pool_a)}  POOL_B={len(pool_b)}")

    sqli_set1, sqli_set2 = split_combos_by_technique(
        enumerate_combos(SQLI_TECHNIQUES, SQLI_MUTEX), HELDOUT_TECHNIQUES["sqli"])
    xss_set1, xss_set2 = split_combos_by_technique(
        enumerate_combos(XSS_TECHNIQUES, [set(XSS_ENCODERS)]), HELDOUT_TECHNIQUES["xss"])
    if verbose:
        print(f"  combos: sqli SET_1={len(sqli_set1)} SET_2={len(sqli_set2)} | "
              f"xss SET_1={len(xss_set1)} SET_2={len(xss_set2)}")
        print(f"  held-out transforms: {HELDOUT_TECHNIQUES}")

    combo_sets = {
        ("sqli", "SET_1"): list(sqli_set1), ("sqli", "SET_2"): list(sqli_set2),
        ("xss", "SET_1"): list(xss_set1), ("xss", "SET_2"): list(xss_set2),
    }

    seen: set = set()
    triggers: list = []
    rows: list = []

    for split_name, pool_name, set_name, share in SPLIT_PLAN:
        pool = pool_a if pool_name == "A" else pool_b
        target = int(round(share * n_attack))
        for family in ("sqli", "xss"):
            family_seeds = [s for s in pool if s["seed_id"].startswith(family)]
            rows.extend(generate_attacks(
                family_seeds, combo_sets[(family, set_name)], target // 2,
                allow_plain=(set_name == "SET_1"), split_name=split_name,
                seen=seen, triggers=triggers))

    # benign, mirroring the attack allocation so every test split has both classes
    benign_rows: list = []
    attempts = 0
    while len(benign_rows) < n_benign and attempts < n_benign * 8:
        attempts += 1
        row = gen_benign()
        digest = wire_hash(row["method"], row["host"], row["url"], row["content"])
        if digest in seen:
            continue
        seen.add(digest)
        benign_rows.append(row)

    rng.shuffle(benign_rows)
    cursor = 0
    for split_name, _, _, share in SPLIT_PLAN:
        count = int(round(share * n_benign))
        for row in benign_rows[cursor:cursor + count]:
            row["split"] = split_name
        cursor += count
    for row in benign_rows[cursor:]:
        row["split"] = "train"
    rows.extend(benign_rows)

    rnd.shuffle(rows)
    return rows, triggers


# ---------------------------------------------------------------------------
COLUMNS = ["request_id", "method", "url", "host", "user_agent", "cookie",
    "content_type", "content", "classification", "attack_category",
    "attack_technique", "dbms", "seed_id", "context_location",
    "obfuscation_techniques", "assigned_combo", "obfuscation_type",
    "technique_count", "difficulty_level", "is_second_order", "is_time_based",
    "linked_request_id", "benign_kind", "benign_obfuscation", "source", "split"]


def write_csv(rows: list[dict], path: Path) -> None:
    """Serialise in memory, then write once.

    The output directory is often a mounted/network filesystem where every
    small write costs a round trip -- 100k row-by-row writes took over a
    minute, a single buffered write takes under a second.
    """
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=COLUMNS,
                            quoting=csv.QUOTE_MINIMAL, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        record = dict(row)
        record["is_second_order"] = str(record["is_second_order"]).lower()
        record["is_time_based"] = str(record["is_time_based"]).lower()
        writer.writerow(record)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        handle.write(buffer.getvalue())


def stats(rows: list[dict], triggers: list[dict]) -> None:
    attacks = [r for r in rows if r["classification"] == "anomalous"]
    benign = [r for r in rows if r["classification"] == "normal"]
    print("\n-- composition --")
    print(f"  total rows       : {len(rows):,}")
    print(f"  classification   : {dict(Counter(r['classification'] for r in rows))}")
    print(f"  attack_category  : {dict(Counter(r['attack_category'] for r in attacks))}")
    print(f"  benign_kind      : {dict(Counter(r['benign_kind'] for r in benign))}")
    print(f"  obfuscation_type : {dict(Counter(r['obfuscation_type'] for r in attacks))}")
    print(f"  context_location : {dict(Counter(r['context_location'] for r in attacks))}")
    print(f"  second-order trig: {len(triggers):,} (written to a separate file)")

    print("\n-- splits --")
    for name, _, _, _ in SPLIT_PLAN:
        part = [r for r in rows if r["split"] == name]
        n_att = sum(1 for r in part if r["classification"] == "anomalous")
        print(f"  {name:22s} n={len(part):>7,}  normal={len(part) - n_att:>6,}  "
              f"anomalous={n_att:>6,}")

    seeds_used = {r["seed_id"] for r in attacks if r["seed_id"]}
    print(f"\n  distinct seeds used : {len(seeds_used):,}")
    print(f"  attack rows / seed  : {len(attacks) / max(len(seeds_used), 1):.1f}")

    train_seeds = {r["seed_id"] for r in attacks if r["split"] == "train"}
    for name in ("test", "test_unseen_technique", "test_unseen_seed", "test_unseen_both"):
        test_seeds = {r["seed_id"] for r in attacks if r["split"] == name}
        if test_seeds:
            overlap = len(test_seeds & train_seeds) / len(test_seeds)
            print(f"  seed overlap train->{name:22s}: {overlap * 100:5.1f}%")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scale", choices=["pilot", "full"], default="pilot")
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    if args.scale == "pilot":
        n_benign, n_attack = 3000, 3000
        out = args.out or "obfu_http_dataset_v2_pilot.csv"
    else:
        n_benign, n_attack = 50000, 50000
        out = args.out or "obfu_http_dataset_v2.csv"

    out_path = Path(out)
    if not out_path.is_absolute():
        out_path = PROJECT_ROOT / "DataSet" / out_path.name

    print(f"== generating scale={args.scale} ==")
    rows, triggers = build(n_benign, n_attack)
    write_csv(rows, out_path)

    trigger_path = out_path.with_name(out_path.stem + "_second_order_triggers.csv")
    write_csv(triggers, trigger_path)

    print(f"\nwrote {out_path}")
    print(f"wrote {trigger_path}")
    stats(rows, triggers)


if __name__ == "__main__":
    main()
