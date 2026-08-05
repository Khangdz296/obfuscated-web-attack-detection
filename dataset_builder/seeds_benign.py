#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Benign content bank -- the symmetric counterpart to the attack seed banks.

Why this file exists
--------------------
After the first v2 pass the attack side drew from 1088 lexically distinct seeds
while the benign side drew from about 40 hand-written strings. A char n-gram
model does not need to understand SQL to exploit that: it memorises the 40
benign strings and calls everything else an attack. The measured effect was a
99.4% logistic-regression accuracy that barely moved when hard negatives were
added.

Benign traffic therefore needs the same generative diversity as attack traffic.
These banks build legitimate SQL, markup, JavaScript and natural language from
the same kind of vocabulary matrix used for the attack seeds, so that
"looks like code" stops being a free answer.

Nothing here is an attack. Every string is content a real application would
legitimately store, display or log.
"""
from __future__ import annotations

import random

TABLES = ["users", "orders", "products", "invoices", "customers", "sessions",
          "payments", "reviews", "categories", "shipments", "inventory",
          "employees", "tickets", "subscriptions", "addresses", "audit_log"]

COLUMNS = ["id", "name", "email", "status", "created_at", "updated_at", "total",
           "quantity", "price", "customer_id", "order_id", "sku", "region",
           "currency", "channel", "rating", "title", "body", "phone", "city"]

AGGREGATES = ["COUNT(*)", "SUM(total)", "AVG(price)", "MAX(created_at)",
              "MIN(price)", "COUNT(DISTINCT customer_id)"]


def build_benign_sql(rng: random.Random) -> list[str]:
    """Legitimate SQL as it appears in tickets, runbooks and docs."""
    out = []
    for _ in range(700):
        table = rng.choice(TABLES)
        cols = ", ".join(rng.sample(COLUMNS, k=rng.randint(1, 4)))
        shape = rng.choice([
            f"SELECT {cols} FROM {table} WHERE {rng.choice(COLUMNS)} = ?",
            f"SELECT {cols} FROM {table} ORDER BY {rng.choice(COLUMNS)} DESC LIMIT {rng.randint(10, 500)}",
            f"SELECT {rng.choice(AGGREGATES)} FROM {table} GROUP BY {rng.choice(COLUMNS)}",
            f"UPDATE {table} SET {rng.choice(COLUMNS)} = :value WHERE id = :id",
            f"INSERT INTO {table} ({cols}) VALUES (:a, :b)",
            f"SELECT a.{rng.choice(COLUMNS)}, b.{rng.choice(COLUMNS)} FROM {table} a "
            f"JOIN {rng.choice(TABLES)} b ON a.id = b.{rng.choice(COLUMNS)}",
            f"DELETE FROM {table} WHERE created_at < :cutoff",
            f"SELECT {cols} FROM {table} WHERE {rng.choice(COLUMNS)} IN (:ids)",
            f"CREATE INDEX idx_{table}_{rng.choice(COLUMNS)} ON {table} ({rng.choice(COLUMNS)})",
            f"SELECT {cols} FROM {table} WHERE {rng.choice(COLUMNS)} LIKE :pattern",
        ])
        prefix = rng.choice([
            "", "query: ", "the report runs ", "slow query found: ",
            "migration step 3: ", "we replaced it with ", "see runbook: ",
            "EXPLAIN output for ", "nightly job executes ", "please review ",
        ])
        # SQL comment markers belong in benign traffic too. Left out, "--" and
        # "/*" become free attack detectors -- they were the top two features a
        # logistic regression picked up.
        suffix = rng.choice([
            " -- runs nightly", " -- see ticket #4821", " -- do not remove",
            " /* added in v2.4 */", " /* index hint */", " /* legacy path */",
            " (parameterised)", " ;", "", " -- TODO: paginate",
            " -- owner: data-team", " /* verified */",
        ])
        out.append(prefix + shape + suffix)
    return out


HTML_TAGS = ["p", "div", "span", "section", "article", "h2", "h3", "li", "td",
             "blockquote", "figcaption", "label", "strong", "em", "small"]
HTML_ATTRS = ['class="note"', 'class="product-title"', 'id="summary"',
              'style="color:#333"', 'data-id="42"', 'role="note"',
              'aria-label="details"', 'class="row col-md-6"', 'lang="vi"']
HTML_TEXT = ["Ships in 2 days", "Xin chào bạn", "Free returns within 30 days",
             "Best seller", "Only 3 left in stock", "Giao hàng toàn quốc",
             "Rated 4.8 by 1200 buyers", "Includes 2-year warranty",
             "Bảo hành 12 tháng", "New arrival", "Limited edition"]


def build_benign_html(rng: random.Random) -> list[str]:
    """Rich-text content a CMS or review form legitimately accepts."""
    out = []
    for _ in range(700):
        tag = rng.choice(HTML_TAGS)
        inner_tag = rng.choice(["b", "i", "strong", "em", "u", "code", "mark"])
        text = rng.choice(HTML_TEXT)
        shape = rng.choice([
            f"<{tag}>{text}</{tag}>",
            f"<{tag} {rng.choice(HTML_ATTRS)}>{text}</{tag}>",
            f"<{tag}>{text} <{inner_tag}>{rng.choice(HTML_TEXT)}</{inner_tag}></{tag}>",
            f"<ul><li>{text}</li><li>{rng.choice(HTML_TEXT)}</li></ul>",
            f"<a href=\"/products/{rng.randint(1, 999)}\">{text}</a>",
            f"<img src=\"/img/{rng.randint(1, 999)}.png\" alt=\"{text}\">",
            f"<table><tr><td>{rng.choice(COLUMNS)}</td><td>{rng.randint(1, 99)}</td></tr></table>",
            f"<{tag}>{text}<br>{rng.choice(HTML_TEXT)}</{tag}>",
            f"<blockquote cite=\"/reviews/{rng.randint(1, 999)}\">{text}</blockquote>",
            f"<figure><img src=\"/m/{rng.randint(1, 99)}.jpg\"><figcaption>{text}</figcaption></figure>",
        ])
        out.append(shape)
    return out


JS_FUNCS = ["init", "render", "submitForm", "loadData", "onReady", "track",
            "formatPrice", "toggleMenu", "validate", "debounce", "parseConfig"]
JS_APIS = ["document.getElementById", "document.querySelector", "fetch",
           "JSON.parse", "JSON.stringify", "localStorage.getItem",
           "window.addEventListener", "Array.from", "Object.assign"]


def build_benign_js(rng: random.Random) -> list[str]:
    """Real front-end code, including the APIs an attack would also touch."""
    out = []
    for _ in range(500):
        fn = rng.choice(JS_FUNCS)
        api = rng.choice(JS_APIS)
        shape = rng.choice([
            f"function {fn}(){{var e={api}('app');return e}}",
            f"const {fn}=(a,b)=>{api}(a).concat(b);export default {fn};",
            f"window.addEventListener('load',function(){{{fn}()}});",
            f"var s=String.fromCharCode({','.join(str(rng.randint(65, 122)) for _ in range(5))});console.log(s);",
            f"const cfg=JSON.parse(atob(process.env.CONFIG||'e30='));",
            f"$(document).ready(function(){{$('.{rng.choice(['btn', 'card', 'nav'])}').on('click',{fn})}});",
            f"module.exports=function({fn}){{return {api}({fn})}};",
            f"!function(t){{var e=t.jQuery;e.fn.{fn}=function(){{return this}}}}(window);",
            f"async function {fn}(){{const r=await fetch('/api/v1/{rng.choice(TABLES)}');return r.json()}}",
            f"if(typeof {fn}==='function'){{{fn}({{retry:{rng.randint(1, 5)}}})}}",
        ])
        out.append(shape)
    return out


NL_TEMPLATES = [
    "how do I escape &lt;{tag}&gt; tags in a {place}?",
    "the docs say use &lt;br&gt; not \\n for line breaks",
    "our query is parameterised, we pass ? not string concatenation",
    "we switched to prepared statements after the {n}th audit",
    "error log shows: syntax error near &#39;--&#39; at line {n}",
    "please sanitise &amp;lt; and &amp;gt; before rendering the {place}",
    "the ORM builds SELECT ... FROM {table} JOIN {table2} automatically",
    "reading about UNION types in TypeScript, not SQL",
    "the alert() helper in our SDK shows a toast, not a popup",
    "we log every DELETE FROM statement for audit purposes",
    "select the {adj} option from the dropdown, then press save",
    "union station is near the {place}, about {n} minutes on foot",
    "order by date is fine but I'd rather sort by {col}",
    "drop shipping guide for {n} suppliers",
    "insert coin arcade near the {place}",
    "can't reproduce: the value was O'{name} and it saved fine",
    "D'Angelo's order (#{n}) shipped yesterday",
    "the formula is (a+b)*c > {n}, not a+b*c",
    "it's the customer's third attempt -- don't retry again",
    "we're using x < y && y < z for the range check",
    "the file is named report(final).xlsx -- note the parentheses",
    "he said \"that's not what I ordered\" and asked for a refund",
    "table and chair set, {n}cm x {n}cm, ships flat",
    "having trouble with checkout on the {place} page",
    "group by category, then count the {col} column",
    "create table saw stand, {adj} model",
    "truncate the description to {n} characters for the preview",
    "grant park picnic blanket, {adj} size",
    "declare the variable before the loop, not inside it",
    "exec summary is on page {n} of the report",
]

NL_FILL = {
    "tag": ["div", "p", "script", "style", "code", "pre"],
    "place": ["blog", "checkout", "product page", "dashboard", "help centre",
              "station", "warehouse", "office"],
    "adj": ["cheapest", "second", "premium", "compact", "standard", "deluxe"],
    "name": ["Brien", "Neill", "Connor", "Sullivan", "Hara"],
    "col": ["price", "rating", "created_at", "quantity", "status"],
}


def build_benign_text(rng: random.Random) -> list[str]:
    """Natural language that happens to contain attack-shaped tokens."""
    out = []
    for template in NL_TEMPLATES:
        for _ in range(12):
            filled = template
            for key, values in NL_FILL.items():
                filled = filled.replace("{" + key + "}", rng.choice(values))
            filled = filled.replace("{table2}", rng.choice(TABLES))
            filled = filled.replace("{table}", rng.choice(TABLES))
            filled = filled.replace("{n}", str(rng.randint(2, 400)))
            out.append(filled)
    return out


def build_benign_banks(seed: int = 1337) -> dict[str, list[str]]:
    """Deterministic. Returns one de-duplicated list per content family."""
    rng = random.Random(seed)
    banks = {
        "sql": build_benign_sql(rng),
        "html": build_benign_html(rng),
        "js": build_benign_js(rng),
        "text": build_benign_text(rng),
    }
    return {name: sorted(set(values)) for name, values in banks.items()}


if __name__ == "__main__":
    banks = build_benign_banks()
    total = sum(len(v) for v in banks.values())
    print(f"total benign content strings: {total}")
    for name, values in banks.items():
        print(f"  {name:5s} {len(values):4d}   e.g. {values[0][:70]}")
