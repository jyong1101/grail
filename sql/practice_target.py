#!/usr/bin/env python3
"""Local SQL injection practice target (SQLite, python stdlib only). Listens on 127.0.0.1 only.

  python3 practice_target.py [port]        default port 8090, Ctrl-C to stop
  python3 sqlauto.py http://127.0.0.1:8090/              whole site
  python3 sqlauto.py http://127.0.0.1:8090/search        one page

/catalog /cart /account /search /orders   same five shapes as the school practice set
                                          (UNION, JSON body, cookie, = < > filter, md5-signed parameter)
/x/...                                    variants: string context, login form, LIKE search, bare token in an
                                          odd table, spaces stripped, UNION/SELECT deleted, case-sensitive blacklist, base64 value, header
"""
import sqlite3, json, hashlib, re, sys, threading, base64, html, collections
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

LOCK = threading.Lock()
STATS = collections.Counter()

def mkdb(script):
    c = sqlite3.connect(":memory:", check_same_thread=False)
    c.executescript(script)
    return c

PRODUCTS = """CREATE TABLE products(id INTEGER, name TEXT, price TEXT, descr TEXT);
INSERT INTO products VALUES (1,'Kettle','19.90','Boils water.'),(2,'Toaster','24.50','Two slots.'),
(3,'Lamp','12.00','Warm light.'),(4,'Mug','4.20','Holds tea.'),(5,'Clock','15.75','Ticks.');"""
DBS = {
 "catalog": mkdb(PRODUCTS + "CREATE TABLE flag(flag TEXT); INSERT INTO flag VALUES('ehCTF{l1_un10n_c4t4l0g}');"),
 "cart":    mkdb(PRODUCTS + "CREATE TABLE flag(flag TEXT); INSERT INTO flag VALUES('ehCTF{l2_js0n_b0dy}');"),
 "account": mkdb("CREATE TABLE members(id INTEGER, name TEXT, email TEXT); INSERT INTO members VALUES(1,'alice','a@shop.test'),(2,'bob','b@shop.test');"
                 "CREATE TABLE flag(flag TEXT); INSERT INTO flag VALUES('ehCTF{l3_c00k13_c0unts}');"),
 "search":  mkdb("CREATE TABLE posts(id INTEGER, title TEXT); INSERT INTO posts VALUES(1,'Hello'),(2,'Sale'),(3,'Hours'),(4,'Jobs'),(5,'About');"
                 "CREATE TABLE flag(flag TEXT); INSERT INTO flag VALUES('ehCTF{l4_n0_3qu4ls}');"),
 "orders":  mkdb("CREATE TABLE orders(id INTEGER, item TEXT); INSERT INTO orders VALUES(1,'Kettle'),(2,'Lamp'),(3,'Mug');"
                 "CREATE TABLE flag(flag TEXT); INSERT INTO flag VALUES('ehCTF{l5_s1gn3d_n0t_s4f3}');"),
 # ---- variants ----
 "article": mkdb("CREATE TABLE articles(id INTEGER, slug TEXT, title TEXT, body TEXT, author TEXT);"
                 "INSERT INTO articles VALUES(1,'welcome','Welcome','First post.','ed'),(2,'news','News','Second post.','ann');"
                 "CREATE TABLE vault(id INTEGER, owner TEXT, secret_value TEXT);"
                 "INSERT INTO vault VALUES(1,'ed','nothing here'),(2,'root','ehCTF{v1_n0t_c4ll3d_fl4g}');"),
 "login":   mkdb("CREATE TABLE users(id INTEGER, username TEXT, password TEXT, role TEXT);"
                 "INSERT INTO users VALUES(1,'admin','Sup3rS3cret!x','admin'),(2,'guest','guest','user');"),
 "find":    mkdb("CREATE TABLE books(id INTEGER, title TEXT, author TEXT); INSERT INTO books VALUES(1,'Dune','Herbert'),(2,'Emma','Austen'),(3,'Ulysses','Joyce');"
                 "CREATE TABLE notes(id INTEGER, note TEXT); INSERT INTO notes VALUES(1,'buy milk'),(2,'call bob'),(3,'ehCTF{v3_r0w_thr33}'),(4,'gym'),(5,'pay rent');"),
 "staff":   mkdb("CREATE TABLE staff(id INTEGER, name TEXT); INSERT INTO staff VALUES(1,'kim'),(2,'lee');"
                 "CREATE TABLE access_tokens(staff_id INTEGER, token TEXT); INSERT INTO access_tokens VALUES(1,'v4-bare-token-7f3a9c');"),
}
for k in ("nospace", "nokw", "case", "b64", "hdr"):
    DBS[k] = mkdb(PRODUCTS + "CREATE TABLE visitors(ip TEXT, visits INTEGER); INSERT INTO visitors VALUES('10.0.0.5',3);"
                  "CREATE TABLE flag(flag TEXT); INSERT INTO flag VALUES('ehCTF{%s_v4r14nt}');" % k)

def q(db, sql):
    with LOCK:
        return DBS[db].execute(sql).fetchall()

NAV = ('<nav><a href="/">Home</a> <a href="/catalog">Catalog</a> <a href="/cart">Cart</a> <a href="/account">Account</a> '
       '<a href="/search">Search</a> <a href="/orders">Orders</a> <a href="/x/">More</a></nav>')
def page(title, body):
    return ("<!doctype html><html><head><title>%s - Corner Shop</title>\n<style>body{font-family:sans-serif;margin:2em} "
            "nav a{margin-right:1em} .msg{padding:.5em;background:#eee}</style></head>\n<body>%s\n<h1>%s</h1>\n%s\n"
            "<footer><small>Corner Shop demo</small></footer></body></html>" % (title, NAV, title, body))
def msg(t): return '<p class="msg">%s</p>' % t
def rows_html(rows): return "\n".join("<div class='row'>" + "".join("<p>%s</p>" % c for c in r) + "</div>" for r in rows)

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    def log_message(self, *a): pass
    def send(self, body, code=200, ctype="text/html; charset=utf-8"):
        b = body.encode()
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def reflect(self, db, sql, title, empty, show_err=True):
        try: rows = q(db, sql)
        except Exception as e:
            return self.send(page(title, msg("SQL error: %s" % html.escape(str(e)) if show_err else empty)))
        self.send(page(title, rows_html(rows) if rows else msg(empty)))
    def count(self, db, sql, title, yes, no, show_err=True):
        try: rows = q(db, sql)
        except Exception as e:
            return self.send(page(title, msg("SQL error: %s" % html.escape(str(e)) if show_err else no)))
        self.send(page(title, msg(yes % len(rows) if "%d" in yes else yes) if rows else msg(no)))

    def do_GET(self):
        u = urlparse(self.path); qs = parse_qs(u.query, keep_blank_values=True); p = u.path
        g = lambda k, d=None: qs.get(k, [d])[0]
        if p == "/__stats": return self.send(json.dumps(STATS), ctype="application/json")
        if p == "/__reset": STATS.clear(); return self.send("ok")
        STATS[p] += 1
        if p == "/":
            return self.send(page("Home", "<p>Welcome to the shop.</p>"))
        if p == "/catalog":
            if "item" not in qs:
                rows = q("catalog", "SELECT id,name,price FROM products")
                return self.send(page("Catalog", "<ul>" + "".join('<li>%s - $%s <a href="/catalog?item=%d">View</a></li>' % (n, pr, i) for i, n, pr in rows) + "</ul>"))
            return self.reflect("catalog", "SELECT id, name, price, descr FROM products WHERE id = %s" % g("item"), "Catalog", "That item is not in the catalog.")
        if p == "/cart":
            return self.send(page("Cart", '<p id="out" class="msg">Your cart is empty.</p>\n<button onclick="addToCart(1)">Add to Cart</button>\n'
                "<script>\nasync function addToCart(id) {\n  const res = await fetch('/cart', {\n    method: 'POST',\n"
                "    headers: {'Content-Type': 'application/json'},\n    body: JSON.stringify({id: String(id)})\n  });\n"
                "  const data = await res.json();\n  document.getElementById('out').textContent = data.message;\n}\n</script>"))
        if p == "/account":
            m = re.search(r"(?:^|;\s*)uid=([^;]*)", self.headers.get("Cookie", ""))
            no = "No member is registered under that id, so there is no account to show. Check the id and try again."
            if not m: return self.send(page("Account", msg(no)))
            return self.count("account", "SELECT name FROM members WHERE id = %s" % unquote(m.group(1)), "Account", "%d profile(s) matched", no)
        if p == "/search":
            form = '<form method="get" action="/search"><input name="q" placeholder="post number"><button>Search</button></form>'
            if "q" not in qs: return self.send(page("Search", form))
            v = g("q")
            for ch in "=<>": v = v.replace(ch, "")
            no = "No post carries that number, so there is nothing to show here. Post numbers run from 1 upwards."
            try: rows = q("search", "SELECT title FROM posts WHERE id = %s" % v)
            except Exception as e: return self.send(page("Search", form + "\n" + msg("SQL error: %s" % html.escape(str(e)))))
            return self.send(page("Search", form + "\n" + msg("%d title(s) matched." % len(rows) if rows else no)))
        if p == "/orders":
            if "id" not in qs:
                return self.send(page("Orders", "<ul>" + "".join('<li><a href="/orders?id=%d&amp;h=%s">Order %d</a></li>' % (i, hashlib.md5(str(i).encode()).hexdigest(), i) for i in (1, 2, 3)) + "</ul>"))
            i, h = g("id", ""), g("h", "")
            if hashlib.md5(i.encode()).hexdigest() != h:
                return self.send(page("Orders", msg("That lookup carried no valid signature for its id.")))
            return self.count("orders", "SELECT item FROM orders WHERE id = %s" % i, "Orders", "Order found.", "No such order.", show_err=False)
        # ------------------------------------------------ variants
        if p == "/x/":
            return self.send(page("More", '<ul><li><a href="/x/article?slug=welcome">Article</a></li><li><a href="/x/login">Login</a></li>'
                '<li><a href="/x/find">Find a book</a></li><li><a href="/x/staff?id=1">Staff</a></li><li><a href="/x/nospace?id=1">Stock</a></li>'
                '<li><a href="/x/nokw?item=1">Deals</a></li><li><a href="/x/case?item=1">Offers</a></li><li><a href="/x/b64?id=MQ==">Coupon</a></li><li><a href="/x/hdr">Visits</a></li></ul>'))
        if p == "/x/article":
            return self.reflect("article", "SELECT title, body, author FROM articles WHERE slug = '%s'" % g("slug", "welcome"), "Article", "No such article.")
        if p == "/x/login":
            return self.send(page("Login", '<form method="post" action="/x/login"><input name="username"><input name="password" type="password"><button>Sign in</button></form>'))
        if p == "/x/find":
            form = '<form method="get" action="/x/find"><input name="term"><button>Find</button></form>'
            if "term" not in qs: return self.send(page("Find a book", form))
            return self.reflect("find", "SELECT title, author FROM books WHERE title LIKE '%%%s%%'" % g("term"), "Find a book", "No book matched.")
        if p == "/x/staff":
            return self.count("staff", "SELECT name FROM staff WHERE id = %s" % g("id", "1"), "Staff", "Staff member found.", "No staff member with that id.")
        if p == "/x/nospace":
            return self.count("nospace", "SELECT name FROM products WHERE id = %s" % g("id", "1").replace(" ", ""), "Stock", "%d item(s) in stock.", "Nothing in stock under that number.")
        if p == "/x/nokw":
            return self.reflect("nokw", "SELECT id, name, price FROM products WHERE id = %s" % re.sub("union|select", "", g("item", "1"), flags=re.I), "Deals", "No deal with that number.")
        if p == "/x/case":                                             # blacklist knows only the all-upper and all-lower spelling
            v = g("item", "1")
            for w in ("UNION", "union", "SELECT", "select"): v = v.replace(w, "")
            return self.reflect("case", "SELECT id, name, price FROM products WHERE id = %s" % v, "Offers", "No offer with that number.")
        if p == "/x/b64":
            try: v = base64.b64decode(g("id", "MQ==")).decode()
            except Exception: return self.send(page("Coupon", msg("Bad coupon code.")))
            return self.reflect("b64", "SELECT id, name, price FROM products WHERE id = %s" % v, "Coupon", "No coupon for that code.")
        if p == "/x/hdr":
            return self.count("hdr", "SELECT visits FROM visitors WHERE ip = '%s'" % self.headers.get("X-Forwarded-For", "127.0.0.1"), "Visits", "Welcome back.", "First visit recorded.")
        self.send(page("Not found", msg("No such page.")), 404)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0")); body = self.rfile.read(n).decode("utf-8", "replace"); p = urlparse(self.path).path
        STATS[p] += 1
        if p == "/cart":
            try: pid = json.loads(body)["id"]
            except Exception: return self.send(json.dumps({"ok": False, "message": "Malformed request."}), 400, "application/json")
            try: rows = q("cart", "SELECT name FROM products WHERE id = %s" % pid)
            except Exception as e: return self.send(json.dumps({"ok": False, "message": "SQL error: %s" % e}), ctype="application/json")
            return self.send(json.dumps({"ok": bool(rows), "message": "%d item(s) added to your cart." % len(rows) if rows else "That product does not exist, so nothing was added."}), ctype="application/json")
        if p == "/x/login":
            f = parse_qs(body, keep_blank_values=True); u = f.get("username", [""])[0]; pw = f.get("password", [""])[0]
            try: rows = q("login", "SELECT id, username, role FROM users WHERE username = '%s' AND password = '%s'" % (u, pw))
            except Exception: rows = []
            if not rows: return self.send(page("Login", msg("Login failed.")))
            extra = " Admin note: ehCTF{v2_l0g1n_byp4ss}" if rows[0][2] == "admin" else ""
            return self.send(page("Login", msg("Welcome back, %s!%s" % (html.escape(str(rows[0][1])), extra))))
        self.send(page("Not found", msg("No such page.")), 404)

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8090
    print("SQLi practice target on http://127.0.0.1:%d/  (Ctrl-C to stop)" % port, flush=True)
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
