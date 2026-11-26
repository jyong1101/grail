# Burp Suite (see, change and replay web requests)

## Goal
Sit between the browser and the site: look at every request, change one and send it again (Repeater), or send hundreds with one value changing (Intruder) to find the valid username / password / id.

## New to this? Read once (2 minutes)
When you click a button, the browser sends a **request** (a few lines of text: what page, what values) and the site sends back a **response** (status code, length, the page). Burp shows both and lets you edit the request before it goes.

| Tab | What it is for | Use it when |
|---|---|---|
| **Proxy → HTTP history** | a list of every request the browser made | "what does this page actually send?" (field names, cookies, hidden values) |
| **Proxy → Intercept** | holds each request until you press Forward | you want to change a value before the site sees it |
| **Repeater** | one request, edit → Send → read response, as often as you like | trying payloads by hand: SQL `'`, `../`, another id, another cookie |
| **Intruder** | one request sent many times, a marked value replaced from a list | which username exists? which password? which id has a page? |
| **Decoder** | encode / decode base64, URL, hex | a cookie or value looks scrambled |
| **Comparer** | shows the difference between two responses | "valid user" and "invalid user" pages look the same to the eye |

A hit in Intruder is the row that is **different** from all the others: another **Status** (200 among 401s) or another **Length**.

**Checklist**
- [ ] Burp's own browser open, site loads through it
- [ ] the request I care about found in HTTP history (the one sent when I pressed the button)
- [ ] only ONE thing changed per try
- [ ] Intruder results sorted by Status, then by Length → the odd row
- [ ] big wordlist? → not Intruder (slow in the free edition) → hydra / ffuf: [04_web_brute](04_web_brute.md)

# Commands

### Step 0: start
```bash
burpsuite &                    # Temporary project → Next → Use Burp defaults → Start Burp
```
**Proxy** tab → **Intercept** → **Open browser** (Burp's built-in browser: no proxy or certificate setup needed). Browse to `http://$IP/` in THAT browser.
Keep **Intercept is off** while you just browse; everything still lands in **Proxy → HTTP history**.

### Step 1: look (HTTP history)
Do the action once in the browser (log in with `a` / `b`, press the button, open the link) → **Proxy → HTTP history** → click the newest row.
- top line `POST /login HTTP/1.1` = method + path · the last line of a POST = the values sent (`username=a&password=b`)
- `Cookie:` line = what the site remembers about you · `Authorization: Basic …` = a pop-up login (the value is base64 of `user:pass`)
- lower half = the response: status (200 / 302 / 401 / 403 / 404), `Content-Length`, the page
- right-click the row → **Send to Repeater** (Ctrl+R) or **Send to Intruder** (Ctrl+I)

### Step 2: change one request by hand (Repeater)
**Repeater** tab → edit anything in the left box → **Send** → response on the right. Repeat.
```text
id=1            → id=2, id=0, id=7                    hidden pages / other users' data          → 03_web_enum
id=1            → id=1'    id=1 OR 1=1                SQL error or more rows                    → 05_sqli
page=home.php   → page=../../etc/passwd               file contents come back                   → 06_lfi
host=1.2.3.4    → host=1.2.3.4; id                    command output comes back                 → 14_web_inject
Cookie: role=guest → role=admin   ·   admin=0 → admin=1
User-Agent: …   → Mozilla/5.0 …                       site blocks "automated clients"
add a header:   X-Forwarded-For: 127.0.0.1            page says "local only" / 403
GET /admin      → POST /admin  (right-click → Change request method)
```
- special characters in a value (space, `&`, `'`, `;`) → select the value → right-click → **Convert selection → URL → URL-encode key characters** (Ctrl+U).
- response tabs: **Pretty / Raw** = the text · **Render** = how the browser would show it. Search box under the response: type `flag`.
- each try is kept: the `<` `>` arrows step back through earlier requests.

### Step 3: try many values (Intruder)
1. **Send to Intruder** → **Positions**: press **Clear §**, select ONLY the part that should change, press **Add §**.
   `username=§user§&password=x`
2. **Payloads** → payload type:
   - **Simple list** → **Load…** a wordlist file (or **Paste**)
   - **Numbers** → From `0` To `99` Step `1`, Min integer digits `2` (gives 00, 01 … 99; use `3` for 000 … 999) — for names that follow a pattern, mark only the digits: `username=user0§00§`
3. **Start attack**. A table fills: one row per value.
4. Click the **Status** column, then the **Length** column to sort. All rows the same except one → that one is the answer (valid username, right password, the id that has a page).
5. Click the odd row → **Response** → read it (flag may be right there).

Attack type (drop-down above the request), when more than one § pair is marked:
| Type | Does | Use |
|---|---|---|
| Sniper | one list, one position at a time | the normal case: one value changes |
| Battering ram | one list, same value in every position | same word needed twice |
| Pitchfork | list 1 + list 2 side by side (1st with 1st, 2nd with 2nd) | known pairs user1:pass1, user2:pass2 |
| Cluster bomb | every combination of list 1 × list 2 | unknown user AND unknown password (small lists only) |

Mark the failures automatically: Intruder → **Settings** → **Grep - Match** → Clear → Add the text a failed login shows (`Invalid`) → a tick column appears; the row WITHOUT the tick is the hit.

### Step 4: pop-up login (HTTP Basic) in Intruder
The browser sends `Authorization: Basic dXNlcjpwYXNz` = base64 of `user:pass`. So the payload must be built and encoded:
1. Positions: `Authorization: Basic §x§`
2. Which USERNAME exists: Payloads = the username list → **Payload processing** → Add → **Add suffix** `:x` → Add → **Encode → Base64-encode**. Untick **URL-encode these characters** at the bottom.
3. The PASSWORD for a known user: Payloads = password list → Add prefix `<user>:` → Base64-encode. Untick URL-encode.
4. Odd Status / Length = hit. Select its payload → **Decoder** → Decode as Base64 → read `user:pass`.

### Step 5: the same job from the terminal (faster for big lists)
The free edition slows Intruder down on purpose. More than a few hundred tries → hydra or ffuf:
```bash
seq -f "user%03g" 0 99 > users.txt                                                  # username list from the pattern in the Q
# pop-up login (Basic auth) = hydra http-get
hydra -l <user> -P <wordlist> -f -t 4 $IP http-get /dir/login.php                   # ONE user, password list
hydra -L users.txt -P <wordlist> -f -t 4 $IP http-get /dir/login.php                # user list × password list (slower)
# HTML form = hydra http-post-form  "path:body:F=text shown when login FAILS"
hydra -l <user> -P <wordlist> -f $IP http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid"
```
`-l` one user · `-L` user file · `-P` password file · `-f` stop at the first hit · `-t 4` four at a time (`-t 1` when told the server blocks) · `-s PORT` other port · `-S` https · `-V` show each try.
Field names (`username`, `password`) and the fail text come from Step 1 (HTTP history). Full detail: [04_web_brute](04_web_brute.md).

### Step 6: small tools
- **Decoder**: paste → **Decode as** Base64 / URL / Hex (or **Smart decode**) → edit → **Encode as** the same → paste back into Repeater.
- **Comparer**: right-click a response → **Send to Comparer** (do it for two responses) → Comparer → **Words** → differences highlighted.
- Request → terminal: right-click → **Copy as curl command (bash)**.
- Request → sqlmap: right-click → **Copy to file** `req.txt` → `sqlmap -r req.txt --batch --dump` → [05_sqli](05_sqli.md).
- A button does the work and the address never changes → the request is in HTTP history (look for POST / JSON) → Send to Repeater.

### Helpline
```bash
# Burp's browser will not open (Kali, running as root) → Settings → Tools → Burp's browser → tick "Allow Burp's browser to run without a sandbox".
# page hangs forever → Intercept is ON and holding the request → press Forward, or switch Intercept off.
# nothing appears in HTTP history → you are browsing in Firefox, not in Burp's own browser.
# localhost / 127.0.0.1 targets do not show → use the machine's real IP or name.
# Intruder: every row identical → wrong part marked with §, or the fail page is the same for every value → compare by Length, add Grep - Match.
# Intruder: every Basic-auth try 401 with odd payloads → "URL-encode these characters" still ticked (it turns = into %3d).
# Intruder crawls → free edition is throttled → Step 5 (hydra / ffuf) for anything over a few hundred tries.
# hydra says EVERY password is valid → wrong module (form vs pop-up) or wrong F= text.
# length differs on every row (page echoes your value) → sort by Status, or use Grep - Match instead of Length.
# no Burp at all → browser F12 → Network tab shows the same request; right-click → Copy as cURL.
```
