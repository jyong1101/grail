# Web Enumeration

## Goal
Find what the site hides: comments, files, folders, other hostnames, other IDs.

**Fast path (script)** — all scripts: [15_scripts](15_scripts.md)
```bash
ctf --auto-web "http://$IP/"          # finds the inputs and runs every test it suggests + page source + comments
ctf --web "http://$IP"                # server, robots.txt, hidden directories and their files
ctf --source "http://$IP/page"        # comments, hidden fields, passwords in HTML / JS, encoded strings
```
Misses / wrong → by hand below.

**Checklist**
- [ ] page source + every linked `.css` / `.js` read?
- [ ] `/robots.txt`?
- [ ] folders opened with trailing `/` (directory listing)?
- [ ] brute dirs at root AND inside each folder found?
- [ ] other hostname / vhost?
- [ ] number in URL changed?
- [ ] images on page downloaded → [08_stego_forensics](08_stego_forensics.md)?

# Commands

### Step 1: source, comments, linked files ("inspect")
```bash
curl -s http://$IP/ | grep -iE 'flag|<!--|pass|hidden|key'
curl -s http://$IP/ | grep -oE '(href|src)="[^"]+"'            # every linked file → open each .css / .js
curl -s http://$IP/style.css | grep -iE 'flag|/\*'
curl -s http://$IP/script.js | grep -iE 'flag|//|/\*'
curl -sI http://$IP/                                            # odd headers, Set-Cookie
```
Browser: Ctrl+U = source · F12 → Sources / Network / Storage (cookies) / Console.
Flag may be split: part 1 in HTML comment, part 2 in CSS, part 3 in JS → join in order.

### Step 2: robots + usual suspects
```bash
curl -s http://$IP/robots.txt          # flag itself, or Allow/Disallow paths → visit every path listed
for p in sitemap.xml backup/ admin/ secret/ flag.txt flag .git/HEAD .env index.php.bak; do echo "$(curl -s -o /dev/null -w '%{http_code}' http://$IP/$p) $p"; done
```

### Step 3: directory listing
Open the folder itself: `http://$IP/<dir>/` → page "Index of /<dir>" lists files + sub-folders, including ones not linked anywhere. "Hidden directory" answer = folder name shown there.

### Step 4: brute dirs / files
```bash
gobuster dir -u http://$IP -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,bak,zip -t 30
gobuster dir -u http://$IP/<dir>/ -w /usr/share/wordlists/dirb/common.txt -x php,txt        # repeat inside each folder
ffuf -u http://$IP/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .php,.txt,.bak,.zip,.old
```
Bigger list: `/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt`

### Step 5: blocked (403 / empty / "automated client")
```bash
curl -s -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" http://$IP/path/file.txt     # look like a browser
curl -s -H "X-Forwarded-For: 127.0.0.1" http://$IP/admin/
```
or just open it in the browser.

### Step 6: other hostnames (vhosts) on the same IP
```bash
echo "$IP site.local dev.site.local login.site.local" | sudo tee -a /etc/hosts      # names from Q / DNS / page links
curl -s -H "Host: dev.site.local" http://$IP/                                       # test one name without editing hosts
ffuf -u http://$IP/ -H "Host: FUZZ.site.local" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <size of normal page>
```
Each new hostname = new site → redo Steps 1–4 on it. Try obvious ones by hand: `dev` `admin` `test` `staging` `login` `www`.

### Step 7: number in URL (IDOR)
```bash
for i in $(seq 0 20); do echo "$i $(curl -s "http://$IP/page.php?id=$i" | wc -c)"; done     # different size = different content
curl -s "http://$IP/page.php?id=7"
```
Links only show ids 1–5 → try 0, 6, 7 … Same trick: `?user=`, `?doc=2.txt`, numbers inside cookies.

### Step 8: grab files / images from the page
```bash
wget -nd -r -l1 -A 'jpg,jpeg,png,gif,bmp,wav' -P img http://$IP/      # all images → [08_stego_forensics](08_stego_forensics.md)
wget "http://$IP/path/file"
```

### Next
input box / `?id=` reacts to `'` → [05_sqli](05_sqli.md) · `?page=<file>` → [06_lfi](06_lfi.md) · login → [04_web_brute](04_web_brute.md) · box runs a command / page shows your text back / cookie token → [14_web_inject](14_web_inject.md)

### Helpline
```bash
# zsh "no matches found" → URL contains ? or & → wrap the URL in quotes.
# gobuster: "server returns a status code that matches … => 200 (Length: N)" → add --exclude-length N   (ffuf: -fs N)
# folder answers 403 → still brute inside it; files in it can be 200.
# curl shows nothing → -i (status + headers), -L (follow redirect), -k (https).
# cookie looks encoded → [09_decode](09_decode.md); then change it:  curl -b "role=admin" URL   (0→1, user→admin, guest→admin)
# other cheap tries on any input:  ; id   | id   $(id)   (command injection → 14_web_inject.md)
```
