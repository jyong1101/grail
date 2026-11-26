# Cracking (archives, hashes, encrypted text)

## Goal
Recover the password with a wordlist, open the thing.

**Fast path (script)** — all scripts: [15_scripts](15_scripts.md)
```bash
ctf --crack <hash | file with hashes>         # names the hash type, runs john, shows the password   ( --wordlist <list> )
ctf --crack <id_rsa | x.zip | x.pdf | x.7z | x.rar | x.kdbx | x.docx>    # locked file: runs the matching *2john first
```
Misses / wrong → by hand below.

**Checklist**
- [ ] `file x` → what is it really?
- [ ] wordlist: the one the Q gives first, else rockyou
- [ ] cracked password reused elsewhere? (ssh, web login, steghide, other zip)

# Commands

### Step 1: zip
```bash
zip2john secret.zip > zip.hash
john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash      # (john zip.hash alone = default modes, fine for weak passwords)
john --show zip.hash                                           # print the cracked password again
unzip -P '<pass>' secret.zip                                   # or: 7z x -p'<pass>' secret.zip
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt secret.zip # alternative tool
```

### Step 2: other protected files (same pattern: `X2john` → `john`)
```bash
rar2john f.rar > h      7z2john f.7z > h       pdf2john f.pdf > h      office2john f.docx > h
ssh2john id_rsa > h     keepass2john f.kdbx > h
john --wordlist=/usr/share/wordlists/rockyou.txt h ; john --show h
ls /usr/bin /usr/sbin | grep 2john                             # list all converters
```

### Step 3: bare hash
```bash
hashid '<hash>'                                                # or identify by length ↓
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt ; john --show --format=raw-md5 hash.txt
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt         # add --show to reprint
```
| Looks like | Type | john `--format=` | hashcat `-m` |
|---|---|---|---|
| 32 hex | MD5 | raw-md5 | 0 |
| 40 hex | SHA1 | raw-sha1 | 100 |
| 64 hex | SHA256 | raw-sha256 | 1400 |
| 128 hex | SHA512 | raw-sha512 | 1700 |
| `*` + 40 HEX | MySQL | mysql-sha1 | 300 (delete the `*` first) |
| `$1$…` | md5crypt | md5crypt | 500 |
| `$6$…` | sha512crypt (Linux shadow) | sha512crypt | 1800 |
| `$y$…` | yescrypt (new Linux) | crypt | n/a |
| `$2y$` `$2b$` | bcrypt | bcrypt | 3200 |
| 32 hex from Windows | NTLM | nt | 1000 |

Linux files: `unshadow passwd shadow > u.txt ; john --wordlist=… u.txt`. Online (if allowed): crackstation.net
Hash not in the table → compare its look with the full list (every type, its `-m` number and a sample): https://hashcat.net/wiki/doku.php?id=example_hashes · same list offline: `hashcat --example-hashes | less`
Hash is itself encoded (base64 / hex wrapped) → decode first: https://gchq.github.io/CyberChef/ ("Magic") or [09_decode](09_decode.md)

### Step 4: OpenSSL-encrypted text (base64 beginning `U2FsdGVkX1` = "Salted__") + password given
```bash
echo -n 'U2FsdGVkX1…' | openssl enc -aes-256-cbc -d -base64 -A -pass pass:'<password>'
# "bad decrypt" → add -pbkdf2 ; still bad → add -md sha256, then -md md5 (use the exact options the Q shows) ; cipher may differ: -aes-128-cbc
openssl enc -aes-256-cbc -d -a -in file.enc -out out.txt -pass pass:'<password>'       # from a file
```

### Helpline
```bash
# john "No password hashes loaded" → wrong --format, or already cracked (john --show h).
# john calls a 32-hex hash "LM" → force --format=raw-md5.
# rockyou missing → sudo gunzip /usr/share/wordlists/rockyou.txt.gz
# base64 / hex are ENCODINGS, not hashes → decode, don't crack → [09_decode](09_decode.md)
# john running: any key = status, q = stop. Found passwords live in ~/.john/john.pot
# unzip -l file.zip lists names without the password → names are hints.
# not in wordlist → hints in Q (name, year, pattern) → crunch <len> <len> -t <pattern>   (@ lower  , upper  % digit  ^ symbol)
```
