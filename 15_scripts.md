# Scripts: what to run first

## Goal
Scripts take the first pass on every question; whatever they miss goes to the by-hand note. Never wait on a script: start it, move on.

Two tools:
- `ctf` = classmate's kit (all categories). Installed as a command. Help: `ctf --help` · check the machine: `ctf --doctor $IP`
- `bof-scripts/` = my own (overflow + format string only). Run from the folder that contains `bof-scripts/`.

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

### Helpline
```bash
# ctf: command not found → bash <kit folder>/ctf-auto.sh <same arguments>
# a ctf run prints "ctf --do N" suggestions → they are the next step, run them.
# --auto still on a binary port after minutes → leave it; do that port yourself with go.py in tab 2.
# a script says "plain value" / "the program said something new" with no flag → treat as NOT solved, check by hand.
# password guessing is never started by --enum / --auto → run the printed --form-brute / --brute / --ssh-brute line in its own tab.
# never point a script at the CTFd scoreboard site, only at targets the paper names.
```
