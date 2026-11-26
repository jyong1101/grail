# ICT2212 CTF — Index

Loop: read Q → match clue in router → open note → steps top-down → submit → next.
**Scripts first** → [15_scripts](15_scripts.md) (start `ctf --auto` in its own tab, then one command per Q). No new result in `marks × 2.5 min` → skip, return later. Stuck → [99_STUCK](99_STUCK.md). Night before → [98_SETUP](98_SETUP.md).

## First 5 minutes
```bash
export IP=1.2.3.4                     # ← real target IP. Every command uses $IP ; re-export when Q switches to the other IP
mkdir -p ~/exam && cd ~/exam          # all downloads + outputs here
nmap -Pn -sV $IP -oN nmap_$IP.txt     # own tab. Paper limits scanning ("first 100 ports only")? → add -p 1-100 BEFORE running
```
- [ ] read ALL questions + marks first → cheapest marks first
- [ ] which IP belongs to which questions?
- [ ] answer format = the example in the Q (name only? no version? only the text inside `flag{}`?)
- [ ] slow jobs (hydra / aircrack / sqlmap / gobuster) → own tab, work on next Q meanwhile
- [ ] every password / string / hint found → `~/exam/loot.txt` (reused later)

## Router: clue → note
| Clue in question / what you see | Open |
|---|---|
| web server name · OS / Linux name · country hosted · open port · software on port · "don't use nmap" | [01_recon](01_recon.md) |
| ftp · anonymous · smb / share · dns / zone · snmp / monitoring / UDP · odd port · ssh banner · "backdoor" · `nc` | [02_services](02_services.md) |
| web root · robots · hidden directory / file · inspect / source / comment · subdomain / vhost · number in URL · 403 | [03_web_enum](03_web_enum.md) |
| login page · username naming convention · brute-force · wordlist given | [04_web_brute](04_web_brute.md) |
| box that pings / runs something · page shows your text back · `<script>` · alert · cookie / token / JWT · port that takes commands | [14_web_inject](14_web_inject.md) |
| search box · database · `id=1` · SQL error · "dump" · DB user / authentication string | [05_sqli](05_sqli.md) |
| `?page=` `?file=` `?lang=` · read a file · folder beside web root · need `.php` source | [06_lfi](06_lfi.md) |
| zip / rar / pdf password · hash · "forgot password" · text starting `U2FsdGVkX1` | [07_crack](07_crack.md) |
| image / audio / file given · "hidden" · "whisper" · "steg" · picture on the web page | [08_stego_forensics](08_stego_forensics.md) |
| unreadable text: `==` · dots/dashes · `pi pika` · hex · 0/1 · "rotated" · "base" · odd unicode · AES key | [09_decode](09_decode.md) |
| `.cap` / `.pcap` · Wi-Fi · WPA · handshake · KEK · SSID / BSSID · deauth · evil twin | [10_wireless](10_wireless.md) |
| "type this exactly" · too slow by hand · timed questions over `nc` | [11_nc_scripting](11_nc_scripting.md) |
| C source with `gets` / `strcpy` / `read` · `win()` · "smash the stack" · return address | [12_bof](12_bof.md) |
| `printf(buf)` · service repeats what you type · `%x` · output shows more than you sent | [13_fmt](13_fmt.md) |
| password / SSH key found · "log in" · command box → shell · reverse shell · flag not readable · sudo | [16_shell](16_shell.md) |
| Burp · intercept / Repeater / Intruder · "what does the button send" · change a request and resend | [17_burp](17_burp.md) |
| which script for which question · reading the flags box | [15_scripts](15_scripts.md) |

No clue word → search all notes: `grep -rniE 'word' <this folder>`

## Likely flows (the output of one step is the input of the next)
```text
Box, first look
  scan → version / banner answers → web server + Linux name → country                    → 01_recon
  every open port touched: FTP anonymous · SMB no password · DNS zone · SNMP public       → 02_services
  odd port → nc + curl → prints a flag / waits for input / takes commands                 → 02_services, 14_web_inject

Web site
  page source + css + js → robots.txt → listed folder → directory listing → file          → 03_web_enum
  other host name on the same IP → new site → start again                                 → 03_web_enum
  number in the URL → change it → hidden page                                             → 03_web_enum
  login page → cheap tries → username list from the naming pattern → password brute       → 04_web_brute
  logged in → flag on the page / in a file listed there / in the cookie                   → 03_web_enum, 14_web_inject
  search box / id= → ' → all rows → other tables → DB accounts                            → 05_sqli
  ?page= / ?file= → ../ → filter bypass → php source as base64                            → 06_lfi
  box that runs a command / shows your text back                                          → 14_web_inject

Files
  anonymous FTP / share → readme names the next service → zip → crack → flag              → 02_services, 07_crack
  hash or locked file → identify → wordlist → password → reuse it everywhere              → 07_crack
  string that starts U2FsdGVkX1 + a passphrase → openssl                                  → 07_crack
  image → metadata → passphrase → steghide → morse / base32 / base64                      → 08_stego_forensics, 09_decode
  unreadable text → recognise the look → decode → repeat until readable                   → 09_decode
  plain capture → logins in clear text / files transferred                                → 08_stego_forensics

Wireless capture
  handshake → crack → key into Wireshark → the value asked for / web traffic              → 10_wireless
  frames only → hidden SSID, BSSID, association ID · deauth → twin AP → stolen login      → 10_wireless

Port + C source / binary
  timed or "type this exactly" service                                                    → 11_nc_scripting
  overflow: neighbour variable → return address → flag function / shellcode               → 12_bof
  printf(input): read the stack → read a pointer → write with %n                          → 13_fmt

Got a password or key anywhere → try it on ssh, ftp, web login, zip, steghide             → 16_shell
```

## Usual paper shape (gauge only)
- Part 1, first IP: recon answers → web enum → login brute → flags. Short answers, do first.
- Part 2, second IP / files: wireless capture · web attacks · stego · `nc` service + BOF · format string.
- Challenge titles are puns → they name the tool / port / technique. Read them twice.

## Time
3 h ≈ 70 marks → ~2.5 min per mark. 4-mark Q = 10 min max, then move on. Last 15 min: re-submit sure answers, check formats.
