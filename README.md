# Grail — CTF field notes

Personal open-book notes for a practical CTF: one page per topic, each page laid out the same way so it can be used under time pressure.

## How to use
1. Open [00_INDEX](00_INDEX.md). Find the clue from the question in the router table → it names the page.
2. On the page, top to bottom: **Goal** → **Fast path (script)** → **Checklist** → **Commands** (by hand, step by step) → **Helpline** (what an error or odd result means).
3. Stuck for more than `marks × 2.5 min` → [99_STUCK](99_STUCK.md), then move on.

Every command uses `$IP` (and `$PORT`). Set them once per terminal tab:
```bash
export IP=<target>  PORT=<port>
```

## Pages
| Page | Use it for |
|---|---|
| [00_INDEX](00_INDEX.md) | first 5 minutes · clue → page router · likely flows · time budget |
| [01_recon](01_recon.md) | what is it: web server, OS, country, open ports, software versions |
| [02_services](02_services.md) | FTP · SSH banner · SMB · DNS · SNMP · unknown ports · talking to a port with `nc` |
| [03_web_enum](03_web_enum.md) | page source, robots, hidden folders and files, virtual hosts, numbers in the URL |
| [04_web_brute](04_web_brute.md) | login pages: username list from a naming pattern, password guessing |
| [05_sqli](05_sqli.md) | SQL injection: by hand and with sqlmap, cookies / JSON / blind / filters |
| [06_lfi](06_lfi.md) | file inclusion: traversal, filter bypass, reading PHP source |
| [07_crack](07_crack.md) | hashes, locked zip / pdf / ssh key, OpenSSL-encrypted text |
| [08_stego_forensics](08_stego_forensics.md) | hidden data in images / audio / files, file headers, plain packet captures |
| [09_decode](09_decode.md) | recognise an encoding by its look and decode it |
| [10_wireless](10_wireless.md) | Wi-Fi captures: crack, decrypt, SSID / BSSID / AID, evil twin |
| [11_nc_scripting](11_nc_scripting.md) | services that need exact bytes or fast answers |
| [12_bof](12_bof.md) | buffer overflow, explained from zero, with the one-liners |
| [13_fmt](13_fmt.md) | format strings: leak with `%p` / `%s`, write with `%n` |
| [14_web_inject](14_web_inject.md) | command injection, XSS, cookie tokens, ports that take commands |
| [15_scripts](15_scripts.md) | which script to run for which kind of question, and how to read its result |
| [16_shell](16_shell.md) | a password, key or shell was found: log in, look around, read the flag |
| [17_burp](17_burp.md) | Burp Suite from zero: history, Repeater, Intruder, Basic-auth payloads, hydra equivalents |
| [98_SETUP](98_SETUP.md) | do before the day: tools, wordlists, checks |
| [99_STUCK](99_STUCK.md) | 60-second reset when nothing works |

## Scripts the notes refer to
- `bof-scripts/` — my own solver for overflow and format-string services: https://github.com/jyong1101/bof-scripts (`python3 bof-scripts/go.py HOST PORT [binary] [source.c] [notes.txt]`).
- `ctf` — a classmate's all-category helper script, installed as a command.
- `sql/sqlauto.py` — small SQL-injection helper used on the SQLi page.

Each page also works without any of them: skip the "Fast path" block and follow **Commands**.

## Scope
Only for targets a challenge or lab names. Standard-library Python and the usual Kali tools; no online services are required.
