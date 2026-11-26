# Services (route by port)

## Goal
Every open port = free loot or the hint for the next step. Connect, list, download all, read all.

**Fast path (script)** — all scripts: [15_scripts](15_scripts.md)
```bash
ctf --enum $IP                                        # FTP / SMB / SSH banner / SNMP / DNS / odd ports in one run, flags in the box at the end
ctf --banner $IP:$PORT --send 'id; ls -la; cat flag*'  # one odd port that waits for input
ctf --brute ftp://$IP:$PORT --user <name>              # password guessing: ftp ssh telnet mysql pop3 imap
```
Misses / wrong → by hand below.

**Checklist**
- [ ] every open port touched with a client?
- [ ] unknown port → `nc` AND `curl` it
- [ ] no-password access tried? (ftp `anonymous`, smb `-N`, snmp `public`)
- [ ] every downloaded file read? (hints name the next service / share / user)
- [ ] creds found → retry on ssh, ftp, web login, zip, steghide

# Commands

### Any port: first touch
```bash
nc -nv $IP $PORT                   # banner / flag / prompt. "backdoor" Qs: flag may simply print. Ctrl+C quits
curl -s http://$IP:$PORT/          # answers HTTP? → [03_web_enum](03_web_enum.md)
nmap -Pn -sV -sC -p $PORT $IP
nmap -Pn --script banner -p $PORT $IP          # banner grab with nmap (lecture 3)
```
Talking to a port by hand with `nc` (when the client tool is missing, or the port is unknown):
```bash
nc -nv $IP $PORT                                   # connect, read the banner; nothing shown → press Enter, type HELP / help / ?
nc -nv -w3 $IP $PORT </dev/null                    # banner only, give up after 3 s (does not hang)
echo | nc -nv -w3 $IP $PORT                        # same but sends one Enter first (some services wait for it)
echo 'HELP' | nc -nv -w3 $IP $PORT                 # send one line, read the reply
for p in 21 22 23 25 80 110 143 2222 8080 31337; do echo "== $p"; nc -nv -w2 $IP $p </dev/null 2>&1 | head -3; done    # banner of each open port in one go
nc -zv -w1 $IP 20-100 2>&1 | grep -E 'open|succeeded'      # port sweep with nc alone ("first 100 ports", nmap not allowed)
nc -nvu -w2 $IP 161                                # UDP port (-u); silence is normal for UDP
printf 'GET / HTTP/1.0\r\nHost: %s\r\n\r\n' "$IP" | nc -w3 $IP 80 | head -20         # web server by hand: Server: header = software (+ Linux name in brackets)
printf 'HEAD / HTTP/1.0\r\n\r\n' | nc -w3 $IP $PORT                                   # is this odd port HTTP? headers only
printf 'USER anonymous\r\nPASS x\r\nPWD\r\nQUIT\r\n' | nc -w3 $IP 21                 # FTP login by hand: 230 = in
printf 'USER <user>\r\nPASS <pass>\r\nLIST\r\nRETR 1\r\nQUIT\r\n' | nc -w3 $IP 110   # POP3 mailbox: list + read mail 1
printf 'EHLO x\r\nVRFY root\r\nQUIT\r\n' | nc -w3 $IP 25                              # SMTP: banner names the software; VRFY tests a user name
nc -nv $IP $PORT | tee port_$PORT.txt              # keep a copy of everything it prints
nc -nv $IP $PORT | xxd | head                      # reply looks empty / garbled → see the raw bytes
```
- `-n` no DNS lookup · `-v` say "open" / "refused" · `-w N` stop after N s of silence · `-u` UDP · `-z` only test if open.
- "Connection refused" = closed · hangs with no text = open but waiting for YOU (press Enter) or filtered · `(UNKNOWN) … open` = connected.
- Service wants lines ending `\r\n` (HTTP, FTP, SMTP, POP3) → use the `printf` forms above; plain `echo` sends only `\n`.
- ncat instead of nc (TLS port, e.g. 443 / 993): `ncat --ssl $IP 443` · or `openssl s_client -connect $IP:443 -quiet`

Asks you to enter a string → [12_bof](12_bof.md) / [13_fmt](13_fmt.md) · wants a fast reply → [11_nc_scripting](11_nc_scripting.md)

### 21 FTP (also on odd ports)
```bash
curl -s --user anonymous: ftp://$IP/                    # list        (odd port: ftp://$IP:$PORT/)
curl -s --user anonymous: ftp://$IP/ -X 'LIST -a'        # list WITH hidden .files (plain listing skips them)
curl -s --user anonymous: ftp://$IP/README.txt          # print a file
curl -s --user anonymous: -O ftp://$IP/dir/file.zip     # download
wget -m ftp://anonymous:anonymous@$IP                   # mirror everything
ftp $IP $PORT                                           # Name: anonymous   Password: <Enter>
#   ls -la | cd dir | binary | get file | mget * | passive | bye
```
zip → [07_crack](07_crack.md) · image → [08_stego_forensics](08_stego_forensics.md)

### 22 SSH (often moved: 2222 …)
```bash
ssh -p $PORT anyname@$IP           # text shown before the password prompt may be the flag / hint
ssh -p $PORT <user>@$IP            # with found creds · key file / inside the shell → [16_shell](16_shell.md)
```

### 139 / 445 SMB
```bash
smbclient -L //$IP -N                          # list shares, no password
smbclient //$IP/<share> -N                     # inside:  ls | cd dir | get file | more file | exit
smbclient //$IP/<share> -N -c 'recurse ON; prompt OFF; mget *'     # download everything
smbclient //$IP/<share> -U '<user>%<pass>'     # with creds
enum4linux -a $IP                              # users + shares overview
nbtscan $IP ; nmblookup -A $IP                 # NetBIOS name / workgroup of the box (lecture 3)
```

### 53 DNS
```bash
dig axfr @$IP <domain>             # zone transfer = every record; read TXT lines + new hostnames
dig @$IP <domain> TXT              # single record types: TXT, ANY, NS, MX, A
dig @$IP <sub>.<domain> TXT
dig -x $IP @$IP                    # domain unknown → reverse lookup names it; also try the name on the web page / in the FTP readme
for s in www dev admin login flag test staging mail ns1; do echo "$s: $(dig +short @$IP $s.<domain> A $s.<domain> TXT | tr '\n' ' ')"; done     # AXFR refused → guess names
```
Domain comes from the Q / a web page / nmap output. New hostnames → [03_web_enum](03_web_enum.md) Step 6.

### 161/udp SNMP ("monitoring", "not everything is TCP")
```bash
snmpwalk -v2c -c public $IP                        # dump; flag hides in a STRING line (location / contact / description)
snmpwalk -v2c -c public $IP | grep -iE 'flag|STRING'
snmpwalk -v1 -c public $IP                         # if v2c is silent
snmp-check $IP
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt $IP     # guess community
```

### Other
```bash
telnet $IP 23
mysql -h $IP -u <user> -p --skip-ssl               # 3306 with creds:  show databases; use db; show tables; select * from t;
```

### Helpline
```bash
# FTP "230 Login successful" = in. Listing hangs → type passive (toggle) or use the curl form.
# FTP: type binary before get on zip/images (or use curl -O), else file corrupts.
# SMB NT_STATUS_ACCESS_DENIED on one share → try the next share.
# AXFR "Transfer failed" = refused → query TXT/ANY by hand; guess names: www dev admin login flag.
# SNMP "Timeout: No Response" = wrong community or version (it never says "wrong password").
# port prints nothing → press Enter / type HELP; try nc AND curl AND browser.
# title = riddle for the port/protocol (numbers adding up to a port, "sharing" = SMB, "not TCP" = UDP).
```
