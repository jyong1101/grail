# Recon & Scan

## Goal
Answer "what is it?" questions: web server, Linux name, country, open port, software on a port.

**Fast path (script)** — all scripts: [15_scripts](15_scripts.md)
```bash
ctf --enum $IP                       # ≈2 min: ports, versions, every service, every web site; ends with a numbered to-do list → ctf --do 1
ctf --enum $IP --ports 1-100         # Q limits the port range
```
Misses / wrong → by hand below.

**Checklist**
- [ ] Q bans nmap or limits ports? obey it (blocked IP = lost paper)
- [ ] `-Pn` on every nmap (cloud hosts ignore ping)
- [ ] answer = NAME only unless version asked (`nginx`, `vsftpd`, `Ubuntu Linux`)

# Commands

### Step 1: web server + Linux name WITHOUT nmap
```bash
curl -sI http://$IP | grep -i '^server'     # Server: nginx/1.18.0 (Ubuntu) → web server = nginx, Linux = Ubuntu
curl -sIL http://$IP                        # all headers, follows redirects (also X-Powered-By)
whatweb http://$IP                          # HTTPServer[..] + Country[..] in one go
curl -s http://$IP/nopage123 | tail -5      # 404 page footer often shows server + OS
```
Browser: F12 → Network → reload → click first row → Response Headers → `Server`.
Online (if allowed): builtwith.com → type the IP · Wappalyzer extension · shodan.io/host/<ip> · sitereport.netcraft.com (server, OS, hosting country) · web.archive.org (old versions of a page)

### Step 2: country / who hosts it
```bash
whois $IP | grep -iE 'country|orgname|netname'     # Country: US → United States
curl -s ipinfo.io/$IP                              # country, region, org
host $IP                                           # reverse DNS: ec2-…<region>.compute.amazonaws.com
nslookup <hostname>                                # given a name instead of an IP → its IP(s)
```
AWS name → place: `compute-1` = us-east-1 N. Virginia (US) · `us-east-2` Ohio · `us-west-1` N. California · `us-west-2` Oregon · `ap-southeast-1` Singapore · `ap-southeast-2` Sydney · `ap-northeast-1` Tokyo · `ap-south-1` Mumbai · `eu-west-1` Ireland · `eu-west-2` London · `eu-central-1` Frankfurt

### Step 3: open ports
```bash
nmap -Pn -p 1-100 $IP                   # "scan only the first 100 ports"
nmap -Pn $IP                            # top 1000 (default)
nmap -Pn -p 8000-8100 $IP               # a range named in the Q
nmap -Pn -p- --min-rate 1000 -T4 $IP    # all 65535: ONLY if Q allows; finds odd ports (2222, 31337 …)
sudo nmap -Pn -sU --top-ports 20 $IP    # UDP: snmp 161, dns 53, tftp 69
```

### Step 4: software / version on a port
```bash
nmap -Pn -sV -p 21,80 $IP               # VERSION column: vsftpd 3.0.5 | nginx 1.18.0 (Ubuntu)
nmap -Pn -sV -sC -p <port> $IP          # + default scripts (ftp-anon, http-title …). -A = -sV -sC -O together
nc -nv $IP <port>                       # raw banner, e.g. 220 (vsFTPd 3.0.5) / SSH-2.0-…
```

### Step 5: operating system
```bash
sudo nmap -Pn -O $IP                    # "OS guesses: Linux 4.15 …" → OS = Linux
```
Linux NAME (distro) = the bracket in a `-sV` line or the `Server:` header: `(Ubuntu)` `(Debian)` `(CentOS)` `(Amazon Linux)` `(Red Hat …)`. SSH banner `…p1 Ubuntu-3` / `…Debian-5` names it too.

### Step 6: known hole in that version ("which CVE / exploit", old software named in the Q)
```bash
searchsploit vsftpd 2.3.4               # software + version from the -sV line → titles of public exploits
searchsploit -x <path shown>            # read one (q quits)        searchsploit -m <path shown>   # copy it here
nmap -Pn --script vuln -p <port> $IP    # nmap's own check, names CVEs
```

### Next
port list → [02_services](02_services.md) · web port → [03_web_enum](03_web_enum.md)

### Helpline
```bash
# "Host seems down" → add -Pn.        -O / -sS / -sU need sudo.
# STATE: open = service listening | closed = reachable, nothing there | filtered = firewall dropped it
# slow → fewer ports (-p), add -T4.   Q warns "may be blocked" → no -p-, no -A, one scan at a time.
# name-only answers: "nginx" not "nginx 1.18.0" · "vsftpd" not "vsftpd 3.0.5" (Q example shows the wanted form).
# SERVICE column is a guess from the port number; trust VERSION (-sV) or the banner.
# -oN file.txt saves output → re-read, don't re-scan.
# zsh "no matches found" → put the URL in quotes.
```
