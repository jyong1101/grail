# Setup (do BEFORE exam day, needs internet)

## Goal
Every tool the notes call exists on the exam VM, wordlists are in place, nothing has to be searched for during the paper.

**Checklist**
- [ ] missing tools installed (Step 1) and re-checked (Step 2)
- [ ] rockyou unpacked; module wordlist from LMS saved in `~/exam/`
- [ ] offline CyberChef opens in the browser
- [ ] this folder + `bof-scripts/` + `sql/` on the exam machine; `python3 bof-scripts/go.py -h` runs
- [ ] classmate's kit installed: `ctf --help` first line shows the version; `ctf --doctor 127.0.0.1` has no [FIX] line
- [ ] VM reaches the internet; sudo password known

# Commands

### Step 1: install what this Kali lacks
```bash
sudo apt update
sudo apt install -y stegseek fcrackzip stegsnow pngcheck hexedit gcc-multilib
sudo gem install zsteg
python3 -m venv ~/venv && ~/venv/bin/pip install base65536        # used as: ~/venv/bin/python -c "import base65536…"
```
Optional (audio stego): `sudo apt install -y audacity`

### Step 2: verify everything
```bash
for t in nmap nc curl whois dig whatweb gobuster ffuf hydra sqlmap john zip2john fcrackzip hashid hashcat \
  steghide stegseek exiftool binwalk foremost zsteg strings xxd aircrack-ng airdecap-ng tshark wireshark \
  snmpwalk onesixtyone smbclient ftp expect gdb gcc objdump ROPgadget msf-pattern_create pwn openssl crunch burpsuite; do
  command -v $t >/dev/null || echo "MISSING: $t"; done
python3 -c "import pwn, Cryptodome, numpy; print('python libs ok')"
~/venv/bin/python -c "import base65536; print('base65536 ok')"
```

### Step 3: wordlists
```bash
ls -lh /usr/share/wordlists/rockyou.txt || sudo gunzip /usr/share/wordlists/rockyou.txt.gz
ls /usr/share/wordlists/dirb/common.txt /usr/share/seclists/Discovery/Web-Content/ | head -3      # seclists missing → sudo apt install seclists
mkdir -p ~/exam        # put the module's wordlist from LMS here
```

### Step 4: offline CyberChef
github.com/gchq/CyberChef/releases → download `CyberChef_vX.zip` → unzip → open `CyberChef_vX.html` in Firefox → bookmark. Works with no internet.

### Step 5: toolkit + notes
```bash
cd <folder that holds bof-scripts/> && python3 bof-scripts/solve.py -h | head -3
bash bof-scripts/smoke.sh                                                # 30 s: are the tools alive?  (selftest.sh = full gate, ~1 h)
grep -rniE 'kek' <notes folder> | head -2                           # search across notes works
```

### Step 6: network sanity (also when the VM "loses" internet mid-exam)
```bash
ping -c1 8.8.8.8 ; curl -sI https://example.com | head -1
sudo systemctl restart NetworkManager                               # VM side
```
VMware host side (Windows admin prompt): `net stop "VMware NAT Service" & net start "VMware NAT Service"` (same for "VMware DHCP Service").

### Helpline
```bash
# pip refuses ("externally-managed-environment") → use the venv line above, not sudo pip.
# gcc -m32 fails (missing headers) → gcc-multilib from Step 1.
# sqlmap --eval needs the prefix SQLMAP_UNSAFE_EVAL=1 on this sqlmap version.
# shell is zsh: quote every URL; unquoted $var is NOT split into words (use explicit args).
# nmap -O / -sU, wireshark capture, tee /etc/hosts need sudo → test the password now.
```
