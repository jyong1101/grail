# Stego & File Forensics

## Goal
Find data hidden in / after / inside a file. Cheap checks first, stop when something shows.

**Fast path (script)** — all scripts: [15_scripts](15_scripts.md)
```bash
ctf --analyze <file>              # any file: what it is, flags inside, which command next
ctf --stegchain pic.jpg           # metadata → decode → steghide (empty + found passphrases) → appended data → morse / base32
ctf --lsb pic.png                 # PNG bit planes, also saved as pictures to LOOK at
ctf --pcap cap.pcap               # plain capture: logins in clear text, forms, files, flags
ctf --folder ~/exam/files         # all of the above on every file in the folder
```
Misses / wrong → by hand below.

**Checklist** (in this order)
- [ ] `file` · `exiftool` · `strings`
- [ ] `binwalk`
- [ ] `steghide` with EMPTY passphrase (jpg / bmp / wav)
- [ ] passphrase hunt (metadata, Q text, web page) → then wordlist
- [ ] png / bmp → `zsteg`
- [ ] result unreadable → [09_decode](09_decode.md)

# Commands

### Step 0: file is on a web page → get the original
```bash
wget "http://$IP/path/pic.jpg"                                         # never screenshot / re-save
wget -nd -r -l1 -A 'jpg,jpeg,png,gif,bmp,wav' -P img http://$IP/       # every image on the page
```

### Step 1: look
```bash
file pic.jpg                               # real type (extension can lie)
exiftool pic.jpg                           # Comment / Author / Description ← flags + passphrases sit here
strings -n 6 pic.jpg | grep -iE 'flag|pass|key|ctf|\{'
strings -n 6 pic.jpg | tail -20            # text appended at the end
xxd pic.jpg | tail -5                      # hex view of the end (head -3 for the header)
```

### Step 2: files inside the file
```bash
binwalk pic.jpg                            # lists embedded zip / png / …
binwalk -e pic.jpg                         # extract → _pic.jpg.extracted/
unzip pic.jpg                              # works when a zip is appended
foremost -i pic.jpg -o carved/
```

### Step 3: steghide (JPG, BMP, WAV, AU only)
```bash
steghide extract -sf pic.jpg               # at "Enter passphrase:" just press Enter first
steghide extract -sf pic.jpg -p '<pass>'
cat <file it wrote>
steghide info pic.jpg                      # shows embedded file name (asks passphrase too)
```
Passphrase candidates: exiftool Comment (decode it if base64) · words in Q / title / page · file name · earlier flags and passwords.

### Step 4: passphrase unknown → wordlist
```bash
stegseek pic.jpg /usr/share/wordlists/rockyou.txt          # seconds; result in pic.jpg.out
# no stegseek installed:
for p in $(cat wordlist.txt); do steghide extract -sf pic.jpg -p "$p" -xf loot.txt -f -q 2>/dev/null && { echo "PASS=$p"; break; }; done
```

### Step 5: PNG / BMP / GIF / audio / text
```bash
zsteg -a pic.png                           # LSB-hidden text (png / bmp)
pngcheck -v pic.png                        # broken or extra chunks
python3 -c "from PIL import Image; im=Image.open('pic.png').convert('RGB'); [Image.eval(c,lambda v:(v&1)*255).save(n+'0.png') for c,n in zip(im.split(),'rgb')]"   # bit 0 of each colour as r0.png g0.png b0.png → OPEN them: drawn text / QR is seen, not read
exiftool anim.gif                          # GIF Comment field
convert anim.gif frame_%02d.png            # split animation into frames
stegsnow -C note.txt ; cat -A note.txt     # hidden spaces/tabs in text
```
Audio: Audacity / Sonic Visualiser → spectrogram view; beeps = morse → [09_decode](09_decode.md).
Online (if allowed): futureboy.us/stegano/decinput.html (steghide in browser) · aperisolve.com · stegonline.georgeom.net

### Step 6: file won't open / `file` says "data" → header bytes
| Type | Starts with (hex) |
|---|---|
| JPG | `FF D8 FF` (ends `FF D9`) |
| PNG | `89 50 4E 47 0D 0A 1A 0A` |
| GIF | `47 49 46 38` ("GIF8") |
| ZIP / docx | `50 4B 03 04` ("PK") |
| PDF | `25 50 44 46` ("%PDF") |
| ELF | `7F 45 4C 46` |
| RAR · 7z · GZ | `52 61 72 21` · `37 7A BC AF` · `1F 8B` |

`xxd file | head -1` vs table → wrong extension: rename; wrong bytes: fix with `hexedit file`.

### Step 7: ordinary (non Wi-Fi) pcap
```bash
strings -n 6 cap.pcap | grep -iE 'flag|pass|user'
tshark -r cap.pcap -q -z io,phs                                       # which protocols are inside
tshark -r cap.pcap -Y http.request -T fields -e http.request.method -e http.host -e http.request.uri
tshark -r cap.pcap -Y 'http.request.method == "POST"' -T fields -e http.request.uri -e urlencoded-form.key -e urlencoded-form.value     # logins
tshark -r cap.pcap -q -z follow,tcp,ascii,0                           # read conversation 0, then 1, 2 …
tshark -r cap.pcap --export-objects http,objs                         # save transferred files → run Steps 1–5 on them
# logins sent in clear text (sniffing):
tshark -r cap.pcap -Y 'ftp.request.command == "USER" || ftp.request.command == "PASS"' -T fields -e ftp.request.command -e ftp.request.arg
tshark -r cap.pcap -Y 'pop.request.command == "USER" || pop.request.command == "PASS" || imap.request' -T fields -e pop.request.command -e pop.request.parameter -e imap.request
tshark -r cap.pcap -Y http.authbasic -T fields -e http.host -e http.authbasic                # browser pop-up login, already decoded user:pass
tshark -r cap.pcap -Y telnet -T fields -e telnet.data | tr -d '\n' ; echo                    # telnet types one letter per packet (letters may show doubled)
tshark -r cap.pcap -Y dns.qry.name -T fields -e dns.qry.name | sort -u                       # names looked up (data hidden in DNS names → [09_decode](09_decode.md))
tshark -r cap.pcap -Y 'ftp-data' -T fields -e ftp-data.command -e data.data | head           # file sent over FTP → easier: Wireshark, Follow → TCP Stream → Save as raw
sqlite3 found.db .tables ; sqlite3 found.db .dump | grep -iE 'flag|pass'                     # a .db / .sqlite file came out
```
Wireshark: right-click packet → Follow → TCP Stream · File → Export Objects → HTTP. Wi-Fi capture → [10_wireless](10_wireless.md).

### Helpline
```bash
# steghide "could not extract any data with that passphrase" = wrong passphrase (or nothing hidden).
# steghide "file format … not supported" = png/gif → zsteg / binwalk / strings instead.
# extracted text = dots and dashes → morse; ends with = → base64 / base32 → [09_decode](09_decode.md)
# ONE extracted file can hold several answers (first plain, second encoded) → read all of it.
# http.file_data prints hex → pipe through: xxd -r -p
```
