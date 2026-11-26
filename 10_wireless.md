# Wireless (802.11 `.cap` / `.pcap`)

## Goal
Crack the Wi-Fi password from the handshake → decrypt → read what is inside (KEK, web traffic, logins). Or answer SSID / BSSID / AID questions straight from the frames.

**Fast path (script)** — all scripts: [15_scripts](15_scripts.md)
```bash
ctf --wifi-crack wifi.cap                  # handshake → password → decrypt → KEK, traffic, flags   ( --ssid '<name>' --wordlist <list> ; WEP too )
ctf --wifi-hidden survey.pcap              # hidden SSID + BSSID + AID for every client that got in   ( one client: add its MAC as the last word )
ctf --evil-twin twin.pcap                  # finds the twinned network, the victim and the stolen login   ( --ssid '<name>' --psk '<wifi password>' when the Q gives them )
FLAGFMT=SIT ctf --wifi-hidden survey.pcap  # answer wanted as SIT{…} → put the wrapper in front
```
Misses / wrong → by hand below.

**Checklist**
- [ ] `aircrack-ng file` → which networks, which has a handshake?
- [ ] password already given in the Q? → skip cracking, go to Step 3
- [ ] cracked with the Q's wordlist, else rockyou?
- [ ] key entered in Wireshark → EAPOL / data decoded?
- [ ] answer format (hex string? decimal? colons or not?)

# Commands

### Step 1: what is in the capture
```bash
aircrack-ng wifi.cap                  # table: # · BSSID · ESSID · Encryption  →  "WPA (1 handshake)" = crackable
```

### Step 2: crack
```bash
aircrack-ng -w /usr/share/wordlists/rockyou.txt wifi.cap                 # → KEY FOUND! [ password ]
aircrack-ng -w /usr/share/wordlists/rockyou.txt -e '<ESSID>' wifi.cap    # several networks: choose by name (or -b <BSSID>)
aircrack-ng wifi.cap                                                      # WEP: no wordlist needed
```

### Step 3: decrypt + read in Wireshark
Edit → Preferences → Protocols → IEEE 802.11 → ✔ Enable decryption → Decryption keys: Edit… → `+` → Key type `wpa-pwd` → Key `<password>` (or `<password>:<SSID>`) → OK.
Shortcut: right-click any packet → Protocol Preferences → IEEE 802.11 → Decryption keys…
- **KEK / KCK**: filter `eapol` → click "Message 3 of 4" (or "Group Message 1 of 2") → 802.1X Authentication → WPA Key Data → `[KCK: …]` `[KEK: …]`
- **traffic**: filter `http` / `dns` → right-click → Follow → TCP Stream · File → Export Objects → HTTP

### Step 3 (terminal instead)
```bash
K='uat:80211_keys:"wpa-pwd","<password>:<SSID>"'
tshark -r wifi.cap -o wlan.enable_decryption:TRUE -o "$K" -Y eapol -V | grep -E 'Message number|KCK|KEK'
tshark -r wifi.cap -o wlan.enable_decryption:TRUE -o "$K" -Y eapol -T fields -e frame.number -e wlan.analysis.kck -e wlan.analysis.kek

airdecap-ng -e '<SSID>' -p '<password>' wifi.cap        # writes wifi-dec.cap = plain traffic
airdecap-ng -w <WEP key as hex, no colons> wifi.cap     # WEP capture instead
tshark -r wifi-dec.cap -q -z io,phs                     # protocols inside
tshark -r wifi-dec.cap -Y http.request -T fields -e http.request.method -e http.host -e http.request.uri
tshark -r wifi-dec.cap -Y 'http.request.method == "POST"' -T fields -e http.request.uri -e urlencoded-form.key -e urlencoded-form.value    # logins
tshark -r wifi-dec.cap -Y http -V | grep -iE 'flag|Form item'
tshark -r wifi-dec.cap --export-objects http,objs ; strings -n 6 wifi-dec.cap | grep -iE 'flag|pass'
```

### Step 4: questions about the frames (no cracking)
| Frame | Display filter |
|---|---|
| Beacon (AP announces SSID) | `wlan.fc.type_subtype == 8` |
| Probe request / response | `wlan.fc.type_subtype == 4` / `== 5` |
| Association request / response | `== 0` / `== 1` |
| Reassociation request / response | `== 2` / `== 3` |
| Authentication | `== 11` |
| Deauthentication / Disassociation | `== 12` / `== 10` |
| Handshake | `eapol` |
| one device | `wlan.addr == aa:bb:cc:dd:ee:ff` (`wlan.sa` sender · `wlan.da` receiver · `wlan.bssid` AP) |
| success only | `wlan.fixed.status_code == 0` |

```bash
tshark -r s.pcap -Y 'wlan.fc.type_subtype == 8' -T fields -e wlan.bssid -e wlan.ssid | sort -u      # every AP; SSID prints as hex
echo 436f66666565 | xxd -r -p                                                                        # hex SSID → text
tshark -r s.pcap -Y '(wlan.fc.type_subtype == 0 || wlan.fc.type_subtype == 1) && wlan.addr == <client mac>' \
  -T fields -e frame.number -e wlan.fc.type_subtype -e wlan.sa -e wlan.da -e wlan.bssid -e wlan.ssid -e wlan.fixed.status_code -e wlan.fixed.aid
printf '%d\n' 0x0c01                                                                                 # AID hex → decimal
```
- **Hidden SSID**: beacons carry an empty name; the real name is in the client's Association Request / a Probe Response (Tagged parameters → SSID).
- **Which network did client X join**: Association Response (subtype 1) sent to X with status 0 → BSSID = that AP; SSID = in X's Association Request just before; **AID** = Fixed parameters → Association ID of that response.
- **Deauth attack**: burst of subtype 12 frames. **Evil twin**: one SSID, two BSSIDs; after the deauth the client joins the other BSSID. Victim login = POST sent through the rogue BSSID / the entry that breaks the pattern of the rest.

### Helpline
```bash
# aircrack asks "Index number of target network ?" → type the row # that shows (1 handshake).
# "(0 handshake)" / "No valid WPA handshakes found" → that row can't be cracked; choose another row / file.
# "Passphrase not in dictionary" → other wordlist (the Q's own, full rockyou); hint words in Q → make a small list by hand.
# Wireshark still shows only "Data" / no [KEK] → key typo, wrong SSID after the colon, or reload needed (Ctrl+R).
# formats: BSSID sometimes wanted without colons · AID in decimal · KEK = the hex inside [KEK: …].
# plain pcap (not Wi-Fi) → [08_stego_forensics](08_stego_forensics.md) Step 7.
```
