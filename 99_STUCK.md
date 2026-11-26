# Stuck Reset

## Goal
Leave a dead end in 60 seconds with one cheap next test, or skip the question.

Open when: 3rd try of the same idea · no new output for `marks × 2.5 min` · not sure what the Q wants.

# 60-second reset
1. Re-read title + text aloud. Titles are puns: they name the tool, port, or technique.
2. What exactly must be submitted? (name / number / hex / text inside braces)
3. What do I HAVE? (files, addresses printed, passwords, hints from earlier Qs) → `cat ~/exam/loot.txt`
4. Which note fits? → [00_INDEX](00_INDEX.md) router. Checklist of that note fully ticked?
5. Cheapest untried thing → do it. Nothing → skip, note the Q number, return later.

# Is it me or the target?
```bash
echo $IP ; ping -c1 8.8.8.8 ; curl -sI http://$IP | head -1      # right IP? internet? target alive?
```
- [ ] new terminal tab → `export IP=…` again
- [ ] right IP for this Q (paper says which Qs use which IP)
- [ ] URL quoted? (`zsh: no matches found`)
- [ ] pasted quotes are straight `'` `"`, dashes are `-`
- [ ] tool still running in another tab? (hydra / sqlmap / aircrack finish quietly)
- [ ] `sudo` needed? (`-O`, `-sU`, `/etc/hosts`)

# Answer rejected
- [ ] format: example in the Q (lower/upper case, with or without `flag{}`, name without version, decimal vs hex)
- [ ] trailing space / newline copied?
- [ ] look-alikes: `0`/`O`, `1`/`l`/`I` → copy-paste, don't retype
- [ ] decoded one layer too few? (still looks like base64 / hex) → [09_decode](09_decode.md)
- [ ] flag belongs to a DIFFERENT question (two flags found on one path)

# Chains seen again and again (output of one step = input of the next)
```text
metadata comment → base64 → steghide passphrase → hidden file → decode
image on web page → steghide (empty passphrase) → morse / base64 / base32
anonymous FTP → readme hints next service → zip → crack → flag
robots.txt → folder → directory listing → login → username list → brute → flag
capture → aircrack → key into Wireshark → KEK / web traffic / logins
nc service prints addresses → overflow / format string → flag
SQL error → sqlmap dump → flag table / DB user hash
```
Any password found anywhere → try it on: zip, steghide, ssh, ftp, web login.

# Nothing matches a note
```bash
file <thing> ; strings -n 6 <thing> | head -30        # unknown file
nc -nv $IP $PORT ; curl -s http://$IP:$PORT/          # unknown port
grep -rniE '<word from the Q>' <notes folder>         # search every note
```
Then: skip. One hard question must not eat three easy ones.

> [!important] Helpline
> Cheapest test first. One change at a time. New evidence or move on.
