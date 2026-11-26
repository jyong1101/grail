# nc + scripting

## Goal
Talk to a TCP service: send exact bytes, or answer faster than fingers can.

**Checklist**
- [ ] `nc` once by hand → copy the exact prompt text
- [ ] human speed enough? no → script it
- [ ] bytes ≥ 0x80 in payload → binary-safe way only

# Commands

### nc basics
```bash
nc -nv $IP $PORT                                 # interactive; Ctrl+C quits
echo 'answer' | nc -w3 $IP $PORT                 # send one line, wait 3 s for the reply
printf 'first\nsecond\n' | nc -w3 $IP $PORT      # several answers, in order
(echo 'payload'; cat) | nc $IP $PORT             # send, then keep typing (e.g. after getting a shell)
```

### Raw bytes (addresses, non-printables)
```bash
python3 -c 'import sys; sys.stdout.buffer.write(b"A"*44 + b"\x96\x91\x04\x08" + b"\n")' | nc -w3 $IP $PORT
printf 'AAAA\x96\x91\x04\x08\n' | nc -w3 $IP $PORT
python2 -c 'print "A"*44 + "\x96\x91\x04\x08"' | nc -w3 $IP $PORT
```
Never python3 `print("\x96…")`: bytes ≥ 0x80 get mangled (UTF-8). Use `sys.stdout.buffer.write(b"…")`.

### "Type this exactly" / timed rounds → save as `a.py`, run `python3 a.py`
```python
from pwn import *
import re
io = remote("IP", PORT)
try:
    io.recvuntil(b"exactly: ")               # text printed right before the random string
    io.sendline(io.recvline().strip())       # read the string, send it back
    while True:                              # further rounds, e.g. "What is 12 + 30? "
        q = io.recvuntil(b"? ")
        io.sendline(str(eval(re.search(rb"\d+ *[-+*/] *\d+", q).group().decode())).encode())
except EOFError:
    pass
print(io.recvall(timeout=2).decode())
```
Echo only → delete the `while` block. See all traffic → add `context.log_level = "debug"` under the imports.

### Same without pwntools (plain socket)
```python
import socket, time
s = socket.create_connection(("IP", PORT))
buf = b""
while b"exactly: " not in buf or not buf.endswith(b"\n"):
    buf += s.recv(4096)
s.sendall(buf.split(b"exactly: ")[1].strip() + b"\n")
time.sleep(0.5); print(s.recv(4096).decode())
```

### Same with expect → `expect a.exp`
```tcl
set timeout 3
spawn nc IP PORT
expect -re {exactly: ([^\r\n]+)}
send "$expect_out(1,string)\r"
expect eof
```

### pwntools cheats
```text
io = remote("IP", PORT)            or process("./bin") to test locally
io.recvuntil(b"text")   io.recvline()   io.recv(4096)   io.recvall(timeout=2)
io.sendline(b"x")       adds \n  (gets / fgets / scanf)
io.send(b"x")           exact bytes (read)
io.interactive()        hand over the keyboard (shell)
p32(0x08049196)         → b"\x96\x91\x04\x08"      p64(0x401186) for 64-bit
```

### Helpline
```bash
# reply never comes → program waits for Enter: add \n (sendline / echo, not printf without \n).
# script hangs at recvuntil → the text doesn't match exactly (spaces, colon, capitals) → copy it from the nc output.
# EOFError = server closed → print(io.recvall()) or debug log to see its last words.
# "pwn cyclic N" prints no newline → (pwn cyclic 200; echo) | nc …
# nc -w3 quits too early on slow servers → raise to -w10.
```
