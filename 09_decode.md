# Decode / Crypto

## Goal
Recognise the encoding by its look → decode → repeat until readable (layers are normal).

**Fast path (script)** — all scripts: [15_scripts](15_scripts.md)
```bash
ctf --decode "<string>"           # base64 / base32 / hex / url / rot13, layers followed
ctf --rot-brute "<string>"        # all 25 rotations
```
Misses / wrong → by hand below.

**Checklist**
- [ ] matched the look in the table?
- [ ] output still odd → run the table again on the output
- [ ] hint words in Q/title (rotate, base, 64, morse, a number) used?

# Recognise → decode
| Looks like | It is | Use |
|---|---|---|
| `A-Z a-z 0-9 + /`, ends `=` or `==` | Base64 | one-liners |
| only `A-Z` and `2-7`, ends `=` … `======` | Base32 | one-liners |
| only `0-9 a-f` | Hex | one-liners |
| words keep their shape, letters wrong (`synt{…}`) | ROT13 / Caesar | one-liners · all shifts: snippet C |
| `%66%6c%61%67` · `&#102;&#108;` · text backwards | URL · HTML entities · reversed | one-liners |
| `01100110 01101100` · `102 108 97` · `146 154 141` | binary · decimal · octal | snippet N |
| `.- -... / -.-.` | Morse | snippet M |
| `pi pika pipi pikachu` · `+++[>++<-]>.` | Pikalang · Brainfuck | snippet P |
| strange CJK / symbols, hint "65536" or "FFFF+1" | Base65536 | snippet U |
| `eyJ….eyJ….xxx` | JWT | each dot-part → base64 |
| starts `U2FsdGVkX1` | OpenSSL AES, needs password | [07_crack](07_crack.md) Step 4 |
| 32 / 40 / 64 hex, meaningless | hash | [07_crack](07_crack.md) Step 3 |

### One-liners (put the text in place of X)
```bash
echo 'X' | base64 -d                                   # Base64
echo 'X' | base32 -d                                   # Base32
echo 'X' | xxd -r -p                                   # Hex → text
echo 'X' | tr 'A-Za-z' 'N-ZA-Mn-za-m'                  # ROT13
echo 'X' | tr 'A-Za-z' 'ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba'      # Atbash (a↔z)
echo 'X' | rev                                         # reversed
python3 -c "import sys,urllib.parse as u;print(u.unquote(sys.argv[1]))" 'X'       # URL %xx
python3 -c "import sys,html;print(html.unescape(sys.argv[1]))" 'X'                # HTML &#xx;
echo $((0xFFFF+1)) ; printf '%d\n' 0x1f ; printf '%x\n' 255                       # hex maths · hex→dec · dec→hex
```

# Snippets

### N: numbers → text (change the `2` to 10 or 8)
```bash
python3 -c "import sys;print(''.join(chr(int(b,2)) for b in sys.argv[1].split()))" '01100110 01101100 01100001 01100111'
```

### C: Caesar, all 25 shifts (pick the readable line)
```bash
python3 -c "
import sys
s=sys.argv[1]
for k in range(1,26): print(k,''.join(chr((ord(c)-(65 if c.isupper() else 97)+k)%26+(65 if c.isupper() else 97)) if c.isalpha() else c for c in s))" 'Iodj{fdhvdu}'
```

### M: Morse (text in `m.txt`; letters split by spaces, words by `/` or newline)
```bash
python3 -c "
import sys
M={'.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G','....':'H','..':'I','.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R','...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X','-.--':'Y','--..':'Z','-----':'0','.----':'1','..---':'2','...--':'3','....-':'4','.....':'5','-....':'6','--...':'7','---..':'8','----.':'9','---...':':','-...-':'=','.-.-.-':'.','--..--':',','..--..':'?','-..-.':'/','-....-':'-','..--.-':'_','-.--.':'(','-.--.-':')','-.-.--':'!','.--.-.':'@'}
print(''.join(' ' if c=='/' else M.get(c,'?') for c in sys.stdin.read().split()))" < m.txt
```

### P: Pikalang / Brainfuck → save as `bf.py`, run `python3 bf.py code.txt`
```python
import sys
src=open(sys.argv[1]).read()
P={'pipi':'>','pichu':'<','pi':'+','ka':'-','pikachu':'.','pikapi':',','pika':'[','chu':']'}
if 'pi' in src: src=''.join(P.get(w,'') for w in src.split())
code=[c for c in src if c in '><+-.,[]']; tape=[0]*30000; p=i=0; st=[]; jmp={}
for n,c in enumerate(code):
    if c=='[': st.append(n)
    if c==']': j=st.pop(); jmp[j]=n; jmp[n]=j
while i<len(code):
    c=code[i]
    if c=='>': p+=1
    elif c=='<': p-=1
    elif c=='+': tape[p]=(tape[p]+1)%256
    elif c=='-': tape[p]=(tape[p]-1)%256
    elif c=='.': sys.stdout.write(chr(tape[p]))
    elif c=='[' and tape[p]==0: i=jmp[i]
    elif c==']' and tape[p]!=0: i=jmp[i]
    i+=1
print()
```

### U: Base65536 (needs the module → [98_SETUP](98_SETUP.md))
```bash
~/venv/bin/python -c "import base65536;print(base65536.decode(open('message.txt').read().replace(' ','').strip()))"
```

### X: XOR with one unknown byte (hex input) → prints readable candidates
```bash
python3 -c "
import sys
d=bytes.fromhex(sys.argv[1])
for k in range(256):
    o=bytes(b^k for b in d)
    if all(32<=c<127 for c in o): print(k,o.decode())" '<hex>'
```

### A: AES key given but "partially wrong" + plaintext & ciphertext given → fix one byte by brute force
```bash
python3 -c "
import numpy as np
from Cryptodome.Cipher import AES
pt=np.load('plaintext.npy'); ct=np.load('ciphertext.npy')
p=bytes(pt[0].astype('uint8')); c=bytes(ct[0].astype('uint8'))
key=bytearray.fromhex('<16 key bytes as given>')
for i in range(16):
    for b in range(256):
        k=bytearray(key); k[i]=b
        if AES.new(bytes(k),AES.MODE_ECB).encrypt(p)==c: print('byte',i,'->',k.hex(' ').upper())"
```

# GUI / online
CyberChef (offline copy → [98_SETUP](98_SETUP.md)): drag "Magic" for auto-detect; From Base64 · From Base32 · ROT13 · From Morse Code · From Hex · XOR Brute Force.
Online (if allowed): dcode.fr/cipher-identifier · dcode.fr/pikalang-language · https://gchq.github.io/CyberChef/ · quipqiup.com (substitution)

### Helpline
```bash
# decoded but still odd → another layer: base64 → base32 → rot13 chains are common.
# base64 "invalid input" → padding missing: append = or == ; or a stray space/newline inside the string.
# ALL CAPS + digits 2-7 = base32. Mixed case = base64.
# morse has no case → answer usually UPPERCASE; one long word → split by sense. "?" in output = unknown symbol, check spacing.
# decoded line like "FLAG1:xxxFLAG2:yyy" = two answers; the second may need one more decode.
# Vigenère needs a key (look in Q / file name); Bacon, Rail fence, substitution → CyberChef / dcode.
```
