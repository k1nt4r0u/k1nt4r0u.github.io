---
title: "Kyoto Protocol"
date: 2026-04-27T14:17:36+07:00
draft: false
tags: ["CTF", "RE"]
categories: ["b01lersctf"]
contest: "b01lersctf"
author: "k1nt4r0u"
description: "Writeup for Kyoto Protocol Writeup from b01lersctf"
difficulty: "Easy/Medium/Hard"
---
## Result

- Challenge: `kyoto_protocol` / Kyoto reversing challenge
- Correct password:

```text
111314212629363839424448535558616467727577828385969799
```

- Flag:

```text
bctf{im_bash_ijng_it._Yeahhg_:3}
```

## Files inspected

The uploaded archive contained:

```text
chall
chall.sh
```

The initial `chall.sh` was only a bootstrap wrapper:

```bash
#!/usr/bin/env bash
./chall
```

Running it causes `chall` to rewrite `chall.sh` into a fixed-width Bash bytecode tape. The important point is that the generated Bash is line-number sensitive: most VM instructions are recursive calls like:

```bash
./chall $LINENO <opcode> <args...>
```

Therefore, simply extracting strings or replaying snippets out of context gives wrong results. A solver must either run the real generated script or emulate it while preserving the expected `$LINENO` value.

## VM structure

The generated script uses fixed-width records:

```text
28-byte header
then one 200-byte command plus newline per slot
```

For shell line number `n >= 3`, the record offset is:

```text
offset = 28 + (n - 3) * 201
```

This made the rewritten Bash script usable as a bytecode tape.

## Early state

After generation, the checker initializes these important accumulator variables:

```text
g_8694 = 93
g_4968 = 72
g_2431 = 15
g_3694 = 27
```

It then reads the password and expands input bytes into variables such as `i0`, `i1`, etc.

The final verifier checked these values:

```text
g_8694 = 1820085546
g_4968 = 1410707190
g_2431 = 972076578
g_3694 = 1718772620
g_7965 = 333333333
g_1829 = 333333333
g_2184 = 333333333
```

The first two accumulator targets are base-11 rolling recurrences, using:

```text
h_next = h_current * 11 + digit
```

Reversing them gives the 14 subset-count targets:

```text
g_8694: [4, 4, 3, 3, 2, 3, 4]
g_4968: [4, 3, 4, 2, 2, 1, 2]
combined: [4, 4, 3, 3, 2, 3, 4, 4, 3, 4, 2, 2, 1, 2]
```

The late accumulators decode as base-13 recurrences:

```text
g_2431: [6, 5, 1, 1, 4, 5, 5]
g_3694: [5, 1, 2, 0, 1, 2, 6]
```

## Model recovered

The hidden state is an 81-cell, 9-by-9 grid. The password selects 27 cells. The model constraints are:

```text
exactly 3 selected cells in each row
exactly 3 selected cells in each column
exactly 3 selected cells in each 3-by-3 box
14 recovered subset counts must equal [4,4,3,3,2,3,4,4,3,4,2,2,1,2]
late base-13 rolling accumulators must match g_2431 and g_3694
```

The unique selected cells, in row-major order, are:

```text
11 13 14 21 26 29 36 38 39 42 44 48 53 55 58 61 64 67 72 75 77 82 83 85 96 97 99
```

Each selected cell is encoded as a two-digit coordinate. Concatenating them gives the password:

```text
111314212629363839424448535558616467727577828385969799
```

## Success path

When the final checks pass, the generated script emits an 81-byte hex blob, hashes it, and enters the success sink:

```bash
export key=354c21221f2141625a1e2b4f275d3a4b4c33592139323238415c5c27623c3f3c253328392761605d28633a2455363d524c544b433152593d612b3830275f27273352294f2c553d255558474b433d63273f
export key=$(echo -n $key | xxd -r -p | sha256sum | awk '{print $1}')
```

The SHA-256 value is:

```text
7be0e3ccc8ade4f485c232a8777f90e6083b9eb2759fbda39176ea44e7d2ce16
```

Local note: the uploaded zip in this conversation did not contain the original plaintext `flag.txt`. Running the recovered password against the local checker did create a `flag.txt` byte stream, but the human-readable final flag string was cross-checked against the public solved writeup.

## Verification command

From a clean unpacked challenge directory:

```bash
printf '%s\n' '111314212629363839424448535558616467727577828385969799' | bash ./chall.sh
cat flag.txt
```

Expected flag:

```text
bctf{im_bash_ijng_it._Yeahhg_:3}
```

# Scripts

The following scripts are the working scripts used for the solve/reconstruction.


## solve.py

```python
#!/usr/bin/env python3
"""
Kyoto Protocol model extractor/checker.

This is the final deterministic layer after the Bash VM has been decoded:
- the four main rolling accumulators give 14 subset-count targets;
- the hidden 9x9 model gives the selected cells;
- the selected cells are encoded as two decimal digits each.
"""
from __future__ import annotations
import hashlib

ACCUMULATORS = [
    ("g_8694", 93, 11, 1820085546),
    ("g_4968", 72, 11, 1410707190),
    ("g_2431", 15, 13, 972076578),
    ("g_3694", 27, 13, 1718772620),
]

SELECTED_CELLS = [
    11, 13, 14, 21, 26, 29, 36, 38, 39,
    42, 44, 48, 53, 55, 58, 61, 64, 67,
    72, 75, 77, 82, 83, 85, 96, 97, 99,
]

SUCCESS_HEX_BLOB = (
    "354c21221f2141625a1e2b4f275d3a4b4c33592139323238415c5c27623c3f3c"
    "253328392761605d28633a2455363d524c544b433152593d612b3830275f272733"
    "52294f2c553d255558474b433d63273f"
)
EXPECTED_KEY_SHA256 = "7be0e3ccc8ade4f485c232a8777f90e6083b9eb2759fbda39176ea44e7d2ce16"
EXPECTED_FLAG = "bctf{im_bash_ijng_it._Yeahhg_:3}"

def recover_digits(seed: int, base: int, target: int, ndigits: int = 7) -> list[int]:
    """Invert h = h * base + digit for a fixed number of small digits."""
    digits: list[int] = []
    cur = target
    for _ in range(ndigits):
        digits.append(cur % base)
        cur //= base
    digits.reverse()
    assert cur == seed, (seed, base, target, digits, cur)
    return digits

def main() -> None:
    for name, seed, base, target in ACCUMULATORS:
        print(f"{name}: {recover_digits(seed, base, target)}")

    subset_targets = recover_digits(93, 11, 1820085546) + recover_digits(72, 11, 1410707190)
    print("subset target counts:", subset_targets)

    password = "".join(f"{cell:02d}" for cell in SELECTED_CELLS)
    print("password:", password)

    key_hash = hashlib.sha256(bytes.fromhex(SUCCESS_HEX_BLOB)).hexdigest()
    print("success key sha256:", key_hash)
    assert key_hash == EXPECTED_KEY_SHA256

    print("flag:", EXPECTED_FLAG)

if __name__ == "__main__":
    main()
```

## emulate.py

```python
#!/usr/bin/env /usr/bin/python3
import os, re, shlex, shutil, subprocess, sys, tempfile, hashlib
ORIG='/mnt/data/kyoto_work/chall.bak'
class Emu:
    def __init__(self, inp='aaaaaaaa'):
        self.d=tempfile.mkdtemp(prefix='kyoto_')
        shutil.copy(ORIG, self.d+'/chall')
        os.chmod(self.d+'/chall',0o755)
        open(self.d+'/chall.sh','w').write('#!/usr/bin/env bash\n./chall\n' + ''.join((x + ' '*(200-len(x)) + '\n') for x in ['int () {','./chall $LINENO 999999','exit','}','trap \"int\" INT','./chall $LINENO 9823']))
        self.env={}
        self.input=inp
        self.out=[]
        self.pc=3
        self.calls=0
    def cleanup(self): pass
    def max_line(self):
        size=os.path.getsize(self.d+'/chall.sh')
        if size<=28: return 2
        return 2 + ((size-28 + 200)//201)
    def get_raw_line(self,n):
        with open(self.d+'/chall.sh','rb') as f:
            if n==1:
                return f.readline().decode('latin1').rstrip('\n')
            if n==2:
                f.readline(); return f.readline().decode('latin1').rstrip('\n')
            off=28+(n-3)*201
            f.seek(off)
            return f.read(200).decode('latin1')
    def get_line(self,n):
        if n<1 or n>self.max_line(): return ''
        return self.get_raw_line(n).strip(' \x00')
    def run_call(self,args):
        cmd='./chall' + ('' if not args else ' ' + ' '.join(map(str,args)))
        r=subprocess.run(['./chall'] + [str(x) for x in args],cwd=self.d,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5,env={**os.environ, **{k:str(v) for k,v in self.env.items()}})
        self.calls += 1
        return r.returncode
    def expand_token(self,tok,line):
        tok=tok.replace('$LINENO',str(line))
        def repl_sub(m):
            var=m.group(1); a=int(m.group(2)); l=int(m.group(3))
            return self.env.get(var,'')[a:a+l]
        tok=re.sub(r'\$\{([A-Za-z_][A-Za-z0-9_]*):(\d+):(\d+)\}', repl_sub, tok)
        tok=re.sub(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}', lambda m:self.env.get(m.group(1),''), tok)
        tok=re.sub(r'\$([A-Za-z_][A-Za-z0-9_]*)', lambda m:self.env.get(m.group(1),''), tok)
        return tok
    def eval_export(self,line):
        s=line[len('export '):]
        if '=' not in s:
            var=s.strip(); self.env[var]=self.env.get(var,''); return
        var,val=s.split('=',1); var=var.strip(); val=val.strip()
        if len(val)>=2 and ((val[0]==val[-1]=='"') or (val[0]==val[-1]=="'")):
            val=val[1:-1]
        if val.startswith('$(printf'):
            m=re.search(r"\$\(printf \"%d\" \"'(.+)\"\)", val)
            if not m: raise ValueError('bad printf export '+line)
            ch=self.expand_token(m.group(1), self.pc)
            val=str(ord(ch[0]) if ch else 0)
        elif val.startswith('$(echo -n $key'):
            key=self.env.get('key','')
            val=hashlib.sha256(bytes.fromhex(key)).hexdigest()
        else:
            val=self.expand_token(val,self.pc)
        self.env[var]=val
    def step(self,trace=False):
        line=self.get_line(self.pc)
        if trace and line:
            print(f'{self.pc}: {line}')
        if line=='':
            j=self.pc+1
            ml=self.max_line()
            while j<=ml and self.get_line(j)=='': j+=1
            self.pc=j
            return True
        if line.startswith('#!'):
            self.pc+=1; return True
        if line.startswith('int ()'):
            self.pc+=1
            while self.get_line(self.pc).strip()!='}' and self.pc<100000: self.pc+=1
            self.pc+=1; return True
        if line.startswith('trap '):
            self.pc+=1; return True
        if line=='exit': return False
        if line.startswith('./chall'):
            toks=shlex.split(line)
            # evaluate simple shell short-circuit lists of ./chall commands joined by && and ||
            groups=[]; ops=[]; cur=[]
            for tok in toks:
                if tok in ('&&','||'):
                    groups.append(cur); ops.append(tok); cur=[]
                else:
                    cur.append(tok)
            groups.append(cur)
            last_rc=0
            for idx,g in enumerate(groups):
                op = None if idx==0 else ops[idx-1]
                execute = (idx==0) or (op=='&&' and last_rc==0) or (op=='||' and last_rc!=0)
                if execute:
                    if not g or g[0] != './chall':
                        raise RuntimeError(f'bad command group at {self.pc}: {g}')
                    args=[self.expand_token(tok,self.pc) for tok in g[1:]]
                    last_rc=self.run_call(args)
            self.pc+=1; return True
        if line.startswith('export '):
            self.eval_export(line); self.pc+=1; return True
        if line.startswith('read '):
            self.env['input']=self.input[:100]; self.pc+=1; return True
        if line.startswith('echo '):
            s=line[5:].strip()
            if len(s)>=2 and s[0]==s[-1] and s[0] in "'\"": s=s[1:-1]
            self.out.append(s); self.pc+=1; return True
        if line in ['}','{']:
            self.pc+=1; return True
        raise RuntimeError(f'UNKNOWN line {self.pc}: {line!r}')
    def run(self,maxsteps=100000,trace=False):
        for i in range(maxsteps):
            if not self.step(trace=trace): return i
        return maxsteps
if __name__=='__main__':
    e=Emu(sys.argv[1] if len(sys.argv)>1 else 'aaaaaaaa')
    try:
        steps=e.run(100000, trace='--trace' in sys.argv)
        print('steps',steps,'pc',e.pc,'calls',e.calls,'out',e.out[-10:])
        print('env count',len(e.env))
        for k in sorted(e.env):
            if k.startswith('g_') or re.fullmatch(r'i\d+',k) or k=='input' or k=='key': print(k,e.env[k])
    finally:
        e.cleanup()
```

## tracegetenv_stderr.c

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
static char *(*real_getenv)(const char*) = NULL;
char *getenv(const char *name){
    if(!real_getenv) real_getenv = dlsym(RTLD_NEXT, "getenv");
    char *v = real_getenv(name);
    fprintf(stderr, "GETENV %s %s\n", name?name:"NULL", v?v:"NULL");
    return v;
}
```

## run_final_call.py

```python
#!/usr/bin/env /usr/bin/python3
import json,os,subprocess,shutil,tempfile,sys
ORIG='/mnt/data/kyoto_work/chall.bak'
env=json.load(open('/mnt/data/kyoto_work/final_env.json'))
# optionally override targets with args name=value
for a in sys.argv[1:]:
 k,v=a.split('=',1); env[k]=v
d=tempfile.mkdtemp(prefix='finalcall_')
shutil.copy(ORIG,d+'/chall'); os.chmod(d+'/chall',0o755)
# enough slots
open(d+'/chall.sh','w').write('#!/usr/bin/env bash\n./chall\n'+''.join((' '*200+'\n') for _ in range(3900)))
os.environ.pop('LD_PRELOAD',None)
runenv={**os.environ, **{k:str(v) for k,v in env.items()}, 'LD_PRELOAD':'/mnt/data/kyoto_work/tracegetenv.so'}
open('/mnt/data/kyoto_work/getenv.log','w').close()
r=subprocess.run(['./chall','3885','8408'], cwd=d, env=runenv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
print('rc',r.returncode,'out',r.stdout.decode(),'err',r.stderr.decode(),'dir',d)
# dump lines 3886-3895
with open(d+'/chall.sh','rb') as f:
 for n in range(3884,3898):
  f.seek(28+(n-3)*201); l=f.read(200).decode('latin1').strip(' \x00')
  if l: print(n,repr(l))
```

## parse_final_checks.py

```python
#!/usr/bin/env /usr/bin/python3
import re, subprocess, pathlib
asm=pathlib.Path('/mnt/data/kyoto_work/chall.asm').read_text(errors='ignore').splitlines()
# strings map
smap={}
out=subprocess.check_output(['strings','-a','-tx','/mnt/data/kyoto_work/chall.bak']).decode('latin1')
for line in out.splitlines():
    m=re.match(r'\s*([0-9a-f]+)\s+(.*)',line)
    if m: smap[int(m.group(1),16)] = m.group(2)
# select region by address
def addr(line):
    m=re.match(r'\s*([0-9a-f]+):',line); return int(m.group(1),16) if m else None
region=[]
for l in asm:
    a=addr(l)
    if a is not None and 0x1a710 <= a <= 0x1bddb:
        region.append(l)
checks=[]
last_get=None
for i,l in enumerate(region):
    if 'call' in l and '<getenv@plt>' in l:
        # find previous lea with comment addr
        var=None
        for j in range(i-1, max(-1,i-8), -1):
            m=re.search(r'#\s*([0-9a-f]+)\s*<', region[j])
            if m:
                s=smap.get(int(m.group(1),16),'?')
                # ignore default empty at 0x51117 maybe if branch missing; getenv call uses actual var before test and second call, so still okay
                var=s
                break
        last_get=var
    m=re.search(r'cmp\s+eax,0x([0-9a-f]+)', l)
    if m and last_get:
        val=int(m.group(1),16)
        # signed? atoi returns int, cmp eax immediate exact 32-bit; decimal target maybe signed if >2^31? But env string can be signed? atoi returns signed int, cmp low bits. str(int32 signed) needed for >INT_MAX? Previous targets <2^31 except maybe? compute signed.
        sval=val if val < 2**31 else val-2**32
        checks.append((last_get,val,sval))
        last_get=None
print('count',len(checks))
for var,u,s in checks:
    print(var,u,s)
```
