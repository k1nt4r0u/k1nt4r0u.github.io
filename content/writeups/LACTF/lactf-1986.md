---
title: "Lactf 1986"
date: 2026-02-07T23:04:22+07:00
draft: false
tags: ["ctf", "reversing", "pwn", "crypto", "web", "forensics", "misc"]
categories: ["CTF Name"]
contest: "LACTF 2026"
author: "k1nt4r0u"
description: "A detailed writeup for Lactf 1986 challenge"
difficulty: "Easy/Medium/Hard"
---
# LACTF '86 Flag Checker — Writeup

## Challenge Overview

We're given two files:
- **CHALL.EXE** — A 16-bit MS-DOS executable (9.8 KB)
- **CHALL.IMG** — A 1.44 MB FAT12 floppy disk image containing the same `CHALL.EXE`

Running `strings` on the binary reveals it's a flag checker:

```
UCLA NetSec presents: LACTF '86 Flag Checker
Check your Flag: 
Sorry, the flag must begin with "lactf{..."
Sorry, that's not the flag.
Indeed, that's the flag!
```

## Reversing the Binary

### MZ Header Analysis

The executable is a standard MZ DOS binary compiled with what appears to be Turbo C:

| Field              | Value          |
|--------------------|----------------|
| Header size        | 48 bytes (0x30)|
| Entry point (CS:IP)| 0000:02C2     |
| Code segment       | 0x0000–0x238F (file offset 0x30) |
| Data segment       | 0x2390–0x26D5 (file offset 0x23C0) |

### Main Function (`fcn.000000b0`)

Using radare2 (`r2 -a x86 -b 16`), the main logic was disassembled. It performs three steps:

#### Step 1 — Prefix Validation

The checker reads user input and verifies the first 5 characters match `lactf{`:

```asm
cmp byte [bp - 0x16], 0x6c   ; 'l'
cmp byte [bp - 0x15], 0x61   ; 'a'
cmp byte [bp - 0x14], 0x63   ; 'c'
cmp byte [bp - 0x13], 0x74   ; 't'
cmp byte [bp - 0x12], 0x66   ; 'f'
cmp byte [bp - 0x11], 0x7b   ; '{'
```

If any mismatch, it prints `"Sorry, the flag must begin with "lactf{...""` and exits.

#### Step 2 — Hash the Input (Seed the PRNG)

The function at `fcn.00000010` computes a 20-bit hash of the entire input string. Tracing the assembly:

```asm
; For each character c in input:
;   left-shift state by 6 bits  → state * 64
;   left-shift state by 1 bit   → state * 2
;   add: state*64 + state*2 + state = state * 67
;   add character value
;   mask to 20 bits (AND si, 0xF keeps upper 4 bits)
```

In Python:

```python
def hash_string(s):
    state = 0
    for c in s:
        state = (67 * state + c) % (1 << 20)
    return state
```

This produces a 20-bit seed value in `DX:AX`.

#### Step 3 — LFSR XOR Stream Cipher

The function at `fcn.0000007b` implements a 20-bit Linear Feedback Shift Register (LFSR). Each step:

1. Compute feedback bit = `bit0 XOR bit3`
2. Right-shift the 20-bit state by 1
3. Insert feedback bit at position 19 (MSB)

```python
def lfsr_step(state):
    feedback = (state & 1) ^ ((state >> 3) & 1)
    state = (state >> 1) | (feedback << 19)
    return state & 0xFFFFF
```

The main loop iterates over each character of the input (up to 0x49 = 73 characters):

```asm
loop:
    call lfsr_step              ; advance PRNG
    mov al, [state_low]         ; get low byte of state
    xor al, input[i]            ; XOR with input character
    cmp al, expected[i]         ; compare with expected ciphertext
    je  continue                ; if match, continue
    ; else print "Sorry, that's not the flag." and exit
```

### Expected Ciphertext

The 73-byte expected ciphertext is stored in the data segment at `DS:0x146` (file offset `0x2506`):

```
b6 8c 95 8f 9b 85 4c 5e  ec b6 b8 c0 97 93 0b 58
77 50 b0 2c 7e 28 7a f1  b6 04 ef be 5c 44 78 e8
99 81 04 8f 03 40 a7 3f  fa b7 08 01 63 52 e3 ad
d1 85 9f 94 21 d5 2a 5c  20 d4 31 12 ce aa 16 c7
ad df 29 5d 72 fc 24 90  2c
```

## Solution Strategy

The cipher is: `ciphertext[i] = input[i] XOR lfsr_keystream[i]`

The LFSR keystream is fully determined by the 20-bit seed, which is the hash of the input. This creates a circular dependency — the seed depends on the plaintext, and the plaintext depends on the seed.

However, the seed is only **20 bits** (1,048,576 possible values). We can brute-force all seeds:

1. For each candidate seed (0 to 2²⁰ − 1):
   - Generate the LFSR keystream
   - Decrypt: `plaintext[i] = ciphertext[i] XOR keystream_low_byte[i]`
   - Check if result starts with `lactf{` and ends with `}`
   - Verify: `hash(plaintext) == seed`

## Solve Script

```python
def lfsr_step(state):
    feedback = (state & 1) ^ ((state >> 3) & 1)
    state = (state >> 1) | (feedback << 19)
    return state & 0xFFFFF

def hash_string(s):
    state = 0
    for c in s:
        state = (67 * state + c) % (1 << 20)
    return state

expected = bytes([
    0xb6, 0x8c, 0x95, 0x8f, 0x9b, 0x85, 0x4c, 0x5e,
    0xec, 0xb6, 0xb8, 0xc0, 0x97, 0x93, 0x0b, 0x58,
    0x77, 0x50, 0xb0, 0x2c, 0x7e, 0x28, 0x7a, 0xf1,
    0xb6, 0x04, 0xef, 0xbe, 0x5c, 0x44, 0x78, 0xe8,
    0x99, 0x81, 0x04, 0x8f, 0x03, 0x40, 0xa7, 0x3f,
    0xfa, 0xb7, 0x08, 0x01, 0x63, 0x52, 0xe3, 0xad,
    0xd1, 0x85, 0x9f, 0x94, 0x21, 0xd5, 0x2a, 0x5c,
    0x20, 0xd4, 0x31, 0x12, 0xce, 0xaa, 0x16, 0xc7,
    0xad, 0xdf, 0x29, 0x5d, 0x72, 0xfc, 0x24, 0x90,
    0x2c,
])

for seed in range(1 << 20):
    state = seed
    plaintext = bytearray()
    for i in range(len(expected)):
        state = lfsr_step(state)
        plaintext.append(expected[i] ^ (state & 0xFF))
    try:
        text = plaintext.decode('ascii')
    except:
        continue
    if text.startswith('lactf{') and text.endswith('}'):
        if hash_string(plaintext) == seed:
            print(f"Flag: {text}")
            break
```

The brute-force completes in under a minute and finds seed `0xf3fb5`.

## Flag

```
lactf{3asy_3nough_7o_8rute_f0rce_bu7_n0t_ea5y_en0ugh_jus7_t0_brut3_forc3}
```

## Summary

| Component       | Detail                                    |
|-----------------|-------------------------------------------|
| Architecture    | 16-bit x86 (MS-DOS MZ executable)         |
| Cipher          | LFSR-based XOR stream cipher              |
| LFSR width      | 20 bits                                   |
| Feedback taps   | bit 0 ⊕ bit 3                             |
| Seed derivation | Polynomial hash: `s = 67·s + c (mod 2²⁰)`|
| Key weakness    | 20-bit keyspace → brute-forceable (~1M)   |
| Flag length     | 73 characters                             |

