---
title: "Lactf 1986"
date: 2026-02-07T23:04:22+07:00
draft: false
tags: ["CTF", "RE"]
categories: ["LACTF 2026"]
contest: "LACTF 2026"
author: "k1nt4r0u"
description: "Bruteforcing a 20-bit self-seeded stream cipher in a retro DOS flag checker"
difficulty: "Medium"
---
## First look

This one came with a very on-theme setup: a tiny `CHALL.EXE` DOS program and a floppy image containing the same executable. A quick `strings` pass already told me it was a flag checker:

```text
UCLA NetSec presents: LACTF '86 Flag Checker
Check your Flag:
Sorry, the flag must begin with "lactf{..."
Sorry, that's not the flag.
Indeed, that's the flag!
```

So the question was not what the binary did, but whether it hid the flag in a way that was annoying enough to matter.

## What the checker really does

Loading the program in `radare2` as 16-bit x86 made the structure fairly clear.

The first part is just a prefix check. The binary rejects anything that does not begin with `lactf{`, so there is nothing interesting there.

The second part is where the actual trick lives. The checker hashes the entire input into a 20-bit state:

```python
def hash_string(data):
    state = 0
    for byte in data:
        state = (67 * state + byte) % (1 << 20)
    return state
```

That 20-bit value becomes the seed for a small LFSR:

```python
def lfsr_step(state):
    feedback = (state & 1) ^ ((state >> 3) & 1)
    return ((state >> 1) | (feedback << 19)) & 0xFFFFF
```

The checker advances the LFSR once per character, takes the low byte, XORs it with the candidate flag byte, and compares the result against a 73-byte constant stored in the data segment.

So the validation logic is:

```text
expected[i] == input[i] XOR keystream[i]
```

At first glance that looks circular, because the input determines the seed and the seed determines the keystream that decrypts the input.

## The weakness

The circular dependency looks clever, but the state is only 20 bits wide. That is just `2^20` possibilities, which is completely brute-forceable.

So instead of trying to solve the algebra directly, I treated the embedded bytes as ciphertext and tested every possible seed:

1. Generate the LFSR keystream for a candidate seed.
2. XOR it with the stored bytes to recover a plaintext candidate.
3. Keep only printable candidates that look like `lactf{...}`.
4. Re-hash that plaintext and check whether it reproduces the same seed.

That last check is what resolves the circular dependency cleanly.

## Solving it

The full brute-force script is short:

```python
def lfsr_step(state):
    feedback = (state & 1) ^ ((state >> 3) & 1)
    return ((state >> 1) | (feedback << 19)) & 0xFFFFF

def hash_string(data):
    state = 0
    for byte in data:
        state = (67 * state + byte) % (1 << 20)
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
    plain = bytearray()
    for byte in expected:
        state = lfsr_step(state)
        plain.append(byte ^ (state & 0xFF))
    try:
        text = plain.decode("ascii")
    except UnicodeDecodeError:
        continue
    if text.startswith("lactf{") and text.endswith("}") and hash_string(plain) == seed:
        print(hex(seed), text)
        break
```

The correct seed turned out to be `0xf3fb5`, and the recovered plaintext was the flag.

## Flag

```text
lactf{3asy_3nough_7o_8rute_f0rce_bu7_n0t_ea5y_en0ugh_jus7_t0_brut3_forc3}
```

## Takeaway

The interesting part here was not the DOS binary itself. It was noticing that the fancy self-seeded stream cipher still collapsed to a tiny brute-force space. Once I stopped treating the seed dependency as a blocker, the solve became a straightforward offline search.
