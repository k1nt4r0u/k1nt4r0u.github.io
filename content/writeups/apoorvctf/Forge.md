---
title: "Forge"
date: 2026-03-07T00:04:27+07:00
draft: false
tags: ["ctf", "re"]
categories: ["apoorvctf 2026"]
contest: "apoorvctf 2026"
author: "k1nt4r0u"
description: "Cutting through anti-debug noise and solving Forge as linear algebra over a custom byte field"
difficulty: "Medium"
---

# apoorvctf 2026 — Forge

## First impression

`forge` looked much worse than it really was.

The binary is stripped, PIE, and imports a mix of `ptrace`, `fork`, `prctl`, `mmap`, `RAND_bytes`, `EVP_sha256`, and `EVP_aes_256_gcm`. That is exactly the kind of import table that tries to make you expect anti-debugging, runtime decryption, and maybe a second stage.

I did chase that direction for a bit. One decoded string in `.rodata` even hinted at `payload>bin`, which made it look like something external might be missing.

The good news is that none of that turned out to matter.

## The real pivot

The turning point was simply watching what the main loop actually did instead of what the imports suggested.

Once I looked at the repeated operations, the pattern was hard to miss:

- pick a pivot
- find an inverse
- normalize a row
- eliminate that column from every other row

That is Gaussian elimination, not cryptography.

The binary was solving a fixed linear system over bytes. The multiplication was not normal integer multiplication, though. Every product came from a `256 x 256` lookup table stored in `.rodata`, so the arithmetic was happening in a custom GF(256)-style field.

That changed the whole challenge. I no longer cared about the anti-debug path or the missing payload hint. I only needed the constants.

## Rebuilding the system

The relevant data was all embedded in the main binary:

- a `56 x 56` coefficient matrix
- a 56-byte right-hand side
- a 65536-byte multiplication table

Together they form a `56 x 57` augmented matrix.

So I wrote a small Python solver that:

1. reads the binary bytes,
2. extracts the matrix and multiplication table from `.rodata`,
3. performs the same row-reduction logic as the binary,
4. finds multiplicative inverses by scanning for `mul(a, x) == 1`,
5. and finally reads the last column once the matrix is reduced.

That is enough because the verifier is deterministic. The flag is already baked into the embedded system.

## Why the static route works

This is the part I liked most about the challenge: it is mostly misdirection.

The program wants you to spend time on the surrounding noise:

- anti-debugging
- OpenSSL calls
- process tricks
- a suspicious payload path

But the actual answer is sitting in plain sight as a solvable algebra problem. Once I committed to that interpretation, the challenge became much smaller.

## Result

The reduced matrix decoded cleanly as ASCII:

```text
APOORVCTF{Y0u_4ctually_brOught_Y0ur_owN_Firmw4re????!!!}
```

## Takeaway

`Forge` is a good reminder that "lots of crypto imports" is not the same thing as "the solve is cryptography." The real signal was the row-reduction pattern. After that, the rest of the binary was just decoration.
