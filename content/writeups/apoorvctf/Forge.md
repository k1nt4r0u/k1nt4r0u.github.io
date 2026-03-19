---
title: "Forge"
date: 2026-03-07T00:04:27+07:00
draft: false
tags: ["ctf", "reversing", "pwn", "crypto", "web", "forensics", "misc"]
categories: ["CTF Name"]
contest: "apoorvctf 2026"
author: "k1nt4r0u"
description: "A detailed writeup for Forge challenge"
difficulty: "Easy/Medium/Hard"
---

# Forge Writeup

## Summary

This challenge is a stripped 64-bit ELF binary named `forge`.
Although it includes anti-debugging and a misleading runtime path, the flag can be recovered statically from constants embedded in the binary.

## Final Flag

`APOORVCTF{Y0u_4ctually_brOught_Y0ur_owN_Firmw4re????!!!}`

## Solve script

A standalone solver is included as `solve.py` in the same folder.

Run it with:

- `python3 solve.py`

It reads the local `forge` binary, extracts the matrix and multiplication table from `.rodata`, performs the same elimination as the binary, and prints the recovered flag.

## Step-by-step solve

### 1. Identify the binary

First, I checked the file type and basic properties:

- It is a stripped PIE ELF executable.
- It links against OpenSSL.
- It imports functions like `ptrace`, `fork`, `prctl`, `mmap`, `RAND_bytes`, `EVP_sha256`, and `EVP_aes_256_gcm`.

That combination strongly suggests:

- anti-debugging / anti-analysis logic,
- some cryptographic helper routines,
- and likely a staged or obfuscated verification flow.

### 2. Check strings, but do not trust them too much

Running `strings` gave mostly noise plus OpenSSL symbols.
That indicated the binary was not going to reveal the flag directly through printable strings.

One useful clue was an XOR-obfuscated string in `.rodata` that decodes to:

- `payload>bin`

This suggests the program expects or references another stage, but that stage was not present in the workspace.

### 3. Disassemble the main logic

I used `objdump` to inspect the main function and found:

- an early `ptrace` anti-debug check,
- memory mappings with `mmap`,
- a large table copied from `.rodata`,
- and a long loop that performs row operations on fixed-size blocks.

The important observation was that the program repeatedly:

- selects a pivot,
- finds a multiplicative inverse,
- normalizes a row,
- and XORs scaled rows into the others.

That is the shape of Gaussian elimination.

### 4. Recognize the arithmetic domain

The verifier does not use normal integer multiplication.
Instead, it indexes a `256 x 256` lookup table stored in `.rodata` and uses the result as multiplication.

So the solver is performing linear algebra over a custom GF(256)-style byte field.

The relevant embedded data is:

- a 56x56 coefficient matrix,
- a 56-byte right-hand-side vector,
- and the 65536-byte multiplication table.

Together they form a 56x57 augmented matrix.

### 5. Rebuild the matrix statically

From the `.rodata` layout, I extracted:

- each row of 56 coefficients from the large constant block,
- one extra byte per row from a smaller nearby constant block,
- then assembled them into the augmented system.

At that point, the challenge reduced to emulating the binary's elimination logic exactly.

### 6. Emulate the binary's elimination

I wrote a short Python script to:

- load the binary bytes,
- extract the matrix and multiplication table,
- perform pivot search and row swapping,
- compute multiplicative inverses by scanning for `mul(a, x) == 1`,
- normalize pivot rows,
- eliminate all other rows,
- and finally read the last column of the reduced matrix.

After reduction, the left side becomes the identity matrix and the final column is the solution.

### 7. Decode the result

The recovered 56-byte solution decoded cleanly as ASCII:

`APOORVCTF{Y0u_4ctually_brOught_Y0ur_owN_Firmw4re????!!!}`

## Why static analysis was enough

Even though the binary contains runtime behavior involving:

- random data generation,
- SHA-256,
- AES-256-GCM,
- and a child process / second-stage path,

none of that was necessary to recover the flag.

The actual printable success data is already determined by the embedded linear system in the main binary.
So the missing external stage does not block the solve.

## Key takeaway

The main trick of the challenge is misdirection:

- anti-debugging makes dynamic analysis annoying,
- crypto calls make it look like the flag is hidden behind encryption,
- but the core solve is actually linear algebra over a byte field.

Once the row-reduction logic is recognized, the flag falls out directly.

