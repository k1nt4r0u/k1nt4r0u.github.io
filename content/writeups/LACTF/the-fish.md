---
title: "The Fish"
date: 2026-02-07T16:34:23+07:00
draft: false
tags: ["ctf", "re"]
categories: ["CTF Name"]
contest: "LACTF 2026"
author: "k1nt4r0u"
description: "Description: "
---
# Fish CTF Challenge — Solution

## Flag

```
lactf{7h3r3_m4y_83_50m3_155u35_w17h_7h15_1f_7h3_c011472_c0nj3c7ur3_15_d15pr0v3n}
```

> *"there may be some issues with this if the collatz conjecture is disproven"*

---

## Overview

The challenge provides a Python-based **><> (Fish) esoteric language** interpreter and a one-line Fish program (the "fisherator") that checks user input against a hardcoded large integer.

## Algorithm (Forward)

The fisherator transforms the flag in two stages:

### Stage 1 — Base-256 Encoding

The flag string is converted into a single big integer by treating its ASCII bytes as a big-endian base-256 number:

$$\text{acc} = \sum_{i=0}^{n} \text{ord}(c_i) \cdot 256^{n-i}$$

This is equivalent to `int.from_bytes(flag.encode(), 'big')`.

### Stage 2 — Collatz Path Encoding

A modified [Collatz sequence](https://en.wikipedia.org/wiki/Collatz_conjecture) is run on `acc`, encoding each step's parity into a `counter`:

```
counter = 1
while acc ≠ 1:
    counter *= 2
    if acc is even:
        acc = acc // 2
    else:
        counter += 1
        acc = (acc * 3 + 1) // 2
```

The final `counter` is compared against the hardcoded target number via the `n` instruction. If they match, the flag is correct.

## Reversing

### Step 1 — Undo the Collatz Encoding

Starting from `counter = TARGET` and `acc = 1`, reverse each step by inspecting the parity of `counter`:

```python
while counter > 1:
    if counter % 2 == 0:       # was an even Collatz step
        counter //= 2
        acc *= 2
    else:                       # was an odd Collatz step
        counter = (counter - 1) // 2
        acc = (acc * 2 - 1) // 3
```

This recovers the original big integer in **2999 steps**.

### Step 2 — Decode the Integer

Convert the recovered integer back to bytes (big-endian) to obtain the flag:

```python
flag = acc.to_bytes((acc.bit_length() + 7) // 8, 'big').decode('ascii')
```


