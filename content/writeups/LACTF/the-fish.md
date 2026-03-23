---
title: "The Fish"
date: 2026-02-07T16:34:23+07:00
draft: false
tags: ["CTF", "RE"]
categories: ["LACTF 2026"]
contest: "LACTF 2026"
author: "k1nt4r0u"
description: "Reversing the Fish checker by undoing its Collatz-style encoding"
---
## Setup

The challenge came with a Python-based `><>` (Fish) interpreter and a one-line Fish program that checked the input against one huge constant.

The hint was the important part:

> "there may be some issues with this if the collatz conjecture is disproven"

That line was enough to stop me from treating this like a generic esolang problem. The checker was clearly doing some arithmetic transform, and the Collatz reference suggested that the flag was being folded into a single integer rather than checked character by character.

## First clue

After translating the Fish program into normal logic, the checker reduced to two stages.

First, it turned the input string into one big integer by reading the bytes as a big-endian base-256 number:

$$
\text{acc} = \sum_{i=0}^{n} \text{ord}(c_i) \cdot 256^{n-i}
$$

So at that point the input was effectively:

```python
acc = int.from_bytes(flag.encode(), "big")
```

Then it ran a modified Collatz process and packed the parity decisions into another integer:

```python
counter = 1
while acc != 1:
    counter *= 2
    if acc % 2 == 0:
        acc //= 2
    else:
        counter += 1
        acc = (acc * 3 + 1) // 2
```

The checker never compared the string directly. It only compared the final `counter` against a hardcoded target.

That mattered because it meant I did not need to emulate the Fish program forward. I only needed to invert the transform.

## Turning the checker around

The useful observation is that every loop iteration doubles `counter`, and the odd branch adds one on top of that. So if I start from the final target and walk backward, the parity of `counter` tells me which branch was taken.

- even `counter` means the forward step came from an even Collatz update
- odd `counter` means the forward step came from the modified odd update

That gives a clean reverse procedure:

```python
while counter > 1:
    if counter % 2 == 0:
        counter //= 2
        acc *= 2
    else:
        counter = (counter - 1) // 2
        acc = (acc * 2 - 1) // 3
```

Running that backward walk recovered the original big integer after 2999 steps.

That was the only real pivot in the challenge. Once the reverse direction was clear, the rest was just decoding bytes.

## Recovering the flag

After reconstructing `acc`, I converted it back to a byte string:

```python
flag = acc.to_bytes((acc.bit_length() + 7) // 8, "big").decode("ascii")
print(flag)
```

That produced:

```text
lactf{7h3r3_m4y_83_50m3_155u35_w17h_7h15_1f_7h3_c011472_c0nj3c7ur3_15_d15pr0v3n}
```

## Verification

The recovered string matched the challenge theme exactly and includes the Collatz joke from the hint, which is a good sign that the reverse process is correct.

Final flag:

```text
lactf{7h3r3_m4y_83_50m3_155u35_w17h_7h15_1f_7h3_c011472_c0nj3c7ur3_15_d15pr0v3n}
```
