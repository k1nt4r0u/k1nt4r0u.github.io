---
title: "Requiem"
date: 2026-03-07T00:05:34+07:00
draft: false
tags: ["ctf", "re"]
categories: ["apoorvctf 2026"]
contest: "apoorvctf 2026"
author: "k1nt4r0u"
description: "Recovering an embedded flag from a Rust binary by finding the XOR-then-wipe routine"
difficulty: "Easy"
---

# apoorvctf 2026 — Requiem

## First look

`requiem` is a stripped Rust ELF, which usually means a lot of disassembly noise before you get to the part that matters.

Running it gave a very suspicious three-line script:

```text
loading flag
printing flag.....
RETURN TO ZERO!!!!!!!!
```

No flag ever appeared, but the message was already telling the story. Something was probably being decoded in memory and then wiped immediately.

## Making sure the flag is local

Before digging into the binary, I wanted to know whether the program fetched the flag from outside.

`strace` answered that quickly: there was no meaningful flag file access and no network activity. That meant the flag was almost certainly embedded in the binary itself, or at least derived entirely from embedded data.

That narrowed the search a lot.

## The suspicious blob next to the strings

The next useful move was checking strings with offsets. The interesting output looked like this:

```text
47000 loading flag
4851f i'printing flag.....
48534 RETURN TO ZERO!!!!!!!!
```

That odd `i'printing flag.....` line was the clue. It meant there were printable bytes immediately before the visible string, which usually means some nearby data blob is being interpreted as text.

Dumping the surrounding `.rodata` region revealed a 45-byte chunk right before `printing flag.....`:

```text
3b2a3535282c392e3c21146a05176a08690508690b0f6b6917056b14050e126b6f0569020a69086b6914196927
```

That did not look random enough to be compressed and did not look structured enough to be plain text. XOR-encoded data was the obvious guess.

## Finding the decode loop

Once I looked for cross-references to that blob, the core logic showed up quickly. The important loop does exactly this:

- load one byte from the embedded blob,
- XOR it with `0x5a`,
- write it to an output buffer,
- repeat for `0x2d` bytes.

In other words:

```python
flag = bytes(byte ^ 0x5A for byte in blob)
```

The joke line at runtime also turned out to be literal. Right after decoding the buffer, the program zeroes it out byte by byte. So the challenge is not "make it print the flag," it is "notice the decode before the wipe."

## The easy mistake

One small detail is easy to miss.

The final encoded byte, `27`, sits directly in front of the `printing flag.....` string. If you stop the blob one byte too early, you lose the closing brace.

That last byte matters:

$$
0x27 \oplus 0x5a = 0x7d
$$

and `0x7d` is `}`.

So the entire 45-byte blob has to be included.

## Recovering the flag

At that point the solve is just one line of Python:

```python
blob = bytes.fromhex(
    "3b2a3535282c392e3c21146a05176a08690508690b0f6b6917056b14050e126b"
    "6f0569020a69086b6914196927"
)
print(bytes(byte ^ 0x5A for byte in blob).decode())
```

Output:

```text
apoorvctf{N0_M0R3_R3QU13M_1N_TH15_3XP3R13NC3}
```

## Takeaway

This one looks noisy because it is a Rust binary, but the solve is tiny once the runtime hint clicks. The binary really does "return to zero." The whole challenge is about catching the XOR decode before the program wipes its own work.
