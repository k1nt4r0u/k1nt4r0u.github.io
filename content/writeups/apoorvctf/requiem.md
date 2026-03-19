---
title: "Requiem"
date: 2026-03-07T00:05:34+07:00
draft: false
tags: ["ctf", "reversing", "pwn", "crypto", "web", "forensics", "misc"]
categories: ["CTF Name"]
contest: "apoorvctf 2026"
author: "k1nt4r0u"
description: "A detailed writeup for Requiem challenge"
difficulty: "Easy/Medium/Hard"
---

## Requiem Writeup

This challenge is a reverse engineering task on a stripped Linux ELF called `requiem`.

The binary looks annoying at first because it is compiled from Rust, which usually means:

- lots of code in the disassembly
- many standard library routines
- very little useful symbol information

Even with that noise, the actual flag logic is small. The intended path is to find where the flag is stored, recover the decode operation, and reconstruct the output before the program destroys it.

## Goal

Recover the flag from the binary.

Final flag:

```text
apoorvctf{N0_M0R3_R3QU13M_1N_TH15_3XP3R13NC3}
```

## Step 1: Basic Recon

First, identify what the file is:

```bash
file requiem
```

Output:

```text
ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
```

That tells us a few important things:

- it is a Linux x86-64 binary
- PIE means addresses are position-independent at runtime
- stripped means function names are mostly gone

Then check protections:

```bash
checksec file requiem
```

Relevant result:

```text
Full RELRO
NX enabled
PIE enabled
No canary found
```

For a reversing challenge, the protections are not the main issue. They mostly matter for pwn tasks. Here they just confirm this is not about a simple buffer overflow exploit.

## Step 2: Run the Binary

After marking it executable, run it:

```bash
chmod +x requiem
./requiem
```

It prints:

```text
loading flag
printing flag.....
RETURN TO ZERO!!!!!!!!
```

This is already a strong hint.

The program claims it is loading and printing the flag, but it never actually shows it. The line `RETURN TO ZERO!!!!!!!!` suggests that whatever value holds the flag may be getting reset or wiped before the program finishes.

## Step 3: Check for External Flag Reads

The next question is simple: does the binary read the flag from a file, environment variable, or network source?

Tracing syscalls is the fastest way to answer that:

```bash
strace -o /tmp/requiem.strace ./requiem
tail -n 80 /tmp/requiem.strace
```

What matters from the trace is that there is no meaningful file access for a flag. The only notable read is `/proc/self/maps`, which Rust binaries sometimes inspect for runtime reasons.

This gives an important conclusion:

- the flag is probably embedded in the binary itself
- or it is generated entirely in memory from embedded data

That narrows the problem a lot.

## Step 4: Search for Useful Strings

Now inspect strings in the binary:

```bash
strings -tx requiem | grep -E 'loading flag|printing flag|RETURN TO ZERO|flag'
```

This gives offsets like:

```text
47000 loading flag
4851f i'printing flag.....
48534 RETURN TO ZERO!!!!!!!!
```

This output is more useful than it looks.

The interesting detail is the strange `i'printing flag.....` result. That means the bytes immediately before the string are also printable and are likely part of some nearby data blob. In reverse challenges, that often means encrypted or transformed flag bytes are sitting right next to user-facing strings in `.rodata`.

## Step 5: Dump the Nearby Read-Only Data

To inspect the region around those strings:

```bash
objdump -s -j .rodata --start-address=0x484e0 --stop-address=0x48580 requiem
```

Relevant bytes:

```text
484f0 2e727300 3b2a3535 282c392e 3c21146a
48500 05176a08 69050869 0b0f6b69 17056b14
48510 050e126b 6f056902 0a69086b 69141969
48520 27707269 6e74696e 6720666c 61672e2e
48530 2e2e2e0a 52455455 524e2054 4f205a45
48540 524f2121 21212121 21210a00
```

The bytes starting at `0x484f4` up to just before `printing flag.....` are the real target. That chunk is 45 bytes long. It looks random enough that it is probably encrypted or XORed.

The full blob is:

```text
3b2a3535282c392e3c21146a05176a08690508690b0f6b6917056b14050e126b6f0569020a69086b6914196927
```

## Step 6: Find Code That Uses the Blob

At this point, the job is to answer two questions:

1. where is this blob referenced?
2. what operation is applied to it?

Using disassembly, the important reference shows up at `0xba37`:

```text
0xba37  lea r12, [rip + 0x3cab6]
```

That instruction loads a pointer to the blob in `.rodata`.

Disassembling around that area reveals the core loop:

```text
0xba37  lea r12, [rip + 0x3cab6]   ; encoded bytes
...
0xba7b  movzx ebp, byte [r15 + r12]
...
0xba60  xor bpl, 0x5a
0xba69  mov byte [rax + r15], bpl
0xba6d  inc r15
0xba75  cmp r15, 0x2d
```

This is the entire decode routine in practice:

- read one byte from the embedded blob
- XOR it with `0x5a`
- store the result into an output buffer
- repeat for `0x2d` bytes

Since `0x2d = 45`, we know exactly how many bytes to decode.

## Step 7: Understand the Trick

The program still does not print the flag, so what happens after decoding?

Immediately after the decode loop, the function clears the buffer byte by byte:

```text
0xbb00  mov byte [rax + rsi], 0
0xbb04  mov byte [rax + rsi + 1], 0
...
0xbb40  mov byte [rax + rdx], 0
```

That matches the runtime hint perfectly.

`RETURN TO ZERO!!!!!!!!` is not just flavor text. The program literally returns the flag buffer to zero after recovering it.

So the challenge is not about getting the program to print the flag. It is about spotting the decode routine before the wipe and reproducing it ourselves.

## Step 8: Decode the Flag Manually

Once we know the blob and the XOR key, the solve is straightforward.

Python one-liner version:

```python
blob = bytes.fromhex("3b2a3535282c392e3c21146a05176a08690508690b0f6b6917056b14050e126b6f0569020a69086b6914196927")
flag = bytes(b ^ 0x5A for b in blob)
print(flag.decode())
```

Output:

```text
apoorvctf{N0_M0R3_R3QU13M_1N_TH15_3XP3R13NC3}
```

## Why the Last Byte Matters

A small detail can trip you up here.

If you only decode the bytes that look obviously non-string-like, you may miss the final encoded byte `27`, which sits directly before the text `printing flag.....`.

That byte is part of the 45-byte encoded flag.

When XORed with `0x5a`:

$$
0x27 \oplus 0x5a = 0x7d
$$

`0x7d` is `}`, the closing brace of the flag.

So the full encoded blob must include that last byte.

## Solve Script

The full solve script is in [solve.py](./solve_requiem.py).

For convenience, here it is as well:

```python
#!/usr/bin/env python3

ENCODED_FLAG = bytes.fromhex(
	"3b2a3535282c392e3c21146a05176a08690508690b0f6b6917056b14050e126b"
	"6f0569020a69086b6914196927"
)
XOR_KEY = 0x5A


def main() -> None:
	flag = bytes(byte ^ XOR_KEY for byte in ENCODED_FLAG)
	print(flag.decode())


if __name__ == "__main__":
	main()
```

## Short Version

- the binary does not load a flag from a file
- the flag is stored as an encoded blob in `.rodata`
- a loop XORs each byte with `0x5a`
- the decoded buffer is wiped immediately afterward
- reproducing the XOR locally gives the flag

## Flag

```text
apoorvctf{N0_M0R3_R3QU13M_1N_TH15_3XP3R13NC3}
```
