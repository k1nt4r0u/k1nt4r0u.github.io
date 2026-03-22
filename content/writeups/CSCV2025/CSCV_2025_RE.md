---
title: "CSCV_2025_RE"
date: 2025-12-25T22:33:30+07:00
draft: false
tags: ["ctf", "re"]
categories: ["CTF Name"]
contest: "CSCV_2025_RE"
author: "k1nt4r0u"
description: "Two CSCV reversing solves: an anti-debug fake flag checker and a PyInstaller chatbot with a native AES decryptor"
---

# CSCV 2025 Reversing Notes

## ReezS

### First wrong turn

My first read on this binary was completely wrong. It looked like a normal flag checker, so I did what I usually do for that kind of challenge: identify the comparison logic, lift the constants, and script the inverse.

![image](/images/CSCV/CSCV_1.png)

![image](/images/CSCV/CSCV_2.png)

That script only gave me:

```text
sorry_this_is_fake_flag!!!!!!!!!
```

That should have been a clue immediately, but I still lost a lot of time staring at the control flow.

The behavior that finally forced me to rethink the challenge was this:

- under a debugger, `sorry_this_is_fake_flag!!!!!!!!!` was accepted
- running the same input normally, it failed

Same input, same binary, different result. That is not a math mistake. That is environment-sensitive behavior.

### The actual pivot

After the contest I came back to the import table, and the answer was sitting there:

![image](/images/CSCV/CSCV_3.png)

`IsDebuggerPresent` is imported, and the program checks it very early.

![image](/images/CSCV/CSCV_4.png)

![image](/images/CSCV/CSCV_5.png)

That explained the split behavior perfectly. The fake string was not a failed inversion of the real checker. It was bait. The binary was selecting different encoded data depending on whether a debugger was attached.

Once I knew that, I stopped trying to model every branch. I just took the two real encoded blocks from the debugger-only path, XORed them with the constant mask, swapped the halves into the right order, and reversed the decoded string.

This is the cleaned-up version of the script:

```python
def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def main():
    factor0 = bytes([0xAA]) * 16
    factor1 = bytes.fromhex('939FCF9C9B9998C99DC8C9989ECFCB9A')
    factor2 = bytes.fromhex('9F9D9D9DCB989A9B999A98CF9DCFCFCF')
    part1 = xor_bytes(factor1, factor0)
    part2 = xor_bytes(factor2, factor0)
    flag_bytes = part2 + part1
    print(f"CSCV2025{{{flag_bytes.decode('utf-8')[::-1]}}}")


if __name__ == '__main__':
    main()
```

That recovered:

```text
CSCV2025{0ae42cb7c2316e59eee7e203102a7775}
```

The whole solve really came down to noticing that the checker was lying differently depending on whether it saw a debugger.

## Chatbot

### First pass

This executable looked different right away. Opening it in IDA showed PyInstaller-style markers, so instead of treating it like a normal native binary, I treated it like a packaged Python app with a native helper library.

![image](/images/CSCV/CSCV_6.png)

That meant the first useful step was extraction, not decompilation. I used `pyinstxtractor.py` to unpack the bundled files:

![image](/images/CSCV/CSCV_7.png)

I did not have `decompyle3` available, so I used an online decompiler to get a readable `main.py`. The high-level flow was enough:

- load `libnative.so`
- optionally run an integrity check
- verify a token for `role == VIP`
- if that passes, call `decrypt_flag_file("flag.enc")`

That last point was the real clue. The program pretends the hard part is token validation, but the Python side already tells us the flag is sitting in a local encrypted file and the decryption routine lives in the native library we already have.

So I stopped caring about forging a VIP token and moved straight to `libnative.so`.

![image](/images/CSCV/CSCV_8.png)

### Native side

Inside the library, `decrypt_flag_file` calls `recover_key`:

![image](/images/CSCV/CSCV_9.png)

And `recover_key` is much simpler than the name makes it sound. It just rebuilds the original AES key from an obfuscated byte array and a short repeating mask:

![image](/images/CSCV/CSCV_10.png)

Back in `decrypt_flag_file`, the logic is straightforward:

- read the first 16 bytes of `flag.enc` as the IV,
- treat the rest as ciphertext,
- choose the AES branch based on key length,
- decrypt.

Because the recovered key is 32 bytes long, the branch used here is AES-256-CBC.

That means the whole solve can be reproduced locally without ever passing the token check.

I reimplemented the key recovery and decryption in Python:

```python
#!/usr/bin/env python3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

OBF_KEY = [
    0xEE, 0x50, 0xD1, 0xAA, 0xE0, 0x97, 0x5F, 0x43, 0xDD, 0xA8, 0xAC, 0x83,
    0xF0, 0x05, 0xF3, 0xFF, 0x62, 0x08, 0xF4, 0x44, 0x4B, 0x2C, 0x55, 0xEC,
    0xB9, 0x65, 0x23, 0xCC, 0x25, 0x65, 0xEE, 0x70
]
MASK = [0x2a, 0x2a, 0xa, 0x9a]


def recover_key():
    recovered_key = bytearray(32)
    recovered_key[0] = 0xC4
    for i in range(1, 32):
        mask_byte = MASK[i & 3]
        recovered_key[i] = OBF_KEY[i] ^ mask_byte
    return bytes(recovered_key)


key = recover_key()


def decrypt_flag_file(filename):
    with open(filename, "rb") as f:
        iv = f.read(16)
        ct = f.read()
    cipher = Cipher(algorithms.AES256(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()


def main():
    decrypted_data = decrypt_flag_file("flag.enc")
    if decrypted_data:
        print(decrypted_data.decode("utf-8"))


if __name__ == "__main__":
    main()
```

That decrypted the bundled file and printed:

```text
CSCV2025{reversed_vip*_chatbot_bypassed}
```

The nice part of this challenge is that the intended story is "become VIP," but the cleaner reversing route is just to follow the local decryption path and ignore the access-control theater entirely.


