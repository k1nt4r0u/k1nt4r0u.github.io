---
title: "WannaGame Championship 2025 - Reversing Writeup"
date: 2025-12-25T21:37:47+07:00
draft: false
categories: ["ctf", "WannaGame Championship 2025"]
contest: "WannaGame Championship 2025"
author: "k1nt4r0u"
description: "Cleaned-up event notes for three WannaGame reversing challenges, kept honest where the original solve artifacts are incomplete"
---

# WannaGame Championship 2025 — Reversing Notes

These are cleaned-up contest notes rather than polished full writeups. `Buzzing` has a complete solve path, but `Checker` and `Dutchman_app` are intentionally kept as partial notes because the missing final artifacts are not preserved in this repo. I would rather leave those gaps visible than pretend I remember more than I actually do.

## Buzzing

I started this one in the wrong direction. My first instinct was to copy the challenge out of the remote environment and reverse it locally, but that was not really necessary.

After poking around the instance with basic Linux commands, the useful observation was that the restriction seemed to be tied to the literal `/readflag` path. In other words, eBPF was likely filtering commands that referenced that exact pathname, not blocking the underlying file from running under a different name.

That makes the bypass almost trivial:

```sh
ln -s /readflag /tmp/solve
/tmp/solve
```

Running the symlinked path was enough to read `/flag`.

I do not have the exact printed flag string saved in these notes, but the actual solve path was just this symlink bypass. The important idea was realizing the filter cared about the command path, not the file contents.

## Checker

This challenge gave a Windows PE wrapper:

```text
checker.exe: PE32+ executable for MS Windows 6.00 (console), x86-64, 6 sections
```

The first useful step was reversing the wrapper itself, not the checker logic. In IDA, `main` asks the user to choose checker `1` or `2`, maps that choice to resource IDs `101` and `102`, extracts the selected resource into a file named `flag_checker.exe`, executes it, waits for it to finish, and then deletes it.

That immediately changed the plan. I did not need to understand the wrapper deeply. I just needed to catch the extracted payloads before they were removed.

So I broke on `DeleteFileA`, ran the wrapper twice with the two different options, and recovered both embedded `flag_checker.exe` files for offline analysis.

### Checker 1

The first recovered checker was the one I made meaningful progress on.

The code looked messy enough that I initially was not sure what family of transform I was even looking at. After following cross-references and leaning on AI for algorithm identification, the checker turned out to apply several layers in sequence:

- ChaCha20
- an LCG-based byte mask
- RC4
- a repeating XOR with the key `skibidi`

The key material itself was not the hardest part. Most of it was easy to recover from constants and xrefs. The annoying piece was the LCG seed. I grabbed that dynamically by breaking immediately after the call to `sub_140002370(1337)` and reading `rax`, which gave me `0xAD66AA22`.

With that seed, I could reverse the layers:

![image](/images/WGC2025/WGC2025_1.png)

![image](/images/WGC2025/WGC2025_2.png)

```python
from Crypto.Cipher import ARC4, ChaCha20

target_signed = [-4, 118, -44, 9, -93, -40, 80, 47, -71, -41, -70, -32, -80, 52, -78]
ciphertext = bytes((x + 256) % 256 for x in target_signed)
key_xor = b"skibidi"
key_rc4 = bytes(range(1, 17))
key_chacha = b"\xAA" * 32
nonce_chacha = b"\x45" * 12

def chacha(data, key, nonce):
    return ChaCha20.new(key=key, nonce=nonce).decrypt(data)

def lcg(data, seed):
    out = bytearray()
    state = seed & 0xFFFFFFFFFFFFFFFF
    for byte in data:
        mask = 0
        tmp = state
        for _ in range(8):
            mask ^= tmp & 0xFF
            tmp >>= 8
        out.append(byte ^ (mask & 0xFF))
        state = (state * 0x5851F42D4C957F2D + 0x14057B7EF767814F) & 0xFFFFFFFFFFFFFFFF
    return bytes(out)

def rc4(data, key):
    return ARC4.new(key).decrypt(data)

def xor(data, key):
    return bytes(d ^ key[i % len(key)] for i, d in enumerate(data))

print(xor(rc4(lcg(chacha(ciphertext, key_chacha, nonce_chacha), 0xAD66AA22), key_rc4), key_xor))
```

That recovered:

```text
W1{Ch4ng1ng_d4t
```

And that is where my preserved notes stop. I did not finish reconstructing parts 2 and 3 from the second checker during the event, so I am leaving this section as a partial solve rather than fabricating the missing ending.

### Checker 2

I also recovered the second embedded checker, which appears to be responsible for the remaining parts of the flag, but these notes do not contain a finished analysis or final reconstruction. The honest state is simply: wrapper understood, payload extraction solved, checker 1 partly reversed, full flag not preserved.

## Dutchman_app

This challenge unpacked into an APK, so the first pass was standard Android reversing with `jadx`.

`MainActivity` immediately showed a few suspicious details:

- a lockout stored in `SharedPreferences`
- a native library load for `check_new_detection`
- logic that appeared to reject unauthorized devices before the real app flow could continue

![image](/images/WGC2025/WGC2025_3.png)

The `UnlockTime` value is set to `currentTimeMillis() + 180000`, so getting rejected means waiting three minutes before the app will even let you try again. That made the device-gating logic worth bypassing first.

I moved from `jadx` to `apktool`, decompiled the APK, and patched `MainActivity.smali` to jump over the device check. The point was not to solve the whole challenge in smali, just to keep the app alive long enough to see the next stage.

The patch was essentially:

```smali
if-nez p1, :cond_11
if-nez v1, :cond_11
if-nez v3, :cond_11
if-nez v4, :cond_c
```

with an added branch to skip the rejection path.

![image](/images/WGC2025/WGC2025_4.png)

That was the meaningful pivot. After rebuilding and retrying post-contest, I could at least reach the security-key screen, which confirmed that the Java layer was only the front door and the real logic likely lived in the native library.

At that point I switched to the bundled `.so` files:

```text
arm64-v8a/libcheck_new_detection.so
armeabi-v7a/libcheck_new_detection.so
x86/libcheck_new_detection.so
x86_64/libcheck_new_detection.so
```

But the notes preserved here stop before the native analysis reaches a final key or flag.

So the honest state of this writeup is:

- I identified and bypassed the device-gating layer,
- I confirmed the native library was the next target,
- I do not have the rest of the solve path or final flag saved in this repo.



