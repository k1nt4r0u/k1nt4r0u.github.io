---
title: "CSCV_2025_RE"
date: 2025-12-25T22:33:30+07:00
draft: false
tags: ["ctf", "re"]
categories: ["CTF Name"]
contest: "CSCV_2025_RE"
author: "k1nt4r0u"
description: "Description: "
---

### ReezS
When I take the very first look at this program i was just thinking this must be a basic `flag_checker` program

![image](/images/CSCV/CSCV_1.png)

![image](/images/CSCV/CSCV_2.png)

so I basically just wrote a script in order to get the flag but all I got is `sorry_this_is_fake_flag!!!!!!!!!`

I took me more than 4 hours finding sussy stuff in this program. Fortunately, I realized that when I use debugger to run the program with key `sorry_this_is_fake_flag!!!!!!!!!`, it always returns `Yes` but when I run the program in my shell with the same key, it returns `No`. Despite of seeing that, I didn't do anything but just tried to figure out the program flow (I'm blind tho)

After the contest, thanks to an anti-debug challenge, I came up with the idea to check the import page which shows all function are imported into the program 

![image](/images/CSCV/CSCV_3.png)

Here we can see that `IsDebuggerPresent` is imported

As I thought, `IsDebuggerPresent` is called when starting the program to check if it is being run by a debugger or not

![image](/images/CSCV/CSCV_4.png)

![image](/images/CSCV/CSCV_5.png)

Thus, the actual encoded flag are used to check our input when we use debugger so we just replace it in script and get the real flag hehe 
This is my script:

```python
def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))
def main():
    factor0 = bytes.fromhex('A' * 32)
    factor1 = bytes.fromhex('939FCF9C9B9998C99DC8C9989ECFCB9A')  
    factor2 = bytes.fromhex('9F9D9D9DCB989A9B999A98CF9DCFCFCF')
    part1 = xor_bytes(factor1, factor0) 
    part2 = xor_bytes(factor2, factor0)
    flag_bytes = part2 + part1
    print(f"CSCV2025{{{flag_bytes.decode('utf-8')[::-1]}}}")
if __name__ == '__main__':
    main()
```

`CSCV2025{0ae42cb7c2316e59eee7e203102a7775}`

### Chatbot
In this challenge, I used IDA to disassemble the program and then I see some useful information

![image](/images/CSCV/CSCV_6.png)

which means this is a pyinstaller generated executable file. Knowing that, I used `pyinstxtractor.py` to extract the file.

![image](/images/CSCV/CSCV_7.png)
While inspecting file `main.pyc`, since I cannot install `decompyle3` (skill issues), I used a decompiler online and got `main.py`

```python
import base64
import json
import time
import random
import sys
import os
from ctypes import CDLL, c_char_p, c_int, c_void_p
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import ctypes

def get_resource_path(name):
    if getattr(sys, 'frozen', False):
        base = sys._MEIPASS
    else:  # inserted
        base = os.path.dirname(__file__)
    return os.path.join(base, name)

def load_native_lib(name):
    return CDLL(get_resource_path(name))
if sys.platform == 'win32':
    LIBNAME = 'libnative.dll'
else:  # inserted
    LIBNAME = 'libnative.so'
lib = None
check_integrity = None
decrypt_flag_file = None
free_mem = None
try:
    lib = load_native_lib(LIBNAME)
    check_integrity = lib.check_integrity   
    check_integrity.argtypes = [c_char_p]
    check_integrity.restype = c_int
    decrypt_flag_file = lib.decrypt_flag_file
    decrypt_flag_file.argtypes = [c_char_p]
    decrypt_flag_file.restype = c_void_p
    free_mem = lib.free_mem
    free_mem.argtypes = [c_void_p]
    free_mem.restype = None
except Exception as e:
    print('Warning: native lib not loaded:', e)
    lib = None
    check_integrity = None
    decrypt_flag_file = None
    free_mem = None

def run_integrity_or_exit():
    if check_integrity:
        ok = check_integrity(sys.executable.encode())
        if ok:
            print('[!] Integrity failed or debugger detected. Exiting.')
            sys.exit(1)
PUB_PEM = b'-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsJftFGJC6RjAC54aMncA\nfjb2xXeRECiwHuz2wC6QynDd93/7XIrqTObeTpfBCSpOKRLhks6/nzZFTTshttps://hackmd.io/uC9DCV3lSUqkaUnt-NlQzAYdQCj\n4roXhWo5lFfH0OTL+164VoKnmUkQ9dppzpmV0Kpk5IQhEyuPYzJfFAlafcHdQvUo\nidkqcOPpR7hznJPEuRbPxJod34Bph/u9vePKcQQfe+/l/nn02nbfYWTuGtuEdpHq\nMkktl4WpB50/a5ZqYkW4z0zjFCY5LIPE7mpUNLrZnadBGIaLoVV2lZEBdLt6iLkV\nHXIr+xNA9ysE304T0JJ/DwM1OXb4yVrtawbFLBu9otOC+Gu0Set+8OjfQvJ+tlT/\nzQIDAQAB\n-----END PUBLIC KEY-----'
public_key = None
try:
    pub_path = get_resource_path('public.pem')
    if os.path.exists(pub_path):
        with open(pub_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read())
    else:  # inserted
        public_key = serialization.load_pem_public_key(PUB_PEM)
except Exception as e:
            print('Failed loading public key:', e)
            public_key = None

def b64url_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

def b64url_decode(s):
    s = s | ('=', 4, len(s) - 4) | 4
    return base64.urlsafe_b64decode(s.encode())

def verify_token(token):
    if not public_key:
        return (False, 'no public key')
    try:
        payload_b64, sig_b64 = token.strip().split('.', 1)
        payload = b64url_decode(payload_b64)
        sig = b64url_decode(sig_b64)
        public_key.verify(sig, payload, padding.PKCS1v15(), hashes.SHA256())
        j = json.loads(payload.decode())
        if j.get('role')!= 'VIP':
            return (False, 'role != VIP')
        if j.get('expiry', 0) < int(time.time()):
            return (False, 'expired')
    except Exception as e:
            return (False, str(e))
    else:  # inserted
        return (True, j)    

def sample_token_nonvip():
    payload = json.dumps({'user': 'guest', 'expiry': int(time.time()) + 3600, 'role': 'USER'}).encode()
    return b64url_encode(payload)

def main():
    run_integrity_or_exit()
    print('=== Bot Chat === \n    1.chat\n    2.showtoken\n    3.upgrade \n    4.quit')
    queries = 0
    while True:
        cmd = input('> ').strip().lower()
        if cmd in ['quit', 'exit']:
            return
        if cmd == 'chat':
            if queries < 3:
                print(random.choice(['Hi', 'Demo AI', 'Hello!', 'How can I assist you?', 'I am a chatbot', 'What do you want?', 'Tell me more', 'Interesting', 'Go on...', 'SIUUUUUUU', 'I LOVE U', 'HACK TO LEARN NOT LEARN TO HACK']))
                queries = queries | 1
            else:  # inserted
                print('Free queries exhausted. Use \'upgrade\'')
        else:  # inserted
            if cmd == 'showtoken':
                print('Token current:' + sample_token_nonvip())
            else:  # inserted
                if cmd == 'upgrade':
                    run_integrity_or_exit()
                    token = input('Paste token: ').strip()
                    ok, info = verify_token(token)
                    if ok:  
                        if decrypt_flag_file is None:
                            print('Native library not available -> cannot decrypt')
                        else:  # inserted
                            flag_path = get_resource_path('flag.enc').encode()
                            res_ptr = decrypt_flag_file(flag_path)
                            if not res_ptr:
                                print('Native failed to decrypt or error')
                            else:  # inserted
                                flag_bytes = ctypes.string_at(res_ptr)
                                try:
                                    flag = flag_bytes.decode(errors='ignore')
                                except:
                                    flag = flag_bytes.decode('utf-8', errors='replace')
                                print('=== VIP VERIFIED ===')
                                print(flag)
                                free_mem(res_ptr)
                        return None
                    print('Token invalid:', info)
                else:  # inserted
                    print('Unknown. Use chat/showtoken/upgrade/quit')
if __name__ == '__main__':
    main()

```

```python
def load_native_lib(name):
    return CDLL(get_resource_path(name))
if sys.platform == 'win32':
    LIBNAME = 'libnative.dll'
else:  # inserted
    LIBNAME = 'libnative.so'
...
try:
    lib = load_native_lib(LIBNAME)
```

Looking at the flag-decrypting part after verifying token, There's a function `decrypt_flag_file` which decrypt the encoded flag file from its path. Also, return to the top of this code, this function is imported from `libnative.so` (or `libnative.dll`) and here i got `libnative.so` so I used `IDA` to inspect the file to see what it do to decrypt the flag

![image](/images/CSCV/CSCV_8.png)

`decrypt_flag_file` function calls `recover_key`

![image](/images/CSCV/CSCV_9.png)

`recover_key` just deobfuscate the `OBF_KEY` with `MASK` through bunch of `XOR` operation to get the original `key`

![image](/images/CSCV/CSCV_10.png)

back to `decrypt_flag_file`, this program reads the first 16 bytes from flag.enc file as `iv` and the rest as `ciphertext`. It also compare the length of key with `0x1F`  in order to decide which decryption to use for each case

so that's all of the decryption logic

this is my script:
```python
#!/usr/bin/env python3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
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
    key_len = len(key)
    with open(filename, "rb") as f:
        iv = f.read(16)
        ct = f.read()
    cipher_alg = algorithms.AES256(key)
    cipher = Cipher(cipher_alg, modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadded_plaintext = decryptor.update(ct) + decryptor.finalize()
    return unpadded_plaintext

def main():
    ENCRYPTED_FILE_NAME = "flag.enc"
    decrypted_data = decrypt_flag_file(ENCRYPTED_FILE_NAME)
    if decrypted_data:
        print(decrypted_data.decode('utf-8'))
if __name__ == "__main__":
    main()
```

`CSCV2025{reversed_vip*_chatbot_bypassed}`



