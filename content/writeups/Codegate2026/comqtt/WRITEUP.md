---
title: "Comqtt"
date: 2026-03-29T21:54:48+07:00
draft: false
tags: ["CTF", "RE"]
categories: ["Codegate2026"]
contest: "Codegate2026"
author: "k1nt4r0u"
description: "Writeup for Comqtt from Codegate2026"
difficulty: "Easy/Medium/Hard"
---



# CODEGATE 2026 Quals - comqtt

- Category: Pwn
- Challenge: `mqtt` / `comqtt`
- Solver: `solve.py`

## TL;DL

The broker has a retained-message deletion bug that leaves a stale tail entry behind after compaction. On the next retained insert, that stale slot frees a payload pointer that a live retained entry still references. Because each client runs in its own thread and glibc tcache is per-thread, that one mistake becomes a cross-thread tcache-dup primitive. I used it first to build an arbitrary-read oracle, then to dump the live libc image, resolve `system()` from the in-memory ELF data, and finally overwrite `free@GOT` with the real runtime address instead of guessing a libc version.

## Overview

The first thing I had to stop getting wrong was the network layout. The public port is not the MQTT broker. It is an admin console that prints:

```text
Broker port : <ephemeral_port>
```

The admin socket stays open while the real broker runs elsewhere. That means I have two different channels to think about:

- the admin socket, which gives me the broker port and later returns the command output
- the broker port, where all heap corruption happens through MQTT traffic

That split shaped the exploit from the start. Any time I forgot that the admin side and the broker side were different processes and different sockets, I ended up debugging the wrong thing.

The binary itself is a non-PIE 64-bit ELF with NX, a canary, and partial RELRO. That already pushed me toward heap corruption and GOT overwrite rather than trying to invent a stack bug that was not there.

## Analysis

The root bug sits in retained-message deletion. When the broker deletes a retained topic, it frees the payload, decrements the retained count, and copies the last retained entry over the deleted slot. The old tail slot is never cleared. On the next retained insert, that stale slot is treated like reusable metadata and its payload pointer gets freed again even though a live retained entry still points to it.

By itself, that is a use-after-free with a stale metadata reference. The reason it becomes a real exploit primitive is the threading model. Each MQTT client is handled in its own detached thread, and glibc tcache is per-thread. That means the same small chunk can be freed into two different tcaches:

1. once in thread A
2. again in thread B

After that, both threads can allocate the same address from their own bins. That is the core of the exploit.

I did not try to jump straight to code execution from there. The first thing I wanted was a leak. With modern glibc, safe-linking makes blind poisoning much less pleasant, and I needed to know exactly what process I was corrupting. Replaying the freed retained payload gives back the first qword of a tcache entry, which is enough to recover the safe-linking mask for that chunk. That made later poisoning controlled instead of hopeful.

Once I had the mask, I redirected one duplicated small chunk onto retained metadata for a topic I kept named `LEAK`. That was a deliberate design choice. I wanted a primitive that fit the broker's normal behavior. If retained metadata for `LEAK` points to an arbitrary address and size, then a normal subscribe to `LEAK` turns the broker into an arbitrary-read oracle. That is much easier to debug than a one-shot smash straight into the GOT.

The most annoying failure in the whole solve came after that stage. My first exploit guessed a specific Ubuntu `glibc 2.39` point release and computed `system()` from a leaked function pointer using hard-coded offsets. That worked locally and still failed remotely. This is exactly the kind of pwn failure I distrust most, because everything before the final overwrite looks healthy. The heap corruption works, the leaks look real, and only the last jump target is wrong.

That is why I changed techniques. Instead of arguing with the remote libc version, I used the arbitrary-read primitive properly. After leaking one GOT entry, I dumped the live mapped libc image from memory, searched that dump for the ELF header, walked the dynamic table, and resolved `system` from the actual dynsym data in the running process.

That was the right pivot because it removed the last brittle assumption from the exploit. From that point on, the final overwrite targeted the real `system()` of the real process I was currently exploiting.

The other practical issue was thread lifetime. Once two tcaches share corrupted state, closing helper connections too aggressively is a good way to crash the exploit during thread teardown instead of during the interesting part. The final solver keeps several corrupted client trios alive on purpose. It looks messy, but that mess is there because it matched the service's behavior better than trying to clean up politely.

One rerun detail was worth keeping in the writeup because it reflects a real implementation edge. Running the solver locally against `deploy/mqtt` hit the fallback libc-dump path and later timed out during an arbitrary-read round. Running the same logic against the packaged `ubuntu-server` wrapper succeeded immediately. That reinforced the earlier lesson: for this challenge, matching the intended runtime environment matters.

## Exploit

The final flow was:

1. Connect to the admin console and parse the ephemeral broker port.
2. Seed retained topics so the metadata layout becomes predictable.
3. Use multiple client threads to duplicate one small chunk across two tcaches.
4. Leak the safe-linking mask from the freed retained payload.
5. Poison the duplicated chunk onto retained metadata for topic `LEAK`.
6. Subscribe to `LEAK` and use the broker as an arbitrary-read primitive.
7. Leak `read@GOT`, then dump the live libc image and resolve `system()` from the in-memory ELF structures.
8. Run a second corruption round against the GOT window.
9. Overwrite only `free@GOT` with the resolved `system()` address.
10. Send a normal non-retained publish whose payload is `cat /home/ctf/flag`.
11. Let the broker free that temporary payload and read the command output back on the admin socket.

I like this endgame because it is boring in the right way. Once `free@GOT` points to `system`, I do not need a fancy trigger. The broker already allocates and frees temporary publish payloads during ordinary operation. Using a normal publish as the trigger keeps the exploit aligned with the program's real control flow instead of forcing an unnatural crashy path.

## Verification

The packaged local reproduction still works and returns the placeholder flag:

```text
codegate2026{fake_flag}
```

For the live service, I had a successful fresh rerun on March 29, 2026 that produced:

```text
codegate2026{07fd7ea9d9e17fd79f4f6274a3e421904edf570d193e6610dc3bec7e80490fa1c2bad262e3a08434c800c0a25cc5875de4a3298221442c071275}
```

I also had a later rerun time out in the arbitrary-read stage after the quiet-output cleanup, which is worth mentioning because it reflects real exploit fragility rather than a documentation issue. The working path is solid, but it is still a multithreaded heap exploit against a network service, not a one-packet toy.

Final flag:

```text
codegate2026{07fd7ea9d9e17fd79f4f6274a3e421904edf570d193e6610dc3bec7e80490fa1c2bad262e3a08434c800c0a25cc5875de4a3298221442c071275}
```
