---
title: "Tinyirc"
date: 2026-03-29T21:54:48+07:00
draft: false
tags: ["CTF", "RE"]
categories: ["Codegate2026"]
contest: "Codegate2026"
author: "k1nt4r0u"
description: "Writeup for Tinyirc from Codegate2026"
difficulty: "Easy/Medium/Hard"
---



# CODEGATE 2026 Quals - tinyIRC

- Category: Pwn
- Challenge: `tinyIRC`
- Remote launcher: `nc 15.165.70.236 20998`
- Solver: `solve.py`

## TL;DL

The wrapper port is not the IRC service. It prints the real port, keeps the wrapper process attached to the child, and becomes the side channel that later carries the leak and the flag. Inside the IRC server, `QUIT` clears a client slot while the recv loop is still using the stale pointer, and a reused slot can come back with a negative `input_len`. That negative length becomes a reusable cross-slot overwrite. I used it first to turn `memmove()` into `printf()` for a same-process libc leak, then to replace `strtok@got` with `system()` and run `cat /home/ctf/flag >&2`.

## Overview

The most important thing to understand first is that `20998` is not the actual IRC port. Connecting there starts the real server on a random port and prints a line like:

```text
tinyIRC server listening on port <random_port>
```

That sounds like a wrapper nuisance, but it is actually part of the exploit surface. The wrapper socket stays open, and later it becomes the place where the leaked libc address and the final flag come back. So I treated it as a control channel from the beginning rather than as a throwaway launcher.

The binary itself is a non-PIE 64-bit ELF with NX, a canary, CET, and partial RELRO. That combination already pushed me away from any fantasy about an easy stack overwrite. If I was going to get code execution, it was much more likely to come from a stable logic bug plus a GOT pivot than from fighting the mitigations head on.

## Analysis

Each IRC client lives in a fixed-size slot in `.bss`. The fields that matter are the input buffer and the input length. Once I mapped those, the bug in the `QUIT` path became the center of the challenge.

The problem is not that `QUIT` merely disconnects a client. The real issue is timing inside the recv loop. After one full IRC line is parsed, `disconnect()` clears the client slot immediately, but the surrounding loop keeps running with the pointer it already had. That means the rest of the loop is now operating on stale state that no longer matches what the connection manager thinks is in that slot.

My first question was whether that only bought me a crash or a one-shot disconnect bug. It turned out to be much better than that because reconnecting into the same slot does not fully reinitialize the structure. In particular, a negative `input_len` can survive across reuse.

That made the technique choice much clearer. I did not need to force control flow directly. I needed to turn stale slot reuse into a stable write primitive.

The useful magic value was slot 1 with `len = -111`. That offset is not arbitrary. It lines up so that writes through slot 1 walk back into slot 0's header:

```text
slot1.buffer - 111 = slot0.len
```

So one carefully sized packet sent through the recycled slot can repair slot 1 just enough to keep it usable while also overwriting `slot0.len` with the next negative value I want. That is what makes the exploit chain reusable instead of one-shot.

The next thing I had to learn the hard way was that the primitive does not behave like a tiny arbitrary write. Short writes are unreliable because the recv loop checks whether `len + recv_len` exceeds the buffer limit before copying, and a negative `len` looks enormous in that arithmetic. The workaround was to stop thinking in terms of small surgical writes. Each exploit stage became a broad overwrite that starts near the target and stretches forward into the real buffer.

That shaped the first stage. I chose `memmove@got` as the first target because the server naturally calls `memmove()` inside the recv path, and I already had a convenient output channel on the wrapper socket. Replacing `memmove` with `printf@plt` lets me turn a normal server action into a format-string leak without restarting the child. I also patched `strtok@got` to a tiny helper so the parser survived long enough to use the leak.

That decision was much better than trying to jump straight to `system()`. I needed a libc address from the same child process first, and the `printf()` pivot gave me one in a way that fit the service's normal behavior.

The actual leak became clean once I mapped the positional-argument layout. After I knew which overwritten qwords showed up as which `printf` arguments, I could plant `fprintf@got` in a controlled slot and recover the live libc address with a single format string.

Then the second stage reused the same negative-length primitive, this time starting near `strtok@got`. Once libc was known, `strtok -> system` was the neatest endgame because the call site was already there. I only had to make sure the first argument was a command string:

```text
cat /home/ctf/flag >&2
```

Sending it to stderr mattered because stderr was still attached to the wrapper socket I had kept alive from the beginning.

The part that made this challenge feel real instead of toy-like was process lifetime. The exploit is easy to describe if each stage gets a fresh process. The actual challenge is keeping the same child alive through the leak and the final pivot. That is why the solver is organized around one long-lived instance instead of many short disconnected attempts.

## Exploit

The final order was:

1. Connect to the wrapper and read the real IRC port.
2. Keep that wrapper socket open because it will later carry the leak and the flag.
3. Open the victim connection that will trigger both corruption stages.
4. Recycle a helper slot until it comes back with `len = -111`.
5. Use that helper slot to set `slot0.len = -0xD7`.
6. Perform the broad overwrite starting at `memmove@got` and pivot `memmove()` into `printf()`.
7. Leak `fprintf@libc`, compute the libc base, then compute `system()`.
8. Re-arm the helper path and set `slot0.len = -0xC7`.
9. Perform the second broad overwrite starting at `strtok@got`.
10. Trigger `system("cat /home/ctf/flag >&2")` and read the result on the wrapper socket.

I wrapped the whole exploit in retries because the transport still has timing edges, but the exploit chain itself is not guesswork once the same child survives both stages.

## Verification

I reran `solve.py` on March 29, 2026 with the quieter default output path. The service still behaves like a per-instance challenge, so I am treating the value below as a fresh rerun example rather than pretending there is one eternal tinyIRC flag.

The successful rerun printed:

```text
codegate2026{382ade6995beaf7de132a74d99285e638c92a0f0231e1ca091c39ace85450036e6d5b15634e078d01ab1bee515893575dccc097c02f509ee52e271ce9b95f36b85f26013f452cd76}
```

Final flag:

```text
codegate2026{382ade6995beaf7de132a74d99285e638c92a0f0231e1ca091c39ace85450036e6d5b15634e078d01ab1bee515893575dccc097c02f509ee52e271ce9b95f36b85f26013f452cd76}
```
