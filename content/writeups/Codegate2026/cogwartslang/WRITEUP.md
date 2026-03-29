---
title: "Cogwartslang"
date: 2026-03-29T21:54:48+07:00
draft: false
tags: ["CTF", "RE"]
categories: ["Codegate2026"]
contest: "Codegate2026"
author: "k1nt4r0u"
description: "Writeup for Cogwartslang from Codegate2026"
difficulty: "Easy/Medium/Hard"
---



# CODEGATE 2026 Quals - CogwartsLang

- Category: Reverse Engineering
- Challenge: `CogwartsLang`
- Solver: `solve.grim`

## TL;DL

The language syntax is mostly decoration. The real challenge is the oracle host module loaded by `harness`. Once I understood that the important state lived in the host and not in the source language, the solve became a timing problem: reconstruct the oracle's arithmetic, identify the exact checkpoint and ticket values, and call the host functions in the right order without accidentally burning extra ticks.

## Overview

The execution model makes the attack surface very clear:

```sh
/home/cogwarts/bin/harness "$TMP" \
  --host /home/cogwarts/bin/liboracle_host.so \
  --host /home/cogwarts/bin/libstdlib_host.so
```

That immediately told me what not to spend too much time on. The only thing I control is the submitted source file. The harness and both host libraries are fixed. So if I want the flag, the important question is not "what cute thing can I do with the language syntax?" but "what does the oracle host expect, and how can I drive it precisely?"

That was an important correction early on because the challenge presentation makes it very tempting to overfocus on the language itself. In practice, the language is just the surface I use to call the host.

## Analysis

The binaries were not stripped, which made the first pass much friendlier than I expected. `harness` accepts a one-argument `solve[x]`, and the language exposes `host_import` and `host_call`. Once I noticed those primitives, I stopped treating the sugared `oracle[...]` syntax as something sacred. I wanted direct host interaction, because that was where the real state lived.

The first useful move was to wrap the oracle host locally and log what it was initialized with. That immediately exposed two constants:

- `seed = 0x5f64d765889c6342`
- `input_hash = 0xeacadd96dae055b8`

The `input_hash` result was especially informative because it did not change when I changed the submitted source. That ruled out a whole family of wrong ideas. The challenge was not hashing my specific grimoire and expecting me to manipulate that derived value. The important state was already fixed in the host. My script only needed to drive the host into the success condition.

Once I shifted to that mindset, the meaningful host commands were easy to isolate: `seed`, `tick`, `checkpoint`, `ticket`, and `witness`. Reconstructing the host state structure showed that success is essentially a state-machine condition: set the witness bit and all three checkpoint bits while staying inside the ticket validity window.

The next part that cost time was arithmetic fidelity. The oracle logic uses Murmur-style mixing constants, which at first glance look like ordinary 64-bit math. My first reconstruction treated it that way and produced values that were plausible but consistently wrong. The missing detail was truncation. Several parts of the implementation fall through 32-bit registers before widening again. Once I mirrored those truncations correctly, the checkpoint and ticket values stopped drifting and started matching the host's actual expectations.

That is also why I chose to model the host logic directly instead of trying to brute-force the command values. The values are not huge by cryptographic standards, but the timing interactions make blind search the wrong tool. Reverse the math once, then use the exact answers.

The last real obstacle was timing. Using the sugared `oracle[...]` form caused extra host imports and consumed ticks in places I did not want. That made otherwise correct checkpoint and witness values fail because I was arriving at them in the wrong host state. This was the final pivot of the solve: import the oracle once with `host_import["oracle"]`, keep the handle, and use raw `host_call()` so every tick spent is one I intended to spend.

That explains why the final grimoire looks more awkward than elegant. The repeated `seed` calls are not decorative. They are there because I needed the oracle state machine at a very specific tick count before I invoked the meaningful commands.

## Exploit

The final solve script is short, but every line is there for a reason:

1. Import the oracle exactly once.
2. Burn 57 dummy `seed` calls to advance the internal tick counter to the right state.
3. Call `checkpoint` for index `2` with `652393318`.
4. Call `checkpoint` for index `1` with `2916723419`.
5. Call `checkpoint` for index `0` with `984171264`.
6. Call `ticket` with `917138306`.
7. Call `witness` with `3074120555`.

I arrived at that exact order because the host state is doing two things at once:

- validating the numeric relationships
- enforcing when those relationships are allowed to become true

So the solve is not just "find the right constants." It is "find the right constants and spend the right number of ticks before using them."

## Verification

I reran the solve locally on March 29, 2026 through the shipped harness and host libraries, and it still reached the success path:

```text
Success! codegate2026{fake_flag}
```

That local rerun is enough to confirm that the call order, arithmetic, and timing are still right. I did not have a fresh public remote endpoint available in the repo during this rewrite pass, so the real flag below is still the one from the earlier successful remote submission of the same `solve.grim`.

Final flag:

```text
codegate2026{f384dc82142a7d21afd1e10b7f55be4d6798d7973720d536a903d64469d91074f25f04345e9375f8dfe647aa33e367006adc198362eb40f0a94a27f26be6b509fee2d0c33e63}
```
