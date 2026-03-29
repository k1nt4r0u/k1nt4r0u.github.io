---
title: "Greybox"
date: 2026-03-29T21:54:48+07:00
draft: false
tags: ["CTF", "RE"]
categories: ["Codegate2026"]
contest: "Codegate2026"
author: "k1nt4r0u"
description: "Writeup for Greybox from Codegate2026"
difficulty: "Easy/Medium/Hard"
---



# CODEGATE 2026 Quals - Greybox

- Category: Reverse Engineering
- Challenge: `Oh! My Greybox Keeps Running!`
- Files: `deploy/prob`, `deploy/target`
- Solver: `solver.py`

## TL;DL

The binary hides a small VM behind fake `FILE` state and libc teardown machinery. The hard part is not the arithmetic. The hard part is recognizing that the weird runtime wrapper is only there to make the VM harder to spot. Once I aligned the handler table correctly and confirmed how the scheduler dispatches handlers, the shortest reliable solve was to record one concrete trace, replay that trace symbolically, and let `z3` recover the 64-byte accepted input.

## Overview

This challenge looked small enough that I expected either a packed checker or a very compact VM, and `strings` pushed me toward the second explanation immediately:

```text
Sucess!
Flag is codegate2026{%.*s}
Wrong!
./target
Input:
Input length must be 64bytes...
```

That single format string matters a lot. It means the binary is not printing a hidden flag from data or code. It is printing the accepted 64-byte input back inside the flag format. Once I knew that, the whole problem became "recover the exact accepted input" rather than "find some secret string in memory."

The handout included only the stripped ELF, a `target` blob, and the Docker setup. So my first goal was not to understand every libc trick around it. It was to find the real execution engine hidden inside the wrapper.

## Analysis

`main` itself is very small. It reads 64 bytes, then hands control to a much larger helper that loads `./target`, builds a pair of internal state objects, and initializes a 19-entry function table. My first pass over that function table was not productive at all. It looked like broken disassembly: overlapping handlers, strange fallthrough, and code that did not make semantic sense.

That turned out to be my mistake, not the binary's. The jump table was real, but several handlers were being decoded from the wrong byte boundary. Once I corrected the alignment, the whole VM snapped into focus. The "greybox" feeling of impossible control flow was mostly an artifact of reading the dispatcher one byte off.

The next question was why the handlers were not called in a normal loop. The answer is the challenge gimmick: the binary builds fake `FILE`-like objects and lets libc teardown paths drive the scheduler. I confirmed that with a failing run under `strace`, because the process kept doing libc-flavored cleanup work long after `main` should have been finished. That was enough for me. I did not need to reverse every fake `FILE` field in detail. I only needed to follow execution until I understood the dispatch rule and the state transitions.

That was a deliberate choice. I could have spent a lot more time explaining every part of the fake runtime, but that would not have moved me toward the accepted input any faster. Once I could see the scheduler clearly, the VM itself was much more ordinary than the wrapper tried to suggest.

The key dispatch rule came from tracing the scheduler in GDB:

```text
handler = target[pc] + carry - 3
```

The carry bit depends on which of the two fake states is active, so the state alternation is predictable. From there the handlers were small and readable: register moves, immediate loads, input-word loads and stores, arithmetic and logical ops, shifts, compare-not-equal, branches, and a finish handler.

The next important question was whether I needed full path exploration. If the executed handler sequence depended heavily on the input, a one-trace solve would have been fragile. What made this challenge pleasant is that the control-flow skeleton is effectively fixed for the interesting path. The input changes values in registers, but not the overall sequence of handlers I needed to model. That is why I chose a trace-and-replay solve rather than trying to symbolically model the entire scheduler from scratch.

Once I trusted that choice, the rest of the design followed naturally:

- run the VM concretely once
- record the exact handler trace
- rebuild only that trace symbolically

That is much cleaner than trying to derive one huge symbolic model from disassembly alone. It also let me avoid over-engineering the solver. I did not need a full VM lifter. I only needed a faithful replay of the executed path.

I also added printable constraints first because the successful input is printed directly back as the flag body. That was not required for correctness, but it was a practical choice. If several satisfying assignments existed, I wanted the one that turned into a sensible printable flag string.

## Exploit

The final solver does exactly the minimum I found trustworthy:

1. Execute the checker once with zero input.
2. Record the executed `(pc, state, handler)` trace and the concrete branch outcomes.
3. Rebuild that same trace symbolically using sixteen unknown 32-bit words.
4. Emit SMT-LIB and let `z3` solve it instead of hand-writing one giant formula.
5. Ask for a printable model first, then relax that constraint only if necessary.
6. Pack the model back into 64 bytes and verify it against the original program before printing.

I liked this approach because it matches the actual challenge structure. The binary is trying hard to hide a small deterministic computation inside a noisy runtime shell. Replaying the real executed path is a direct answer to that design. I am not fighting the wrapper on its terms. I am stepping around it.

## Verification

I reran `solver.py` on March 29, 2026 after cleaning up the default output path. The solver now prints only the final recovered flag, and it still self-verifies the candidate against the original binary before returning success.

The rerun produced:

```text
codegate2026{4h!_C0ngr47u147i0ns!_L37_m3_kn0w_why_7his_gr3y_b0x_d03s_n07_3nd!}
```

Final flag:

```text
codegate2026{4h!_C0ngr47u147i0ns!_L37_m3_kn0w_why_7his_gr3y_b0x_d03s_n07_3nd!}
```
