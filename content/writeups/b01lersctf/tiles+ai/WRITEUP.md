---
title: "Tiles+ai"
date: 2026-04-27T14:17:36+07:00
draft: false
tags: ["CTF", "RE"]
categories: ["b01lersctf"]
contest: "b01lersctf"
author: "k1nt4r0u"
description: "Writeup for Tiles+ai from b01lersctf"
difficulty: "Easy/Medium/Hard"
---
The binary is a static stripped ELF that refuses to run unless the CPU exposes Sapphire Rapids AMX features. Local execution in the sandbox was blocked by both the CPUID gate and the lack of AMX support, so the solve path had to come from static reconstruction of the AMX dataflow.

## Triage

The useful anchors were:

- `flag.txt`
- `incorrect`
- `flag{fake_flag}`
- a tight cluster of `ldtilecfg`, `tileloadd`, `tdpbssd`, `tilestored`, and `tilerelease`

The main function starts by:

1. Checking CPUID bits for the AMX feature set.
2. Loading a tile configuration from `.rodata`.
3. Iterating three times, once per prompt.
4. Seeding a 3-matrix state block from `.rodata`.
5. Reading one line of input for that stage.
6. Processing the input two characters at a time.
7. Printing `incorrect` and exiting on any failed invariant.
8. Opening `flag.txt` and printing it after all three stages succeed.

## The AMX Configuration

The tile config at `0x410100` defines:

- `tmm0..tmm2`: `16 x 16` byte tiles
- `tmm3..tmm5`: `4 x 64` byte tiles
- `tmm6..tmm7`: `16 x 64` byte destination tiles, i.e. `16 x 16` int32 results

That matches the standard AMX int8 dot-product shape:

- left operand: ordinary `16 x 16`
- right operand: packed `4 x 64`
- output: `16 x 16` int32

The program then immediately exposes its structure in `.rodata`:

- `0x409000 + 0x100 * a`: matrix family `A[a]`
- `0x40a000 + 0x100 * a`: matrix family `B[a]`
- `0x40b000 + 0x2400 * (a >> 3) + 0x900 * b`: nine `C[(a>>3)][b][k][j]` matrices
- `0x40f800 + 0x300 * stage`: per-stage seed state

## Parsing

Each token is exactly two characters:

- first char: hex nibble `a` in `0..f`
- second char: base-4 digit `b` in `0..3`

So the search alphabet is 64 symbols total.

## The Key Simplification

The first constant family is trivial:

- `A[a]` is the diagonal projector `E_a`

The second one is just:

- `B[a] = I - E_a`

That means a token only rewrites one column of the current state.

Let `S0, S1, S2` be the current three `16 x 16` byte matrices. For token `(a, b)` with `h = a >> 3`, the program computes:

```text
S'_k =
    C[h][b][k][0] * (S0 * E_a)
  + C[h][b][k][1] * (S1 * E_a)
  + C[h][b][k][2] * (S2 * E_a)
  + S_k * (I - E_a)
```

Important detail: `tmm7` is zeroed once per output matrix, not once for the whole token. Missing that makes stages 0 and 2 look impossible.

After each token the binary:

1. Copies the new `3 x 0x100` state back into the live buffer.
2. Enforces the row constraints on the first `0x240` bytes.
3. Continues with the next token.

At end of line it checks that byte `0x412380` equals `1`, i.e. offset `0x110` inside the live state.

## Search Strategy

Because the seed states and the `C` tables are sparse, the reachable state graph is much smaller than the raw `256^768` state space suggests. Once the per-token update rule was reconstructed, a plain BFS over valid states was enough to recover shortest accepting lines for each of the three prompts.

I kept two helpers in the workspace while solving:

- `solver.cpp`: a compiled state-space searcher
- `solve.py`: a convenience script that prints the recovered lines and can submit them remotely

## Recovered Inputs

Stage 0:

```text
01e2e210f3f3f3010101
```

Stage 1:

```text
01f320e201
```

Stage 2:

```text
0120a2a2c231f2f2f2109393019311e320b211e3e300e31010923092921111c311d230e23030d310f3209201e2e210b3b3b30101
```

These were verified against the reconstructed model. Each line preserves the row-sparsity invariants after every token, and each leaves the required byte at offset `0x110` equal to `1`.

## Getting the Flag

With network access enabled, submitting the three recovered lines to the remote service returned:

```text
bctf{in_the_matrix_straight_up_multiplying_it_ec3428a06}
```

To replay the solve, run:

```bash
python solve.py --remote
```

or paste the three lines manually into:

```bash
ncat --ssl tiles--ai.opus4-7.b01le.rs 8443
```

The local binary still falls back to `flag{fake_flag}` if `flag.txt` is missing, but the remote service returns the real flag shown above.
