---
title: "Favorite Potato"
date: 2026-04-27T14:17:36+07:00
draft: false
tags: ["CTF", "RE"]
categories: ["b01lersctf"]
contest: "b01lersctf"
author: "k1nt4r0u"
description: "Writeup for Favorite Potato Writeup from b01lersctf"
difficulty: "Easy/Medium/Hard"
---
`favorite_potato` ships a Python wrapper, a tiny `test.bin`, and a large compressed `code.bin.gz`. The wrapper makes the challenge goal explicit:

- pick random initial `A,X,Y`
- run the binary
- show the final `A,X,Y`
- recover the original input triple

For the real challenge the service repeats that 20 times and prints the flag only if every recovered triple is correct.

## 1. Triage

The local files are:

```text
screenshot.png
code.bin.gz
favorite_potato.py
favorite_potato.zip
test.bin
```

The important part of [`favorite_potato.py`](./favorite_potato.py) is:

```python
def singleEval(binary, msg):
  A0,X0,Y0 = randomAXY()
  A,X,Y = run_c64(binary, A0, X0, Y0)
  print(f"{msg}: A={A} X={X} Y={Y}")
  return [str(v) for v in (A0,X0,Y0)]
```

The helper itself was not included, so the task had to be solved from the machine code.

`test.bin` is only 9 bytes long:

```text
08 18 69 2a ca c8 c8 28 60
```

That disassembles as:

```asm
php
clc
adc #$2a
dex
iny
iny
plp
rts
```

So the execution model is normal 6502 register code: the program receives starting `A,X,Y` and returns final `A,X,Y`.

## 2. What `code.bin` really is

`code.bin.gz` inflates to about 5.82 MiB. At first that looks annoying because a normal 6502 only addresses 64 KiB, but decoding the blob as plain 6502 bytes shows a much cleaner picture:

- there are no `JSR` or `JMP` instructions
- there is only one `RTS`, at the very end
- the file is a giant straight-line program with tiny local loops

The filename inside the gzip archive is `code-10k.bin`, which matches the layout exactly:

- total length: `5,820,001`
- round size: `582`
- number of rounds: `10,000`
- final byte: the single terminating `RTS`

Each 582-byte round is structurally identical. Comparing adjacent rounds shows that only 8 bytes change:

```python
[3, 38, 167, 232, 263, 396, 451, 580]
```

Those 8 bytes are the per-round immediates.

## 3. Lifting one round

I first wrote a minimal 6502 interpreter for the exact opcodes used by the challenge:

- `PHP`, `PLP`, `PHA`, `PLA`
- `ADC #imm`, `SBC #imm`
- `TXA`, `TAX`, `TYA`, `TAY`, `TSX`, `TXS`
- `INX`, `DEX`, `INY`
- `LDX #imm`, `LSR A`
- `ORA #imm`, `EOR #imm`
- `BCC`, `BNE`, `RTS`

That matched `test.bin`, so the model was correct.

Then I isolated the repeated stack-macros inside a single 582-byte round. Those macros reduce to a small set of byte operations:

- swap `A` and `X`
- swap `A` and `Y`
- swap `X` and `Y`
- `X += A`
- `Y += A`
- `A ^= Y`
- `A = ror(A, k)`
- `A ^= const`
- `A += const`

After collapsing the round, the whole 582-byte block becomes:

```python
r1 = ror(x, k1)
x2 = (a + c0 + x) & 0xff
yv = ((y ^ r1 ^ c2) + x2 + c3) & 0xff
r2 = ror(x2, k4)
r3 = ror(yv, k6)

a_out = r3 ^ r2 ^ c7
x_out = r1 ^ r2 ^ c5
y_out = r3
```

The three rotation counts are just the three `LDX #imm` bytes taken mod 8, because the code implements rotation by repeating `LSR` many times.

I validated this formula against the interpreter on multiple rounds and multiple sample states, and then against the full 10,000-round program. The full formula matched the original interpreter output exactly.

## 4. Inverting the round

This round is easy to invert because `y_out` directly gives `r3`.

From

```python
a_out = r3 ^ r2 ^ c7
x_out = r1 ^ r2 ^ c5
y_out = r3
```

we recover:

```python
r3 = y_out
r2 = a_out ^ r3 ^ c7
r1 = x_out ^ r2 ^ c5
```

Then undo the rotations:

```python
x2 = rol(r2, k4)
x  = rol(r1, k1)
```

Undo the addition into `x2`:

```python
a = (x2 - c0 - x) & 0xff
```

And undo the `yv` construction:

```python
yv = rol(r3, k6)
y  = ((yv - x2 - c3) & 0xff) ^ r1 ^ c2
```

So one inverse round is:

```python
r3 = y
r2 = a ^ r3 ^ c7
r1 = x ^ r2 ^ c5
x2 = rol(r2, k4)
x0 = rol(r1, k1)
a0 = (x2 - c0 - x0) & 0xff
y0 = ((rol(r3, k6) - x2 - c3) & 0xff) ^ r1 ^ c2
```

Running those inverse rounds from round 9999 down to round 0 recovers the original input triple almost instantly.

## 5. Solving the remote service

With the inverse in place, the remote solve is just:

1. connect with SSL
2. choose `R`
3. parse the 20 final triples
4. invert each triple through the 10,000 rounds
5. send the recovered `A,X,Y` values back

The solver script in does exactly that:

```python
#!/usr/bin/env python3
import argparse
import gzip
import re
import socket
import ssl
from pathlib import Path


ROUND_SIZE = 582
ROUND_IMMEDIATE_OFFSETS = [3, 38, 167, 232, 263, 396, 451, 580]
HOST = "favorite-potato.opus4-7.b01le.rs"
PORT = 8443


def rol8(value: int, amount: int) -> int:
    amount %= 8
    if amount == 0:
        return value & 0xFF
    return (((value << amount) & 0xFF) | (value >> (8 - amount))) & 0xFF


def ror8(value: int, amount: int) -> int:
    amount %= 8
    if amount == 0:
        return value & 0xFF
    return ((value >> amount) | ((value << (8 - amount)) & 0xFF)) & 0xFF


def extract_round_constants(code_path: Path) -> list[tuple[int, ...]]:
    if code_path.exists():
        code = code_path.read_bytes()
    else:
        gzip_path = code_path.with_suffix(code_path.suffix + ".gz")
        if not gzip_path.exists():
            raise FileNotFoundError(f"could not find {code_path} or {gzip_path}")
        code = gzip.decompress(gzip_path.read_bytes())
    rounds = len(code) // ROUND_SIZE
    return [
        tuple(code[round_index * ROUND_SIZE + offset] for offset in ROUND_IMMEDIATE_OFFSETS)
        for round_index in range(rounds)
    ]


def run_rounds(initial_state: tuple[int, int, int], round_constants: list[tuple[int, ...]]) -> tuple[int, int, int]:
    a, x, y = initial_state
    for c0, k1, c2, c3, k4, c5, k6, c7 in round_constants:
        r1 = ror8(x, k1)
        x2 = (a + c0 + x) & 0xFF
        yv = ((y ^ r1 ^ c2) + x2 + c3) & 0xFF
        r2 = ror8(x2, k4)
        r3 = ror8(yv, k6)
        a = (r3 ^ r2 ^ c7) & 0xFF
        x = (r1 ^ r2 ^ c5) & 0xFF
        y = r3
    return a, x, y


def invert_rounds(final_state: tuple[int, int, int], round_constants: list[tuple[int, ...]]) -> tuple[int, int, int]:
    a, x, y = final_state
    for c0, k1, c2, c3, k4, c5, k6, c7 in reversed(round_constants):
        r3 = y
        r2 = a ^ r3 ^ c7
        r1 = x ^ r2 ^ c5
        x2 = rol8(r2, k4)
        original_x = rol8(r1, k1)
        original_a = (x2 - c0 - original_x) & 0xFF
        original_y = (((rol8(r3, k6) - x2 - c3) & 0xFF) ^ r1 ^ c2) & 0xFF
        a, x, y = original_a, original_x, original_y
    return a, x, y


def solve_remote(round_constants: list[tuple[int, ...]], host: str, port: int) -> str:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=10) as raw_sock:
        with context.wrap_socket(raw_sock, server_hostname=host) as sock:
            read_until(sock, b"> ")
            sock.sendall(b"R\n")
            transcript = read_until(sock, b"Input #1 - A,X,Y: ")
            output_text = transcript.decode("utf-8", "replace")

            outputs = [
                (int(match.group(1)), int(match.group(2)), int(match.group(3)))
                for match in re.finditer(r"Final output #\d+: A=(\d+) X=(\d+) Y=(\d+)", output_text)
            ]
            if len(outputs) != 20:
                raise RuntimeError(f"expected 20 outputs, got {len(outputs)}")

            for index, final_state in enumerate(outputs, start=1):
                original_state = invert_rounds(final_state, round_constants)
                line = f"{original_state[0]},{original_state[1]},{original_state[2]}\n".encode()
                sock.sendall(line)
                if index < len(outputs):
                    read_until(sock, f"Input #{index + 1} - A,X,Y: ".encode())
                else:
                    output_text += read_all(sock).decode("utf-8", "replace")

    match = re.search(r"Here is your flag: (.+)", output_text)
    if not match:
        raise RuntimeError("flag not found in remote output")
    return match.group(1).strip()


def read_until(sock: ssl.SSLSocket, marker: bytes) -> bytes:
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def read_all(sock: ssl.SSLSocket) -> bytes:
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def main() -> None:
    parser = argparse.ArgumentParser(description="Solve b01lers CTF favorite_potato")
    parser.add_argument("--code", default="code.bin", help="path to the decompressed code blob")
    parser.add_argument("--host", default=HOST, help="remote host")
    parser.add_argument("--port", default=PORT, type=int, help="remote port")
    parser.add_argument(
        "--check",
        nargs=3,
        metavar=("A", "X", "Y"),
        type=int,
        help="run the forward transform locally on one A,X,Y triple",
    )
    parser.add_argument(
        "--invert",
        nargs=3,
        metavar=("A", "X", "Y"),
        type=int,
        help="invert one final output triple locally",
    )
    args = parser.parse_args()

    round_constants = extract_round_constants(Path(args.code))

    if args.check is not None:
        print(run_rounds(tuple(args.check), round_constants))
        return

    if args.invert is not None:
        print(invert_rounds(tuple(args.invert), round_constants))
        return

    print(solve_remote(round_constants, args.host, args.port))


if __name__ == "__main__":
    main()
```

Running it produced:

```text
Correct!
Here is your flag: bctf{Nev3r_underst00d_why_we_n33d_TSX_and_TXS_unt1l_n0w..:D}
```

## 6. Flag

```text
bctf{Nev3r_underst00d_why_we_n33d_TSX_and_TXS_unt1l_n0w..:D}
```
