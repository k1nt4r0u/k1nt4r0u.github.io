---
title: "Interpreter Required"
date: 2026-03-19T08:47:50+07:00
draft: false
tags: ["ctf", "reversing"]
categories: ["RE"]
contest: "DiceCTF 2026"
author: "k1nt4r0u"
description: "A detailed writeup for Interpreter Required challenge"
difficulty: "Medium"
---

# DiceCTF — Interpreter Required (Rev)

## Flag

```
dice{y0u_int3rpret3d_Th3_CJK_gr4mMaR_succ3ssfully}
```

## Challenge Description

> I found this riddle in some ancient language...
> (don't interpret the puzzle, it will OOM your computer)

We are given:
- `interpreter` — a stripped, statically-linked ELF 64-bit binary
- `flag_riddle.txt` — a 1685-line program written in an esoteric language using Chinese characters
- `flag` — a dummy flag file required by the interpreter at runtime

Running the interpreter directly on `flag_riddle.txt` outputs the flag character-by-character via individual `write()` syscalls, but is astronomically slow due to Church-encoded lambda calculus reduction — it would take longer than the heat death of the universe to finish.

The task is to **statically analyze** the program and compute the flag without running it.

## Analysis

### Step 1: Identifying the Language

The program begins with definitions that are immediately recognizable as **Church encoding** in lambda calculus, expressed with Chinese characters:

```
真以矛盾而为矛矣    →  真(矛, 盾) = 矛       (Church True:  λa.λb. a)
假以矛盾而为盾矣    →  假(矛, 盾) = 盾       (Church False: λa.λb. b)
正以人而为人矣      →  正(人) = 人           (Identity:     λx. x)
```

The syntax follows a consistent grammar:

| Token | Meaning |
|-------|---------|
| `以...而为` | Function definition: `以` introduces parameters, `而为` begins the body |
| `矣` | End of statement |
| `于` | Function application (left to right) |
| `为` | Assignment / binding |

### Step 2: Reversing the Interpreter Binary (IDA)

Decompilation of the binary confirmed the language is a pure lambda calculus interpreter with three node types:

| Type | Structure | Meaning |
|------|-----------|---------|
| 0 | `{0, name}` | Variable reference |
| 1 | `{1, param, body}` | Lambda abstraction |
| 2 | `{2, func, arg}` | Application |

The main loop extracts flag characters from a Church-encoded linked list:
1. Test if the list is non-empty using `在(本(list))(真)(假)` — a Church boolean check
2. Extract the current value with `用(本(list))` — gets the head's value
3. Convert the Church numeral to an integer by counting `f` applications in `λf.λx. f(f(...f(x)...))` — this is `sub_402494`
4. Output the character and advance to the tail with `末(list)`

The reduction engine (`sub_402191`) performs standard normal-order beta reduction, one step at a time — which is correct but brutally slow for Church-encoded arithmetic.

### Step 3: Decoding the Primitives

The "poem" section defines Church numerals and arithmetic combinators:

| Symbol | Definition | Operation |
|--------|-----------|-----------|
| `無` | `λf. id` | Church numeral **0** |
| `乙` | `λf.λx. f(f(x))` | Church numeral **2** |
| `丙` | `λf.λx. f(f(f(x)))` | Church numeral **3** |
| `丁` | `λf.λx. f(f(f(f(x))))` | Church numeral **4** |
| `生` | Successor | `succ(n) = n + 1` |
| `合` | `λm.λn. m(succ)(n)` | **Addition** |
| `销` | Church monus | **Subtraction** (truncated at 0) |
| `次` | `λm.λn. λf. m(n(f))` | **Multiplication** (composition) |
| `分` | Complex Church division | **Integer division** |
| `幂` | `λm.λn. n(m)` | **Exponentiation** |
| `阶` | Y-combinator factorial | **Factorial** |

### Step 4: Binary Number Literals

Numbers are encoded with `朝...暮` (dawn...dusk) brackets containing bit sequences:

- `春` (spring) = bit **0**
- `秋` (autumn) = bit **1**
- Bits are read **LSB-first** (least significant bit first)

Example: `朝秋春秋秋暮` → bits `1,0,1,0` → `1 + 0 + 4 + 0 = 5`

### Step 5: Data Structures

The flag is stored as a Church-encoded linked list:

| Symbol | Meaning |
|--------|---------|
| `有(x)` | `cons(true, x)` — a present/non-empty node |
| `无` | `cons(false, id)` — nil/empty list |
| `双(a, b)` | `λf. f(b, a)` — flip/pair |
| `本(p)` | `fst(p)` — extract first element |
| `末(p)` | `snd(p)` — extract second element |
| `在(x)` | `x(true)` — presence check |
| `用(x)` | `x(false)` — value extraction |

The flag list `旗` is constructed as nested pairs:
```
旗 = 双(有(㐀))(双(有(㐁))(双(有(㐂))(...(完)...)))
```

### Step 6: The Data Section

The bulk of the file (~2704 variable definitions) computes 136 flag character values using CJK Extension A characters (㐀–㺏) as variable names.

- **Indices 0–50**: Direct binary literals encoding ASCII values
- **Indices 51–135**: Computed via arithmetic expressions (add, sub, mul, div, pow, factorial)

Each computed flag character follows a pattern like:
```
㐳 = lit(10)
㐴 = fact(㐳)         → 10!
㐵 = lit(8)
㐶 = fact(㐵)         → 8!
㐷 = add(㐴, 㐶)      → 10! + 8!
㐸 = lit(3669110)
㐹 = sub(㐷, 㐸)      → (10! + 8!) - 3669110 = 10
㐺 = lit(32)
㐻 = fact(㐺)         → 32!
㐼 = lit(31)
㐽 = fact(㐼)         → 31!
㐾 = div(㐻, 㐽)      → 32!/31! = 32
㐿 = lit(32)
㑀 = mul(㐾, 㐿)      → 32 × 32 = 1024  ... (not used directly)
㑁 = add(㐹, 㑀)      → final value = 10 = '\n'
```

The key insight is that large factorials **cancel out** through division (e.g., `n!/m!` for close `n,m`), keeping the final results in ASCII range.

## Solution

### Critical Discovery: Operation Mapping

The breakthrough was recognizing that `销` is **subtraction** (not multiplication) and `次` is **multiplication** (not subtraction/application). The evidence:

- `fact(10) + fact(8) = 3,669,120` paired with literal `3,669,110` — the subtraction `销` gives `10` (a newline character), confirming `销 = sub`.
- `次(a, b)` composes Church numerals: `λf. a(b(f))`, which is multiplication. This is standard Church encoding.

### Solver

```python
import re, math

with open('flag_riddle.txt', 'r') as f:
    content = f.read()

# Strip all non-CJK characters (punctuation, English text, whitespace)
clean = re.sub(r'[^\u2E00-\u2FFF\u3200-\u33FF\u3400-\u4DBF\u4E00-\u9FFF]', '', content)

# Locate data section and flag construction
data_start = clean.index('㐀为朝')
data = clean[data_start:]
flag_start = data.index('旗为')
code_section = data[:flag_start]
flag_section = data[flag_start:]

# Extract ordered flag variable names from: 旗为双为有㐀矣于双为有㐁矣于...完矣
flag_names = re.findall(r'有(.)', flag_section)

# Parse all variable definitions (split on 矣)
variables = {}
for stmt in code_section.split('矣'):
    stmt = stmt.strip()
    if not stmt or '为' not in stmt:
        continue
    name = stmt[:stmt.index('为')]
    expr = stmt[stmt.index('为')+1:]
    if len(name) != 1 or not expr:
        continue

    if expr.startswith('朝') and '暮' in expr:
        # Binary literal: LSB-first, 春=0, 秋=1
        bits = expr[1:expr.index('暮')]
        value = sum((1 << i) for i, ch in enumerate(bits) if ch == '秋')
        variables[name] = ('lit', value)
    elif expr[0] == '合': variables[name] = ('add', expr[1], expr[2])
    elif expr[0] == '销': variables[name] = ('sub', expr[1], expr[2])
    elif expr[0] == '次': variables[name] = ('mul', expr[1], expr[2])
    elif expr[0] == '分': variables[name] = ('div', expr[1], expr[2])
    elif expr[0] == '幂': variables[name] = ('pow', expr[1], expr[2])
    elif expr[0] == '阶': variables[name] = ('fact', expr[1])

# Evaluate with memoization
cache = {}
def evaluate(name):
    if name in cache: return cache[name]
    op, *args = variables[name]
    if   op == 'lit':  r = args[0]
    elif op == 'add':  r = evaluate(args[0]) + evaluate(args[1])
    elif op == 'sub':  r = max(evaluate(args[0]) - evaluate(args[1]), 0)
    elif op == 'mul':  r = evaluate(args[0]) * evaluate(args[1])
    elif op == 'div':  r = evaluate(args[0]) // evaluate(args[1])
    elif op == 'pow':  r = evaluate(args[0]) ** evaluate(args[1])
    elif op == 'fact': r = math.factorial(evaluate(args[0]))
    cache[name] = r
    return r

# Compute and print the flag
flag = ''.join(chr(evaluate(name)) for name in flag_names)
print(flag)
```

### Output

```
=== INTERPRETER REQUIRED ===
Calculating flag...


Thanks for playing!

旗子：
dice{y0u_int3rpret3d_Th3_CJK_gr4mMaR_succ3ssfully}
这是λ之道也！
```

The flag characters after the `}` are Unicode CJK characters that spell out `旗子：` (flag:) and `这是λ之道也！` (This is the way of λ!).

## Summary

| Step | Task |
|------|------|
| 1 | Identify the language as Church-encoded lambda calculus with Chinese syntax |
| 2 | Reverse the interpreter binary to confirm node types and reduction strategy |
| 3 | Map the correct binary encoding: LSB-first, `春`=0, `秋`=1 |
| 4 | Discover `销`=subtraction, `次`=multiplication (not the other way around) |
| 5 | Build a static evaluator using Python big integers and `math.factorial` |
| 6 | Evaluate all 136 flag characters from the arithmetic expression DAG |

The challenge is a beautiful marriage of lambda calculus theory and reverse engineering — the Church encoding makes direct execution infeasible (OOM), but the arithmetic expressions are designed so that massive factorials cancel through division, yielding small ASCII values.
