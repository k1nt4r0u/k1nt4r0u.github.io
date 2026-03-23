---
title: "Interpreter Required"
date: 2026-03-19T08:47:50+07:00
draft: false
tags: ["CTF", "RE"]
categories: ["DiceCTF 2026"]
contest: "DiceCTF 2026"
author: "k1nt4r0u"
description: "Parsing the CJK lambda-calculus riddle into ordinary arithmetic instead of reducing it"
difficulty: "Medium"
---
## First reaction

The challenge description tells you, very politely, not to solve it the obvious way:

> don't interpret the puzzle, it will OOM your computer

That was accurate. The provided interpreter can start reducing the source program, but doing the whole thing through Church-encoded lambda calculus is hopelessly slow. So from the beginning, the real solve was always going to be static analysis.

## Recognizing the language

The first definitions in `flag_riddle.txt` give the theme away:

```text
真以矛盾而为矛矣
假以矛盾而为盾矣
正以人而为人矣
```

Those are just Church booleans and the identity function written with Chinese tokens. Once that clicked, the file stopped looking like an unknown esolang and started looking like a parser problem.

The core grammar is compact:

| Token | Meaning |
|-------|---------|
| `以...而为` | function definition |
| `于` | application |
| `为` | binding |
| `矣` | end of statement |

## Confirming it in the binary

I still checked the interpreter in IDA to make sure the source-language guess matched reality.

The decompilation confirmed a normal lambda-calculus interpreter with three node types:

| Type | Meaning |
|------|---------|
| `0` | variable reference |
| `1` | lambda abstraction |
| `2` | application |

The output path was also revealing. The interpreter walks a Church-encoded linked list, converts one Church numeral at a time into an integer by counting `f` applications, writes the corresponding byte, then advances to the tail.

That was the key mental shift: I did not need to evaluate the lambda calculus directly. I only needed to recover the arithmetic expression graph that eventually produced those numerals.

## Turning the source into ordinary data

A few encodings matter:

- `朝...暮` wraps binary literals
- `春` means bit `0`
- `秋` means bit `1`
- bits are read least-significant-bit first

So something like:

```text
朝秋春秋暮
```

represents `1 + 0 + 4 = 5`.

The flag itself is stored as a linked list built from Church-style helpers such as `双`, `有`, `无`, `本`, `末`, `在`, and `用`. Once I parsed the `旗` definition, I had the exact order of the variables that corresponded to flag characters.

The remaining work was evaluating the definitions that produced those variables.

## The important operator mapping

The place I could have gone wrong was the arithmetic vocabulary.

The critical discovery was:

- `销` is subtraction
- `次` is multiplication

The sanity check that made this clear was one of the data chains:

```text
10! + 8! = 3669120
3669120 - 3669110 = 10
```

That only makes sense if `销` means subtraction. After that, the rest of the numeric expressions started falling into place.

The nice design choice in the challenge is that it uses huge operations like factorial without making the final values huge. Terms such as `32! / 31!` collapse cleanly back to small integers, so a plain Python evaluator with big integers is enough.

## Solver

My static solver did three things:

1. strip away non-CJK wrapper text,
2. parse each definition into a tiny expression DAG,
3. evaluate literals, add/sub/mul/div/pow/factorial recursively with memoization.

This was enough:

```python
import math
import re

clean = re.sub(r"[^\u2E00-\u9FFF]", "", open("flag_riddle.txt", "r").read())
data = clean[clean.index("㐀为朝"):]
flag_start = data.index("旗为")
code_section = data[:flag_start]
flag_names = re.findall(r"有(.)", data[flag_start:])

variables = {}
for stmt in code_section.split("矣"):
    if "为" not in stmt:
        continue
    name, expr = stmt.split("为", 1)
    if len(name) != 1 or not expr:
        continue
    if expr.startswith("朝") and "暮" in expr:
        bits = expr[1:expr.index("暮")]
        variables[name] = ("lit", sum((1 << i) for i, ch in enumerate(bits) if ch == "秋"))
    elif expr[0] == "合":
        variables[name] = ("add", expr[1], expr[2])
    elif expr[0] == "销":
        variables[name] = ("sub", expr[1], expr[2])
    elif expr[0] == "次":
        variables[name] = ("mul", expr[1], expr[2])
    elif expr[0] == "分":
        variables[name] = ("div", expr[1], expr[2])
    elif expr[0] == "幂":
        variables[name] = ("pow", expr[1], expr[2])
    elif expr[0] == "阶":
        variables[name] = ("fact", expr[1])

cache = {}
def eval_var(name):
    if name in cache:
        return cache[name]
    op, *args = variables[name]
    if op == "lit":
        value = args[0]
    elif op == "add":
        value = eval_var(args[0]) + eval_var(args[1])
    elif op == "sub":
        value = max(eval_var(args[0]) - eval_var(args[1]), 0)
    elif op == "mul":
        value = eval_var(args[0]) * eval_var(args[1])
    elif op == "div":
        value = eval_var(args[0]) // eval_var(args[1])
    elif op == "pow":
        value = eval_var(args[0]) ** eval_var(args[1])
    else:
        value = math.factorial(eval_var(args[0]))
    cache[name] = value
    return value

print("".join(chr(eval_var(name)) for name in flag_names))
```

## Flag

```text
dice{y0u_int3rpret3d_Th3_CJK_gr4mMaR_succ3ssfully}
```

The program continues with extra Chinese text after the closing brace, but the ASCII substring above is the actual flag.

## Takeaway

I liked this challenge because the "esoteric interpreter" part is mostly there to scare you into doing too much work. Once the syntax and operator mapping were clear, the right move was to throw away the interpreter and treat the source as serialized arithmetic.
