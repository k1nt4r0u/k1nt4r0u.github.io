---
title: "Explorer"
date: 2026-03-19T08:44:36+07:00
draft: false
tags: ["ctf", "re"]
categories: ["RE"]
contest: "DiceCTF 2026"
author: "k1nt4r0u"
description: "Reversing a kernel maze device and solving the harder problem of getting a tiny helper into the VM"
difficulty: "Medium"
---

# DiceCTF 2026 — Explorer

## First look

This challenge shipped a `bzImage`, an `initramfs.cpio.gz`, and a remote VM that dropped into a BusyBox shell. That immediately made me think "driver challenge," so I unpacked the initramfs before spending time on the remote instance.

The `init` script confirmed that instinct:

```sh
if [ ! -e /dev/challenge ]; then
  mknod /dev/challenge c 10 123
fi
chmod 666 /dev/challenge
exec setsid cttyhack su -s /bin/sh ctf
```

So the whole challenge surface was a world-writable character device exposed to an unprivileged user. At that point the job was clear: reverse the device interface, then talk to it directly.

## Reversing the device

After extracting `vmlinux` from the kernel image, I traced the misc-device handlers and mapped the useful IOCTLs:

| IOCTL | Value | Meaning |
|-------|-------|---------|
| `RESET` | `0x6489` | Start a new maze |
| `GET_MOVES` | `0x80046486` | Return a bitmask of valid moves |
| `GET_FLAG` | `0x80406487` | Return the flag at the goal cell |
| `MOVE` | `0x40046488` | Move in one of six directions |

The driver implements a 3D maze. The movement indices come in opposite pairs:

- `0 <-> 2`
- `1 <-> 3`
- `4 <-> 5`

Once I understood that, the kernel part of the challenge got much simpler. This was just DFS with backtracking.

## The maze was easy

The actual search logic is standard:

1. `RESET` the maze,
2. ask `GET_MOVES` for valid directions,
3. try each unexplored move,
4. call `GET_FLAG` after each step,
5. backtrack when stuck.

So the algorithm was never the hard part.

## The upload constraint was the real obstacle

What actually slowed me down was the environment.

The VM was tiny, there was no convenient upload path, and the session timed out quickly. My first attempt used a normal statically linked helper binary, and it was far too large to paste over the connection reliably.

That forced the real pivot in the solve: the helper had to be rebuilt as something much smaller.

I rewrote it to avoid libc entirely and use only raw syscalls for the handful of operations I needed:

- `open`
- `ioctl`
- `write`
- `exit`

Then I built it with size-focused flags, stripped it aggressively, compressed it, base64-encoded it, and uploaded it through a heredoc. That was the difference between "interesting local solve" and "actually usable on remote."

The final delivery path looked like this:

```sh
cat > /tmp/exp.b64 <<'__EOF__'
<base64 payload>
__EOF__
base64 -d /tmp/exp.b64 > /tmp/exp
chmod +x /tmp/exp
/tmp/exp
```

Once the helper was inside the VM, it could talk to `/dev/challenge`, explore the maze, and ask for the flag from the goal cell.

## Flag

```text
dice{twisty_rusty_kernel_maze}
```

## Takeaway

`Explorer` has two separate solves layered on top of each other:

- reverse the kernel driver well enough to recover the IOCTL protocol,
- then package that logic into a binary small enough for the hostile remote environment.

The first half was normal reversing. The second half was what made the challenge memorable.
