---
title: "Explorer"
date: 2026-03-19T08:44:36+07:00
draft: false
tags: ["ctf", "reversing"]
categories: ["RE"]
contest: "DiceCTF 2026"
author: "k1nt4r0u"
description: "A detailed writeup for Explorer challenge"
difficulty: "Easy/Medium/Hard"
---

# DiceCTF — Explorer (Rev/Kernel)

**Category:** Reversing  
**Flag:** `dice{twisty_rusty_kernel_maze}`

## Challenge

We are given two files:
- `bzImage` — compressed Linux kernel image
- `initramfs.cpio.gz` — initial ramdisk filesystem

Connecting to the remote service (`nc explorer.chals.dicec.tf 1337`) boots a minimal Linux VM and drops us into a BusyBox shell as user `ctf`.

## Analysis

### Extracting the kernel and filesystem

```bash
# Extract the raw ELF kernel image
./extract-vmlinux bzImage > vmlinux

# Extract the initramfs
mkdir extracted && cd extracted
zcat ../initramfs.cpio.gz | cpio -idmv
```

### Init script

The `init` script reveals the setup:

```sh
#!/bin/sh
set -eu
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
mount -t tmpfs -o mode=1777,nosuid,nodev tmpfs /tmp
chmod 1777 /tmp

if [ ! -e /dev/challenge ]; then
  mknod /dev/challenge c 10 123
fi
chmod 666 /dev/challenge
mkdir -p /home/ctf
chown 1000:1000 /home/ctf
exec setsid cttyhack su -s /bin/sh ctf
```

Key observations:
- A character device `/dev/challenge` (major 10, misc device) is created
- It's world-readable/writable (`chmod 666`)
- We run as unprivileged user `ctf` (uid 1000)

### Reversing the kernel module

By reversing the kernel module embedded in `vmlinux`, we identify a **3D maze** implemented as a kernel device driver. The driver exposes the following IOCTL interface:

| IOCTL | Value | Description |
|-------|-------|-------------|
| `RESET` | `0x6489` (25737) | Reset the maze to a new random state |
| `GET_MOVES` | `0x80046486` | Get available moves as a bitmask (6 directions) |
| `MOVE` | `0x40046488` | Move in a direction (0–5) |
| `GET_FLAG` | `0x80406487` | Read the flag (only works at the goal cell) |

The 6 directions map to a 3D grid: up/down/left/right/forward/back, with opposite pairs: `{0↔2, 1↔3, 4↔5}`.

## Solution

### Algorithm: Depth-First Search

The maze is a standard 3D graph. We perform an iterative DFS:

1. **Reset** the maze
2. **Get available moves** at current position (bitmask of 6 directions)
3. For each available direction (skipping the one we came from):
   - **Move** in that direction
   - **Check for flag** — if we get a non-empty string starting with `dice{`, we win
   - Recurse (push onto stack)
4. If no moves left, **backtrack** (move in opposite direction, pop stack)

### The upload problem

The remote environment is a minimal BusyBox system accessed via `nc`. There's no way to directly upload a binary — no `wget`, no `scp`, and the VM has a connection timeout. Pasting a statically-linked binary as base64 is the only option, but a standard `gcc -static` binary is **~700KB** (too large, times out).

### Making a tiny binary

We wrote `exploit_tiny.c` — a **libc-free exploit using raw syscalls only**:

```c
/* No #include <stdio.h>, no libc — raw syscalls */
#define SYS_open   2
#define SYS_ioctl  16
#define SYS_write  1
#define SYS_exit   60

static long syscall3(long nr, long a1, long a2, long a3) {
    long ret;
    __asm__ volatile("syscall" : "=a"(ret)
        : "a"(nr), "D"(a1), "S"(a2), "d"(a3)
        : "rcx","r11","memory");
    return ret;
}
// ... minimal wrappers for open/ioctl/write/exit
```

Compilation pipeline:

```bash
gcc -nostdlib -static -Os -s \
    -fno-stack-protector -fno-builtin \
    -Wl,--gc-sections -ffunction-sections -fdata-sections \
    exploit_tiny.c -o exp_tiny
strip --strip-all exp_tiny          # 13 KB
upx --best --lzma exp_tiny -o exp_tiny_upx  # 6.2 KB → 8.3 KB base64
```

Result: **714 KB → 6.2 KB** — a 115x reduction.

### Automated upload via pwntools

The `solve.py` script automates the entire process:

1. **Compile** the tiny exploit locally (with UPX compression)
2. **Connect** to remote via pwntools
3. **Upload** the binary using a shell heredoc (fast single-block transfer):
   ```
   cat > /tmp/exp.b64 <<'__EOF__'
   <base64 data>
   __EOF__
   ```
4. **Decode and run**:
   ```
   base64 -d /tmp/exp.b64 > /tmp/exp
   chmod +x /tmp/exp
   /tmp/exp
   ```
5. **Verify** integrity with md5sum before execution

### Execution

```
$ python3 solve.py
[*] Compiling minimal exploit (no libc)...
[+] Built exp_tiny_upx (6220 bytes)
[*] Payload: 6220 bytes -> 8296 b64 chars, md5=1e71def4b4dd718472720d0e47c49941
[+] Opening connection to explorer.chals.dicec.tf on port 1337: Done
[+] Got shell!
[+] Uploading payload via heredoc: Done (8313 bytes)
[+] MD5 matches! Binary uploaded correctly.
[+] Running /tmp/exp...
[+] FLAG: dice{twisty_rusty_kernel_maze}
EXIT_CODE=0
```

## Files

| File | Description |
|------|-------------|
| `exploit.c` | Initial exploit (libc, ~700KB static binary) |
| `exploit_tiny.c` | Optimized exploit (no libc, raw syscalls, 13KB → 6KB with UPX) |
| `solve.py` | Automated compile + upload + execute via pwntools |
| `extract-vmlinux` | Script to extract raw kernel ELF from bzImage |

## Key Takeaways

- **Kernel rev challenges** often involve reversing IOCTL interfaces from the kernel binary
- When remote upload is constrained, **eliminate libc** and use raw syscalls + UPX to minimize binary size
- **Heredoc upload** (`cat <<EOF`) is much faster than per-line `echo >>` over a slow connection
- Always **verify upload integrity** (md5sum) before running — corruption causes silent kernel panics

