---
title: "Cobweb"
date: 2026-03-29T21:54:48+07:00
draft: false
tags: ["CTF", "RE"]
categories: ["Codegate2026"]
contest: "Codegate2026"
author: "k1nt4r0u"
description: "Writeup for Cobweb from Codegate2026"
difficulty: "Easy/Medium/Hard"
---



# CODEGATE 2026 Quals - Cobweb

- Category: Web
- Challenge: `Cobweb`
- Description: `I wanted to create a web application.. but I don't know how to use web frameworks. So I decided to use pure C to make a web application!`
- Solver: `exploit_admin_post_xss.py`
- Transport helper: `solve.py`

## TL;DL

The challenge looks like a stored-XSS task at first, but that is only half right. The actual entry point is a one-byte stack overwrite in `edit_post`. If I make the escaped content length land exactly on `0x6000`, the trailing NUL from `html_escape()` zeros the low byte of the saved `user_id` local. That pushes the request into the admin SQL branch, rewrites my post as `user_id = 0`, and then the admin-only render path decodes the escaped content back into raw HTML. Only after that ownership flip does the stored script become real JavaScript in the bot's browser.

## Overview

The challenge description ended up being more honest than it first sounded. This really is a tiny web application written directly in C, and it behaves like one. Every control-port connection spawns a fresh HTTP server on a random port, prints that port, and tears the whole database down when the run ends.

That wrapper behavior mattered immediately for two reasons:

1. every connection starts from a clean database
2. I cannot hard-code the real HTTP port because it changes every run

The second infrastructure detail mattered even more once I started sending real requests: the server only performs one `recv()` per request. That means normal HTTP clients can make the service look buggy in the wrong way. A large form body can be split across packets, and the server will happily parse the first chunk as if it were the whole request.

That is why I kept raw-socket helpers around for the full solve. With this service, transport is part of the bug surface. Treating it like a normal web server would have hidden the real application behavior.

## Analysis

The first thing I checked was the obvious web idea: stored XSS. There is a report feature, there is an admin bot, and the bot carries the flag in a cookie. That is exactly the kind of surface where I want to test a simple `<script>` payload first before inventing something more exotic.

That idea failed for a real reason, not because I tested it badly. Both create and edit escape post content before it reaches storage. Once I verified that in the code and in live behavior, plain stored XSS stopped being the main path.

There was another bug that looked promising for a while: the request parser uses plain `strtok()` in threaded code, so there is a genuine parser race. I reproduced that locally and kept the notes because it is a real bug, but it never became the route to the flag. The reason I moved away from it is practical. `/report` is POST-only, and path-steering alone was not giving me a clean way to turn the bot's visit into the action I needed. It was interesting evidence, but it was not carrying the solve forward.

The real pivot came from looking at the escaping path more carefully. If stored XSS was dead at insert time, the next question was whether anything later turned escaped content back into HTML. That is what made me compare the normal post-render path against the admin-owned post-render path instead of staring at the parser race forever.

Two details lined up there:

- admin-owned posts are rendered differently
- `html_escape()` has an off-by-one at the output boundary

The bug in `html_escape()` is small but precise. When it handles `"` it writes `&quot;`, and if the escaped output lands exactly on the destination limit, it still writes the terminating NUL one byte past the end. In `edit_post`, that one byte lands on the low byte of the saved `user_id` local. So a normal user id like:

```text
0x00000001
```

becomes:

```text
0x00000000
```

At first that looks like a cute one-byte corruption with unclear value. The reason I kept pulling on it is that `user_id` is not just checked for authorization. It is used to choose which SQL update query runs. Once that low byte becomes zero, the handler stops acting like a normal user edit and takes the admin branch, which also forces `user_id = 0` on the stored post.

That was the moment the challenge finally clicked for me. I was not trying to turn a one-byte overwrite into control flow hijack. I was using a one-byte overwrite to cross a trust boundary inside the application's own logic.

The next question was what I gained by making the post admin-owned. That answer was even better than expected. Normal posts store escaped content and display it safely. Admin-owned posts go through an entity-decoding path before being inserted into the page. So the exact payload that was harmless as stored text for a normal post becomes live HTML once I force the post into the admin render path.

That is why the final technique is a two-stage chain instead of "just XSS":

1. use the off-by-one to force an ownership change
2. let the admin renderer resurrect the escaped script

The last difficulty was delivery. The off-by-one only happens if the escaped content length is exactly `0x6000`, and the server's one-`recv()` request handling makes large form submissions unreliable if they are encoded naively. The fix was pragmatic:

- compute the exact escaped length offline
- keep form encoding minimal
- leave quotes raw so the body does not triple in size
- send synchronized edit bursts over separate sockets until one full request lands cleanly

It is not pretty, but it is the first version that behaved the same way remotely and locally.

## Exploit

The final exploit flow was:

1. Connect to the control port and recover the real ephemeral HTTP port.
2. Register and log in as a normal user.
3. Create a seed post so I have a stable post id.
4. Build a second-stage edit body whose escaped length is exactly `0x6000`.
5. Send that edit request in synchronized bursts until the post flips into the admin-owned render path.
6. Re-fetch the post and confirm that raw `<script>` now appears in the HTML instead of literal escaped text.
7. Report the post.
8. Let the bot visit the now-admin-owned post, execute the revived script, and submit `document.cookie` back into the same post.
9. Fetch the post again and extract the `flag=...` cookie value from the stored content.

I wrote the exploit this way because each checkpoint proves something different. Seeing raw `<script>` in the post page proves the off-by-one and ownership flip worked. Seeing the flag cookie later proves the bot really executed the revived script. Splitting the chain that way made debugging much easier than treating it as one black-box web exploit.

## Verification

The older local notes for `cobweb` turned out to be stale once I tested the updated public hosts. Running the current exploit against the new control endpoints and got: 
- `codegate2026{edaa67b3a065abe46f5d64ea9338d0b0622000c646b47abf49c7e3d3d09419a53d5ae63dcfb496935cfc9099e2b3d1d1bc3c787e933e5e2175cca4a50cfe864f0e23bf14d3ec3409}`

`43.203.149.201:9883` still timed out from this environment, so the infrastructure is not perfectly uniform, but the exploit path itself is now fully confirmed.

For the successful runs, the decisive progression was:

```text
[+] created post 1
[+] admin-owned raw script confirmed in post HTML
[+] report submitted
codegate2026{...}
```

The service is clearly instance-specific, so I am recording one representative fresh rerun flag below.

Final flag:

```text
codegate2026{edaa67b3a065abe46f5d64ea9338d0b0622000c646b47abf49c7e3d3d09419a53d5ae63dcfb496935cfc9099e2b3d1d1bc3c787e933e5e2175cca4a50cfe864f0e23bf14d3ec3409}
```
