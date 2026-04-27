# Blog Rice Continuation Notes - 2026-04-26

## Latest Handoff Pointer

For the latest state after the April 27 TOC/image-zoom iterations and the pending hover-effects request, start with:

```text
BLOG_CONTINUE_CODING_HANDOFF_2026-04-27.md
```

For the latest state after restoring the required font, search, and image zoom while keeping the site fast, start with:

```text
BLOG_PERFORMANCE_RESTORE_HANDOFF_2026-04-26.md
```

This older continuation note still contains useful visual-history context, but some sections below are stale after the performance restore pass. In particular, do not rely on older statements about search, image zoom, or the full font set without checking the newer handoff first.

## Scope

Repository:

```text
/home/kintarou/dung_hoc/dung_hoang_blog/my-blog
```

Original request:

```text
$archlinux-ricing rice my blog in ~/dung_hoc/dung_hoang_blog/ and make it faster
```

Latest visual requirement from the user:

```text
colorscheme need to be pale blue white snow and cold not green, no green or nord should be in the color scheme
```

Follow-up correction from the user:

```text
it's still too green go look at my quickshell bar, my niri rice, for correct colors
```

Latest follow-up requirement:

```text
rebuild the colorscheme of light mode it's too light and i dont like the background of homepage, too simple, also redesign the writeup page (the page that shows writeups under competitions) to make every page in blogs as fast as it can an smooth, but also aesthetic
```

This file started as a resume handoff. The continuation pass completed the palette cleanup, then a second pass corrected the color direction to match the live Quickshell bar and Niri rice: `#11111b` background, `#cdd6f4` text, `#a6adc8` subtext, `#b0c4ef` accent, and Niri-style `#93c5fd` / `#60a5fa` active blues.

Current preview URL:

```text
http://localhost:1314/
```

## User Requirements To Preserve

1. The default appearance must be dark mode.
2. Light mode must remain readable and easier to see.
3. The whole color system should feel like pale blue on white snow: cold, clean, soft, and comfortable.
4. No green in the palette. This includes literal green colors and green-looking blue/teal values.
5. No Nord-style palette. Avoid the familiar dark blue-gray/Nord feeling.
6. Keep the blog fast. Do not reintroduce heavy blur, broad scroll scripts, or always-on animations on mobile/writeup pages.
7. Keep the blog as a real usable site, not a landing-page gimmick. The first viewport should still show the actual blog identity and recent content should remain visible below.

## Current Git State

At the time this handoff was written:

```text
 M assets/css/custom.css
 M assets/css/schemes/kintarou.css
 M config/_default/params.toml
 M content/_index.md
 M layouts/partials/extend-footer.html
 M layouts/partials/header/fixed-fill-blur.html
?? layouts/_default/_markup/
?? layouts/partials/home/
?? layouts/partials/recent-articles/
?? static/fonts/VictorMono-Bold.woff2
?? static/fonts/VictorMono-BoldItalic.woff2
?? static/fonts/VictorMono-Italic.woff2
?? static/fonts/VictorMono-Regular.woff2
?? static/fonts/VictorMono-SemiBold.woff2
?? static/fonts/VictorMono-SemiBoldItalic.woff2
```

Important: `layouts/_default/_markup/render-codeblock.html` was already untracked before this work started. Do not claim it as newly created unless you verify otherwise.

## Build Status

The build passes with this command:

```bash
hugo --gc --cacheDir /tmp/hugo_cache_my_blog
```

Known warnings still printed by Hugo:

```text
WARN  Skip unknown config key "params.author"
WARN  Module "blowfish" is not compatible with this Hugo version: 0.141.0/0.157.0 extended; run "hugo mod graph" for more information.
WARN  deprecated: .Site.Data was deprecated in Hugo v0.156.0 and will be removed in a future release. Use hugo.Data instead.
```

These warnings were pre-existing or theme-related enough that they did not block this visual/performance pass.

The local preview server was running during the pass:

```text
http://localhost:1314/
```

Port `1313` was already occupied, so the preview used `1314`.

## What Was Changed For Performance

### Fonts

Added local WOFF2 variants under `static/fonts/`:

```text
static/fonts/VictorMono-Regular.woff2
static/fonts/VictorMono-Bold.woff2
static/fonts/VictorMono-Italic.woff2
static/fonts/VictorMono-BoldItalic.woff2
static/fonts/VictorMono-SemiBold.woff2
static/fonts/VictorMono-SemiBoldItalic.woff2
```

Reason: use local compressed font assets instead of heavier TTF paths where possible.

### Homepage Hero

Added:

```text
layouts/partials/home/hero.html
```

Behavior:

1. Uses Hugo image pipeline for homepage image.
2. Creates WebP derivatives:
   - `900x webp q72`
   - `1800x webp q76`
3. Loads hero image eagerly with `fetchpriority="high"`.
4. Keeps homepage content and social links inside the custom hero.
5. Uses `layouts/partials/recent-articles/main.html` under a new recent section.

### Recent Articles

Added:

```text
layouts/partials/recent-articles/main.html
layouts/partials/recent-articles/list.html
```

Behavior:

1. Renders lightweight recent writeup cards.
2. Uses description first, then summary fallback.
3. Avoids heavy panel nesting.

### Header / Blur

Edited:

```text
layouts/partials/header/fixed-fill-blur.html
```

Intent:

1. Remove some expensive blur/background behavior from the homepage interior.
2. Use a `.home-header-spacer` rather than relying on the original header fill behavior.

### Footer / Runtime JS Gating

Edited:

```text
layouts/partials/extend-footer.html
```

Intent:

1. Skip scroll-progress on mobile, homepage, writeups, and reduced-motion cases.
2. Preserve existing behavior where it is cheap enough.
3. Keep previous writeups performance improvements intact.

## What Was Changed For The Homepage Markup

Edited:

```text
content/_index.md
```

The Blowfish button shortcode produced important utility classes that forced white text on the light palette. The buttons were changed from:

```md
{{< button href="/writeups/" >}}Browse writeups{{< /button >}}
{{< button href="/about/" >}}About me{{< /button >}}
```

to:

```html
<a class="landing-button landing-button--primary" href="/writeups/">Browse writeups</a>
<a class="landing-button" href="/about/">About me</a>
```

Reason: make the local palette fully control button colors in both modes.

## Current Appearance Config

Edited:

```text
config/_default/params.toml
```

Current relevant state:

```toml
colorScheme = "kintarou"
defaultAppearance = "dark"
autoSwitchAppearance = false
```

Why:

1. The user asked why dark mode was not default.
2. `defaultAppearance = "dark"` restores dark as default.
3. `autoSwitchAppearance = false` avoids the OS/browser preference overriding the intended default during visual testing.

If the user later wants automatic system-theme switching, change only `autoSwitchAppearance`; do not collapse dark and light variables together again.

## Current Color Scheme State

Edited:

```text
assets/css/schemes/kintarou.css
```

This file now defines a Quickshell/Niri-aligned cold blue palette. It includes 950 stops for dark mode compatibility:

```css
--color-neutral-950: 17, 17, 27;
--color-primary-950: 27, 32, 58;
--color-secondary-950: 20, 25, 45;
```

The main visual override is in:

```text
assets/css/custom.css
```

The active split palette begins around the comment:

```css
/* Final split-mode snow palette. Dark mode is the default; light mode stays readable. */
```

Current active structure:

```css
:root {
  /* light mode variables */
}

html.dark {
  /* dark mode variables */
}
```

This fixed the earlier mistake where `:root, html.dark` shared one light-mode palette and made dark mode disappear.

## Palette Cleanup Status

Completed in the continuation pass:

1. Deleted the inactive `@media not all` single-mode snow palette block.
2. Renamed `--blog-accent-green` to `--blog-accent-frost`.
3. Renamed `--blog-accent-amber` to `--blog-accent-ice`.
4. Removed the known green-tinted values and bad names from the searched CSS/config/content/layout set.
5. Rebalanced the active dark palette toward the live Quickshell bar and Niri border colors instead of the greener snow-cyan values.

Verification search now returns no matches:

```bash
rg -n "#c0e2f3|#C0E2F3|#6da1b9|#6DA1B9|192, 226, 243|109, 161, 185|199, 235, 250|167, 213, 232|57, 99, 122|#7fd3ff|#8fd3ff|#9be7ff|#0b6fa4|green|amber|nord" assets/css config content layouts
```

Current dark palette anchor:

```css
--snow-bg: #11111b;
--snow-bg-deep: #1e1e2e;
--snow-surface-solid: #1e1e2e;
--snow-ink: #cdd6f4;
--snow-muted: #a6adc8;
--snow-steel: #b0c4ef;
--snow-link: #93c5fd;
```

Current light palette anchor:

```css
--snow-bg: #dce4f2;
--snow-bg-deep: #cfd8ea;
--snow-surface-solid: #e8eef8;
--snow-ink: #1e1e2e;
--snow-muted: #434d67;
--snow-steel: #6578aa;
--snow-link: #3f5fb0;
```

## Latest Light/Home/Writeups Pass

Completed after the user said light mode was still too light and the homepage background was too simple:

1. Darkened light mode from near-white snow to a colder mist palette.
2. Bound both homepage and interior fixed headers to the same cold nav surface instead of the Blowfish white fallback.
3. Increased homepage image presence in light mode while keeping the text side protected by an overlay.
4. Added static grid/line depth to the homepage background without radial blobs, blur-heavy panels, or animation.
5. Redesigned `/writeups/` into a competition archive index with header stats, two-column desktop competition cards, one-column mobile cards, compact metadata, and expanded entry lists.
6. Added `content-visibility: auto` and intrinsic sizing to repeated article/writeup card surfaces to keep long pages smooth.
7. Matched scrollbar track/thumb colors to the active light/dark palette so mobile screenshots do not show a generic gray strip.
8. Follow-up cleanup removed stale bright-cyan literal values from the older CSS block and rebound them to the final cold-blue variables.
9. Homepage hero spacing was tightened and top-aligned so the recent-writeups section is visible in the first viewport on mobile and desktop.
10. Viewport-based font sizing was removed from the custom homepage/writeups CSS touched in this pass.

## Performance Emergency Pass

Completed after the user said the whole page felt visibly laggy and bloated on PC and mobile:

1. Disabled always-on Blowfish widgets: `enableA11y`, `enableSearch`, `enableCodeCopy`, `disableImageZoom = true`, and `footer.showScrollToTop = false`.
2. Removed the scroll-progress footer injection completely; `layouts/partials/extend-footer.html` is intentionally empty now.
3. Removed `scroll-smooth` from `layouts/_default/baseof.html`.
4. Set global views/likes and article likes to false so no metadata counter UI is generated.
5. Flattened the paint path in `assets/css/custom.css`: no fixed background pattern, no scroll progress pseudo-element, no hero grid overlay, no panel sheen pseudo-elements, no hover transforms, no broad box shadows, no image filter.
6. Removed shipped local webfonts and font-face declarations. The site now uses system fonts plus local font names if already installed; this cut first-load font bytes to zero.
7. Removed unused `static/mybackground.jpg` and set `defaultSocialImage = ""` so the original 1.6 MB hero JPEG is no longer emitted just for metadata.
8. Rebuilt with `hugo --gc --cleanDestinationDir --cacheDir /tmp/hugo_cache_my_blog` to clear stale hashed bundles from `public/`.

Current tradeoffs:

1. Search is disabled from the nav and the search modal is gone.
2. Image zoom is disabled.
3. Code-copy JS is disabled.
4. The appearance switcher remains.
5. Giscus comments are still lazy-loaded only on article pages.

Latest performance metrics from CDP with cache disabled against `http://127.0.0.1:1314/`:

```text
home mobile 390x900: 6 resources, 175040 total bytes, 3354 JS bytes, 0 font bytes, 8750 image bytes, load 89ms
home desktop 1440x900: 5 resources, 218960 total bytes, 3354 JS bytes, 0 font bytes, 54330 image bytes, load 69ms
writeups mobile 390x900: 4 resources, 164630 total bytes, 3354 JS bytes, 0 font bytes, 0 image bytes, load 92ms
writeups desktop 1440x900: 4 resources, 164630 total bytes, 3354 JS bytes, 0 font bytes, 0 image bytes, load 49ms
```

Latest deploy-size check:

```text
public/ was 22M before cleanup, 9.7M after stale bundle/background cleanup, and 5.5M after removing shipped webfonts.
```

Latest screenshot paths:

```text
/tmp/blog-perf2-home-mobile.png
/tmp/blog-perf2-home-desktop.png
/tmp/blog-perf2-writeups-mobile.png
/tmp/blog-perf2-writeups-desktop.png
```

Latest screenshot paths:

```text
/tmp/blog-home-dark-codex4-390.png
/tmp/blog-home-dark-codex4-1440.png
/tmp/blog-home-light-codex4-390.png
/tmp/blog-writeups-dark-codex4-390.png
/tmp/blog-writeups-light-codex4-390.png
```

Latest CDP metrics confirmed:

```text
390px dark home: overflowX 0, nextSectionVisible true, bodyBg rgb(17, 17, 27), navBg rgba(17, 17, 27, 0.9)
1440px dark home: overflowX 0, nextSectionVisible true, bodyBg rgb(17, 17, 27), navBg rgba(17, 17, 27, 0.9)
390px dark writeups: overflowX 0, writeupsIndex true, bodyBg rgb(17, 17, 27), navBg rgba(17, 17, 27, 0.9)
390px light home: overflowX 0, nextSectionVisible true, bodyBg rgb(220, 228, 242), navBg rgba(214, 224, 241, 0.97)
390px light writeups: overflowX 0, writeupsIndex true, bodyBg rgb(220, 228, 242), navBg rgba(214, 224, 241, 0.97)
```

## Current Visual Verification

Verified with CDP-enforced viewport so Chromium does not fake a 500px CSS viewport when asked for a 390px screenshot.

Important finding:

1. Raw `chromium --screenshot --window-size=390,900` reports a 390px PNG but may lay out at `500px` CSS viewport.
2. CDP `Emulation.setDeviceMetricsOverride` was used to force real `390x900`.
3. Current scroll metrics were clean:

```json
{
  "innerWidth": 390,
  "scrollWidth": 390,
  "bodyScrollWidth": 382
}
```

Screenshot paths from the last useful pass:

```text
/tmp/blog-home-dark-final-390.png
/tmp/blog-writeup-dark-final-390.png
/tmp/blog-home-light-final-390.png
/tmp/blog-writeup-light-final-390.png
```

Earlier desktop screenshot:

```text
/tmp/blog-home-dark-1440.png
```

These are temporary files under `/tmp`; they are useful while the machine/session is still alive, but do not rely on them as durable repo artifacts.

## Known Good Commands

Build:

```bash
hugo --gc --cleanDestinationDir --cacheDir /tmp/hugo_cache_my_blog
```

Run server:

```bash
hugo server -D --disableFastRender --bind 127.0.0.1 --port 1314 --cacheDir /tmp/hugo_cache_my_blog
```

Quick status:

```bash
git status --short
```

Search remaining bad palette names:

```bash
rg -n "#c0e2f3|#C0E2F3|#6da1b9|#6DA1B9|192, 226, 243|109, 161, 185|199, 235, 250|167, 213, 232|57, 99, 122|#7fd3ff|#8fd3ff|#9be7ff|#0b6fa4|green|amber|nord|127, 211, 255|11, 35, 58|cyan" assets/css config content layouts
```

Search active snow variables:

```bash
rg -n "Final split-mode|snow-|blog-accent" assets/css/custom.css assets/css/schemes/kintarou.css
```

## CDP Verification Script Pattern

Use Node with Chrome DevTools Protocol to force real mobile width. This avoids false screenshot conclusions:

```bash
node -e 'const {spawn}=require("child_process"); const fs=require("fs"); const port=9346; const chrome=spawn("chromium",["--headless=new","--disable-gpu","--disable-extensions","--no-first-run","--remote-debugging-port="+port,"--user-data-dir=/tmp/blog-cdp-final-palette","about:blank"],{stdio:"ignore"}); const sleep=ms=>new Promise(r=>setTimeout(r,ms)); (async()=>{let tab; for(let i=0;i<80;i++){try{const tabs=await fetch("http://127.0.0.1:"+port+"/json/list").then(r=>r.json()); tab=tabs.find(t=>t.type==="page"); if(tab) break;}catch(e){} await sleep(100);} const ws=new WebSocket(tab.webSocketDebuggerUrl); let id=0; const pending=new Map(); let loaded=null; ws.onmessage=ev=>{const msg=JSON.parse(ev.data); if(msg.id&&pending.has(msg.id)){pending.get(msg.id)(msg); pending.delete(msg.id);} if(msg.method==="Page.loadEventFired"&&loaded){loaded(); loaded=null;}}; await new Promise(r=>ws.onopen=r); const send=(method,params={})=>new Promise(res=>{const n=++id; pending.set(n,res); ws.send(JSON.stringify({id:n,method,params}));}); await send("Page.enable"); await send("Runtime.enable"); async function load(url,width,height){await send("Emulation.setDeviceMetricsOverride",{width,height,deviceScaleFactor:1,mobile:width<600}); const waitLoad=new Promise(r=>loaded=r); await send("Page.navigate",{url}); await Promise.race([waitLoad,sleep(3000)]); await sleep(650);} async function shot(path){const png=await send("Page.captureScreenshot",{format:"png",fromSurface:true}); fs.writeFileSync(path,Buffer.from(png.result.data,"base64"));} async function metrics(forceLight){if(forceLight){await send("Runtime.evaluate",{expression:"document.documentElement.classList.remove(\"dark\"); localStorage.setItem(\"appearance\",\"light\")"}); await sleep(250);} const expr="(()=>({className:document.documentElement.className,innerWidth:window.innerWidth,scrollWidth:document.documentElement.scrollWidth,bodyScrollWidth:document.body.scrollWidth,bodyBg:getComputedStyle(document.body).backgroundColor,bodyColor:getComputedStyle(document.body).color,firstButton:document.querySelector(\".landing-actions a\")?getComputedStyle(document.querySelector(\".landing-actions a\")).color:null,codeBg:getComputedStyle(document.querySelector(\".highlight\")||document.body).backgroundColor}))()"; const out=await send("Runtime.evaluate",{expression:expr,returnByValue:true}); return out.result.result.value;} await load("http://127.0.0.1:1314/",390,900); const darkHome=await metrics(false); await shot("/tmp/blog-home-dark-final-390.png"); await load("http://127.0.0.1:1314/writeups/dicectf2026/explorer/",390,900); const darkWriteup=await metrics(false); await shot("/tmp/blog-writeup-dark-final-390.png"); await load("http://127.0.0.1:1314/",390,900); const lightHome=await metrics(true); await shot("/tmp/blog-home-light-final-390.png"); await load("http://127.0.0.1:1314/writeups/dicectf2026/explorer/",390,900); const lightWriteup=await metrics(true); await shot("/tmp/blog-writeup-light-final-390.png"); console.log(JSON.stringify({darkHome,darkWriteup,lightHome,lightWriteup},null,2)); ws.close(); chrome.kill();})().catch(e=>{console.error(e); chrome.kill(); process.exit(1);});'
```

## Current Code Structure Notes

### `assets/css/custom.css`

Relevant regions:

1. Old base dark style appears near the top, but stale cyan literals were cleaned out in the follow-up pass.
2. Active split palette starts at:

```css
/* Final split-mode snow palette. Dark mode is the default; light mode stays readable. */
```

The inactive single-mode snow block was removed. Future work should avoid stacking another broad override block below the active split palette unless there is a strong reason.

### `assets/css/schemes/kintarou.css`

Currently defines base Blowfish token values around the Quickshell/Niri palette. It is okay structurally after the palette cleanup.

### `config/_default/params.toml`

Dark default is restored:

```toml
defaultAppearance = "dark"
autoSwitchAppearance = false
```

### `layouts/partials/home/hero.html`

This is the homepage owner. It creates the hero and includes recent articles. Keep this unless rolling back the whole homepage rice.

### `layouts/partials/recent-articles/`

These are lightweight recent card overrides. Keep them unless reverting homepage work.

### `layouts/partials/extend-footer.html`

Intentionally empty after the performance pass. Be careful not to reintroduce global/mobile scroll work here.

## Completed Continuation Plan

Re-run commands used:

```bash
hugo --gc --cacheDir /tmp/hugo_cache_my_blog
rg -n "#c0e2f3|#C0E2F3|#6da1b9|#6DA1B9|192, 226, 243|109, 161, 185|199, 235, 250|167, 213, 232|57, 99, 122|#7fd3ff|#8fd3ff|#9be7ff|#0b6fa4|green|amber|nord|127, 211, 255|11, 35, 58|cyan" assets/css config content layouts
rg -n "font-size: clamp\\([^;]*vw|min-height: clamp\\([^;]*[sv]*vh|padding: clamp\\([^;]*vw" assets/css/custom.css
```

Verified:

1. Homepage dark mobile.
2. Homepage dark desktop.
3. Homepage light mobile.
4. Writeup page dark mobile.
5. Writeup page light mobile.
6. Dark mode is default on a fresh browser profile.
7. No horizontal overflow at `390x900`.
8. Code blocks remain readable.
9. Homepage buttons are legible and not cramped.
10. The searched bad palette names and values return no matches.
11. Homepage recent section is visible within the first viewport at `390x900` and `1440x900`.

## Do Not Do

1. Do not set `:root, html.dark` to the same palette again.
2. Do not reintroduce green, mint, teal-green, beige, orange, purple, or Nord-like color identity.
3. Do not add radial gradient blobs or decorative orbs.
4. Do not use broad blur panels on writeups/mobile; this caused lag in previous work.
5. Do not revert unrelated untracked files without checking whether they were pre-existing.
6. Do not rely only on `chromium --screenshot --window-size=390,900`; use CDP or confirm `window.innerWidth`.

## Current Best Mental Model

The blog should feel like the user's Arch/Niri setup translated into a website, with the live Quickshell bar as the color anchor. The safe interpretation is:

```text
Quickshell #11111b glass base + #b0c4ef accent + #cdd6f4 text + Niri active blues + no green/cyan-teal drift
```
