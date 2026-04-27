# Blog Continue Coding Handoff - 2026-04-27

Repository:

```text
/home/kintarou/dung_hoc/dung_hoang_blog/my-blog
```

Preview server observed during this session:

```text
http://localhost:1314/
```

Observed listener:

```text
127.0.0.1:1314 users:(("hugo",pid=45491,fd=3))
```

This note supersedes the older April 26 resume files for current UI state:

```text
BLOG_PERFORMANCE_RESTORE_HANDOFF_2026-04-26.md
BLOG_RICE_CONTINUATION_2026-04-26.md
```

Those older files still contain useful history, but their git-state sections are stale.

## Current User Direction

The user wants the blog to keep the necessary features but stay fast:

1. Keep Victor Mono.
2. Keep search.
3. Keep image zoom.
4. Keep article TOC usable and visually clean.
5. Keep page performance smooth on PC and mobile.
6. Avoid broad blur, heavy panels, or large runtime effects.
7. Use understated, cold, pale blue / snow styling; avoid green and Nord-like teal/blue-gray drift.

The latest completed interaction was about the mobile TOC title box:

```text
ok now shift that box to the left a little bit so that it stays at center
```

That was completed by shifting the mobile `.toc-inside > summary` left by `0.45rem`.

Immediately before this handoff, the user also started a new request:

```text
good now add hover effect to all buttons or things that can be press
```

That was initially interrupted and documented as pending, then completed after this handoff was created. The current CSS now has a final interaction-polish layer for functional buttons, pressable summaries, nav/search controls, writeup entries, article cards, TOC links, comments loader, and the image-zoom close button.

## Current Git State

Before creating this handoff note, the repository was clean:

```text
git status --short
# no output
```

Current HEAD observed:

```text
301ca29 Changing writeups page layout, panels and optimized pages speed
```

The latest commit stat:

```text
assets/css/custom.css | 11 +++++++++++
```

After this note is added, the expected working tree will include this untracked or modified handoff file. If `BLOG_RICE_CONTINUATION_2026-04-26.md` was updated to point here, that file will also show as modified.

## Build Status

Latest verified build command from the TOC-centering pass:

```bash
hugo --gc --cleanDestinationDir --cacheDir /tmp/hugo_cache_my_blog
```

The build passed.

Known warnings that are expected for this checkout:

```text
WARN  Skip unknown config key "params.author"
WARN  Module "blowfish" is not compatible with this Hugo version: 0.141.0/0.157.0 extended; run "hugo mod graph" for more information.
WARN  deprecated: .Site.Data was deprecated in Hugo v0.156.0 and will be removed in a future release. Use hugo.Data instead.
```

These warnings were not introduced by the TOC or image zoom work. They should not block normal UI iteration unless the next task is explicitly about dependency/theme cleanup.

## Current Feature Baseline

Current important values in `config/_default/params.toml`:

```toml
colorScheme = "kintarou"
defaultAppearance = "dark"
autoSwitchAppearance = false
enableA11y = false
enableSearch = true
enableCodeCopy = false
smartTOC = true
disableImageOptimization = false
disableImageOptimizationMD = false
defaultBackgroundImage = "images/home-background.jpg"
fingerprintAlgorithm = "sha512"
enableStyledScrollbar = true
disableImageZoom = true
showViews = false
showLikes = false
```

Article-level state:

```toml
[article]
showHero = false
layoutBackgroundBlur = true
layoutBackgroundHeaderSpace = true
showTableOfContents = true
showComments = true
showReadingTime = false
showWordCount = false
showZenMode = false
externalLinkForceNewTab = true
```

Meaning:

1. Search is intentionally enabled.
2. Blowfish's built-in eager image zoom is intentionally disabled.
3. Custom lazy image zoom in `layouts/partials/extend-footer.html` is responsible for image zoom.
4. Comments are enabled but lazy loaded by the local comments partial.
5. Views, likes, code-copy, reading time, word count, scroll-to-top, and zen mode are currently disabled for speed and visual quietness.

## Font State

Victor Mono is restored and should be preserved.

Current font files:

```text
static/fonts/VictorMono-Regular.woff2 67424 bytes
static/fonts/VictorMono-Bold.woff2    70300 bytes
```

Current font declarations in `assets/css/custom.css`:

```css
@font-face {
  font-family: 'Victor Mono';
  src: url('/fonts/VictorMono-Regular.woff2') format('woff2');
  font-weight: 400;
  font-style: normal;
  font-display: swap;
}

@font-face {
  font-family: 'Victor Mono';
  src: url('/fonts/VictorMono-Bold.woff2') format('woff2');
  font-weight: 600 800;
  font-style: normal;
  font-display: swap;
}

body,
button,
input,
textarea,
select {
  font-family: 'Victor Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace !important;
}
```

Do not bring back heavy TTF font files unless the user explicitly asks. If italic or semibold variants are needed later, prefer WOFF2 only.

## Search State

Search is required and should remain enabled:

```toml
enableSearch = true
```

Relevant files:

```text
layouts/_default/baseof.html
themes/blowfish/layouts/partials/head.html
themes/blowfish/assets/js/search.js
themes/blowfish/assets/lib/fuse/fuse.min.js
content/search.md
static/js/search.js
```

Important behavior:

1. The local `layouts/_default/baseof.html` includes Blowfish's search partial when `enableSearch` is true.
2. Blowfish appends Fuse and its search JS from the theme head when search is enabled.
3. This adds some JS weight, but the user explicitly wants search back.
4. Do not "optimize" by turning search off again.

If performance work continues, optimize around search instead of removing it. Prefer CSS flattening, lazy-loading other features, and avoiding extra scripts on pages that do not need them.

## Image Zoom State

The image zoom feature is required and should remain.

Current design:

1. `disableImageZoom = true` disables Blowfish's default eager zoom include.
2. Local `layouts/partials/extend-footer.html` lazy-loads Medium Zoom only when real article images exist.
3. The zoom target selector is intentionally narrow:

```js
"main article .article-content img:not(.nozoom), main article .prose figure img:not(.nozoom)"
```

This means:

1. Article/writeup content images can zoom.
2. Images marked `.nozoom` do not zoom.
3. Home hero imagery does not load Medium Zoom.
4. Writeups index/list pages without article images should not load Medium Zoom.

Current custom zoom features:

1. Click article image to open focused zoom.
2. After image is focused, click the opened image to toggle between `1x` and `2x`.
3. Mouse wheel while focused zooms in/out in `0.18` steps.
4. Keyboard controls while focused:
   - `+` or `=` zooms in by `0.25`
   - `-` or `_` zooms out by `0.25`
   - `0` resets to `1x`
5. Touch pinch works on mobile.
6. Drag/pan is enabled only when scale is greater than `1.01`.
7. Escape key still closes through Medium Zoom's built-in listener.
8. A close button is added when zoom opens and removed when zoom closes.

Current close button requirements from the user:

1. Top right, not top left.
2. Standalone button only.
3. No border around it.
4. Transparent background.

Current relevant CSS:

```css
.medium-zoom-close-button {
  position: fixed;
  top: max(0.85rem, env(safe-area-inset-top));
  right: max(0.85rem, env(safe-area-inset-right));
  z-index: 902;
  display: inline-flex;
  width: 2.4rem;
  height: 2.4rem;
  align-items: center;
  justify-content: center;
  border: 0;
  border-radius: 0;
  color: #cdd6f4;
  background: transparent;
  box-shadow: none;
  font-size: 1.9rem;
  font-weight: 700;
  line-height: 1;
  cursor: pointer;
  text-shadow: 0 1px 3px rgba(0, 0, 0, 0.55);
}
```

Potential future improvements:

1. The close button text is currently `"x"` for ASCII compatibility. It could become a proper icon later if a local icon system is already loaded, but do not add a large icon dependency just for this.
2. The panning code does not clamp pan bounds. That is acceptable for now, but if the user complains that images can be dragged too far away, add bounds based on viewport and scaled image size.
3. If a future bug appears with high-resolution `srcset` images, remember Medium Zoom may create a separate HD clone. The current helper uses `.medium-zoom-image--opened`; test with actual writeup screenshots before changing the selector.

## TOC State

Relevant files:

```text
layouts/partials/toc.html
assets/css/custom.css
```

Current structure in `layouts/partials/toc.html`:

1. Desktop TOC:

```html
<details open id="TOCView" class="toc-right ... hidden lg:block">
```

2. Mobile TOC:

```html
<details class="toc-inside ... lg:hidden">
```

Both summaries display:

```go-html-template
{{ i18n "article.table_of_contents" }}
```

Current user requirements already handled:

1. Fix TOC text color.
2. Curve the title box inside the TOC.
3. Remove the TOC background so it sits directly on the post background.
4. Re-pad the mobile "Table of Contents" row.
5. Shift the mobile "Table of Contents" row left so it appears centered.

Current TOC color behavior:

```css
.toc #TableOfContents a {
  color: var(--snow-muted) !important;
  opacity: 1 !important;
}

.toc #TableOfContents a:hover,
.toc #TableOfContents a:focus-visible,
.toc li.toc-active-item > a,
.toc a.toc-active {
  color: var(--snow-ink) !important;
  background: var(--snow-faint) !important;
  box-shadow: inset 0 0 0 1px var(--blog-panel-border) !important;
}
```

Current TOC summary box behavior:

```css
.toc-right > summary,
.toc-inside > summary,
.toc-writeups > summary {
  margin: 0.15rem 0.05rem 0.55rem !important;
  padding: 0.58rem 0.78rem !important;
  border: 1px solid var(--blog-panel-border) !important;
  border-radius: 8px !important;
  color: var(--snow-ink) !important;
}
```

The background is intentionally removed later by a stronger override:

```css
.toc-right > summary,
.toc-inside > summary,
.toc-writeups > summary,
html.dark .toc-right > summary,
html.dark .toc-inside > summary,
html.dark .toc-writeups > summary {
  background: transparent !important;
  box-shadow: none !important;
}
```

Current mobile centering fix:

```css
@media (max-width: 768px) {
  .toc-inside > summary,
  .toc-inside.toc-writeups > summary,
  body.section-writeups .toc-inside.toc-writeups > summary {
    padding: 0.72rem 1rem !important;
    padding-inline-start: 1rem !important;
    padding-inline-end: 1rem !important;
    transform: translateX(-0.45rem);
  }
}
```

Measured result for 390px mobile viewport:

```json
{
  "viewport": 390,
  "summary": {
    "x": 32.00312423706055,
    "w": 326,
    "right": 31.996875762939453,
    "center": 195.00312423706055,
    "delta": 0.003124237060546875,
    "padding": "11.52px 16px",
    "transform": "matrix(1, 0, 0, 1, -7.2, 0)"
  }
}
```

This is effectively centered. Do not remove the `translateX(-0.45rem)` unless the surrounding layout changes.

Current desktop TOC behavior:

1. On desktop (`min-width: 1024px`), the article TOC is removed from the article flex flow and becomes viewport-fixed.
2. It stays visible while scrolling so the user can jump between headings anywhere in the post.
3. The post content/header/footer column is centered on the overall page.
4. The TOC is fixed inside the right-side page gap, matching the left-side gap created by the centered post column.
5. The TOC was moved farther right and shifted upward.

Relevant CSS:

```css
@media (min-width: 1024px) {
  body.page-interior article {
    --post-toc-target-width: clamp(11.5rem, 16vw, 17.5rem);
    --post-content-width: min(92ch, calc(100vw - var(--post-toc-target-width) - var(--post-toc-target-width) - 1.25rem));
    --post-side-gap: calc((100vw - var(--post-content-width)) / 2);
    --post-toc-width: min(var(--post-toc-target-width), calc(var(--post-side-gap) - 1rem));
    --post-toc-right: max(0.75rem, calc((var(--post-side-gap) - var(--post-toc-width)) / 2));
  }

  body.page-interior article .toc {
    position: fixed !important;
    top: 5.25rem !important;
    right: var(--post-toc-right) !important;
    width: var(--post-toc-width) !important;
  }
}
```

Rendered verification on `/writeups/codegate2026/oldschool/writeup/`:

```json
[
  {
    "width": 1024,
    "before": { "position": "fixed", "tocTop": 84, "tocRight": 20, "tocWidth": 178, "contentWidth": 621, "centerDelta": -4, "leftGap": 197.5, "rightGap": 205.5, "scrollY": 0 },
    "after": { "position": "fixed", "tocTop": 84, "tocRight": 20, "tocWidth": 178, "scrollY": 900 }
  },
  {
    "width": 1366,
    "before": { "position": "fixed", "tocTop": 84, "tocRight": 36.9375, "tocWidth": 216.15625, "contentWidth": 802.90625, "centerDelta": -4, "leftGap": 277.546875, "rightGap": 285.546875, "scrollY": 0 },
    "after": { "position": "fixed", "tocTop": 84, "tocRight": 36.9375, "tocWidth": 216.15625, "scrollY": 900 }
  },
  {
    "width": 1600,
    "before": { "position": "fixed", "tocTop": 84, "tocRight": 76.71875, "tocWidth": 253.59375, "contentWidth": 802.90625, "centerDelta": -4, "leftGap": 394.546875, "rightGap": 402.546875, "scrollY": 0 },
    "after": { "position": "fixed", "tocTop": 84, "tocRight": 76.71875, "tocWidth": 253.59375, "scrollY": 900 }
  }
]
```

## Comments State

Relevant file:

```text
layouts/partials/comments.html
```

Current behavior:

1. A visible `Load comments` button exists.
2. Giscus script is not loaded immediately on page load.
3. Giscus loads either when the button is clicked or when the comments section approaches the viewport via `IntersectionObserver`.
4. The observer uses:

```js
{ rootMargin: "320px 0px" }
```

5. Theme changes after load are synced into the Giscus iframe through `postMessage`.

Do not revert this to eager Giscus loading. If the user complains about comments appearing too early, reduce the `rootMargin`; if they complain comments do not appear soon enough, increase it slightly.

## KaTeX State

Relevant file:

```text
layouts/partials/extend-head-uncached.html
```

Current behavior:

1. KaTeX assets are not loaded globally.
2. On writeup pages, raw markdown is scanned for math delimiters:

```go-html-template
findRE `(\$\$|\\\(|\\\[)` .RawContent 1
```

3. Page front matter can override this with:

```toml
math = true
```

or:

```toml
math = false
```

Do not make KaTeX global again unless absolutely necessary.

## Writeups Index State

Relevant file:

```text
layouts/writeups/list.html
```

Current behavior:

1. Writeups are grouped by `contest`.
2. Groups are sorted by latest date descending.
3. Pages inside each contest are sorted by title.
4. The index uses lightweight accordion cards:

```html
<details class="writeups-contest-card">
  <summary class="writeups-contest-summary">
```

5. The list avoids the older heavy nested panel look.

If adding hover effects, include these interactive writeups elements:

```text
.writeups-contest-summary
.writeups-entry
```

Keep effects subtle. Avoid transforms that make the list feel jumpy on mobile.

## Visual / Palette Knowledge

The accepted direction is cold, quiet, snow / pale-blue, and not green.

Useful current palette anchors in `assets/css/custom.css`:

```css
--site-bg-navy: #11111b;
--blog-accent-frost: #b0c4ef;
--blog-accent-ice: #d7e9f4;
```

The user disliked green and Nord-like tones. Avoid introducing:

```text
green
teal
cyan-green
Nord-style blue gray
large purple gradients
beige / tan / espresso palettes
```

Preferred feel:

```text
quiet
premium
cold
snowy
pale blue
high readability
low visual noise
```

## Performance Findings

The lag complaints were about obvious slow feeling on PC and mobile. The working strategy is:

1. Keep required features.
2. Make optional features lazy or disabled.
3. Flatten expensive CSS effects.
4. Avoid always-on blur and big animation surfaces.
5. Keep page interactions cheap on mobile.

Current performance-sensitive decisions:

1. Victor Mono uses WOFF2 only.
2. Search stays on because the user requires it.
3. Medium Zoom is lazy loaded only if article content images exist.
4. Giscus is lazy loaded.
5. KaTeX is gated by content/front matter.
6. Blowfish image optimization remains enabled.
7. Built-in Blowfish image zoom is disabled to avoid eager zoom CSS/JS.
8. Scroll-to-top is disabled.
9. Code copy is disabled.
10. Views and likes are disabled.

There is an `assets/js/scroll-progress.js` file, and `assets/css/custom.css` still contains CSS variables for a top scroll-progress bar. Current search did not find a local include for `assets/js/scroll-progress.js`, so do not assume it is actively running. If future work re-enables it, gate it carefully on mobile and writeups pages.

## Current Local Overrides To Know

Tracked local override files that matter most:

```text
assets/css/custom.css
config/_default/params.toml
layouts/_default/baseof.html
layouts/partials/comments.html
layouts/partials/extend-footer.html
layouts/partials/extend-head-uncached.html
layouts/partials/toc.html
layouts/writeups/list.html
static/fonts/VictorMono-Bold.woff2
static/fonts/VictorMono-Regular.woff2
```

Do not edit the vendored theme under `themes/blowfish/` unless there is no local override path. Prefer local files under `layouts/`, `assets/`, `static/`, and `config/_default/`.

## Completed Hover / Pressable Effects

The user asked:

```text
add hover effect to all buttons or things that can be press or button that is functional
```

This was implemented in `assets/css/custom.css` as a final CSS-only desktop interaction layer after the older performance overrides. It is intentionally limited to `@media (min-width: 1024px) and (hover: hover) and (pointer: fine)` so mobile does not get the hover/press polish.

Covered selectors include:

```css
button,
[role="button"],
label[for],
details > summary,
.bf-icon-color-hover,
a.landing-button,
.home-hero__links a,
.landing-actions a,
.home-recent-more a,
.home-recent-card,
.writeups-contest-summary,
.writeups-entry,
.article-link--card,
.article-link--related,
.article-link--simple.border,
.article-link--shortcode.border,
.term-link--card,
.github-card-wrapper > div,
.codeberg-card-wrapper > div,
.gitea-card-wrapper > div,
#search-results a,
.comments-loader,
.medium-zoom-close-button,
.toc #TableOfContents a
```

Implemented effect style:

1. Subtle color lift.
2. Border-color lift where a border already exists.
3. Subtle hover backgrounds for buttons, summaries, search results, TOC links, and cards.
4. Small `translateY(-1px)` only inside `@media (min-width: 1024px) and (hover: hover) and (pointer: fine)`.
5. Small active press scale for functional controls.
6. `:focus-visible` mirrors hover so keyboard users see the same affordance.
7. `prefers-reduced-motion: reduce` disables transitions and hover transforms.
8. The TOC title summary gets color/background/border hover only. It does not get hover movement because mobile centering depends on `transform: translateX(-0.45rem)`.
9. The image-zoom close button keeps the user's requirement: standalone, top-right, no border, transparent background. Its hover effect is color plus drop-shadow/scale only.

## Verification Commands

Use these commands from repo root:

```bash
git status --short
hugo --gc --cleanDestinationDir --cacheDir /tmp/hugo_cache_my_blog
```

If the preview server is not running:

```bash
hugo server --bind 127.0.0.1 --port 1314 --disableFastRender --cacheDir /tmp/hugo_cache_my_blog
```

If port `1314` is occupied, pick another port such as `1315`.

For mobile TOC layout checks, use a 390px viewport and verify:

1. The mobile TOC summary does not overflow.
2. The left and right visual spacing is balanced.
3. The title remains readable in dark mode.
4. Expanding/collapsing does not shift surrounding content strangely.

For image zoom checks, use a real writeup with screenshots, not the homepage:

1. Click image to open.
2. Click focused image to toggle `2x` / `1x`.
3. Use wheel to zoom.
4. Drag while zoomed.
5. Use `+`, `-`, and `0`.
6. Use close button at top right.
7. Press Escape.
8. Test touch/pinch if possible on mobile emulation.

## Known Safe Boundaries

Safe to change next:

```text
assets/css/custom.css
layouts/partials/extend-footer.html
layouts/partials/toc.html
layouts/partials/comments.html
layouts/writeups/list.html
```

Avoid unless requested:

```text
themes/blowfish/**
static/css/**
old removed font formats
turning off search
turning off image zoom
turning off Victor Mono
```

The `static/css/*` files appear to be legacy/static assets. The active Blowfish path uses Hugo assets and `assets/css/custom.css`, so prefer `assets/css/custom.css` for current styling unless you verify a static page is using the old static CSS.

## Short Continuation Plan

If the next session adjusts hover effects:

1. Open `assets/css/custom.css`.
2. Search for existing hover blocks around:

```bash
rg -n "hover|focus-visible|landing-button|writeups-entry|toc|comments-loader|medium-zoom-close-button" assets/css/custom.css
```

3. Prefer editing the final "Lightweight interaction polish" block near the end of the file.
4. Keep mobile touch behavior stable; do not rely on hover-only affordances.
5. Preserve reduced-motion support.
6. Run Hugo build.
7. Verify desktop and mobile screenshots if possible.

## One-Line Current State

The blog currently has the required font, search, lazy image zoom with focused zoom-in/out controls, lazy comments, gated KaTeX, transparent/centered mobile TOC styling, and a final CSS-only hover/focus polish layer for pressable elements.
