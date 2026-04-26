# Blog Performance Restore Handoff - 2026-04-26

Repository:

```text
/home/kintarou/dung_hoc/dung_hoang_blog/my-blog
```

This note records the current state after the user asked to keep the blog fast but restore the necessary features:

```text
give me back my font, search, image zoom, those are necessary but still make it fast
```

The important direction is no longer "remove everything heavy." The correct target is:

1. Keep Victor Mono.
2. Keep site search.
3. Keep image zoom.
4. Keep the page fast by loading those features in the cheapest practical way.

## High-Level State

The blog is now in a balanced performance state:

1. Victor Mono is restored, but only as compressed WOFF2 files.
2. Search is enabled again.
3. Blowfish's default eager image zoom is disabled.
4. A custom lazy image zoom loader exists in `layouts/partials/extend-footer.html`.
5. The custom zoom loader only targets real article content images:

```js
"main article .article-content img:not(.nozoom), main article .prose figure img:not(.nozoom)"
```

That means:

1. Home page decorative imagery should not load Medium Zoom.
2. The writeups listing page should not load Medium Zoom.
3. Actual image-heavy articles should load Medium Zoom and its CSS.

## Files Currently Touched

Current `git status --short` at the time of this handoff:

```text
 M BLOG_RICE_CONTINUATION_2026-04-26.md
 M assets/css/custom.css
 M config/_default/params.toml
 M layouts/_default/baseof.html
 M layouts/partials/extend-footer.html
 M static/css/base.css
 M static/css/content.css
 M static/css/navigation.css
 D static/fonts/JetBrainsMonoNerdFont-Regular.ttf
 D static/fonts/VictorMono-Bold.ttf
 D static/fonts/VictorMono-BoldItalic.ttf
 D static/fonts/VictorMono-BoldItalic.woff2
 D static/fonts/VictorMono-Italic.ttf
 D static/fonts/VictorMono-Italic.woff2
 D static/fonts/VictorMono-Regular.ttf
 D static/fonts/VictorMono-SemiBold.ttf
 D static/fonts/VictorMono-SemiBold.woff2
 D static/fonts/VictorMono-SemiBoldItalic.ttf
 D static/fonts/VictorMono-SemiBoldItalic.woff2
 D static/mybackground.jpg
```

Important: this handoff file itself is newly added and will also appear in `git status` after creation.

## Current Feature Configuration

Current important values in `config/_default/params.toml`:

```toml
colorScheme = "kintarou"
defaultAppearance = "dark"
autoSwitchAppearance = false
enableA11y = false
enableSearch = true
enableCodeCopy = false
defaultSocialImage = ""
disableImageZoom = true
showViews = false
showLikes = false

[footer]
showScrollToTop = false

[article]
showLikes = false
showComments = true
showTableOfContents = true

[list]
showViews = false
showLikes = false

[taxonomy]
showViews = false
showLikes = false

[term]
showViews = false
showLikes = false
```

Meaning:

1. Search is intentionally back on.
2. Blowfish's built-in image zoom is intentionally off.
3. The custom lazy zoom script is responsible for zoom.
4. Views/likes/scroll-to-top/code-copy/a11y remain off to keep runtime weight down.
5. Comments are still enabled, but they are lazy loaded by the existing comments partial.

## Font State

Only these font files are currently present:

```text
70300 static/fonts/VictorMono-Bold.woff2
67424 static/fonts/VictorMono-Regular.woff2
```

The heavy or less necessary font files are deleted from the working tree:

```text
static/fonts/JetBrainsMonoNerdFont-Regular.ttf
static/fonts/VictorMono-Bold.ttf
static/fonts/VictorMono-BoldItalic.ttf
static/fonts/VictorMono-BoldItalic.woff2
static/fonts/VictorMono-Italic.ttf
static/fonts/VictorMono-Italic.woff2
static/fonts/VictorMono-Regular.ttf
static/fonts/VictorMono-SemiBold.ttf
static/fonts/VictorMono-SemiBold.woff2
static/fonts/VictorMono-SemiBoldItalic.ttf
static/fonts/VictorMono-SemiBoldItalic.woff2
```

Current `assets/css/custom.css` has the restored WOFF2 declarations:

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
```

The whole site is forced back to Victor Mono with:

```css
body,
button,
input,
textarea,
select {
  font-family: 'Victor Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace !important;
}
```

The old static CSS files were also adjusted away from removed JetBrains assets:

```text
static/css/base.css
static/css/content.css
static/css/navigation.css
```

Do not restore the old JetBrains TTF unless the user explicitly asks for it. If more Victor Mono styles are needed later, restore WOFF2 only first. Avoid bringing back TTF variants unless there is a real reason.

## Search State

Search is back on through:

```toml
enableSearch = true
```

Blowfish includes Fuse and `themes/blowfish/assets/js/search.js` in the main JS bundle when search is enabled.

Current observed JS bundle size after search restore:

```text
about 33 KB script payload on the light home/writeups paths
```

The search modal and buttons are present in generated HTML:

```text
#search-button
#search-button-mobile
#search-wrapper
#search-query
#search-results
```

The search overlay blur was flattened in `assets/css/custom.css`:

```css
#search-wrapper {
  backdrop-filter: none !important;
  -webkit-backdrop-filter: none !important;
}
```

### Search Verification Caveat

There were two different browser checks:

1. A browser check against `http://localhost:1314/` did show Fuse as an object and returned one `Cobweb` result.
2. The final interrupted automated check hit a race and called `executeQuery("Cobweb")` while `fuse` was still undefined.

The final error was:

```text
TypeError: Cannot read properties of undefined (reading 'search')
```

This is a real edge case in the theme search flow: if a query is executed before the async index build finishes, `executeQuery()` can touch `fuse.search()` too early.

Recommended next coding step for search:

1. Create a local override at `assets/js/search.js`.
2. Start from `themes/blowfish/assets/js/search.js`.
3. Patch it so `executeQuery()` returns early or stores a pending query until `indexed === true` and `fuse` exists.
4. Optionally disable the search input until `index.json` has loaded.
5. Rebuild and retest with a real browser by opening search, immediately typing `Cobweb`, and waiting for results.

Because Hugo uses `resources.Get "js/search.js"`, a local `assets/js/search.js` should override the theme asset cleanly.

## Image Zoom State

The current strategy is intentionally not the default Blowfish zoom path.

In `config/_default/params.toml`:

```toml
disableImageZoom = true
```

This prevents Blowfish from loading zoom JS in the page head and running it globally from the theme footer.

The local custom lazy loader is in:

```text
layouts/partials/extend-footer.html
```

Current logic:

```go-html-template
{{ $alg := .Site.Params.fingerprintAlgorithm | default "sha512" }}
{{ $zoomCSS := resources.Get "lib/zoom/style.css" | resources.Fingerprint $alg }}
{{ $zoomJS := resources.Get "lib/zoom/zoom.min.umd.js" | resources.Fingerprint $alg }}
<script>
  (() => {
    const targets = document.querySelectorAll(
      "main article .article-content img:not(.nozoom), main article .prose figure img:not(.nozoom)"
    );
    if (!targets.length) {
      return;
    }

    const css = document.createElement("link");
    css.rel = "stylesheet";
    css.href = "{{ $zoomCSS.RelPermalink }}";
    css.integrity = "{{ $zoomCSS.Data.Integrity }}";
    css.crossOrigin = "anonymous";
    document.head.appendChild(css);

    const script = document.createElement("script");
    script.src = "{{ $zoomJS.RelPermalink }}";
    script.integrity = "{{ $zoomJS.Data.Integrity }}";
    script.crossOrigin = "anonymous";
    script.onload = () => {
      window.mediumZoom?.(targets, {
        margin: 24,
        background: "rgba(0,0,0,0.5)",
        scrollOffset: 0,
      });
    };
    document.head.appendChild(script);
  })();
</script>
```

Important details:

1. `extend-footer.html` is called through the Blowfish footer with `partialCached`.
2. The JS itself is page-agnostic and queries the current DOM at runtime, so caching is okay here.
3. Do not make the Hugo template depend on `.Page` or page-specific state inside this cached partial unless you also remove/replace the cached theme call.
4. If zoom seems missing on an article, first check generated HTML for this script, then check whether the selector matches that article's image markup.

## Performance State

The heavy-removal pass currently keeps these things off:

```text
enableA11y = false
enableCodeCopy = false
showViews = false
showLikes = false
footer.showScrollToTop = false
defaultSocialImage = ""
```

`layouts/_default/baseof.html` was changed from:

```html
class="scroll-smooth"
```

to:

```html
class=""
```

This avoids global smooth scrolling.

`assets/css/custom.css` has a "Performance mode" section that removes paint-heavy decoration:

1. hides decorative pseudo-elements,
2. removes several shadows,
3. disables transitions/transforms on cards and links,
4. removes broad background patterns,
5. keeps the cold snow/blue palette.

The old `static/mybackground.jpg` is deleted from the working tree. Keep it deleted unless the user explicitly wants it back.

## Browser Metrics From Latest Checks

These numbers are from headless Chromium against `http://localhost:1314/` after restoring Victor Mono and restricting zoom.

### Home Page

URL:

```text
http://localhost:1314/
```

Observed:

```json
{
  "path": "/",
  "bodyFont": "\"victor mono\", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
  "searchButton": true,
  "searchModal": true,
  "contentImages": 0,
  "zoomLoaded": false,
  "zoomScripts": [],
  "zoomLinks": [],
  "totals": {
    "count": 7,
    "bytes": 341539,
    "byType": {
      "link": 161777,
      "script": 33288,
      "img": 8750,
      "css": 137724
    }
  }
}
```

Interpretation:

1. Font is back.
2. Search UI is present.
3. Zoom does not load on the home page.
4. The home page still loads the two Victor Mono WOFF2 files.

### Writeups Listing Page

URL:

```text
http://localhost:1314/writeups/
```

Observed:

```json
{
  "path": "/writeups/",
  "bodyFont": "\"victor mono\", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
  "searchButton": true,
  "searchModal": true,
  "contentImages": 0,
  "zoomLoaded": false,
  "zoomScripts": [],
  "zoomLinks": [],
  "totals": {
    "count": 6,
    "bytes": 332789,
    "byType": {
      "link": 161777,
      "script": 33288,
      "css": 137724
    }
  }
}
```

Interpretation:

1. Font is back.
2. Search UI is present.
3. Zoom does not load on the writeups index.
4. This is the important mobile-lag path; keep it lean.

### Image-Heavy Article

URL:

```text
http://localhost:1314/writeups/cscv2025/cscv_2025_re/
```

Observed:

```json
{
  "path": "/writeups/cscv2025/cscv_2025_re/",
  "bodyFont": "\"victor mono\", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
  "searchButton": true,
  "searchModal": true,
  "contentImages": 10,
  "zoomLoaded": true,
  "zoomScripts": [
    "http://localhost:1314/lib/zoom/zoom.min.umd.a527109b68c082a70f3697716dd72a9d5aa8b545cf800cecbbc7399f2ca6f6e0ce3e431f2062b48bbfa47c9ea42822714060bef309be073f49b9c0e30d318d7b.js"
  ],
  "zoomLinks": [
    "http://localhost:1314/lib/zoom/style.f9a72b47bc4fa9af793cb3460f24f18e14f340d35d7f0c90de97708fc55237baeff9314ce9011515e687817c471dfa9ac6c6d9a365442cac8747e085de52ac7e.css"
  ],
  "totals": {
    "count": 11,
    "bytes": 488735,
    "byType": {
      "link": 162230,
      "script": 42116,
      "css": 137724,
      "img": 146665
    }
  }
}
```

Interpretation:

1. Zoom is restored where it matters.
2. The article has 10 content images.
3. Zoom JS/CSS are only present on this image-heavy article path.

## Build Status

Last successful build command:

```bash
hugo --gc --cleanDestinationDir --cacheDir /tmp/hugo_cache_my_blog
```

Last observed result:

```text
Pages            51
Paginator pages   2
Non-page files    2
Static files     40
Processed images  2
Aliases           9
Total in        282 ms
```

Known warnings:

```text
WARN  Skip unknown config key "params.author"
WARN  Module "blowfish" is not compatible with this Hugo version: 0.141.0/0.157.0 extended; run "hugo mod graph" for more information.
WARN  deprecated: .Site.Data was deprecated in Hugo v0.156.0 and will be removed in a future release. Use hugo.Data instead.
```

These warnings existed during the earlier work too and did not block the current pass.

## Preview Command

Use this command for local preview:

```bash
hugo server -D --disableFastRender --bind 127.0.0.1 --port 1314 --cacheDir /tmp/hugo_cache_my_blog
```

Use this URL in the browser and in automated checks:

```text
http://localhost:1314/
```

Important: search tests should use `localhost`, not `127.0.0.1`, because Hugo may emit `data-url="http://localhost:1314/"` in the search wrapper. Testing a page loaded from `127.0.0.1` can make the search index request look cross-origin.

## Public Output Size Hotspots

Largest generated files after the current pass:

```text
438936 public/images/CSCV/CSCV_7.png
402218 public/images/WGC2025/WGC2025_4.png
273392 public/js/katex.bundle.9c6e888a180e98e837aff804d18abf2bd8cde4659fd50f3f2660f35d92470ddb4314e9f7ca5325a36b14bb535481c83f6cc7224793e1be163730c169b6bf22e1.js
178208 public/images/WGC2025/WGC2025_3.png
165873 public/images/CSCV/CSCV_8.png
161514 public/css/main.bundle.min.b1ebbfd252944baa8bf93cc5ee66be0cb181256651a6842498c16720ac96baa0f2e58424aa19c4d109ad8fa6d9feec873af001d82d6ed07f23e8098ef80589b8.css
90802 public/index.json
85404 public/images/CSCV/CSCV_5.png
84328 public/android-chrome-512x512.png
82377 public/images/CSCV/CSCV_10.png
73970 public/images/CSCV/CSCV_1.png
70300 public/fonts/VictorMono-Bold.woff2
67424 public/fonts/VictorMono-Regular.woff2
66084 public/images/totoro.png
```

Next meaningful size work:

1. Compress/resize large static PNG writeup images.
2. Investigate why `katex.bundle` is generated even if only a small number of pages need math.
3. Reduce or split `assets/css/custom.css`, which contributes to the 161 KB CSS bundle.
4. Consider shortening search index content if `public/index.json` becomes a bigger issue.

## Important Repo Knowledge

Memory from prior work says these are stable project conventions:

1. `assets/css/custom.css` is the central place for site-specific visual overrides.
2. `layouts/writeups/list.html` owns contest-grouped writeups UI.
3. `layouts/partials/extend-footer.html` is the practical hook for page-wide JS.
4. `body.section-writeups` is the durable CSS/JS gate for writeups-specific behavior.
5. `hugo --gc --cacheDir /tmp/hugo_cache_my_blog` avoids cache path issues in this environment.
6. For writeups-page mobile lag, preserve behavior but remove always-on effects, custom accordion animation, broad progress scripts, and unnecessary blur.

## Do Not Accidentally Regress These

Do not:

1. Set `enableSearch = false`.
2. Remove Victor Mono again.
3. Restore all old font files just to get Victor Mono back.
4. Set `disableImageZoom = false` unless you accept Blowfish's default eager zoom loading.
5. Reintroduce the old global scroll progress script.
6. Reintroduce `scroll-smooth` globally in `baseof.html`.
7. Re-add broad `backdrop-filter` or heavy blur on the search wrapper, TOC, writeups cards, or home cards.
8. Bring back `static/mybackground.jpg` unless explicitly requested.
9. Treat the old `BLOG_RICE_CONTINUATION_2026-04-26.md` as fully current without checking this file first.

## Recommended Next Coding Steps

1. Fix the search race.
   - Create `assets/js/search.js` as a local override.
   - Copy from `themes/blowfish/assets/js/search.js`.
   - Make `executeQuery()` safe when `fuse` is not ready.
   - Retest immediate typing after opening search.

2. Re-run browser verification.
   - Use `http://localhost:1314/`, not `127.0.0.1`.
   - Confirm font on home, writeups, and article.
   - Confirm search returns `Cobweb`.
   - Confirm zoom does not load on `/` or `/writeups/`.
   - Confirm zoom does load on `/writeups/cscv2025/cscv_2025_re/`.

3. Reduce CSS weight.
   - `assets/css/custom.css` has accumulated multiple generations of styling.
   - There are duplicate search/card/writeups blocks.
   - Clean this carefully and test visual output after each chunk.

4. Optimize images.
   - The biggest cold-load wins are static PNGs in `static/images/CSCV` and `static/images/WGC2025`.
   - Prefer Hugo image processing or precompressed WebP/AVIF variants.
   - Do not degrade writeup screenshots so much that reversing details become unreadable.

5. Decide whether KaTeX bundle generation is acceptable.
   - `public/js/katex.bundle...js` is about 273 KB.
   - Earlier work already gated KaTeX through `layouts/partials/extend-head-uncached.html`.
   - If it is still being generated for pages that do not need it, inspect pages with math markers or shortcode usage.

6. Update or retire `BLOG_RICE_CONTINUATION_2026-04-26.md`.
   - It still contains older state from before search/font/zoom were restored.
   - This file is the more current handoff for the latest requirement.

## Quick Commands For The Next Session

Check current worktree:

```bash
git status --short
```

Build:

```bash
hugo --gc --cleanDestinationDir --cacheDir /tmp/hugo_cache_my_blog
```

Preview:

```bash
hugo server -D --disableFastRender --bind 127.0.0.1 --port 1314 --cacheDir /tmp/hugo_cache_my_blog
```

Find the important toggles:

```bash
rg -n "enableSearch|disableImageZoom|enableA11y|enableCodeCopy|showViews|showLikes|showScrollToTop|defaultSocialImage" config/_default/params.toml
```

Check zoom loader:

```bash
sed -n '1,120p' layouts/partials/extend-footer.html
```

Check fonts:

```bash
find static/fonts -maxdepth 1 -type f -printf '%s %p\n' | sort -nr
```

Check large generated files:

```bash
find public -type f -printf '%s %p\n' | sort -nr | sed -n '1,25p'
```

## Current Best Summary

The page is no longer in the stripped emergency mode. It now keeps the user's required features:

1. font restored,
2. search restored,
3. image zoom restored,

while avoiding the worst bloat:

1. only two WOFF2 font files,
2. no old TTF font pile,
3. no eager global zoom,
4. no zoom on home/writeups index,
5. no global smooth scrolling,
6. no scroll-to-top/progress/view/like/code-copy widgets,
7. no heavy search backdrop blur.

The next coding session should focus on the search async race first, then CSS cleanup and image compression.
