# k1nt4r0u's Blog

Personal blog focused on reverse engineering, binary exploitation, and CTF writeups.

## About

- **Author:** k1nt4r0u
- **Theme:** [neopost](https://github.com/salatine/neopost)
- **Built with:** Hugo

## Local Development

```bash
# Install Hugo (extended version)
# https://gohugo.io/installation/

# Clone the repository
git clone --recursive [your-repo-url]
cd my-blog

# Run local server
hugo server -D

# Build site
hugo
```

## Project Structure

- `content/` - Writeups and section content
- `layouts/` - Site-specific Hugo layout overrides
- `static/css/` - Extracted site stylesheet
- `static/js/` - Client-side behavior for theme switching, search, math rendering, and UI helpers
- `static/images/` - Post images and other assets
- `themes/neopost/` - Upstream theme source kept separate from site overrides

## Adding Content

### New Post
```bash
hugo new writeups/my-post.md
```

### New CTF Writeup
```bash
hugo new writeups/my-new-writeup.md
```

## Deployment

This blog is deployed to GitHub Pages. Push to `main` branch to deploy.

## License

Content: All rights reserved  
Theme: GPL-3.0 (neopost)
