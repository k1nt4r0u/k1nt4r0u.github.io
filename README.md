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

## Content Structure

- `content/posts/` - Blog posts and CTF writeups
- `content/sidebar/` - Sidebar bio and info
- `content/welcome-header/` - Main page header
- `static/` - Images and static files

## Adding Content

### New Blog Post
```bash
hugo new content/posts/my-post.md
```

### New CTF Writeup
Use the template at `content/posts/ctf-template.md`

## Deployment

This blog is deployed to GitHub Pages. Push to `main` branch to deploy.

## License

Content: All rights reserved  
Theme: GPL-3.0 (neopost)
