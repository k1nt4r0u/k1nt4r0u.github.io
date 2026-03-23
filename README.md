# k1nt4r0u's Blog

Personal blog focused on reverse engineering, binary exploitation, and CTF writeups.

## About

- **Author:** k1nt4r0u
- **Theme:** [Blowfish](https://github.com/nunocoracao/blowfish)
- **Built with:** Hugo
- **Backup of previous Neopost setup:** `backups/2026-03-23-neopost-snapshot/`

## Local Development

```bash
hugo server -D
```

## Project Structure

- `config/_default/` - Blowfish Hugo configuration files
- `content/` - Writeups and section content
- `layouts/partials/comments.html` - Custom Giscus partial used by Blowfish article pages
- `static/images/` - Post images and other assets
- `themes/blowfish/` - Blowfish theme source
- `themes/neopost/` - Previous theme retained as backup source
- `backups/2026-03-23-neopost-snapshot/` - Snapshot of the previous Neopost-based setup

## Deployment

This blog is deployed to GitHub Pages. Push to `main` to deploy.

## License

Content: All rights reserved  
Theme: MIT (Blowfish), previous Neopost backup remains GPL-3.0
