# NMAP2Flowchart – static (GitHub Pages) edition

The whole NMAP2Flowchart editor, compiled to plain static files and published with GitHub
Pages: **https://nmap2flowchart.4n6post.com/**

Drop in `nmap -oX` XML and get a zoomable, grid-backed diagram of subnets, hosts, open ports and
traceroute hops. Reshape it with layers, sections, notes, icons and hand-drawn connections, then
export to **draw.io**, **Mermaid**, or print-ready **SVG / PNG / PDF**.

Everything happens in the browser – the scan and the diagram never leave the machine. That also
means this build has **no accounts, no saved projects and no shared rooms**: those belong to the
[server build](../App/server), and the app itself is written to work without any backend.

## Where the code comes from

`src/` is a **generated copy** of the app in the main repository
([Jonesckevin/NMAP2Flowchart → `App/src`](https://github.com/Jonesckevin/NMAP2Flowchart/tree/main/App/src),
expected in a sibling checkout at `../App`). Edit the app there (or a file in [overlay/](./overlay)),
then re-sync:

```bash
npm run sync        # rewrite src/ and the shared public/ assets
npm run sync:check  # exit 1 when the copy has drifted (handy before committing)
```

[scripts/sync-from-app.mjs](./scripts/sync-from-app.mjs) copies `../App/src` and `../App/public`,
drops in [overlay/](./overlay), and applies the one text patch the static site needs (the topbar
brand becomes the page's `<h1>`). It fails loudly when upstream markup changes so that the patch
never silently stops applying. Use `--app <dir>` if the app lives somewhere else.

| Path | What it is |
| --- | --- |
| [src/](./src) | Generated copy of `App/src` – do not edit by hand |
| [overlay/](./overlay) | Files that replace their `src/` twin |
| [public/](./public) | `favicon.svg`, app icons, `robots.txt`, `sitemap.xml`, `og-image.png`, `config.js` |
| [index.html](./index.html) | The SEO surface: title, description, canonical, Open Graph, Twitter card, JSON-LD |
| [vite.config.ts](./vite.config.ts) | `base: './'`, so one build works at `/n2f/`, at a custom domain or from disk |

What the overlay changes:

- `src/account/api.ts` – the accounts API client replaced by a stand-in that reports "accounts
  disabled" instead of probing `/api/config`. No request, no sign-in chip.
- `src/shared/useShared.ts` – the shared-room hook replaced by a no-op, so no `/api/shared` probe.
- `src/main.tsx`, `src/analytics.ts`, `src/seo.css` – analytics bootstrap, `<h1>` styling.

Everything else – parsing, layout, editing, layers, risk levels and every exporter – is the app's
own code.

## Local development

```bash
npm ci
npm run dev      # http://localhost:5173
npm run lint     # oxlint
npm run build    # tsc -b && vite build -> dist/
npm run preview  # serve dist/ the way Pages will
```

## Google Analytics

Open [public/config.js](./public/config.js) and paste the GA4 measurement ID:

```js
window.N2F_GA_ID = 'G-XXXXXXXXXX';
```

Empty (the default) means no analytics script is loaded at all – no request, no cookie. Once an ID
is set, `gtag.js` is injected and a single page view is sent; there is no other tracking in the app.

## SEO checklist

The site is a single page, so all of it lives in [index.html](./index.html):

- `<title>`, `<meta name="description">`, `<link rel="canonical">`, Open Graph and Twitter tags.
- `WebApplication` JSON-LD with the feature list and the screenshot.
- [public/robots.txt](./public/robots.txt) and [public/sitemap.xml](./public/sitemap.xml).
- `og-image.png` (1200×630) and `apple-touch-icon.png` in [public/](./public).
- A crawlable introduction inside `#root`, replaced by the editor as soon as React mounts, plus a
  `<noscript>` note.

**If the site moves to its own domain**, update the same URL in four places: `canonical`,
`og:url`, the `og:image`/`twitter:image` URLs and the JSON-LD block in [index.html](./index.html),
the `Sitemap:` line in [public/robots.txt](./public/robots.txt), and `<loc>` in
[public/sitemap.xml](./public/sitemap.xml). A root domain also wants a `CNAME` file in
[public/](./public).

## Deploying

Pages is fed by [.github/workflows/deploy.yml](./.github/workflows/deploy.yml): on every push to
`main` it installs, lints, builds and publishes `dist/`. In the repository settings choose
**Settings → Pages → Build and deployment → Source: GitHub Actions** once. No other configuration
is needed; `base: './'` keeps the paths correct under `/n2f/`.

## License

MIT – see [LICENSE](./LICENSE).
