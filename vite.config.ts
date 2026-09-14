import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "node:path";
import site from "./config/site.json" with { type: "json" };

// Hosts come from config/site.json only. MOTHER_API_ORIGIN may override the API host for
// local development (e.g. http://localhost:8787); production builds use site.json.
const uiOrigin = site.origin;
const apiOrigin = process.env.MOTHER_API_ORIGIN || site.apiOrigin;

function siteMeta(): Plugin {
  const values: Record<string, string> = {
    SITE_ORIGIN: uiOrigin,
    SITE_API_ORIGIN: apiOrigin,
    SITE_BOOKING_URL: site.bookingUrl,
    SITE_NAME: site.name,
    SITE_TITLE: site.title,
    SITE_DESCRIPTION: site.description,
    SITE_TAGLINE: site.tagline,
  };
  return {
    name: "mother-site-meta",
    transformIndexHtml(html) {
      return html.replace(/%(SITE_[A-Z_]+)%/g, (match, key: string) => values[key] ?? match);
    },
    // robots.txt and sitemap.xml are generated from the same config so the UI host
    // (Vercel) owns them. Private console and verification pages are never listed.
    generateBundle() {
      this.emitFile({
        type: "asset",
        fileName: "robots.txt",
        source: `User-agent: *\nAllow: /\nDisallow: /app/\nDisallow: /verify/\n\nSitemap: ${uiOrigin}/sitemap.xml\n`,
      });
      this.emitFile({
        type: "asset",
        fileName: "sitemap.xml",
        source: `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n  <url><loc>${uiOrigin}/</loc><changefreq>weekly</changefreq><priority>1.0</priority></url>\n</urlset>\n`,
      });
    },
  };
}

export default defineConfig({
  root: resolve(import.meta.dirname, "web"),
  publicDir: resolve(import.meta.dirname, "web/public"),
  plugins: [react(), siteMeta()],
  define: {
    __MOTHER_UI_ORIGIN__: JSON.stringify(uiOrigin),
    __MOTHER_API_ORIGIN__: JSON.stringify(apiOrigin),
  },
  build: {
    outDir: resolve(import.meta.dirname, "dist/web"),
    emptyOutDir: true,
    sourcemap: false,
    assetsDir: "assets",
    rollupOptions: {
      input: {
        marketing: resolve(import.meta.dirname, "web/index.html"),
        console: resolve(import.meta.dirname, "web/app/index.html"),
        verify: resolve(import.meta.dirname, "web/verify/index.html"),
      },
    },
  },
});
