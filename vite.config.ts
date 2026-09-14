import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "node:path";
import site from "./config/site.json" with { type: "json" };

// Canonical/OG URLs come from config/site.json only, so a custom-domain cutover
// is one change to that file plus a deploy.
function siteMeta(): Plugin {
  const values: Record<string, string> = {
    SITE_ORIGIN: site.origin,
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
  };
}

export default defineConfig({
  root: resolve(import.meta.dirname, "web"),
  publicDir: resolve(import.meta.dirname, "web/public"),
  plugins: [react(), siteMeta()],
  build: {
    outDir: resolve(import.meta.dirname, "dist/web"),
    emptyOutDir: true,
    sourcemap: false,
    assetsDir: "assets",
    rollupOptions: {
      input: {
        marketing: resolve(import.meta.dirname, "web/index.html"),
        console: resolve(import.meta.dirname, "web/app/index.html"),
      },
    },
  },
});
