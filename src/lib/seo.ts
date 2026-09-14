// robots.txt and sitemap.xml are generated from config/site.json so a custom-domain
// cutover is a single config change.

import site from "../../config/site.json";

export function robotsTxt(): Response {
  const body = `User-agent: *\nAllow: /\nDisallow: /app/\nDisallow: /api/\nDisallow: /v1/\nDisallow: /verify/\n\nSitemap: ${site.origin}/sitemap.xml\n`;
  return new Response(body, { headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "public, max-age=3600" } });
}

export function sitemapXml(): Response {
  const body = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n  <url><loc>${site.origin}/</loc><changefreq>weekly</changefreq><priority>1.0</priority></url>\n</urlset>\n`;
  return new Response(body, { headers: { "Content-Type": "application/xml; charset=utf-8", "Cache-Control": "public, max-age=3600" } });
}
