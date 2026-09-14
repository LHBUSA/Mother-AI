// This Worker serves only API traffic (api.mother.proptechusa.ai and the workers.dev
// fallback); keep it out of search indexes. The UI's robots.txt and sitemap.xml are
// generated into the Vercel build (vite.config.ts).

export function robotsTxt(): Response {
  return new Response("User-agent: *\nDisallow: /\n", { headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "public, max-age=3600" } });
}
