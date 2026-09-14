// Canonical host handling. config/site.json is the only place hostnames live.
//
// `origin` is the public canonical host: marketing, console, passkeys (WebAuthn is
// hostname-bound), invites, badge/verify URLs and SEO all use it.
// `fallbackOrigins` keep serving machine traffic — the gateway API, badge SVGs,
// health — so existing integrations and embeds do not break, while human-facing
// pages redirect to the canonical host.

import site from "../../config/site.json";

export const CANONICAL_ORIGIN: string = site.origin;
const FALLBACK_ORIGINS = new Set<string>(site.fallbackOrigins ?? []);

export function isFallbackOrigin(url: URL): boolean {
  return FALLBACK_ORIGINS.has(url.origin);
}

/** Human-facing paths that must be served from the canonical host. */
function isHumanFacing(pathname: string): boolean {
  return pathname === "/" || pathname === "/index.html" || pathname === "/app" || pathname.startsWith("/app/") || pathname.startsWith("/verify/");
}

/**
 * 308 to the canonical host for human-facing GET/HEAD requests arriving on a fallback
 * host. Path and query are preserved; browsers preserve the URL fragment across
 * redirects, so invite links (#token=…) keep working.
 */
export function canonicalRedirect(request: Request): Response | null {
  const url = new URL(request.url);
  if (!isFallbackOrigin(url)) return null;
  if (request.method !== "GET" && request.method !== "HEAD") return null;
  if (!isHumanFacing(url.pathname)) return null;
  return new Response(null, {
    status: 308,
    headers: { Location: `${CANONICAL_ORIGIN}${url.pathname}${url.search}`, "Cache-Control": "public, max-age=300" },
  });
}
