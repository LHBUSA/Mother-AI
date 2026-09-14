// Hosts. config/site.json is the only place hostnames live.
//
//   origin          public UI (Vercel): marketing, console, /verify, passkeys (WebAuthn RP)
//   apiOrigin       this Worker: gateway, auth, console API, badge SVGs, health
//   fallbackOrigins workers.dev — operational fallback for the API
//
// WebAuthn is bound to the UI origin, never to the host that happens to receive
// the API request.

import site from "../../config/site.json";

export const UI_ORIGIN: string = site.origin;
export const API_ORIGIN: string = site.apiOrigin;
export const RP_ID: string = new URL(UI_ORIGIN).hostname;
const FALLBACK_ORIGINS = new Set<string>(site.fallbackOrigins ?? []);

/** Browser origins allowed to call credentialed/public browser APIs and run passkey ceremonies. */
const DEV_UI_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:8787", "http://127.0.0.1:8787"];

export function allowedBrowserOrigins(environment: string): readonly string[] {
  return environment === "production" ? [UI_ORIGIN] : [UI_ORIGIN, ...DEV_UI_ORIGINS];
}

export function isFallbackOrigin(url: URL): boolean {
  return FALLBACK_ORIGINS.has(url.origin);
}

/** Hosts that serve only machine traffic (API host and fallbacks). */
export function isApiOnlyOrigin(url: URL): boolean {
  return url.origin === API_ORIGIN || FALLBACK_ORIGINS.has(url.origin);
}

/** Human-facing paths that belong to the UI host. */
function isHumanFacing(pathname: string): boolean {
  return pathname === "/" || pathname === "/index.html" || pathname === "/app" || pathname.startsWith("/app/") || pathname.startsWith("/verify/");
}

/**
 * 308 to the UI host for human-facing GET/HEAD requests arriving on an API-only host.
 * Path and query are preserved; browsers preserve the URL fragment across redirects.
 */
export function canonicalRedirect(request: Request): Response | null {
  const url = new URL(request.url);
  if (!isApiOnlyOrigin(url)) return null;
  if (request.method !== "GET" && request.method !== "HEAD") return null;
  if (!isHumanFacing(url.pathname)) return null;
  return new Response(null, {
    status: 308,
    headers: { Location: `${UI_ORIGIN}${url.pathname}${url.search}`, "Cache-Control": "public, max-age=300" },
  });
}
