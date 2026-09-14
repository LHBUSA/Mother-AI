// Endpoint-specific CORS. The UI (Vercel) calls the Worker directly — never through a
// proxy — so rate limits and IP hashing see the real visitor IP.
//
//   credentialed  /api/auth/*, /api/console/*        exact UI origin + credentials
//   public        /api/demo/*, /api/founding-access, exact UI origin, no credentials
//                 /api/founding-access/token,
//                 /api/public/badges/*
//   none          everything else (/v1/* is server-to-server; /badge/*.svg is an image)
//
// Never a wildcard. Disallowed origins receive no CORS headers (and 403 on preflight).

import { allowedBrowserOrigins } from "./site";

export type CorsClass = "credentialed" | "public";

export function corsClass(pathname: string): CorsClass | null {
  if (pathname.startsWith("/api/auth/") || pathname.startsWith("/api/console/")) return "credentialed";
  if (
    pathname.startsWith("/api/demo/") ||
    pathname === "/api/founding-access" ||
    pathname === "/api/founding-access/token" ||
    pathname.startsWith("/api/public/badges/")
  ) {
    return "public";
  }
  return null;
}

const METHODS: Record<CorsClass, string> = {
  credentialed: "GET, POST, PUT, PATCH",
  public: "GET, POST",
};

function allowedOrigin(request: Request, environment: string): string | null {
  const origin = request.headers.get("Origin");
  return origin && allowedBrowserOrigins(environment).includes(origin) ? origin : null;
}

/** Answers a CORS preflight for a browser API path, or returns null when the path has no browser CORS. */
export function preflight(request: Request, environment: string): Response | null {
  if (request.method !== "OPTIONS") return null;
  const cls = corsClass(new URL(request.url).pathname);
  if (!cls) return null;
  const origin = allowedOrigin(request, environment);
  if (!origin) {
    return new Response(JSON.stringify({ error: { code: "CORS_ORIGIN_NOT_ALLOWED", message: "Origin not allowed." } }), {
      status: 403,
      headers: { "Content-Type": "application/json; charset=utf-8", Vary: "Origin", "Cache-Control": "no-store" },
    });
  }
  const headers = new Headers({
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": METHODS[cls],
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "600",
    Vary: "Origin",
    "Cache-Control": "no-store",
  });
  if (cls === "credentialed") headers.set("Access-Control-Allow-Credentials", "true");
  return new Response(null, { status: 204, headers });
}

/** Adds CORS response headers for an allowed browser origin on a browser API path. */
export function applyCors(request: Request, response: Response, environment: string): Response {
  const cls = corsClass(new URL(request.url).pathname);
  const headers = response.headers;
  headers.delete("Access-Control-Allow-Origin");
  headers.delete("Access-Control-Allow-Credentials");
  if (!cls) return response;
  headers.append("Vary", "Origin");
  const origin = allowedOrigin(request, environment);
  if (!origin) return response;
  headers.set("Access-Control-Allow-Origin", origin);
  if (cls === "credentialed") headers.set("Access-Control-Allow-Credentials", "true");
  return response;
}
