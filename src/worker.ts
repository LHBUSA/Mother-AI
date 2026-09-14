// Mother AI — single Worker entry point.
//
//   /v1/*                gateway API (API key auth)
//   /api/auth/*          passkey sign-in, invites, sessions
//   /api/console/*       control-plane API (session auth)
//   /api/demo/*          public demo workspace (stateless)
//   /api/founding-access public early-access capture
//   /badge/{token}.svg   live badge
//   /verify/{token}      public verification page
//   /health, /ready      service health
//   /app/*               control-plane SPA (static assets)
//   everything else      marketing site (static assets)

import type { Env } from "./env";
import { ApiError, errorResponse, json, methodNotAllowed } from "./lib/http";
import { iso } from "./lib/time";
import { withSecurityHeaders } from "./lib/security-headers";
import { routeV1 } from "./api/v1";
import { routeAuth } from "./auth/passkeys";
import { routeConsole } from "./api/console/index";
import { demoEvaluate, demoWorkspace, foundingAccessSubmit, foundingAccessToken, health, ready } from "./api/public";
import { handleBadgeSvg, handleVerifyPage } from "./badge/routes";
import { sweepExpiredApprovals } from "./gateway/approvals";
import { robotsTxt, sitemapXml } from "./lib/seo";
import { canonicalRedirect } from "./lib/site";

const BADGE_SVG = /^\/badge\/([0-9A-Za-z]{1,64})\.svg$/;
const VERIFY = /^\/verify\/([0-9A-Za-z]{1,64})\/?$/;

async function handleApi(request: Request, env: Env, nowMs: number, ctx: ExecutionContext): Promise<Response> {
  const { pathname } = new URL(request.url);
  try {
    if (pathname.startsWith("/api/auth/")) return await routeAuth(request, env, nowMs);
    if (pathname.startsWith("/api/console/")) return await routeConsole(request, env, nowMs, (p) => ctx.waitUntil(p));
    if (pathname === "/api/demo/workspace") return request.method === "GET" ? demoWorkspace() : methodNotAllowed(["GET"]);
    if (pathname === "/api/demo/evaluate") return request.method === "POST" ? await demoEvaluate(request, env) : methodNotAllowed(["POST"]);
    if (pathname === "/api/founding-access/token") return request.method === "GET" ? await foundingAccessToken(env, nowMs) : methodNotAllowed(["GET"]);
    if (pathname === "/api/founding-access") return request.method === "POST" ? await foundingAccessSubmit(request, env, nowMs) : methodNotAllowed(["POST"]);
    throw new ApiError(404, "NOT_FOUND", "Not found.");
  } catch (err) {
    if (err instanceof ApiError) return errorResponse(err);
    console.error("api unhandled error", pathname, err instanceof Error ? err.message : "unknown");
    return errorResponse(new ApiError(500, "INTERNAL_ERROR", "Something went wrong. The error has been logged."));
  }
}

async function serveConsoleShell(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const res = await env.ASSETS.fetch(new Request(new URL("/app/", url.origin), { headers: request.headers }));
  const out = new Response(res.body, res);
  out.headers.set("Cache-Control", "no-cache");
  out.headers.set("X-Robots-Tag", "noindex, nofollow");
  return out;
}

async function notFoundPage(request: Request, env: Env): Promise<Response> {
  const res = await env.ASSETS.fetch(new Request(new URL("/404.html", request.url)));
  if (res.ok) return new Response(res.body, { status: 404, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" } });
  return new Response("Not found", { status: 404, headers: { "Content-Type": "text/plain; charset=utf-8" } });
}

async function route(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);
  const { pathname } = url;
  const nowMs = Date.now();
  const deps = { now: () => Date.now(), waitUntil: (p: Promise<unknown>) => ctx.waitUntil(p) };

  const redirect = canonicalRedirect(request);
  if (redirect) return redirect;

  if (pathname.startsWith("/v1/")) return routeV1(request, env, deps);
  if (pathname.startsWith("/api/")) return handleApi(request, env, nowMs, ctx);
  if (pathname === "/health") return health(env, nowMs);
  if (pathname === "/ready") return ready(env);
  if (pathname === "/robots.txt") return robotsTxt(url);
  if (pathname === "/sitemap.xml") return sitemapXml();

  const badge = BADGE_SVG.exec(pathname);
  if (badge) return request.method === "GET" || request.method === "HEAD" ? handleBadgeSvg(request, env, badge[1]!, nowMs, ctx) : methodNotAllowed(["GET"]);
  const verify = VERIFY.exec(pathname);
  if (verify) return request.method === "GET" || request.method === "HEAD" ? handleVerifyPage(request, env, verify[1]!, nowMs, ctx) : methodNotAllowed(["GET"]);

  if (request.method !== "GET" && request.method !== "HEAD") return methodNotAllowed(["GET"]);

  if (pathname === "/app") return Response.redirect(new URL("/app/", url.origin).toString(), 308);
  if (pathname.startsWith("/app/")) {
    const isAsset = /\.[A-Za-z0-9]{1,8}$/.test(pathname);
    if (!isAsset) return serveConsoleShell(request, env);
  }

  const asset = await env.ASSETS.fetch(request);
  if (asset.status === 404) return notFoundPage(request, env);
  if (/^\/assets\//.test(pathname) && asset.ok) {
    const cached = new Response(asset.body, asset);
    cached.headers.set("Cache-Control", "public, max-age=31536000, immutable");
    return cached;
  }
  return asset;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const { pathname } = new URL(request.url);
    let response: Response;
    try {
      response = await route(request, env, ctx);
    } catch (err) {
      console.error("unhandled", pathname, err instanceof Error ? err.message : "unknown");
      response = pathname.startsWith("/v1/")
        ? json({ decision: "block", error: { code: "INTERNAL_ERROR", message: "Mother AI encountered an internal error; failing closed." } }, 500)
        : json({ error: { code: "INTERNAL_ERROR", message: "Something went wrong." } }, 500);
    }
    return withSecurityHeaders(response, { publicEmbed: BADGE_SVG.test(pathname) });
  },

  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    const nowMs = Date.now();
    const now = iso(nowMs);
    ctx.waitUntil(
      (async () => {
        await sweepExpiredApprovals(env.DB, null, nowMs, 500);
        await env.DB.batch([
          env.DB.prepare(`DELETE FROM auth_challenges WHERE expires_at < ?`).bind(iso(nowMs - 60 * 60 * 1000)),
          env.DB.prepare(`DELETE FROM sessions WHERE expires_at < ?`).bind(iso(nowMs - 7 * 24 * 60 * 60 * 1000)),
        ]);
        console.log("maintenance sweep complete", now);
      })(),
    );
  },
} satisfies ExportedHandler<Env>;
