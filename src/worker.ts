// Mother AI — single Worker entry point.
//
//   /v1/*                gateway API (API key auth)
//   /api/auth/*          passkey sign-in, invites, sessions
//   /api/console/*       control-plane API (session auth)
//   /api/demo/*          public demo workspace (stateless)
//   /api/founding-access public early-access capture
//   /api/public/badges/{t} public verification data (for the UI /verify page)
//   /badge/{token}.svg   live badge
//   /health, /ready      service health
//   /, /app/*, /verify/* 308 to the UI (https://mother.proptechusa.ai, served by Vercel)
//   everything else      404 JSON — this Worker serves no UI

import type { Env } from "./env";
import { ApiError, errorResponse, json, methodNotAllowed } from "./lib/http";
import { iso } from "./lib/time";
import { withSecurityHeaders } from "./lib/security-headers";
import { routeV1 } from "./api/v1";
import { routeAuth } from "./auth/passkeys";
import { routeConsole } from "./api/console/index";
import { demoEvaluate, demoWorkspace, foundingAccessSubmit, foundingAccessToken, health, ready } from "./api/public";
import { handleBadgeSvg, handlePublicBadge } from "./badge/routes";
import { sweepExpiredApprovals } from "./gateway/approvals";
import { robotsTxt } from "./lib/seo";
import { canonicalRedirect } from "./lib/site";
import { applyCors, preflight } from "./lib/cors";

const BADGE_SVG = /^\/badge\/([0-9A-Za-z]{1,64})\.svg$/;
const PUBLIC_BADGE = /^\/api\/public\/badges\/([0-9A-Za-z]{1,64})$/;

async function handleApi(request: Request, env: Env, nowMs: number, ctx: ExecutionContext): Promise<Response> {
  const { pathname } = new URL(request.url);
  try {
    if (pathname.startsWith("/api/auth/")) return await routeAuth(request, env, nowMs);
    if (pathname.startsWith("/api/console/")) return await routeConsole(request, env, nowMs, (p) => ctx.waitUntil(p));
    if (pathname === "/api/demo/workspace") return request.method === "GET" ? demoWorkspace() : methodNotAllowed(["GET"]);
    if (pathname === "/api/demo/evaluate") return request.method === "POST" ? await demoEvaluate(request, env) : methodNotAllowed(["POST"]);
    if (pathname === "/api/founding-access/token") return request.method === "GET" ? await foundingAccessToken(env, nowMs) : methodNotAllowed(["GET"]);
    if (pathname === "/api/founding-access") return request.method === "POST" ? await foundingAccessSubmit(request, env, nowMs) : methodNotAllowed(["POST"]);
    const publicBadge = PUBLIC_BADGE.exec(pathname);
    if (publicBadge) return request.method === "GET" ? await handlePublicBadge(request, env, publicBadge[1]!, nowMs, ctx) : methodNotAllowed(["GET"]);
    throw new ApiError(404, "NOT_FOUND", "Not found.");
  } catch (err) {
    if (err instanceof ApiError) return errorResponse(err);
    console.error("api unhandled error", pathname, err instanceof Error ? err.message : "unknown");
    return errorResponse(new ApiError(500, "INTERNAL_ERROR", "Something went wrong. The error has been logged."));
  }
}

async function route(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const { pathname } = new URL(request.url);
  const nowMs = Date.now();
  const deps = { now: () => Date.now(), waitUntil: (p: Promise<unknown>) => ctx.waitUntil(p) };

  const redirect = canonicalRedirect(request);
  if (redirect) return redirect;

  if (pathname.startsWith("/v1/")) return routeV1(request, env, deps);
  if (pathname.startsWith("/api/")) return handleApi(request, env, nowMs, ctx);
  if (pathname === "/health") return health(env, nowMs);
  if (pathname === "/ready") return ready(env);
  if (pathname === "/robots.txt") return robotsTxt();

  const badge = BADGE_SVG.exec(pathname);
  if (badge) return request.method === "GET" || request.method === "HEAD" ? handleBadgeSvg(request, env, badge[1]!, nowMs, ctx) : methodNotAllowed(["GET"]);

  // The public UI (marketing, console, /verify) is served by Vercel; this Worker is API-only.
  return json({ error: { code: "NOT_FOUND", message: "Not found." } }, 404);
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const { pathname } = new URL(request.url);
    const cors = preflight(request, env.ENVIRONMENT);
    if (cors) return withSecurityHeaders(cors);
    let response: Response;
    try {
      response = await route(request, env, ctx);
    } catch (err) {
      console.error("unhandled", pathname, err instanceof Error ? err.message : "unknown");
      response = pathname.startsWith("/v1/")
        ? json({ decision: "block", error: { code: "INTERNAL_ERROR", message: "Mother AI encountered an internal error; failing closed." } }, 500)
        : json({ error: { code: "INTERNAL_ERROR", message: "Something went wrong." } }, 500);
    }
    return applyCors(request, withSecurityHeaders(response, { publicEmbed: BADGE_SVG.test(pathname) }), env.ENVIRONMENT);
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
