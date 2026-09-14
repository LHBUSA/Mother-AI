import type { Env } from "../env";
import { clientIp } from "../lib/http";
import type { BadgeRow, OrganizationRow } from "../lib/db";
import { iso } from "../lib/time";
import { ENGINE_VERSION } from "../gateway/policy-engine";
import { json } from "../lib/http";
import { SERVICE_VERSION } from "../version";
import {
  BADGE_DISCLAIMER,
  BADGE_TOKEN,
  badgeControls,
  badgeCriteria,
  badgeUrls,
  badgeFactsStatement,
  computeBadgeStatus,
  markActivatedStatement,
  type BadgeFacts,
  type BadgeStatus,
} from "./status";
import { renderBadgeSvg, type BadgeTheme } from "./svg";
import { renderInvalidVerifyPage, renderVerifyPage } from "./verify-page";

type BadgeLookup = { badge: BadgeRow; org: OrganizationRow; facts: BadgeFacts; status: BadgeStatus };

export async function lookupBadge(env: Env, token: string, nowMs: number, ctx: { waitUntil(p: Promise<unknown>): void }): Promise<BadgeLookup | null> {
  if (!BADGE_TOKEN.test(token)) return null;
  const badge = await env.DB.prepare(`SELECT * FROM badges WHERE public_token = ?`).bind(token).first<BadgeRow>();
  if (!badge) return null;
  const [orgRes, factsRes] = await env.DB.batch([
    env.DB.prepare(`SELECT * FROM organizations WHERE id = ?`).bind(badge.organization_id),
    badgeFactsStatement(env.DB, badge.organization_id),
  ]);
  const org = orgRes!.results[0] as OrganizationRow | undefined;
  const facts = factsRes!.results[0] as BadgeFacts | undefined;
  if (!org || !facts) return null;
  const status = computeBadgeStatus(badge, org, badgeCriteria(org, facts));
  if (status === "active" && !badge.activated_at) {
    badge.activated_at = iso(nowMs);
    ctx.waitUntil(markActivatedStatement(env.DB, badge.id, nowMs).run());
  }
  return { badge, org, facts, status };
}

async function limited(request: Request, env: Env): Promise<boolean> {
  const { success } = await env.RL_PUBLIC_BADGE.limit({ key: clientIp(request) });
  return !success;
}

export async function handleBadgeSvg(request: Request, env: Env, token: string, nowMs: number, ctx: ExecutionContext): Promise<Response> {
  const theme: BadgeTheme = new URL(request.url).searchParams.get("theme") === "light" ? "light" : "dark";
  const headers = {
    "Content-Type": "image/svg+xml; charset=utf-8",
    // Revalidate on every view so a suspended or revoked badge never lingers green in a cache.
    "Cache-Control": "no-cache, max-age=0",
    "Cross-Origin-Resource-Policy": "cross-origin",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
  };
  if (await limited(request, env)) {
    return new Response(renderBadgeSvg("invalid", theme), { status: 429, headers });
  }
  const found = await lookupBadge(env, token, nowMs, ctx);
  const state = found ? found.status : "invalid";
  const body = renderBadgeSvg(state, theme);
  const etag = `W/"${state}-${theme}"`;
  if (request.headers.get("If-None-Match") === etag) {
    return new Response(null, { status: 304, headers: { ...headers, ETag: etag } });
  }
  return new Response(body, { status: found ? 200 : 404, headers: { ...headers, ETag: etag } });
}

export async function handleVerifyPage(request: Request, env: Env, token: string, nowMs: number, ctx: ExecutionContext): Promise<Response> {
  const headers = { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" };
  if (await limited(request, env)) {
    return new Response("Too many requests", { status: 429, headers: { "Content-Type": "text/plain; charset=utf-8" } });
  }
  const found = await lookupBadge(env, token, nowMs, ctx);
  if (!found) return new Response(renderInvalidVerifyPage(), { status: 404, headers });
  const html = renderVerifyPage({
    organizationName: found.org.display_name,
    status: found.status,
    criteria: badgeCriteria(found.org, found.facts),
    checkedAt: iso(nowMs),
    activatedAt: found.badge.activated_at,
    lastActivity: found.facts.last_activity,
    token,
  });
  return new Response(html, { status: 200, headers });
}

/**
 * GET /api/public/badges/{token} — read-only verification data for the UI's /verify page.
 * Public, rate limited per client IP, never cached, and limited to what the verification
 * page shows: no internal ids, no token-to-org mapping beyond the display name.
 */
export async function handlePublicBadge(request: Request, env: Env, token: string, nowMs: number, ctx: ExecutionContext): Promise<Response> {
  const headers = { "Cache-Control": "no-store" };
  if (await limited(request, env)) {
    return json({ error: { code: "RATE_LIMITED", message: "Too many verification requests. Try again in a minute." } }, 429, headers);
  }
  const found = await lookupBadge(env, token, nowMs, ctx);
  if (!found) {
    return json({ error: { code: "BADGE_NOT_FOUND", message: "This link does not match any Mother AI badge." } }, 404, headers);
  }
  const criteria = badgeCriteria(found.org, found.facts);
  const dateOnly = (value: string | null) => (value ? value.slice(0, 10) : null);
  return json(
    {
      status: found.status,
      organization: { display_name: found.org.display_name },
      controls: found.status === "revoked" ? [] : badgeControls(criteria),
      checked_at: iso(nowMs),
      activated_on: dateOnly(found.badge.activated_at),
      last_gateway_activity_on: dateOnly(found.facts.last_activity),
      policy_engine: ENGINE_VERSION,
      service_version: SERVICE_VERSION,
      badge: badgeUrls(token),
      disclaimer: BADGE_DISCLAIMER,
    },
    200,
    headers,
  );
}
