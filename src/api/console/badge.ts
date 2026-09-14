import { newId, randomBase62 } from "../../lib/crypto";
import { ApiError, json } from "../../lib/http";
import { iso } from "../../lib/time";
import type { BadgeRow } from "../../lib/db";
import { controlEventStatement } from "../../gateway/audit";
import {
  BADGE_DISCLAIMER,
  badgeCriteria,
  badgeFactsStatement,
  badgeSnippets,
  badgeUrls,
  computeBadgeStatus,
  markActivatedStatement,
  type BadgeFacts,
} from "../../badge/status";
import { assertOrgWritable, type ConsoleContext } from "./context";

async function currentBadge(ctx: ConsoleContext) {
  const [badgeRes, factsRes] = await ctx.db.batch([
    ctx.db.prepare(`SELECT * FROM badges WHERE organization_id = ? AND state <> 'revoked' LIMIT 1`).bind(ctx.orgId),
    badgeFactsStatement(ctx.db, ctx.orgId),
  ]);
  const badge = (badgeRes!.results[0] as BadgeRow | undefined) ?? null;
  const facts = factsRes!.results[0] as BadgeFacts;
  const criteria = badgeCriteria(ctx.session.organization, facts);
  const status = computeBadgeStatus(badge, ctx.session.organization, criteria);
  if (badge && status === "active" && !badge.activated_at) {
    await markActivatedStatement(ctx.db, badge.id, ctx.nowMs).run();
    badge.activated_at = iso(ctx.nowMs);
  }
  return { badge, facts, criteria, status };
}

export async function getBadge(ctx: ConsoleContext): Promise<Response> {
  const { badge, facts, criteria, status } = await currentBadge(ctx);
  const revoked = await ctx.db
    .prepare(`SELECT id, created_at, revoked_at, revoked_reason FROM badges WHERE organization_id = ? AND state = 'revoked' ORDER BY revoked_at DESC LIMIT 10`)
    .bind(ctx.orgId)
    .all();
  return json({
    status,
    eligible: criteria.every((c) => c.met),
    criteria,
    last_gateway_activity: facts.last_activity,
    badge: badge
      ? {
          id: badge.id,
          state: badge.state,
          token: badge.public_token,
          created_at: badge.created_at,
          activated_at: badge.activated_at,
          suspended_at: badge.suspended_at,
          ...badgeUrls(badge.public_token),
          snippets: badgeSnippets(badge.public_token),
        }
      : null,
    revoked_badges: revoked.results,
    disclaimer: BADGE_DISCLAIMER,
  });
}

export async function badgeAction(ctx: ConsoleContext): Promise<Response> {
  assertOrgWritable(ctx);
  const verb = ctx.params[0] as "enable" | "suspend" | "resume" | "rotate";
  const now = iso(ctx.nowMs);
  const existing = await ctx.db.prepare(`SELECT * FROM badges WHERE organization_id = ? AND state <> 'revoked' LIMIT 1`).bind(ctx.orgId).first<BadgeRow>();

  if (verb === "enable") {
    if (existing) throw new ApiError(409, "BADGE_EXISTS", "A badge already exists for this organization.");
    const id = newId("bdg");
    await ctx.db.batch([
      ctx.db
        .prepare(`INSERT INTO badges (id, organization_id, public_token, state, created_at) VALUES (?, ?, ?, 'enabled', ?)`)
        .bind(id, ctx.orgId, randomBase62(32), now),
      controlEventStatement(ctx.db, ctx.orgId, ctx.actor, "badge.created", { type: "badge", id }, {}, now),
    ]);
    return getBadge(ctx);
  }
  if (!existing) throw new ApiError(404, "NOT_FOUND", "No badge exists yet.");

  if (verb === "suspend") {
    if (existing.state === "suspended") return getBadge(ctx);
    await ctx.db.batch([
      ctx.db.prepare(`UPDATE badges SET state = 'suspended', suspended_at = ? WHERE id = ? AND organization_id = ?`).bind(now, existing.id, ctx.orgId),
      controlEventStatement(ctx.db, ctx.orgId, ctx.actor, "badge.suspended", { type: "badge", id: existing.id }, {}, now),
    ]);
    return getBadge(ctx);
  }
  if (verb === "resume") {
    if (existing.state === "enabled") return getBadge(ctx);
    await ctx.db.batch([
      ctx.db.prepare(`UPDATE badges SET state = 'enabled', suspended_at = NULL WHERE id = ? AND organization_id = ?`).bind(existing.id, ctx.orgId),
      controlEventStatement(ctx.db, ctx.orgId, ctx.actor, "badge.resumed", { type: "badge", id: existing.id }, {}, now),
    ]);
    return getBadge(ctx);
  }
  // rotate: permanently revoke the current public token and issue a new one.
  const id = newId("bdg");
  await ctx.db.batch([
    ctx.db
      .prepare(`UPDATE badges SET state = 'revoked', revoked_at = ?, revoked_reason = 'rotated' WHERE id = ? AND organization_id = ?`)
      .bind(now, existing.id, ctx.orgId),
    ctx.db
      .prepare(`INSERT INTO badges (id, organization_id, public_token, state, activated_at, created_at) VALUES (?, ?, ?, ?, ?, ?)`)
      .bind(id, ctx.orgId, randomBase62(32), existing.state, existing.activated_at, now),
    controlEventStatement(ctx.db, ctx.orgId, ctx.actor, "badge.rotated", { type: "badge", id }, { revoked_badge_id: existing.id }, now),
  ]);
  return getBadge(ctx);
}
