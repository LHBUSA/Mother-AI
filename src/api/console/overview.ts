import { json } from "../../lib/http";
import { iso } from "../../lib/time";
import type { BadgeRow, DecisionRow } from "../../lib/db";
import { sweepExpiredApprovals } from "../../gateway/approvals";
import { badgeCriteria, badgeFactsStatement, computeBadgeStatus, type BadgeFacts } from "../../badge/status";
import type { ConsoleContext } from "./context";
import { decisionSummary } from "./audit";

export async function overview(ctx: ConsoleContext): Promise<Response> {
  await sweepExpiredApprovals(ctx.db, ctx.orgId, ctx.nowMs);
  const since = iso(ctx.nowMs - 24 * 60 * 60 * 1000);
  const [counts, hourly, recent, agents, policies, pending, keys, badgeRes, factsRes] = await ctx.db.batch([
    ctx.db.prepare(`SELECT decision, COUNT(*) AS n FROM decisions WHERE organization_id = ? AND created_at >= ? GROUP BY decision`).bind(ctx.orgId, since),
    ctx.db
      .prepare(`SELECT substr(created_at, 1, 13) AS hour, decision, COUNT(*) AS n FROM decisions WHERE organization_id = ? AND created_at >= ? GROUP BY hour, decision`)
      .bind(ctx.orgId, since),
    ctx.db.prepare(`SELECT * FROM decisions WHERE organization_id = ? ORDER BY created_at DESC LIMIT 8`).bind(ctx.orgId),
    ctx.db.prepare(`SELECT COUNT(*) AS n FROM agents WHERE organization_id = ? AND status = 'active'`).bind(ctx.orgId),
    ctx.db.prepare(`SELECT COUNT(*) AS n FROM policies WHERE organization_id = ? AND enabled = 1 AND archived_at IS NULL`).bind(ctx.orgId),
    ctx.db.prepare(`SELECT COUNT(*) AS n FROM approvals WHERE organization_id = ? AND status = 'pending' AND expires_at > ?`).bind(ctx.orgId, iso(ctx.nowMs)),
    ctx.db.prepare(`SELECT COUNT(*) AS n FROM api_keys WHERE organization_id = ? AND revoked_at IS NULL`).bind(ctx.orgId),
    ctx.db.prepare(`SELECT * FROM badges WHERE organization_id = ? AND state <> 'revoked' LIMIT 1`).bind(ctx.orgId),
    badgeFactsStatement(ctx.db, ctx.orgId),
  ]);

  const totals = { total: 0, allow: 0, review: 0, block: 0 };
  for (const r of counts!.results as Array<{ decision: "allow" | "review" | "block"; n: number }>) {
    totals[r.decision] = r.n;
    totals.total += r.n;
  }

  // 24 hourly buckets ending with the current hour; empty hours are real zeros.
  const buckets: Array<{ hour: string; allow: number; review: number; block: number }> = [];
  const currentHour = Math.floor(ctx.nowMs / 3_600_000) * 3_600_000;
  for (let i = 23; i >= 0; i--) buckets.push({ hour: iso(currentHour - i * 3_600_000).slice(0, 13), allow: 0, review: 0, block: 0 });
  const byHour = new Map(buckets.map((b) => [b.hour, b]));
  for (const r of hourly!.results as Array<{ hour: string; decision: "allow" | "review" | "block"; n: number }>) {
    const bucket = byHour.get(r.hour);
    if (bucket) bucket[r.decision] += r.n;
  }

  const org = ctx.session.organization;
  const badge = (badgeRes!.results[0] as BadgeRow | undefined) ?? null;
  const facts = factsRes!.results[0] as BadgeFacts;
  const n = (res: D1Result | undefined) => ((res?.results[0] as { n: number } | undefined)?.n ?? 0);

  return json({
    gateway: { enabled: org.gateway_enabled === 1, status: org.status !== "active" ? "suspended" : org.gateway_enabled === 1 ? "operational" : "disabled" },
    audit_enabled: org.audit_enabled === 1,
    decisions_24h: totals,
    hourly: buckets,
    active_agents: n(agents),
    active_policies: n(policies),
    pending_approvals: n(pending),
    active_keys: n(keys),
    recent: (recent!.results as unknown as DecisionRow[]).map(decisionSummary),
    last_gateway_activity: facts.last_activity,
    badge: { status: computeBadgeStatus(badge, org, badgeCriteria(org, facts)), exists: !!badge },
    server_time: iso(ctx.nowMs),
  });
}
