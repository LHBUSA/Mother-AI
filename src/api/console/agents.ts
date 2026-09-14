import { newId } from "../../lib/crypto";
import { ApiError, json } from "../../lib/http";
import { iso } from "../../lib/time";
import type { AgentRow } from "../../lib/db";
import { controlEventStatement } from "../../gateway/audit";
import { AGENT_KEY, ENVIRONMENTS } from "../../gateway/normalize";
import { Validator, assertOrgWritable, type ConsoleContext } from "./context";
import { decisionSummary } from "./audit";

const MAX_AGENTS = 1000;

interface AgentListRow extends AgentRow {
  bound_policies: number;
  last_activity: string | null;
  allow_7d: number;
  review_7d: number;
  block_7d: number;
}

export async function listAgents(ctx: ConsoleContext): Promise<Response> {
  const since = iso(ctx.nowMs - 7 * 24 * 60 * 60 * 1000);
  const rows = await ctx.db
    .prepare(
      `SELECT a.*,
              (SELECT COUNT(*) FROM agent_policy_bindings b JOIN policies p ON p.id = b.policy_id
                WHERE b.agent_id = a.id AND b.organization_id = a.organization_id AND p.archived_at IS NULL) AS bound_policies,
              (SELECT MAX(created_at) FROM decisions d WHERE d.organization_id = a.organization_id AND d.agent_id = a.id) AS last_activity,
              (SELECT COUNT(*) FROM decisions d WHERE d.organization_id = a.organization_id AND d.agent_id = a.id AND d.created_at >= ?2 AND d.decision = 'allow') AS allow_7d,
              (SELECT COUNT(*) FROM decisions d WHERE d.organization_id = a.organization_id AND d.agent_id = a.id AND d.created_at >= ?2 AND d.decision = 'review') AS review_7d,
              (SELECT COUNT(*) FROM decisions d WHERE d.organization_id = a.organization_id AND d.agent_id = a.id AND d.created_at >= ?2 AND d.decision = 'block') AS block_7d
         FROM agents a WHERE a.organization_id = ?1 ORDER BY a.status, a.display_name`,
    )
    .bind(ctx.orgId, since)
    .all<AgentListRow>();
  const orgPolicies = await ctx.db
    .prepare(`SELECT COUNT(*) AS n FROM policies WHERE organization_id = ? AND scope = 'organization' AND archived_at IS NULL AND enabled = 1`)
    .bind(ctx.orgId)
    .first<{ n: number }>();
  return json({ agents: rows.results, organization_policies: orgPolicies?.n ?? 0 });
}

export async function getAgent(ctx: ConsoleContext): Promise<Response> {
  const id = ctx.params[0]!;
  const agent = await ctx.db.prepare(`SELECT * FROM agents WHERE id = ? AND organization_id = ?`).bind(id, ctx.orgId).first<AgentRow>();
  if (!agent) throw new ApiError(404, "NOT_FOUND", "Agent not found.");
  const since = iso(ctx.nowMs - 7 * 24 * 60 * 60 * 1000);
  const [policies, decisions, stats] = await ctx.db.batch([
    ctx.db
      .prepare(
        `SELECT p.id, p.name, p.effect, p.priority, p.enabled, p.scope, p.version,
                CASE WHEN p.scope = 'organization' THEN 0 ELSE 1 END AS bound
           FROM policies p
          WHERE p.organization_id = ?1 AND p.archived_at IS NULL
            AND (p.scope = 'organization' OR EXISTS (SELECT 1 FROM agent_policy_bindings b WHERE b.policy_id = p.id AND b.agent_id = ?2 AND b.organization_id = ?1))
          ORDER BY CASE p.effect WHEN 'block' THEN 0 WHEN 'review' THEN 1 ELSE 2 END, p.priority, p.created_at`,
      )
      .bind(ctx.orgId, id),
    ctx.db
      .prepare(`SELECT * FROM decisions WHERE organization_id = ? AND agent_id = ? ORDER BY created_at DESC LIMIT 25`)
      .bind(ctx.orgId, id),
    ctx.db
      .prepare(
        `SELECT decision, COUNT(*) AS n FROM decisions WHERE organization_id = ? AND agent_id = ? AND created_at >= ? GROUP BY decision`,
      )
      .bind(ctx.orgId, id, since),
  ]);
  const counts = { allow: 0, review: 0, block: 0 };
  for (const r of stats!.results as Array<{ decision: keyof typeof counts; n: number }>) counts[r.decision] = r.n;
  return json({
    agent,
    policies: policies!.results,
    recent_decisions: (decisions!.results as never[]).map(decisionSummary),
    stats_7d: counts,
  });
}

export async function createAgent(ctx: ConsoleContext): Promise<Response> {
  assertOrgWritable(ctx);
  const v = new Validator(ctx.body);
  const agentKey = v.string("agent_id", { min: 1, max: 128, pattern: AGENT_KEY, lower: true, message: "use lowercase letters, numbers, dots, dashes and underscores" });
  const displayName = v.string("display_name", { min: 1, max: 120 });
  const description = v.string("description", { max: 500, optional: true }) ?? "";
  const environment = v.oneOf("environment", ENVIRONMENTS);
  const defaultMode = v.oneOf("default_mode", ["inherit", "block", "review", "allow"] as const, { optional: true }) ?? "inherit";
  if (environment === "production" && defaultMode === "allow") v.errors.default_mode = "production agents cannot default to allow";
  v.assert();

  const count = await ctx.db.prepare(`SELECT COUNT(*) AS n FROM agents WHERE organization_id = ?`).bind(ctx.orgId).first<{ n: number }>();
  if ((count?.n ?? 0) >= MAX_AGENTS) throw new ApiError(409, "LIMIT_REACHED", `An organization can register at most ${MAX_AGENTS} agents.`);

  const id = newId("agt");
  const now = iso(ctx.nowMs);
  try {
    await ctx.db.batch([
      ctx.db
        .prepare(
          `INSERT INTO agents (id, organization_id, agent_key, display_name, description, environment, status, default_mode, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)`,
        )
        .bind(id, ctx.orgId, agentKey, displayName, description, environment, defaultMode, now, now),
      controlEventStatement(ctx.db, ctx.orgId, ctx.actor, "agent.created", { type: "agent", id }, { agent_id: agentKey, environment, default_mode: defaultMode }, now),
    ]);
  } catch (err) {
    if (err instanceof Error && /UNIQUE/i.test(err.message)) {
      throw new ApiError(409, "AGENT_EXISTS", "An agent with this id already exists.", { fields: { agent_id: "already exists" } });
    }
    throw err;
  }
  const agent = await ctx.db.prepare(`SELECT * FROM agents WHERE id = ?`).bind(id).first<AgentRow>();
  return json({ agent }, 201);
}

export async function updateAgent(ctx: ConsoleContext): Promise<Response> {
  assertOrgWritable(ctx);
  const id = ctx.params[0]!;
  const agent = await ctx.db.prepare(`SELECT * FROM agents WHERE id = ? AND organization_id = ?`).bind(id, ctx.orgId).first<AgentRow>();
  if (!agent) throw new ApiError(404, "NOT_FOUND", "Agent not found.");
  if ("agent_id" in ctx.body || "environment" in ctx.body) {
    throw new ApiError(400, "IMMUTABLE_FIELD", "An agent's id and environment are part of its identity and cannot be changed. Register a new agent instead.");
  }
  const v = new Validator(ctx.body);
  const displayName = v.string("display_name", { min: 1, max: 120, optional: true }) ?? agent.display_name;
  const description = v.string("description", { max: 500, optional: true }) ?? agent.description;
  const status = v.oneOf("status", ["active", "disabled"] as const, { optional: true }) ?? agent.status;
  const defaultMode = v.oneOf("default_mode", ["inherit", "block", "review", "allow"] as const, { optional: true }) ?? agent.default_mode;
  if (agent.environment === "production" && defaultMode === "allow") v.errors.default_mode = "production agents cannot default to allow";
  v.assert();

  const now = iso(ctx.nowMs);
  const changes: Record<string, unknown> = {};
  if (displayName !== agent.display_name) changes.display_name = displayName;
  if (description !== agent.description) changes.description = description;
  if (status !== agent.status) changes.status = status;
  if (defaultMode !== agent.default_mode) changes.default_mode = defaultMode;
  if (!Object.keys(changes).length) return json({ agent });

  await ctx.db.batch([
    ctx.db
      .prepare(`UPDATE agents SET display_name = ?, description = ?, status = ?, default_mode = ?, updated_at = ? WHERE id = ? AND organization_id = ?`)
      .bind(displayName, description, status, defaultMode, now, id, ctx.orgId),
    controlEventStatement(
      ctx.db,
      ctx.orgId,
      ctx.actor,
      status !== agent.status ? (status === "disabled" ? "agent.disabled" : "agent.enabled") : "agent.updated",
      { type: "agent", id },
      { agent_id: agent.agent_key, changes },
      now,
    ),
  ]);
  const updated = await ctx.db.prepare(`SELECT * FROM agents WHERE id = ?`).bind(id).first<AgentRow>();
  return json({ agent: updated });
}

