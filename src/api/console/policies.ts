import { newId } from "../../lib/crypto";
import { ApiError, json } from "../../lib/http";
import { iso } from "../../lib/time";
import { parseJson, type PolicyRow } from "../../lib/db";
import { controlEventStatement } from "../../gateway/audit";
import {
  evaluateSafely,
  validateConditionGroup,
  type ConditionGroup,
  type DefaultDecision,
  type PolicyRecord,
} from "../../gateway/policy-engine";
import { normalizeEvaluateRequest } from "../../gateway/normalize";
import { Validator, assertOrgWritable, type ConsoleContext } from "./context";

const MAX_POLICIES = 500;
const MAX_BOUND_AGENTS = 200;
const REASON_CODE = /^[A-Z][A-Z0-9_]{2,63}$/;

interface PolicyWithAgents extends PolicyRow {
  agent_ids: string;
}

function presentPolicy(row: PolicyWithAgents) {
  const agents = parseJson<Array<{ id: string; agent_key: string } | null>>(row.agent_ids, []).filter(Boolean) as Array<{ id: string; agent_key: string }>;
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    priority: row.priority,
    enabled: row.enabled === 1,
    effect: row.effect,
    scope: row.scope,
    conditions: parseJson<unknown>(row.conditions, null),
    reason_code: row.reason_code,
    reason: row.reason,
    version: row.version,
    archived_at: row.archived_at,
    created_at: row.created_at,
    updated_at: row.updated_at,
    agents,
  };
}

const POLICY_SELECT = `SELECT p.*,
  (SELECT json_group_array(json_object('id', a.id, 'agent_key', a.agent_key))
     FROM agent_policy_bindings b JOIN agents a ON a.id = b.agent_id AND a.organization_id = b.organization_id
    WHERE b.policy_id = p.id AND b.organization_id = p.organization_id) AS agent_ids
  FROM policies p`;

export async function listPolicies(ctx: ConsoleContext): Promise<Response> {
  const includeArchived = ctx.url.searchParams.get("archived") === "1";
  const since = iso(ctx.nowMs - 7 * 24 * 60 * 60 * 1000);
  const [rows, hits] = await ctx.db.batch([
    ctx.db
      .prepare(
        `${POLICY_SELECT} WHERE p.organization_id = ? ${includeArchived ? "" : "AND p.archived_at IS NULL"}
         ORDER BY p.archived_at IS NOT NULL, CASE p.effect WHEN 'block' THEN 0 WHEN 'review' THEN 1 ELSE 2 END, p.priority, p.created_at`,
      )
      .bind(ctx.orgId),
    ctx.db
      .prepare(`SELECT policy_id, COUNT(*) AS n FROM decisions WHERE organization_id = ? AND created_at >= ? AND policy_id IS NOT NULL GROUP BY policy_id`)
      .bind(ctx.orgId, since),
  ]);
  const hitMap = new Map((hits!.results as Array<{ policy_id: string; n: number }>).map((h) => [h.policy_id, h.n]));
  return json({
    policies: (rows!.results as unknown as PolicyWithAgents[]).map((r) => ({ ...presentPolicy(r), decisions_7d: hitMap.get(r.id) ?? 0 })),
  });
}

export async function getPolicy(ctx: ConsoleContext): Promise<Response> {
  const id = ctx.params[0]!;
  const row = await ctx.db.prepare(`${POLICY_SELECT} WHERE p.id = ? AND p.organization_id = ?`).bind(id, ctx.orgId).first<PolicyWithAgents>();
  if (!row) throw new ApiError(404, "NOT_FOUND", "Policy not found.");
  const versions = await ctx.db
    .prepare(`SELECT version, changed_by, created_at, snapshot FROM policy_versions WHERE policy_id = ? AND organization_id = ? ORDER BY version DESC LIMIT 50`)
    .bind(id, ctx.orgId)
    .all<{ version: number; changed_by: string | null; created_at: string; snapshot: string }>();
  return json({
    policy: presentPolicy(row),
    versions: versions.results.map((v) => ({ version: v.version, changed_by: v.changed_by, created_at: v.created_at, snapshot: parseJson(v.snapshot, null) })),
  });
}

interface PolicyInput {
  name: string;
  description: string;
  priority: number;
  enabled: boolean;
  effect: "allow" | "review" | "block";
  scope: "organization" | "agents";
  agentIds: string[];
  conditions: ConditionGroup;
  reasonCode: string | null;
  reason: string | null;
}

async function readPolicyInput(ctx: ConsoleContext): Promise<PolicyInput> {
  const v = new Validator(ctx.body);
  const name = v.string("name", { min: 1, max: 120 });
  const description = v.string("description", { max: 500, optional: true }) ?? "";
  const priority = v.int("priority", { min: 0, max: 10000 });
  const enabled = v.bool("enabled");
  const effect = v.oneOf("effect", ["allow", "review", "block"] as const);
  const scope = v.oneOf("scope", ["organization", "agents"] as const);
  const reasonCode = v.string("reason_code", { max: 64, optional: true });
  const reason = v.string("reason", { max: 500, optional: true });
  if (reasonCode && !REASON_CODE.test(reasonCode)) v.errors.reason_code = "use UPPER_SNAKE_CASE, 3–64 characters";

  let agentIds: string[] = [];
  const rawAgents = ctx.body.agent_ids;
  if (scope === "agents") {
    if (!Array.isArray(rawAgents) || rawAgents.length === 0 || !rawAgents.every((a) => typeof a === "string" && /^agt_[0-9A-Za-z]{22}$/.test(a))) {
      v.errors.agent_ids = "choose at least one agent";
    } else if (rawAgents.length > MAX_BOUND_AGENTS) {
      v.errors.agent_ids = `at most ${MAX_BOUND_AGENTS} agents`;
    } else {
      agentIds = [...new Set(rawAgents as string[])];
    }
  }

  const validated = validateConditionGroup(ctx.body.conditions);
  if (!validated.ok) v.errors.conditions = validated.errors.join("; ");
  v.assert();

  if (agentIds.length) {
    const placeholders = agentIds.map(() => "?").join(",");
    const found = await ctx.db
      .prepare(`SELECT id FROM agents WHERE organization_id = ? AND id IN (${placeholders})`)
      .bind(ctx.orgId, ...agentIds)
      .all<{ id: string }>();
    if (found.results.length !== agentIds.length) {
      throw new ApiError(400, "INVALID_REQUEST", "The request failed validation.", { fields: { agent_ids: "includes an agent that does not exist in this organization" } });
    }
  }

  return {
    name: name!,
    description,
    priority: priority!,
    enabled: enabled!,
    effect: effect!,
    scope: scope!,
    agentIds,
    conditions: (validated as { ok: true; value: ConditionGroup }).value,
    reasonCode: reasonCode || null,
    reason: reason || null,
  };
}

function snapshot(id: string, version: number, input: PolicyInput) {
  return JSON.stringify({
    id,
    version,
    name: input.name,
    description: input.description,
    priority: input.priority,
    enabled: input.enabled,
    effect: input.effect,
    scope: input.scope,
    agent_ids: input.agentIds,
    conditions: input.conditions,
    reason_code: input.reasonCode,
    reason: input.reason,
  });
}

export async function createPolicy(ctx: ConsoleContext): Promise<Response> {
  assertOrgWritable(ctx);
  const input = await readPolicyInput(ctx);
  const count = await ctx.db.prepare(`SELECT COUNT(*) AS n FROM policies WHERE organization_id = ? AND archived_at IS NULL`).bind(ctx.orgId).first<{ n: number }>();
  if ((count?.n ?? 0) >= MAX_POLICIES) throw new ApiError(409, "LIMIT_REACHED", `An organization can have at most ${MAX_POLICIES} active policies.`);

  const id = newId("pol");
  const now = iso(ctx.nowMs);
  const statements = [
    ctx.db
      .prepare(
        `INSERT INTO policies (id, organization_id, name, description, priority, enabled, effect, scope, conditions, reason_code, reason, version, created_by, updated_by, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)`,
      )
      .bind(id, ctx.orgId, input.name, input.description, input.priority, input.enabled ? 1 : 0, input.effect, input.scope, JSON.stringify(input.conditions), input.reasonCode, input.reason, ctx.actor.id, ctx.actor.id, now, now),
    ctx.db
      .prepare(`INSERT INTO policy_versions (id, organization_id, policy_id, version, snapshot, changed_by, created_at) VALUES (?, ?, ?, 1, ?, ?, ?)`)
      .bind(newId("pv"), ctx.orgId, id, snapshot(id, 1, input), ctx.actor.id, now),
    ...input.agentIds.map((agentId) =>
      ctx.db.prepare(`INSERT INTO agent_policy_bindings (organization_id, agent_id, policy_id, created_at) VALUES (?, ?, ?, ?)`).bind(ctx.orgId, agentId, id, now),
    ),
    controlEventStatement(ctx.db, ctx.orgId, ctx.actor, "policy.created", { type: "policy", id }, { name: input.name, effect: input.effect, version: 1 }, now),
  ];
  await ctx.db.batch(statements);
  const row = await ctx.db.prepare(`${POLICY_SELECT} WHERE p.id = ? AND p.organization_id = ?`).bind(id, ctx.orgId).first<PolicyWithAgents>();
  return json({ policy: presentPolicy(row!) }, 201);
}

export async function updatePolicy(ctx: ConsoleContext): Promise<Response> {
  assertOrgWritable(ctx);
  const id = ctx.params[0]!;
  const existing = await ctx.db.prepare(`SELECT * FROM policies WHERE id = ? AND organization_id = ?`).bind(id, ctx.orgId).first<PolicyRow>();
  if (!existing) throw new ApiError(404, "NOT_FOUND", "Policy not found.");
  if (existing.archived_at) throw new ApiError(409, "POLICY_ARCHIVED", "Archived policies cannot be edited.");
  const expectedVersion = ctx.body.expected_version;
  if (typeof expectedVersion !== "number" || expectedVersion !== existing.version) {
    throw new ApiError(409, "VERSION_CONFLICT", "This policy changed since you opened it. Reload to see the latest version.", { current_version: existing.version });
  }
  const input = await readPolicyInput(ctx);
  const nextVersion = existing.version + 1;
  const now = iso(ctx.nowMs);

  // The version-row insert reads `changes()` from the guarded UPDATE: when the
  // optimistic version check fails, snapshot becomes NULL, the NOT NULL
  // constraint aborts the batch, and no binding changes are applied.
  const statements = [
    ctx.db
      .prepare(
        `UPDATE policies SET name = ?, description = ?, priority = ?, enabled = ?, effect = ?, scope = ?, conditions = ?, reason_code = ?, reason = ?,
                version = ?, updated_by = ?, updated_at = ?
          WHERE id = ? AND organization_id = ? AND version = ? AND archived_at IS NULL`,
      )
      .bind(input.name, input.description, input.priority, input.enabled ? 1 : 0, input.effect, input.scope, JSON.stringify(input.conditions), input.reasonCode, input.reason, nextVersion, ctx.actor.id, now, id, ctx.orgId, existing.version),
    ctx.db
      .prepare(
        `INSERT INTO policy_versions (id, organization_id, policy_id, version, snapshot, changed_by, created_at)
         VALUES (?, ?, ?, ?, (SELECT ? WHERE changes() = 1), ?, ?)`,
      )
      .bind(newId("pv"), ctx.orgId, id, nextVersion, snapshot(id, nextVersion, input), ctx.actor.id, now),
    ctx.db.prepare(`DELETE FROM agent_policy_bindings WHERE policy_id = ? AND organization_id = ?`).bind(id, ctx.orgId),
    ...input.agentIds.map((agentId) =>
      ctx.db.prepare(`INSERT INTO agent_policy_bindings (organization_id, agent_id, policy_id, created_at) VALUES (?, ?, ?, ?)`).bind(ctx.orgId, agentId, id, now),
    ),
    controlEventStatement(
      ctx.db,
      ctx.orgId,
      ctx.actor,
      "policy.updated",
      { type: "policy", id },
      { name: input.name, effect: input.effect, enabled: input.enabled, from_version: existing.version, version: nextVersion },
      now,
    ),
  ];
  try {
    await ctx.db.batch(statements);
  } catch (err) {
    if (err instanceof Error && /NOT NULL constraint failed/i.test(err.message)) {
      throw new ApiError(409, "VERSION_CONFLICT", "This policy changed since you opened it. Reload to see the latest version.");
    }
    throw err;
  }
  const row = await ctx.db.prepare(`${POLICY_SELECT} WHERE p.id = ? AND p.organization_id = ?`).bind(id, ctx.orgId).first<PolicyWithAgents>();
  return json({ policy: presentPolicy(row!) });
}

export async function archivePolicy(ctx: ConsoleContext): Promise<Response> {
  assertOrgWritable(ctx);
  const id = ctx.params[0]!;
  const now = iso(ctx.nowMs);
  const results = await ctx.db.batch([
    ctx.db.prepare(`UPDATE policies SET archived_at = ?, enabled = 0, updated_at = ?, updated_by = ? WHERE id = ? AND organization_id = ? AND archived_at IS NULL`).bind(now, now, ctx.actor.id, id, ctx.orgId),
    controlEventStatement(ctx.db, ctx.orgId, ctx.actor, "policy.archived", { type: "policy", id }, {}, now, { onlyIfChanged: true }),
  ]);
  if ((results[0]!.meta.changes ?? 0) !== 1) throw new ApiError(404, "NOT_FOUND", "Policy not found or already archived.");
  return json({ ok: true });
}

/**
 * Dry-run: evaluates a sample action against the organization's current enabled
 * policies, optionally with a draft policy substituted in. Nothing is stored.
 */
export async function simulatePolicy(ctx: ConsoleContext): Promise<Response> {
  const sample = ctx.body.request;
  if (!sample || typeof sample !== "object" || Array.isArray(sample)) {
    throw new ApiError(400, "INVALID_REQUEST", "Provide a sample `request` to simulate.");
  }
  const { action } = normalizeEvaluateRequest({ ...(sample as Record<string, unknown>), request_id: undefined });

  const [agentRes, policyRes] = await ctx.db.batch([
    ctx.db.prepare(`SELECT * FROM agents WHERE organization_id = ? AND agent_key = ?`).bind(ctx.orgId, action.agent),
    ctx.db.prepare(`${POLICY_SELECT} WHERE p.organization_id = ? AND p.archived_at IS NULL AND p.enabled = 1`).bind(ctx.orgId),
  ]);
  const agent = agentRes!.results[0] as { id: string; environment: string; status: string; default_mode: string } | undefined;
  let policies: PolicyRecord[] = (policyRes!.results as unknown as PolicyWithAgents[]).map((row) => {
    const p = presentPolicy(row);
    return {
      id: p.id,
      name: p.name,
      priority: p.priority,
      enabled: p.enabled,
      effect: p.effect,
      scope: p.scope,
      agent_ids: p.agents.map((a) => a.id),
      conditions: p.conditions,
      reason_code: p.reason_code,
      reason: p.reason,
      version: p.version,
      created_at: p.created_at,
    };
  });

  const draft = ctx.body.draft;
  if (draft && typeof draft === "object" && !Array.isArray(draft)) {
    const d = draft as Record<string, unknown>;
    const validated = validateConditionGroup(d.conditions);
    if (!validated.ok) throw new ApiError(400, "INVALID_REQUEST", "The draft policy is invalid.", { fields: { conditions: validated.errors.join("; ") } });
    const draftId = typeof d.id === "string" ? d.id : "pol_draft";
    const effect = d.effect === "allow" || d.effect === "review" || d.effect === "block" ? d.effect : "block";
    policies = policies.filter((p) => p.id !== draftId);
    policies.push({
      id: draftId,
      name: typeof d.name === "string" && d.name ? d.name : "Draft policy",
      priority: typeof d.priority === "number" ? d.priority : 100,
      enabled: true,
      effect,
      scope: d.scope === "agents" ? "agents" : "organization",
      agent_ids: Array.isArray(d.agent_ids) ? (d.agent_ids as unknown[]).filter((x): x is string => typeof x === "string") : [],
      conditions: validated.value,
      reason_code: null,
      reason: null,
      version: 0,
      created_at: iso(ctx.nowMs),
    });
  }

  if (!agent && ctx.session.organization.require_registered_agents === 1) {
    return json({ simulated: true, decision: "block", reason_code: "AGENT_UNKNOWN", reason: `Agent "${action.agent}" is not registered in this organization.`, policy: null, matched: [] });
  }
  if (agent && agent.status !== "active") {
    return json({ simulated: true, decision: "block", reason_code: "AGENT_DISABLED", reason: `Agent "${action.agent}" is disabled.`, policy: null, matched: [] });
  }
  const defaultDecision = (agent && agent.default_mode !== "inherit" ? agent.default_mode : ctx.session.organization.default_decision) as DefaultDecision;
  const result = evaluateSafely({ action: { ...action, environment: agent?.environment ?? action.environment }, agentId: agent?.id ?? null, policies, defaultDecision });
  return json({ simulated: true, ...result });
}
