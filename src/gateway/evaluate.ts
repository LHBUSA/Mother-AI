// POST /v1/evaluate and POST /v1/mcp/evaluate — the policy decision point.
//
// Round trips to D1: one read batch (key + org, agent, policies, prior decision)
// and one write batch (decision [+ approval] [+ key last_used_at]). The decision
// is durably recorded BEFORE the response is returned; if evidence cannot be
// written, the caller receives a block.

import type { Env } from "../env";
import { canonicalJson, newId, sha256Hex, timingSafeEqual } from "../lib/crypto";
import { ApiError, clientIp, json, readJsonObject } from "../lib/http";
import { redactString, redactValue } from "../lib/redact";
import { addSeconds, iso } from "../lib/time";
import { isUniqueViolation, parseJson, type AgentRow, type DecisionRow } from "../lib/db";
import { assertKeyUsable, readBearerKey } from "./identity";
import { normalizeEvaluateRequest, normalizeMcpRequest, type NormalizedRequest } from "./normalize";
import {
  ENGINE_VERSION,
  evaluateSafely,
  type DefaultDecision,
  type EvaluationResult,
  type PolicyRecord,
} from "./policy-engine";
import { approvalView, type ApprovalView } from "./approvals";

export interface GatewayDeps {
  now: () => number;
  waitUntil: (p: Promise<unknown>) => void;
}

interface KeyOrgRow {
  key_id: string;
  key_hash: string;
  key_environment: "live" | "test";
  revoked_at: string | null;
  last_used_at: string | null;
  org_id: string;
  org_status: string;
  gateway_enabled: number;
  audit_enabled: number;
  require_registered_agents: number;
  default_decision: "block" | "review";
  approval_ttl_seconds: number;
}

interface PolicyQueryRow {
  id: string;
  name: string;
  priority: number;
  enabled: number;
  effect: "allow" | "review" | "block";
  scope: "organization" | "agents";
  conditions: string;
  reason_code: string | null;
  reason: string | null;
  version: number;
  created_at: string;
  bound: number;
}

interface ExistingRow extends DecisionRow {
  approval_id: string | null;
  approval_status: "pending" | "approved" | "denied" | "expired" | null;
  approval_expires_at: string | null;
  approval_requested_at: string | null;
  approval_grant_expires_at: string | null;
  approval_consumed_at: string | null;
}

const KEY_TOUCH_INTERVAL_MS = 60_000;

/** Error body for every non-decision gateway response. Always carries decision:block. */
export function gatewayError(err: ApiError, headers: HeadersInit = {}): Response {
  return json({ decision: "block", error: { code: err.code, message: err.message, ...err.extra } }, err.status, headers);
}

export async function handleEvaluate(request: Request, env: Env, deps: GatewayDeps, kind: "api" | "mcp"): Promise<Response> {
  const started = deps.now();

  const ipLimit = await env.RL_GATEWAY_IP.limit({ key: clientIp(request) });
  if (!ipLimit.success) throw new ApiError(429, "RATE_LIMITED", "Too many gateway requests from this address.");

  const key = await readBearerKey(request);
  const body = await readJsonObject(request);
  const normalized: NormalizedRequest = kind === "mcp" ? normalizeMcpRequest(body) : normalizeEvaluateRequest(body);
  const fingerprint = await sha256Hex(canonicalJson(normalized.action));
  const { action } = normalized;

  const db = env.DB;
  const statements = [
    db
      .prepare(
        `SELECT k.id AS key_id, k.key_hash, k.environment AS key_environment, k.revoked_at, k.last_used_at,
                o.id AS org_id, o.status AS org_status, o.gateway_enabled, o.audit_enabled,
                o.require_registered_agents, o.default_decision, o.approval_ttl_seconds
           FROM api_keys k JOIN organizations o ON o.id = k.organization_id
          WHERE k.key_hash = ?`,
      )
      .bind(key.hash),
    db
      .prepare(
        `SELECT a.* FROM api_keys k JOIN agents a ON a.organization_id = k.organization_id
          WHERE k.key_hash = ? AND a.agent_key = ?`,
      )
      .bind(key.hash, action.agent),
    db
      .prepare(
        `SELECT p.id, p.name, p.priority, p.enabled, p.effect, p.scope, p.conditions, p.reason_code, p.reason,
                p.version, p.created_at,
                EXISTS (SELECT 1 FROM agent_policy_bindings b JOIN agents a ON a.id = b.agent_id
                         WHERE b.policy_id = p.id AND b.organization_id = p.organization_id
                           AND a.organization_id = p.organization_id AND a.agent_key = ?) AS bound
           FROM api_keys k JOIN policies p ON p.organization_id = k.organization_id
          WHERE k.key_hash = ? AND p.archived_at IS NULL AND p.enabled = 1`,
      )
      .bind(action.agent, key.hash),
  ];
  if (normalized.requestId) {
    statements.push(existingDecisionStatement(db, key.hash, normalized.requestId));
  }

  let results: D1Result[];
  try {
    results = await db.batch(statements);
  } catch {
    throw new ApiError(503, "GATEWAY_UNAVAILABLE", "Mother AI could not load policy state; failing closed.");
  }

  const keyRow = (results[0]!.results[0] as KeyOrgRow | undefined) ?? null;
  assertKeyUsable(keyRow, key.hash, timingSafeEqual);
  const principal = keyRow!;

  const keyLimit = await env.RL_GATEWAY_KEY.limit({ key: principal.key_id });
  if (!keyLimit.success) throw new ApiError(429, "RATE_LIMITED", "This API key exceeded its gateway rate limit.");

  const existing = normalized.requestId ? ((results[3]!.results[0] as ExistingRow | undefined) ?? null) : null;
  if (existing) {
    return replay(existing, fingerprint, deps);
  }

  const agent = (results[1]!.results[0] as AgentRow | undefined) ?? null;
  const policyRows = results[2]!.results as unknown as PolicyQueryRow[];

  // ---- identity gates (recorded as decisions) ----------------------------
  let result: EvaluationResult;
  let evalMs = 0;
  let environment = action.environment;
  const gate = identityGate(principal, agent, action.environment, action.agent);
  if (gate) {
    result = gate;
  } else {
    if (agent) environment = agent.environment;
    const policies: PolicyRecord[] = policyRows.map((p) => ({
      id: p.id,
      name: p.name,
      priority: p.priority,
      enabled: p.enabled === 1,
      effect: p.effect,
      scope: p.scope,
      agent_ids: p.bound === 1 && agent ? [agent.id] : [],
      conditions: parseJsonOrInvalid(p.conditions),
      reason_code: p.reason_code,
      reason: p.reason,
      version: p.version,
      created_at: p.created_at,
    }));
    const defaultDecision: DefaultDecision =
      agent && agent.default_mode !== "inherit" ? agent.default_mode : principal.default_decision;
    const t0 = performance.now();
    result = evaluateSafely({
      action: { ...action, environment },
      agentId: agent?.id ?? null,
      policies,
      defaultDecision,
    });
    evalMs = performance.now() - t0;
  }

  // ---- durable evidence ---------------------------------------------------
  const nowMs = deps.now();
  const now = iso(nowMs);
  const decisionId = newId("dec");
  const requestId = normalized.requestId ?? newId("req");
  const gatewayMs = nowMs - started;
  const captureContext = principal.audit_enabled === 1;

  const writes: D1PreparedStatement[] = [
    db
      .prepare(
        `INSERT INTO decisions (id, organization_id, request_id, request_fingerprint, api_key_id, agent_id, agent_key,
            protocol, capability, operation, resource, destination, data_class, environment, mcp_server, mcp_tool,
            decision, reason_code, reason, policy_id, policy_version, matched_policies, context, eval_ms, gateway_ms,
            engine_version, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        decisionId,
        principal.org_id,
        requestId,
        fingerprint,
        principal.key_id,
        agent?.id ?? null,
        action.agent,
        action.protocol,
        action.capability,
        action.operation,
        redactString(action.resource),
        action.destination,
        action.data_class,
        environment,
        action.mcp_server,
        action.mcp_tool,
        result.decision,
        result.reason_code,
        result.reason,
        result.policy?.id ?? null,
        result.policy?.version ?? null,
        JSON.stringify(result.matched),
        captureContext ? JSON.stringify(redactValue(action.context)) : null,
        round(evalMs),
        round(gatewayMs),
        result.engine_version,
        now,
      ),
  ];

  let approval: ApprovalView | null = null;
  if (result.decision === "review") {
    const approvalId = newId("apr");
    const expiresAt = addSeconds(now, principal.approval_ttl_seconds);
    writes.push(
      db
        .prepare(
          `INSERT INTO approvals (id, organization_id, decision_id, status, requested_at, expires_at)
           VALUES (?, ?, ?, 'pending', ?, ?)`,
        )
        .bind(approvalId, principal.org_id, decisionId, now, expiresAt),
    );
    approval = approvalView(
      { id: approvalId, status: "pending", requested_at: now, expires_at: expiresAt, grant_expires_at: null, consumed_at: null },
      nowMs,
    );
  }

  if (!principal.last_used_at || nowMs - Date.parse(principal.last_used_at) > KEY_TOUCH_INTERVAL_MS) {
    writes.push(db.prepare(`UPDATE api_keys SET last_used_at = ? WHERE id = ?`).bind(now, principal.key_id));
  }

  try {
    await db.batch(writes);
  } catch (err) {
    if (isUniqueViolation(err) && normalized.requestId) {
      // A concurrent retry with the same request_id won the insert. Return its decision.
      const [again] = await db.batch([existingDecisionStatement(db, key.hash, normalized.requestId)]);
      const row = (again!.results[0] as ExistingRow | undefined) ?? null;
      if (row) return replay(row, fingerprint, deps);
    }
    throw new ApiError(503, "AUDIT_WRITE_FAILED", "Mother AI could not record decision evidence; failing closed.");
  }

  return json(
    {
      decision_id: decisionId,
      request_id: requestId,
      decision: result.decision,
      reason_code: result.reason_code,
      reason: result.reason,
      policy_id: result.policy?.id ?? null,
      policy_version: result.policy?.version ?? null,
      agent_id: action.agent,
      ...(approval ? { approval_id: approval.approval_id, approval } : {}),
      matched_policies: result.matched.map((m) => ({ policy_id: m.policy_id, effect: m.effect, indeterminate: m.indeterminate })),
      engine_version: result.engine_version,
      evaluated_at: now,
      replayed: false,
      latency_ms: { policy: round(evalMs), gateway: round(gatewayMs) },
    },
    200,
    { "Server-Timing": `policy;dur=${round(evalMs)}, gateway;dur=${round(gatewayMs)}` },
  );
}

function existingDecisionStatement(db: D1Database, keyHash: string, requestId: string): D1PreparedStatement {
  return db
    .prepare(
      `SELECT d.*, ap.id AS approval_id, ap.status AS approval_status, ap.expires_at AS approval_expires_at,
              ap.requested_at AS approval_requested_at, ap.grant_expires_at AS approval_grant_expires_at,
              ap.consumed_at AS approval_consumed_at
         FROM api_keys k
         JOIN decisions d ON d.organization_id = k.organization_id
         LEFT JOIN approvals ap ON ap.decision_id = d.id AND ap.organization_id = d.organization_id
        WHERE k.key_hash = ? AND d.request_id = ?`,
    )
    .bind(keyHash, requestId);
}

function identityGate(
  principal: KeyOrgRow,
  agent: AgentRow | null,
  requestedEnvironment: string | null,
  agentKey: string,
): EvaluationResult | null {
  const block = (reason_code: string, reason: string): EvaluationResult => ({
    decision: "block",
    reason_code,
    reason,
    policy: null,
    matched: [],
    evaluated_policies: 0,
    engine_version: ENGINE_VERSION,
  });
  if (!agent) {
    if (principal.require_registered_agents === 1) {
      return block("AGENT_UNKNOWN", `Agent "${agentKey}" is not registered in this organization.`);
    }
    return null;
  }
  if (agent.status !== "active") return block("AGENT_DISABLED", `Agent "${agentKey}" is disabled.`);
  if (requestedEnvironment && requestedEnvironment !== agent.environment) {
    return block(
      "AGENT_ENVIRONMENT_MISMATCH",
      `Request declared environment "${requestedEnvironment}" but agent "${agentKey}" is registered for "${agent.environment}".`,
    );
  }
  if (principal.key_environment === "test" && agent.environment === "production") {
    return block("API_KEY_ENVIRONMENT_MISMATCH", "Test API keys cannot evaluate actions for production agents.");
  }
  return null;
}

function replay(existing: ExistingRow, fingerprint: string, deps: GatewayDeps): Response {
  if (!timingSafeEqual(existing.request_fingerprint, fingerprint)) {
    throw new ApiError(
      409,
      "IDEMPOTENCY_CONFLICT",
      "This request_id was already used for a different action. Use a new request_id for a new action.",
      { decision_id: existing.id },
    );
  }
  const nowMs = deps.now();
  const approval = existing.approval_id
    ? approvalView(
        {
          id: existing.approval_id,
          status: existing.approval_status!,
          requested_at: existing.approval_requested_at!,
          expires_at: existing.approval_expires_at!,
          grant_expires_at: existing.approval_grant_expires_at,
          consumed_at: existing.approval_consumed_at,
        },
        nowMs,
      )
    : null;
  const matched = parseJson<Array<{ policy_id: string; effect: string; indeterminate: boolean }>>(existing.matched_policies, []);
  return json(
    {
      decision_id: existing.id,
      request_id: existing.request_id,
      decision: existing.decision,
      reason_code: existing.reason_code,
      reason: existing.reason,
      policy_id: existing.policy_id,
      policy_version: existing.policy_version,
      agent_id: existing.agent_key,
      ...(approval ? { approval_id: approval.approval_id, approval } : {}),
      matched_policies: matched.map((m) => ({ policy_id: m.policy_id, effect: m.effect, indeterminate: m.indeterminate })),
      engine_version: existing.engine_version,
      evaluated_at: existing.created_at,
      replayed: true,
    },
    200,
    { "Idempotent-Replayed": "true" },
  );
}

function parseJsonOrInvalid(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    return { __invalid__: true };
  }
}

function round(ms: number): number {
  return Math.round(ms * 1000) / 1000;
}
