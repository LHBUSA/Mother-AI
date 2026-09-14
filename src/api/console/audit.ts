import { ApiError, json } from "../../lib/http";
import { parseJson, type ApprovalRow, type DecisionRow } from "../../lib/db";
import { approvalView } from "../../gateway/approvals";
import type { ConsoleContext } from "./context";

export function decisionSummary(d: DecisionRow) {
  return {
    id: d.id,
    request_id: d.request_id,
    agent_id: d.agent_id,
    agent_key: d.agent_key,
    protocol: d.protocol,
    capability: d.capability,
    operation: d.operation,
    resource: d.resource,
    destination: d.destination,
    data_class: d.data_class,
    environment: d.environment,
    mcp_server: d.mcp_server,
    mcp_tool: d.mcp_tool,
    decision: d.decision,
    reason_code: d.reason_code,
    reason: d.reason,
    policy_id: d.policy_id,
    policy_version: d.policy_version,
    created_at: d.created_at,
  };
}

const PAGE = 50;
const TOKEN = /^[a-z0-9][a-z0-9._:/-]{0,127}$/;

export async function listDecisions(ctx: ConsoleContext): Promise<Response> {
  const q = ctx.url.searchParams;
  const where: string[] = ["d.organization_id = ?"];
  const binds: unknown[] = [ctx.orgId];

  const decision = q.get("decision");
  if (decision) {
    if (!["allow", "review", "block"].includes(decision)) throw new ApiError(400, "INVALID_REQUEST", "Invalid decision filter.");
    where.push("d.decision = ?");
    binds.push(decision);
  }
  const agent = q.get("agent");
  if (agent) {
    if (!TOKEN.test(agent)) throw new ApiError(400, "INVALID_REQUEST", "Invalid agent filter.");
    where.push("d.agent_key = ?");
    binds.push(agent);
  }
  const capability = q.get("capability");
  if (capability) {
    if (!TOKEN.test(capability.toLowerCase())) throw new ApiError(400, "INVALID_REQUEST", "Invalid capability filter.");
    where.push("d.capability = ?");
    binds.push(capability.toLowerCase());
  }
  const environment = q.get("environment");
  if (environment) {
    if (!["production", "staging", "development"].includes(environment)) throw new ApiError(400, "INVALID_REQUEST", "Invalid environment filter.");
    where.push("d.environment = ?");
    binds.push(environment);
  }
  const policy = q.get("policy");
  if (policy) {
    if (!/^pol_[0-9A-Za-z]{22}$/.test(policy)) throw new ApiError(400, "INVALID_REQUEST", "Invalid policy filter.");
    where.push("d.policy_id = ?");
    binds.push(policy);
  }
  for (const [param, op] of [["from", ">="], ["to", "<"]] as const) {
    const value = q.get(param);
    if (value) {
      const ms = Date.parse(value);
      if (Number.isNaN(ms)) throw new ApiError(400, "INVALID_REQUEST", `Invalid ${param} date.`);
      where.push(`d.created_at ${op} ?`);
      binds.push(new Date(ms).toISOString());
    }
  }
  const search = q.get("q");
  if (search) {
    if (search.length > 128) throw new ApiError(400, "INVALID_REQUEST", "Search is too long.");
    where.push("(d.request_id = ? OR d.id = ? OR d.resource LIKE ? ESCAPE '\\' OR d.reason_code = ?)");
    const escaped = search.replace(/[\\%_]/g, (c) => `\\${c}`);
    binds.push(search, search, `%${escaped}%`, search.toUpperCase());
  }
  const cursor = q.get("cursor");
  if (cursor) {
    const [ts, id] = cursor.split("|");
    if (!ts || !id || Number.isNaN(Date.parse(ts)) || !/^dec_[0-9A-Za-z]{22}$/.test(id)) throw new ApiError(400, "INVALID_REQUEST", "Invalid cursor.");
    where.push("(d.created_at < ? OR (d.created_at = ? AND d.id < ?))");
    binds.push(ts, ts, id);
  }

  const rows = await ctx.db
    .prepare(
      `SELECT d.*, ap.status AS approval_status, ap.expires_at AS approval_expires_at, p.name AS policy_name
         FROM decisions d
         LEFT JOIN approvals ap ON ap.decision_id = d.id AND ap.organization_id = d.organization_id
         LEFT JOIN policies p ON p.id = d.policy_id AND p.organization_id = d.organization_id
        WHERE ${where.join(" AND ")}
        ORDER BY d.created_at DESC, d.id DESC
        LIMIT ${PAGE + 1}`,
    )
    .bind(...binds)
    .all<DecisionRow & { approval_status: ApprovalRow["status"] | null; approval_expires_at: string | null; policy_name: string | null }>();
  const page = rows.results.slice(0, PAGE);
  const last = page[page.length - 1];
  return json({
    decisions: page.map((d) => ({
      ...decisionSummary(d),
      policy_name: d.policy_name,
      approval_status: d.approval_status && d.approval_expires_at ? approvalView({ id: "", status: d.approval_status, requested_at: "", expires_at: d.approval_expires_at, grant_expires_at: null, consumed_at: null }, ctx.nowMs).status : null,
    })),
    next_cursor: rows.results.length > PAGE && last ? `${last.created_at}|${last.id}` : null,
  });
}

export async function getDecision(ctx: ConsoleContext): Promise<Response> {
  const id = ctx.params[0]!;
  const d = await ctx.db.prepare(`SELECT * FROM decisions WHERE id = ? AND organization_id = ?`).bind(id, ctx.orgId).first<DecisionRow>();
  if (!d) throw new ApiError(404, "NOT_FOUND", "Decision not found.");
  const [approvalRes, versionRes, eventsRes, apiKeyRes] = await ctx.db.batch([
    ctx.db.prepare(`SELECT * FROM approvals WHERE decision_id = ? AND organization_id = ?`).bind(id, ctx.orgId),
    ctx.db
      .prepare(`SELECT snapshot FROM policy_versions WHERE policy_id = ? AND version = ? AND organization_id = ?`)
      .bind(d.policy_id ?? "", d.policy_version ?? -1, ctx.orgId),
    ctx.db
      .prepare(
        `SELECT e.* FROM control_events e
          WHERE e.organization_id = ? AND e.target_type = 'approval'
            AND e.target_id = (SELECT id FROM approvals WHERE decision_id = ? AND organization_id = ?)
          ORDER BY e.created_at`,
      )
      .bind(ctx.orgId, id, ctx.orgId),
    ctx.db.prepare(`SELECT key_prefix, environment FROM api_keys WHERE id = ? AND organization_id = ?`).bind(d.api_key_id ?? "", ctx.orgId),
  ]);
  const approval = approvalRes!.results[0] as ApprovalRow | undefined;
  return json({
    decision: {
      ...decisionSummary(d),
      matched_policies: parseJson(d.matched_policies, []),
      context: d.context === null ? null : parseJson(d.context, {}),
      context_captured: d.context !== null,
      eval_ms: d.eval_ms,
      gateway_ms: d.gateway_ms,
      engine_version: d.engine_version,
      request_fingerprint: d.request_fingerprint,
      api_key: apiKeyRes!.results[0] ?? null,
    },
    policy_snapshot: versionRes!.results[0] ? parseJson((versionRes!.results[0] as { snapshot: string }).snapshot, null) : null,
    approval: approval ? { ...approvalView(approval, ctx.nowMs), acted_at: approval.acted_at, acted_by_name: approval.acted_by_name, note: approval.note } : null,
    approval_events: (eventsRes!.results as Array<{ action: string; actor_label: string | null; actor_type: string; created_at: string; detail: string }>).map((e) => ({
      action: e.action,
      actor_type: e.actor_type,
      actor_label: e.actor_label,
      created_at: e.created_at,
      detail: parseJson(e.detail, {}),
    })),
  });
}

export async function listControlEvents(ctx: ConsoleContext): Promise<Response> {
  const cursor = ctx.url.searchParams.get("cursor");
  const binds: unknown[] = [ctx.orgId];
  let cursorSql = "";
  if (cursor) {
    const [ts, id] = cursor.split("|");
    if (!ts || !id || Number.isNaN(Date.parse(ts)) || !/^evt_[0-9A-Za-z]{22}$/.test(id)) throw new ApiError(400, "INVALID_REQUEST", "Invalid cursor.");
    cursorSql = "AND (created_at < ? OR (created_at = ? AND id < ?))";
    binds.push(ts, ts, id);
  }
  const rows = await ctx.db
    .prepare(`SELECT * FROM control_events WHERE organization_id = ? ${cursorSql} ORDER BY created_at DESC, id DESC LIMIT ${PAGE + 1}`)
    .bind(...binds)
    .all<{ id: string; actor_type: string; actor_label: string | null; action: string; target_type: string | null; target_id: string | null; detail: string; created_at: string }>();
  const page = rows.results.slice(0, PAGE);
  const last = page[page.length - 1];
  return json({
    events: page.map((e) => ({ id: e.id, actor_type: e.actor_type, actor_label: e.actor_label, action: e.action, target_type: e.target_type, target_id: e.target_id, detail: parseJson(e.detail, {}), created_at: e.created_at })),
    next_cursor: rows.results.length > PAGE && last ? `${last.created_at}|${last.id}` : null,
  });
}
