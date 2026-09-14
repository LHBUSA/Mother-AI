import { json } from "../../lib/http";
import { parseJson, type ApprovalRow, type DecisionRow } from "../../lib/db";
import { actOnApproval, approvalView, sweepExpiredApprovals } from "../../gateway/approvals";
import { Validator, assertOrgWritable, type ConsoleContext } from "./context";
import { decisionSummary } from "./audit";
import { notifyApprovalEvent } from "../../notifications/approvals";
import { ApiError } from "../../lib/http";
import { iso } from "../../lib/time";
import { isContained } from "../../runtime/engine";
import { scopeState } from "../../runtime/api";

/** An approval inside a quarantined scope, or issued before its containment epoch, cannot be approved. */
async function approvalScopeContained(ctx: ConsoleContext, approvalId: string): Promise<ApiError | null> {
  const row = await ctx.db
    .prepare(
      `SELECT ap.requested_at, d.agent_id, d.session_id, d.api_key_id FROM approvals ap
         JOIN decisions d ON d.id = ap.decision_id AND d.organization_id = ap.organization_id
        WHERE ap.id = ? AND ap.organization_id = ?`,
    )
    .bind(approvalId, ctx.orgId)
    .first<{ requested_at: string; agent_id: string | null; session_id: string | null; api_key_id: string | null }>();
  if (!row) return null;
  const scope = await scopeState(ctx.db, ctx.orgId, row.agent_id, row.session_id, row.api_key_id ?? "-", iso(ctx.nowMs));
  if (scope.epoch && row.requested_at < scope.epoch) {
    return new ApiError(409, "APPROVAL_INVALIDATED", "This request was made before its scope was contained and can no longer be approved.");
  }
  if (ctx.session.organization.runtime_protection === "enforce" && isContained(scope.worst.state)) {
    return new ApiError(409, "SCOPE_QUARANTINED", "This agent or session is quarantined. Approvals cannot restore access; an authorized human must clear the incident first.", {
      incident_id: scope.worst.incidentId,
    });
  }
  return null;
}

type Joined = ApprovalRow & {
  d_id: string;
  d_json: string;
  policy_name: string | null;
  policy_effect: string | null;
  agent_display_name: string | null;
  agent_environment: string | null;
  notification_status: string | null;
  notification_error: string | null;
};

export async function listApprovals(ctx: ConsoleContext): Promise<Response> {
  await sweepExpiredApprovals(ctx.db, ctx.orgId, ctx.nowMs);
  const status = ctx.url.searchParams.get("status") ?? "pending";
  const filter = status === "pending" ? "AND ap.status = 'pending'" : status === "resolved" ? "AND ap.status <> 'pending'" : "";
  const rows = await ctx.db
    .prepare(
      `SELECT ap.*, d.id AS d_id,
              json_object('id', d.id, 'request_id', d.request_id, 'agent_id', d.agent_id, 'agent_key', d.agent_key, 'protocol', d.protocol,
                          'capability', d.capability, 'operation', d.operation, 'resource', d.resource, 'destination', d.destination,
                          'data_class', d.data_class, 'environment', d.environment, 'mcp_server', d.mcp_server, 'mcp_tool', d.mcp_tool,
                          'decision', d.decision, 'reason_code', d.reason_code, 'reason', d.reason, 'policy_id', d.policy_id,
                          'policy_version', d.policy_version, 'created_at', d.created_at, 'context', d.context) AS d_json,
              p.name AS policy_name, p.effect AS policy_effect, a.display_name AS agent_display_name, a.environment AS agent_environment,
              n.status AS notification_status, n.last_error AS notification_error
         FROM approvals ap
         JOIN decisions d ON d.id = ap.decision_id AND d.organization_id = ap.organization_id
         LEFT JOIN policies p ON p.id = d.policy_id AND p.organization_id = d.organization_id
         LEFT JOIN agents a ON a.id = d.agent_id AND a.organization_id = d.organization_id
         LEFT JOIN approval_notifications n ON n.approval_id = ap.id AND n.organization_id = ap.organization_id AND n.event = 'review_required' AND n.channel = 'slack'
        WHERE ap.organization_id = ? ${filter}
        ORDER BY CASE ap.status WHEN 'pending' THEN 0 ELSE 1 END, ap.requested_at DESC
        LIMIT 100`,
    )
    .bind(ctx.orgId)
    .all<Joined>();
  const counts = await ctx.db
    .prepare(`SELECT status, COUNT(*) AS n FROM approvals WHERE organization_id = ? GROUP BY status`)
    .bind(ctx.orgId)
    .all<{ status: string; n: number }>();
  return json({
    approvals: rows.results.map((r) => {
      const d = parseJson<DecisionRow & { context: string | null }>(r.d_json, {} as DecisionRow);
      return {
        ...approvalView(r, ctx.nowMs),
        acted_at: r.acted_at,
        acted_by_name: r.acted_by_name,
        note: r.note,
        decision: { ...decisionSummary(d), context: d.context ? parseJson(d.context, {}) : null },
        policy: d.policy_id ? { id: d.policy_id, name: r.policy_name, effect: r.policy_effect, version: d.policy_version } : null,
        agent: { display_name: r.agent_display_name, environment: r.agent_environment },
        notification: r.notification_status ? { channel: "slack", status: r.notification_status, error: r.notification_error } : null,
        termination: r.terminated_reason ? { reason: r.terminated_reason, incident_id: r.terminated_incident_id, by: "system" } : null,
      };
    }),
    counts: Object.fromEntries(counts.results.map((c) => [c.status, c.n])),
    server_time: new Date(ctx.nowMs).toISOString(),
  });
}

export async function actApproval(ctx: ConsoleContext): Promise<Response> {
  assertOrgWritable(ctx);
  const [id, verb] = ctx.params as [string, "approve" | "deny"];
  const v = new Validator(ctx.body);
  const note = v.string("note", { max: 500, optional: true });
  v.assert();
  if (verb === "approve") {
    const blocked = await approvalScopeContained(ctx, id);
    if (blocked) throw blocked;
  }
  const row = await actOnApproval(
    ctx.db,
    ctx.orgId,
    id,
    { action: verb, note: note || null, actor: ctx.actor, grantTtlSeconds: ctx.session.organization.approval_grant_ttl_seconds },
    ctx.nowMs,
  );
  ctx.waitUntil(notifyApprovalEvent(ctx.env, ctx.orgId, id, verb === "approve" ? "approved" : "denied"));
  return json({ approval: { ...approvalView(row, ctx.nowMs), acted_at: row.acted_at, acted_by_name: row.acted_by_name, note: row.note } });
}
