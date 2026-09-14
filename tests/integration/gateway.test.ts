import { beforeEach, describe, expect, it } from "vitest";
import { call, createEnv, seedAgent, seedKey, seedOrg, seedPolicy, seedSession, type TestEnv } from "../helpers/env";

const refund = (amount: number, requestId?: string) => ({
  ...(requestId ? { request_id: requestId } : {}),
  agent_id: "billing-agent-prod",
  capability: "payments",
  operation: "refund",
  resource: "payment:pi_123",
  destination: "internal",
  data_class: "financial",
  context: { amount, currency: "USD" },
});

async function setupFinanceOrg(env: TestEnv) {
  const orgId = await seedOrg(env);
  const key = await seedKey(env, orgId);
  const agentId = await seedAgent(env, orgId, "billing-agent-prod");
  const researchId = await seedAgent(env, orgId, "research-agent-prod");
  await seedPolicy(env, orgId, {
    name: "Refunds allowed",
    effect: "allow",
    agentIds: [agentId],
    conditions: { match: "all", conditions: [{ field: "capability", operator: "equals", value: "payments" }, { field: "operation", operator: "equals", value: "refund" }] },
  });
  await seedPolicy(env, orgId, {
    name: "High value refunds",
    effect: "review",
    priority: 20,
    agentIds: [agentId],
    conditions: {
      match: "all",
      conditions: [
        { field: "capability", operator: "equals", value: "payments" },
        { field: "context.amount", operator: "greater_than", value: 1000 },
      ],
    },
  });
  await seedPolicy(env, orgId, {
    name: "Research read only",
    effect: "allow",
    agentIds: [researchId],
    conditions: { match: "all", conditions: [{ field: "operation", operator: "equals", value: "read" }] },
  });
  await seedPolicy(env, orgId, {
    name: "Research no modify",
    effect: "block",
    priority: 10,
    agentIds: [researchId],
    reasonCode: "OPERATION_NOT_ALLOWED",
    conditions: { match: "all", conditions: [{ field: "operation", operator: "in", value: ["modify", "update", "delete"] }] },
  });
  await seedPolicy(env, orgId, {
    name: "Restricted egress",
    effect: "block",
    priority: 1,
    reasonCode: "RESTRICTED_DATA_EGRESS",
    conditions: { match: "all", conditions: [{ field: "data_class", operator: "equals", value: "restricted" }, { field: "destination", operator: "equals", value: "external" }] },
  });
  return { orgId, key, agentId, researchId };
}

describe("POST /v1/evaluate", () => {
  let env: TestEnv;
  let org: Awaited<ReturnType<typeof setupFinanceOrg>>;

  beforeEach(async () => {
    env = createEnv();
    org = await setupFinanceOrg(env);
  });

  it("allows, and records the decision before responding", async () => {
    const res = await call(env, "/v1/evaluate", { key: org.key.raw, json: refund(420, "req_allow_1") });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.decision).toBe("allow");
    expect(body.reason_code).toBe("POLICY_ALLOW");
    expect(body.request_id).toBe("req_allow_1");
    expect(String(body.decision_id)).toMatch(/^dec_/);
    expect(res.headers.get("Server-Timing")).toMatch(/policy;dur=/);
    const row = await env.DB.prepare(`SELECT decision, policy_id, context FROM decisions WHERE id = ?`).bind(body.decision_id).first<{ decision: string; policy_id: string; context: string }>();
    expect(row?.decision).toBe("allow");
    expect(row?.policy_id).toBe(body.policy_id);
    expect(JSON.parse(row!.context)).toEqual({ amount: 420, currency: "USD" });
  });

  it("blocks an unauthorized modify with the policy's reason code", async () => {
    const res = await call(env, "/v1/evaluate", { key: org.key.raw, json: { agent_id: "research-agent-prod", capability: "records", operation: "modify", resource: "customer:1" } });
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.decision).toBe("block");
    expect(body.reason_code).toBe("OPERATION_NOT_ALLOWED");
  });

  it("blocks restricted external egress", async () => {
    const res = await call(env, "/v1/evaluate", {
      key: org.key.raw,
      json: { agent_id: "research-agent-prod", capability: "records", operation: "read", data_class: "restricted", destination: "external" },
    });
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.decision).toBe("block");
    expect(body.reason_code).toBe("RESTRICTED_DATA_EGRESS");
  });

  it("returns review with a pending approval above the threshold", async () => {
    const res = await call(env, "/v1/evaluate", { key: org.key.raw, json: refund(4200, "req_review_1") });
    const body = (await res.json()) as { decision: string; reason_code: string; approval_id: string; approval: { status: string; executable: boolean; expires_at: string } };
    expect(body.decision).toBe("review");
    expect(body.reason_code).toBe("HUMAN_APPROVAL_REQUIRED");
    expect(body.approval_id).toMatch(/^apr_/);
    expect(body.approval.status).toBe("pending");
    expect(body.approval.executable).toBe(false);
  });

  it("fails closed on unknown agents and records the attempt", async () => {
    const res = await call(env, "/v1/evaluate", { key: org.key.raw, json: { agent_id: "shadow-agent", capability: "db", operation: "query" } });
    const body = (await res.json()) as Record<string, unknown>;
    expect(res.status).toBe(200);
    expect(body.decision).toBe("block");
    expect(body.reason_code).toBe("AGENT_UNKNOWN");
    const n = await env.DB.prepare(`SELECT COUNT(*) AS n FROM decisions WHERE agent_key = 'shadow-agent'`).first<{ n: number }>();
    expect(n?.n).toBe(1);
  });

  it("blocks disabled agents, environment mismatches and test keys on production agents", async () => {
    await env.DB.prepare(`UPDATE agents SET status = 'disabled' WHERE id = ?`).bind(org.researchId).run();
    const disabled = (await (await call(env, "/v1/evaluate", { key: org.key.raw, json: { agent_id: "research-agent-prod", capability: "records", operation: "read" } })).json()) as Record<string, unknown>;
    expect(disabled.reason_code).toBe("AGENT_DISABLED");

    const mismatch = (await (await call(env, "/v1/evaluate", { key: org.key.raw, json: { ...refund(10), environment: "staging" } })).json()) as Record<string, unknown>;
    expect(mismatch.reason_code).toBe("AGENT_ENVIRONMENT_MISMATCH");

    const testKey = await seedKey(env, org.orgId, "test");
    const viaTest = (await (await call(env, "/v1/evaluate", { key: testKey.raw, json: refund(10) })).json()) as Record<string, unknown>;
    expect(viaTest.reason_code).toBe("API_KEY_ENVIRONMENT_MISMATCH");
  });

  it("rejects missing, malformed and unknown keys with decision:block", async () => {
    const missing = await call(env, "/v1/evaluate", { json: refund(1) });
    expect(missing.status).toBe(401);
    expect(await missing.json()).toMatchObject({ decision: "block", error: { code: "MISSING_API_KEY" } });

    const malformed = await call(env, "/v1/evaluate", { key: "sk_live_nope", json: refund(1) });
    expect(malformed.status).toBe(401);
    expect(await malformed.json()).toMatchObject({ decision: "block", error: { code: "INVALID_API_KEY" } });

    const unknown = await call(env, "/v1/evaluate", { key: `mai_live_${"x".repeat(40)}`, json: refund(1) });
    expect(unknown.status).toBe(401);
    expect(await unknown.json()).toMatchObject({ decision: "block", error: { code: "INVALID_API_KEY" } });
  });

  it("rejects revoked keys", async () => {
    await env.DB.prepare(`UPDATE api_keys SET revoked_at = ? WHERE id = ?`).bind(new Date().toISOString(), org.key.id).run();
    const res = await call(env, "/v1/evaluate", { key: org.key.raw, json: refund(1) });
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ decision: "block", error: { code: "API_KEY_REVOKED" } });
  });

  it("rejects suspended organizations and disabled gateways", async () => {
    await env.DB.prepare(`UPDATE organizations SET gateway_enabled = 0 WHERE id = ?`).bind(org.orgId).run();
    expect(await (await call(env, "/v1/evaluate", { key: org.key.raw, json: refund(1) })).json()).toMatchObject({ decision: "block", error: { code: "GATEWAY_DISABLED" } });
    await env.DB.prepare(`UPDATE organizations SET gateway_enabled = 1, status = 'suspended' WHERE id = ?`).bind(org.orgId).run();
    const res = await call(env, "/v1/evaluate", { key: org.key.raw, json: refund(1) });
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ decision: "block", error: { code: "ORGANIZATION_DISABLED" } });
  });

  it("validates requests strictly", async () => {
    const res = await call(env, "/v1/evaluate", { key: org.key.raw, json: { agent_id: "Billing Agent!", capability: "", operation: "refund", surprise: true, context: [] } });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { decision: string; error: { code: string; fields: Record<string, string> } };
    expect(body.decision).toBe("block");
    expect(body.error.code).toBe("INVALID_REQUEST");
    expect(Object.keys(body.error.fields).sort()).toEqual(["agent_id", "capability", "context", "surprise"]);

    const notJson = await call(env, "/v1/evaluate", { key: org.key.raw, method: "POST", body: "{nope", headers: { "Content-Type": "application/json" } });
    expect(notJson.status).toBe(400);
    const wrongType = await call(env, "/v1/evaluate", { key: org.key.raw, method: "POST", body: "a=b", headers: { "Content-Type": "application/x-www-form-urlencoded" } });
    expect(wrongType.status).toBe(415);
    const tooBig = await call(env, "/v1/evaluate", { key: org.key.raw, json: { ...refund(1), context: { blob: "x".repeat(9000) } } });
    expect(tooBig.status).toBe(400);
    const get = await call(env, "/v1/evaluate", { key: org.key.raw });
    expect(get.status).toBe(405);
  });

  it("is idempotent: an identical retry returns the same decision without a second record", async () => {
    const first = (await (await call(env, "/v1/evaluate", { key: org.key.raw, json: refund(4200, "req_idem_1") })).json()) as Record<string, unknown>;
    const retry = await call(env, "/v1/evaluate", { key: org.key.raw, json: refund(4200, "req_idem_1") });
    const second = (await retry.json()) as Record<string, unknown>;
    expect(retry.headers.get("Idempotent-Replayed")).toBe("true");
    expect(second.replayed).toBe(true);
    expect(second.decision_id).toBe(first.decision_id);
    expect(second.approval_id).toBe(first.approval_id);
    const n = await env.DB.prepare(`SELECT COUNT(*) AS n FROM decisions WHERE request_id = 'req_idem_1'`).first<{ n: number }>();
    expect(n?.n).toBe(1);
    const a = await env.DB.prepare(`SELECT COUNT(*) AS n FROM approvals`).first<{ n: number }>();
    expect(a?.n).toBe(1);
  });

  it("rejects reuse of a request_id for a different action", async () => {
    await call(env, "/v1/evaluate", { key: org.key.raw, json: refund(420, "req_conflict") });
    const res = await call(env, "/v1/evaluate", { key: org.key.raw, json: refund(9999, "req_conflict") });
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({ decision: "block", error: { code: "IDEMPOTENCY_CONFLICT" } });
  });

  it("isolates tenants: another org's key cannot see agents, policies or request ids", async () => {
    const other = await seedOrg(env, { name: "Globex" });
    const otherKey = await seedKey(env, other);
    await call(env, "/v1/evaluate", { key: org.key.raw, json: refund(420, "req_shared_id") });
    const res = await call(env, "/v1/evaluate", { key: otherKey.raw, json: refund(420, "req_shared_id") });
    const body = (await res.json()) as Record<string, unknown>;
    // Org B has no billing-agent-prod: it must not inherit org A's agent, policies or decision.
    expect(body.replayed).toBe(false);
    expect(body.decision).toBe("block");
    expect(body.reason_code).toBe("AGENT_UNKNOWN");
    const approval = (await (await call(env, "/v1/evaluate", { key: org.key.raw, json: refund(5000, "req_iso_review") })).json()) as { approval_id: string };
    const peek = await call(env, `/v1/approvals/${approval.approval_id}`, { key: otherKey.raw });
    expect(peek.status).toBe(404);
  });

  it("fails closed when a stored policy is malformed", async () => {
    await seedPolicy(env, org.orgId, { name: "Corrupt", effect: "allow", conditions: null, rawConditions: "{not json" });
    const body = (await (await call(env, "/v1/evaluate", { key: org.key.raw, json: refund(10) })).json()) as Record<string, unknown>;
    expect(body.decision).toBe("block");
    expect(body.reason_code).toBe("POLICY_INVALID");
  });

  it("ignores disabled policies", async () => {
    await env.DB.prepare(`UPDATE policies SET enabled = 0 WHERE name = 'Refunds allowed'`).run();
    const body = (await (await call(env, "/v1/evaluate", { key: org.key.raw, json: refund(10) })).json()) as Record<string, unknown>;
    expect(body.decision).toBe("block");
    expect(body.reason_code).toBe("DEFAULT_DENY");
  });

  it("redacts credentials from stored evidence", async () => {
    const res = await call(env, "/v1/evaluate", {
      key: org.key.raw,
      json: { ...refund(10, "req_redact"), context: { amount: 10, api_key: "sk_live_abcdefghijklmnop", note: `use Bearer abcdefghijklmnopqrstuvwxyz`, nested: { password: "hunter2" }, echo: org.key.raw } },
    });
    expect(res.status).toBe(200);
    const row = await env.DB.prepare(`SELECT context FROM decisions WHERE request_id = 'req_redact'`).first<{ context: string }>();
    const stored = JSON.parse(row!.context);
    expect(stored).toEqual({ amount: 10, api_key: "[REDACTED]", note: "[REDACTED]", nested: { password: "[REDACTED]" }, echo: "[REDACTED]" });
    expect(row!.context).not.toContain(org.key.raw);
  });

  it("does not capture context when audit capture is disabled", async () => {
    await env.DB.prepare(`UPDATE organizations SET audit_enabled = 0 WHERE id = ?`).bind(org.orgId).run();
    await call(env, "/v1/evaluate", { key: org.key.raw, json: refund(10, "req_noaudit") });
    const row = await env.DB.prepare(`SELECT context, decision FROM decisions WHERE request_id = 'req_noaudit'`).first<{ context: string | null; decision: string }>();
    expect(row?.decision).toBe("allow");
    expect(row?.context).toBeNull();
  });

  it("rate limits per IP and per key, failing closed", async () => {
    env.limiters.RL_GATEWAY_IP!.blocked = true;
    const res = await call(env, "/v1/evaluate", { key: org.key.raw, json: refund(1) });
    expect(res.status).toBe(429);
    expect(await res.json()).toMatchObject({ decision: "block", error: { code: "RATE_LIMITED" } });
    env.limiters.RL_GATEWAY_IP!.blocked = false;
    env.limiters.RL_GATEWAY_KEY!.blocked = true;
    expect((await call(env, "/v1/evaluate", { key: org.key.raw, json: refund(1) })).status).toBe(429);
  });

  it("does not emit CORS headers", async () => {
    const res = await call(env, "/v1/evaluate", { key: org.key.raw, json: refund(1), headers: { Origin: "https://evil.example" } });
    expect(res.headers.get("Access-Control-Allow-Origin")).toBeNull();
  });
});

describe("POST /v1/mcp/evaluate", () => {
  it("normalizes an MCP tool call and evaluates it", async () => {
    const env = createEnv();
    const orgId = await seedOrg(env);
    const key = await seedKey(env, orgId);
    const agentId = await seedAgent(env, orgId, "sales-agent-prod");
    await seedPolicy(env, orgId, {
      name: "CRM updates via MCP",
      effect: "allow",
      agentIds: [agentId],
      conditions: { match: "all", conditions: [{ field: "protocol", operator: "equals", value: "mcp" }, { field: "mcp.server", operator: "equals", value: "salesforce" }, { field: "mcp.tool", operator: "equals", value: "contacts.update" }] },
    });
    await seedPolicy(env, orgId, {
      name: "No deletes",
      effect: "block",
      conditions: { match: "all", conditions: [{ field: "operation", operator: "glob", value: "*.delete" }] },
    });
    const allow = (await (await call(env, "/v1/mcp/evaluate", { key: key.raw, json: { request_id: "mcp-1", agent_id: "sales-agent-prod", server: "salesforce", tool: "contacts.update", arguments: { id: "003", title: "VP" } } })).json()) as Record<string, unknown>;
    expect(allow.decision).toBe("allow");
    const block = (await (await call(env, "/v1/mcp/evaluate", { key: key.raw, json: { agent_id: "sales-agent-prod", server: "salesforce", tool: "contacts.delete", arguments: { id: "003" } } })).json()) as Record<string, unknown>;
    expect(block.decision).toBe("block");
    const row = await env.DB.prepare(`SELECT protocol, capability, operation, mcp_server, mcp_tool, context FROM decisions WHERE request_id = 'mcp-1'`).first<Record<string, string>>();
    expect(row).toMatchObject({ protocol: "mcp", capability: "salesforce", operation: "contacts.update", mcp_server: "salesforce", mcp_tool: "contacts.update" });
    expect(JSON.parse(row!.context)).toEqual({ id: "003", title: "VP" });

    // The same action through /v1/evaluate has the same fingerprint, so the request_id replays.
    const viaGeneric = (await (
      await call(env, "/v1/evaluate", {
        key: key.raw,
        json: { request_id: "mcp-1", agent_id: "sales-agent-prod", protocol: "mcp", capability: "salesforce", operation: "contacts.update", mcp: { server: "salesforce", tool: "contacts.update" }, context: { id: "003", title: "VP" } },
      })
    ).json()) as Record<string, unknown>;
    expect(viaGeneric.replayed).toBe(true);
  });
});

describe("approval lifecycle", () => {
  let env: TestEnv;
  let org: Awaited<ReturnType<typeof setupFinanceOrg>>;
  let approvalId: string;
  let decisionId: string;

  beforeEach(async () => {
    env = createEnv();
    org = await setupFinanceOrg(env);
    const body = (await (await call(env, "/v1/evaluate", { key: org.key.raw, json: refund(4200, "req_approval") })).json()) as { approval_id: string; decision_id: string };
    approvalId = body.approval_id;
    decisionId = body.decision_id;
  });

  it("approved: approver approves, agent sees executable, consumes once, replay is refused", async () => {
    const approver = await seedSession(env, org.orgId, "approver", "Dana Approver");
    const act = await call(env, `/api/console/approvals/${approvalId}/approve`, { cookie: approver.cookie, json: { note: "Customer verified" } });
    expect(act.status).toBe(200);

    const view = (await (await call(env, `/v1/approvals/${approvalId}`, { key: org.key.raw })).json()) as Record<string, unknown>;
    expect(view).toMatchObject({ status: "approved", executable: true, decision_id: decisionId, request_id: "req_approval" });

    const consume = await call(env, `/v1/approvals/${approvalId}/consume`, { key: org.key.raw, method: "POST" });
    expect(consume.status).toBe(200);
    expect(await consume.json()).toMatchObject({ status: "approved", executable: false });

    const again = await call(env, `/v1/approvals/${approvalId}/consume`, { key: org.key.raw, method: "POST" });
    expect(again.status).toBe(409);
    expect(await again.json()).toMatchObject({ decision: "block", error: { code: "APPROVAL_ALREADY_CONSUMED" } });

    // The original decision is untouched and evidence was appended.
    const decision = await env.DB.prepare(`SELECT decision FROM decisions WHERE id = ?`).bind(decisionId).first<{ decision: string }>();
    expect(decision?.decision).toBe("review");
    const events = await env.DB.prepare(`SELECT action, actor_label FROM control_events WHERE target_id = ? ORDER BY created_at`).bind(approvalId).all<{ action: string; actor_label: string }>();
    expect(events.results.map((e) => e.action)).toEqual(["approval.approved", "approval.consumed"]);
    expect(events.results[0]!.actor_label).toBe("Dana Approver");

    // A retry of the original evaluate reflects the approval state without a new decision.
    const retry = (await (await call(env, "/v1/evaluate", { key: org.key.raw, json: refund(4200, "req_approval") })).json()) as { decision: string; approval: { status: string; consumed_at: string | null } };
    expect(retry.decision).toBe("review");
    expect(retry.approval.status).toBe("approved");
    expect(retry.approval.consumed_at).not.toBeNull();
  });

  it("denied: agent cannot consume", async () => {
    const approver = await seedSession(env, org.orgId, "approver");
    expect((await call(env, `/api/console/approvals/${approvalId}/deny`, { cookie: approver.cookie, json: {} })).status).toBe(200);
    const consume = await call(env, `/v1/approvals/${approvalId}/consume`, { key: org.key.raw, method: "POST" });
    expect(consume.status).toBe(409);
    expect(await consume.json()).toMatchObject({ error: { code: "APPROVAL_DENIED" } });
    const second = await call(env, `/api/console/approvals/${approvalId}/approve`, { cookie: approver.cookie, json: {} });
    expect(second.status).toBe(409);
  });

  it("expired: cannot be approved or executed", async () => {
    await env.shim.sqlite.exec(`DROP TRIGGER approvals_transitions`);
    await env.DB.prepare(`UPDATE approvals SET expires_at = ? WHERE id = ?`).bind(new Date(Date.now() - 1000).toISOString(), approvalId).run();
    await env.shim.sqlite.exec(
      `CREATE TRIGGER approvals_transitions BEFORE UPDATE ON approvals WHEN NOT (NEW.id = OLD.id AND ((OLD.status = 'pending' AND NEW.status IN ('approved','denied','expired')) OR (OLD.status='approved' AND NEW.status='approved' AND OLD.consumed_at IS NULL AND NEW.consumed_at IS NOT NULL))) BEGIN SELECT RAISE(ABORT, 'invalid approval transition'); END;`,
    );
    const view = (await (await call(env, `/v1/approvals/${approvalId}`, { key: org.key.raw })).json()) as Record<string, unknown>;
    expect(view).toMatchObject({ status: "expired", executable: false });
    const approver = await seedSession(env, org.orgId, "approver");
    const act = await call(env, `/api/console/approvals/${approvalId}/approve`, { cookie: approver.cookie, json: {} });
    expect(act.status).toBe(409);
    expect(await act.json()).toMatchObject({ error: { code: "APPROVAL_EXPIRED" } });
    const stored = await env.DB.prepare(`SELECT status FROM approvals WHERE id = ?`).bind(approvalId).first<{ status: string }>();
    expect(stored?.status).toBe("expired");
    const consume = await call(env, `/v1/approvals/${approvalId}/consume`, { key: org.key.raw, method: "POST" });
    expect(await consume.json()).toMatchObject({ error: { code: "APPROVAL_EXPIRED" } });
  });

  it("a viewer cannot approve", async () => {
    const viewer = await seedSession(env, org.orgId, "viewer");
    const res = await call(env, `/api/console/approvals/${approvalId}/approve`, { cookie: viewer.cookie, json: {} });
    expect(res.status).toBe(403);
  });

  it("an approver in another organization cannot act", async () => {
    const other = await seedOrg(env, { name: "Globex" });
    const outsider = await seedSession(env, other, "owner");
    const res = await call(env, `/api/console/approvals/${approvalId}/approve`, { cookie: outsider.cookie, json: {} });
    expect(res.status).toBe(404);
  });
});

describe("append-only evidence", () => {
  it("rejects UPDATE and DELETE on decisions, control events and policy versions, and illegal approval transitions", async () => {
    const env = createEnv();
    const org = await setupFinanceOrg(env);
    const body = (await (await call(env, "/v1/evaluate", { key: org.key.raw, json: refund(4200, "req_tamper") })).json()) as { decision_id: string; approval_id: string };
    expect(() => env.shim.sqlite.exec(`UPDATE decisions SET decision = 'allow' WHERE id = '${body.decision_id}'`)).toThrow(/append-only/);
    expect(() => env.shim.sqlite.exec(`DELETE FROM decisions`)).toThrow(/append-only/);
    env.shim.sqlite.exec(`INSERT INTO control_events (id, organization_id, actor_type, action, created_at) VALUES ('evt_x', '${org.orgId}', 'system', 'x', 'now')`);
    expect(() => env.shim.sqlite.exec(`DELETE FROM control_events`)).toThrow(/append-only/);
    expect(() => env.shim.sqlite.exec(`UPDATE approvals SET decision_id = 'dec_other' WHERE id = '${body.approval_id}'`)).toThrow(/invalid approval transition/);
    env.shim.sqlite.exec(`UPDATE approvals SET status = 'denied' WHERE id = '${body.approval_id}'`);
    expect(() => env.shim.sqlite.exec(`UPDATE approvals SET status = 'approved' WHERE id = '${body.approval_id}'`)).toThrow(/invalid approval transition/);
  });
});
