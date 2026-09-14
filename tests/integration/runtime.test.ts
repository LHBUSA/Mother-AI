import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { base64UrlEncode } from "../../src/lib/crypto";
import { call, createEnv, seedAgent, seedKey, seedOrg, seedPolicy, seedSession, type TestEnv } from "../helpers/env";
import { NOTIFY_TUNING } from "../../src/notifications/approvals";

const SLACK_HOST = ["hooks", "slack", "com"].join(".");
const WEBHOOK = `https://${SLACK_HOST}/services/T0RUNTIME/B0RUNTIME/${"r".repeat(24)}`;

type Json = Record<string, any>;

async function setupOrg(env: TestEnv, opts: { mode?: "off" | "monitor" | "enforce"; name?: string } = {}) {
  const orgId = await seedOrg(env, { name: opts.name ?? "Runtime Co" });
  if (opts.mode) await env.DB.prepare(`UPDATE organizations SET runtime_protection = ? WHERE id = ?`).bind(opts.mode, orgId).run();
  const key = await seedKey(env, orgId);
  const agentId = await seedAgent(env, orgId, "ops-agent");
  const helperId = await seedAgent(env, orgId, "helper-agent");
  const capOp = (op: string) => ({ match: "all", conditions: [{ field: "capability", operator: "equals", value: "canary.records" }, { field: "operation", operator: "equals", value: op }] });
  await seedPolicy(env, orgId, { name: "Read records", effect: "allow", conditions: capOp("read") });
  await seedPolicy(env, orgId, { name: "No deletes", effect: "block", priority: 10, reasonCode: "OPERATION_NOT_ALLOWED", conditions: capOp("delete") });
  await seedPolicy(env, orgId, { name: "Exports need review", effect: "review", priority: 20, conditions: capOp("export") });
  const owner = await seedSession(env, orgId, "owner", "Olive Owner");
  return { orgId, key, agentId, helperId, owner };
}

const act = (operation: string, extra: Json = {}) => ({ agent_id: "ops-agent", capability: "canary.records", operation, resource: "canary:doc-1", ...extra });

describe("runtime containment V1", () => {
  const realFetch = globalThis.fetch;
  const tuning = { ...NOTIFY_TUNING };
  let env: TestEnv;
  let slackCalls: Array<{ url: string; body: string }>;
  let slackMode: "ok" | "500" | "timeout";

  beforeEach(() => {
    env = createEnv({ NOTIFICATION_ENCRYPTION_KEY: base64UrlEncode(crypto.getRandomValues(new Uint8Array(32))) });
    slackCalls = [];
    slackMode = "ok";
    Object.assign(NOTIFY_TUNING, { inlineRetryDelayMs: 0, timeoutMs: 50 });
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (!url.includes(SLACK_HOST)) return realFetch(input, init);
      slackCalls.push({ url, body: String(init?.body ?? "") });
      if (slackMode === "timeout") return new Promise<Response>((_, reject) => init?.signal?.addEventListener("abort", () => reject(init.signal!.reason)));
      return new Response(slackMode === "ok" ? "ok" : "error", { status: slackMode === "ok" ? 200 : 500 });
    }) as typeof fetch;
    for (const level of ["log", "warn", "error"] as const) vi.spyOn(console, level).mockImplementation(() => {});
  });

  afterEach(() => {
    globalThis.fetch = realFetch;
    Object.assign(NOTIFY_TUNING, tuning);
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  const evaluate = async (key: string, body: Json, path = "/v1/evaluate") => {
    const res = await call(env, path, { json: body, key });
    return { status: res.status, body: (await res.json()) as Json };
  };
  const openSession = async (key: string, body: Json = { agent_id: "ops-agent", principal: { type: "user", ref: "u-17" } }) => {
    const res = await call(env, "/v1/sessions", { json: body, key });
    return { status: res.status, body: (await res.json()) as Json };
  };
  const console_ = async (cookie: string, path: string, body?: Json, method?: string) => {
    const res = await call(env, path, body === undefined ? { cookie } : { json: body, cookie, ...(method ? { method } : {}) });
    return { status: res.status, body: (await res.json()) as Json };
  };
  const all = async (sql: string, ...binds: unknown[]) => (await env.DB.prepare(sql).bind(...binds).all<Json>()).results;
  const one = async (sql: string, ...binds: unknown[]) => env.DB.prepare(sql).bind(...binds).first<Json>();
  const subject = (type: string, id: string) => one(`SELECT * FROM risk_subjects WHERE subject_type = ? AND subject_id = ?`, type, id);

  /** The deterministic canary sequence: allow, 3 blocked deletes, unseen MCP tool, review read, restricted read. */
  async function suspiciousSequence(key: string, sessionId: string) {
    const s = { session_id: sessionId };
    const out: Json[] = [];
    out.push((await evaluate(key, act("read", s))).body);
    for (let i = 0; i < 3; i++) out.push((await evaluate(key, act("delete", s))).body);
    out.push((await evaluate(key, { agent_id: "ops-agent", server: "shell", tool: "exec", session_id: sessionId }, "/v1/mcp/evaluate")).body);
    out.push((await evaluate(key, act("read", s))).body);
    out.push((await evaluate(key, act("read", { ...s, data_class: "restricted" }))).body);
    return out;
  }

  // ------------------------------------------------------------------ monitor
  it("monitor mode: signals and risk evidence are recorded, but no decision changes, nothing is quarantined and no alert is sent by default", async () => {
    const org = await setupOrg(env, { mode: "monitor" });
    // A Slack destination exists, but security alerts are off by default: nothing is sent.
    await console_(org.owner.cookie, "/api/console/notifications/slack", { webhook_url: WEBHOOK });
    expect(await one(`SELECT runtime_protection, security_alerts_enabled FROM organizations WHERE id = ?`, org.orgId)).toEqual({ runtime_protection: "monitor", security_alerts_enabled: 0 });
    slackCalls = [];
    const session = (await openSession(org.key.raw)).body.session_id;
    const results = await suspiciousSequence(org.key.raw, session);
    expect(results.map((r) => r.decision)).toEqual(["allow", "block", "block", "block", "block", "allow", "allow"]);
    for (const r of results) expect(r.risk.effective_decision).toBe(r.risk.policy_decision);
    expect(results[6]!.risk.runtime_risk_decision).toBe("block"); // would have quarantined
    // A hard violation in monitor mode is recorded, not enforced.
    await call(env, "/v1/events", { json: { type: "execution.reported", decision_id: results[1]!.decision_id, outcome: "succeeded" }, key: org.key.raw });
    const evals = await all(`SELECT mode, policy_decision, effective_decision FROM risk_evaluations WHERE organization_id = ?`, org.orgId);
    expect(evals.length).toBe(7);
    for (const e of evals) expect([e.mode, e.effective_decision]).toEqual(["monitor", e.policy_decision]);
    expect((await subject("agent", org.agentId))!.state).toBe("review_required");
    const hard = await all(`SELECT signal, subject_type, mode FROM risk_signals WHERE organization_id = ? AND hard = 1 ORDER BY subject_type`, org.orgId);
    expect(hard).toEqual([
      { signal: "EXECUTED_WITHOUT_AUTHORIZATION", subject_type: "agent", mode: "monitor" },
      { signal: "EXECUTED_WITHOUT_AUTHORIZATION", subject_type: "session", mode: "monitor" },
    ]);
    expect(await all(`SELECT * FROM security_incidents`)).toHaveLength(0);
    expect(await all(`SELECT * FROM risk_subjects WHERE state IN ('quarantined', 'contained')`)).toHaveLength(0);
    expect(await all(`SELECT * FROM security_notifications`)).toHaveLength(0);
    expect(slackCalls).toHaveLength(0);
    expect((await console_(org.owner.cookie, "/api/console/security/quarantine", { subject_type: "agent", subject_id: org.agentId, note: "manual in monitor" })).status).toBe(409);
    // Existing clients (no correlation fields) see exactly the old response shape.
    const legacy = (await evaluate(org.key.raw, act("read"))).body;
    expect(legacy.decision).toBe("allow");
    expect(legacy).not.toHaveProperty("risk");
    expect(legacy).not.toHaveProperty("session_id");
  });

  // ------------------------------------------------------------------ invariant
  it("effective-decision invariant: the database rejects any risk evaluation that relaxes policy or disagrees with the stored decision", async () => {
    const org = await setupOrg(env, { mode: "enforce" });
    const verdicts = ["allow", "review", "block"] as const;
    const rank = { allow: 0, review: 1, block: 2 } as const;
    let accepted = 0;
    let rejected = 0;
    for (const mode of ["monitor", "enforce"] as const) {
      for (const policy of verdicts) {
        for (const runtime of verdicts) {
          for (const effective of verdicts) {
            const expected = mode === "monitor" ? policy : verdicts[Math.max(rank[policy], rank[runtime])]!;
            const decisionId = `dec_${crypto.randomUUID().replace(/-/g, "").slice(0, 22)}`;
            await env.DB.prepare(
              `INSERT INTO decisions (id, organization_id, request_id, request_fingerprint, agent_key, protocol, capability, operation, decision, reason_code, reason, engine_version, created_at)
               VALUES (?, ?, ?, 'f', 'ops-agent', 'api', 'c', 'o', ?, 'X', 'x', 'mpe-1.0.0', ?)`,
            ).bind(decisionId, org.orgId, decisionId, effective, new Date().toISOString()).run();
            const insert = env.DB.prepare(
              `INSERT INTO risk_evaluations (decision_id, organization_id, engine_version, mode, policy_decision, runtime_risk_decision, effective_decision, effective_state, created_at)
               VALUES (?, ?, 'mre-1.0.0', ?, ?, ?, ?, 'normal', ?)`,
            ).bind(decisionId, org.orgId, mode, policy, runtime, effective, new Date().toISOString());
            if (effective === expected) {
              await insert.run();
              accepted++;
            } else {
              await expect(insert.run()).rejects.toThrow(/CHECK constraint failed/);
              rejected++;
            }
            expect(rank[effective] >= rank[policy] || effective !== expected).toBe(true);
          }
        }
      }
    }
    expect([accepted, rejected]).toEqual([18, 36]);
    // A risk evaluation whose effective decision differs from the recorded decision row is rejected by trigger.
    const decisionId = `dec_${"m".repeat(22)}`;
    await env.DB.prepare(
      `INSERT INTO decisions (id, organization_id, request_id, request_fingerprint, agent_key, protocol, capability, operation, decision, reason_code, reason, engine_version, created_at)
       VALUES (?, ?, 'mismatch', 'f', 'ops-agent', 'api', 'c', 'o', 'allow', 'X', 'x', 'mpe-1.0.0', ?)`,
    ).bind(decisionId, org.orgId, new Date().toISOString()).run();
    await expect(
      env.DB.prepare(
        `INSERT INTO risk_evaluations (decision_id, organization_id, engine_version, mode, policy_decision, runtime_risk_decision, effective_decision, effective_state, created_at)
         VALUES (?, ?, 'mre-1.0.0', 'enforce', 'block', 'block', 'block', 'normal', ?)`,
      ).bind(decisionId, org.orgId, new Date().toISOString()).run(),
    ).rejects.toThrow(/does not match the recorded decision/);
  });

  // ------------------------------------------------------------------ canary
  it("controlled canary: allowed → suspicious sequence → risk rises → quarantine → next action BLOCKED → Slack incident → human clears → narrow lease works again", async () => {
    const org = await setupOrg(env, { mode: "enforce" });
    await env.DB.prepare(`UPDATE organizations SET security_alerts_enabled = 1 WHERE id = ?`).bind(org.orgId).run();
    expect((await console_(org.owner.cookie, "/api/console/notifications/slack", { webhook_url: WEBHOOK })).status).toBe(201);
    slackCalls = [];
    const session = (await openSession(org.key.raw)).body.session_id as string;
    const leased = (await evaluate(org.key.raw, act("read", { session_id: session, lease: { ttl_seconds: 300, max_uses: 3 } }))).body;
    expect(leased.decision).toBe("allow");
    const oldLease = leased.lease.lease_id as string;

    const r = await suspiciousSequence(org.key.raw, session);
    expect(r[0]!.decision).toBe("allow");
    expect(r[1]!.risk.state).toBe("elevated"); // CAPABILITY_ESCALATION 25
    expect(r[3]!.risk.signals.map((s: Json) => s.code)).toContain("REPEATED_BLOCK"); // 45
    expect(r[4]!.risk.state).toBe("review_required"); // UNEXPECTED_MCP_TOOL → 70
    expect(r[5]!).toMatchObject({ decision: "review", reason_code: "RISK_REVIEW_REQUIRED", risk: { policy_decision: "allow", runtime_risk_decision: "review", effective_decision: "review" } });
    expect(r[6]!).toMatchObject({ decision: "block", reason_code: "AGENT_QUARANTINED", risk: { policy_decision: "allow", runtime_risk_decision: "block", effective_decision: "block", state: "quarantined" } });
    const incidentId = r[6]!.risk.incident_id as string;
    expect(incidentId).toMatch(/^inc_/);

    const next = (await evaluate(org.key.raw, act("read", { session_id: session }))).body;
    expect(next).toMatchObject({ decision: "block", reason_code: "AGENT_QUARANTINED" });
    const noSession = (await evaluate(org.key.raw, act("read"))).body;
    expect(noSession.decision).toBe("block");

    const incident = await one(`SELECT * FROM security_incidents WHERE id = ?`, incidentId);
    expect(incident).toMatchObject({ status: "contained", cause: "score_quarantine", subject_type: "agent", subject_id: org.agentId });
    const cancelled = await all(`SELECT status, acted_by, acted_by_name, terminated_reason FROM approvals WHERE terminated_incident_id = ?`, incidentId);
    expect(cancelled).toEqual([{ status: "denied", acted_by: null, acted_by_name: "Mother AI containment", terminated_reason: "quarantine" }]);
    const alertEvents = (await all(`SELECT event, status FROM security_notifications ORDER BY queued_at`)).map((a) => `${a.event}:${a.status}`);
    expect(alertEvents).toEqual(expect.arrayContaining(["risk_elevated:SENT_TO_PROVIDER", "review_required:SENT_TO_PROVIDER", "quarantined:SENT_TO_PROVIDER", "containment_completed:SENT_TO_PROVIDER"]));
    const quarantineAlert = slackCalls.map((c) => c.body).find((b) => b.includes("MOTHER AI · QUARANTINED"))!;
    expect(quarantineAlert).toContain(incidentId);
    expect(quarantineAlert).not.toContain("canary:doc-1");

    const oldUse = await call(env, `/v1/leases/${oldLease}/use`, { json: { resource: "canary:doc-1" }, key: org.key.raw });
    expect(oldUse.status).toBe(409);

    const cleared = await console_(org.owner.cookie, `/api/console/security/incidents/${incidentId}/clear`, { note: "Canary reviewed; agent behaviour understood." });
    expect(cleared.status).toBe(200);
    expect(slackCalls.some((c) => c.body.includes("MOTHER AI · QUARANTINE CLEARED"))).toBe(true);

    // Old authority never comes back.
    expect(((await (await call(env, `/v1/leases/${oldLease}/use`, { json: { resource: "canary:doc-1" }, key: org.key.raw })).json()) as Json).error.code).toMatch(/LEASE_REVOKED|LEASE_INVALIDATED/);
    // New, narrow authority works.
    const session2 = (await openSession(org.key.raw)).body.session_id as string;
    const fresh = (await evaluate(org.key.raw, act("read", { session_id: session2, lease: { ttl_seconds: 60, max_uses: 1 } }))).body;
    expect(fresh).toMatchObject({ decision: "allow", risk: { effective_decision: "allow" } });
    const use1 = await call(env, `/v1/leases/${fresh.lease.lease_id}/use`, { json: { resource: "canary:doc-1" }, key: org.key.raw });
    expect(use1.status).toBe(200);
    const use2 = await call(env, `/v1/leases/${fresh.lease.lease_id}/use`, { json: { resource: "canary:doc-1" }, key: org.key.raw });
    expect(((await use2.json()) as Json).error.code).toBe("LEASE_EXHAUSTED");
  });

  // ------------------------------------------------------------------ quarantine semantics
  it("quarantined agent always blocks: every policy outcome, both protocols, 100 distinct request_ids", async () => {
    const org = await setupOrg(env, { mode: "enforce" });
    const manual = await console_(org.owner.cookie, "/api/console/security/quarantine", { subject_type: "agent", subject_id: org.agentId, note: "Manual containment test" });
    expect(manual.status).toBe(201);
    for (const op of ["read", "delete", "export"]) {
      expect((await evaluate(org.key.raw, act(op))).body).toMatchObject({ decision: "block", reason_code: "AGENT_QUARANTINED" });
    }
    expect((await evaluate(org.key.raw, { agent_id: "ops-agent", server: "crm", tool: "read" }, "/v1/mcp/evaluate")).body.decision).toBe("block");
    for (let i = 0; i < 100; i++) {
      const r = (await evaluate(org.key.raw, act("read", { request_id: `bypass-${i}` }))).body;
      expect(r.decision).toBe("block");
    }
    expect((await evaluate(org.key.raw, { ...act("read"), agent_id: "helper-agent" })).body.decision).toBe("allow");
    expect(await all(`SELECT id FROM approvals WHERE status = 'pending'`)).toHaveLength(0);
  });

  it("hard deterministic violation quarantines immediately; a single weak behavioral signal never does", async () => {
    const org = await setupOrg(env, { mode: "enforce" });
    const weak = (await evaluate(org.key.raw, act("delete"))).body;
    expect(weak.risk.state).toBe("elevated");
    expect((await subject("agent", org.agentId))!.state).toBe("elevated");
    const reported = await call(env, "/v1/events", { json: { type: "execution.reported", decision_id: weak.decision_id, outcome: "succeeded" }, key: org.key.raw });
    const body = (await reported.json()) as Json;
    expect(reported.status).toBe(201);
    expect(body).toMatchObject({ violation: "EXECUTED_WITHOUT_AUTHORIZATION", risk: { state: "quarantined" } });
    expect(await one(`SELECT cause, severity, status FROM security_incidents WHERE subject_id = ?`, org.agentId)).toMatchObject({ cause: "hard_signal_quarantine", severity: "critical", status: "contained" });
    const signal = await one(`SELECT signal, hard, points, rule_version, mode, observed_at, subject_type, evidence FROM risk_signals WHERE hard = 1`);
    expect(signal).toMatchObject({ signal: "EXECUTED_WITHOUT_AUTHORIZATION", hard: 1, points: 100, rule_version: "mre-1.0.0", mode: "enforce", subject_type: "agent" });
    expect(JSON.parse(signal!.evidence).decision_id).toBe(weak.decision_id);
  });

  it("replay of an old ALLOW after quarantine returns BLOCK, records runtime.replay_blocked and never mutates the original decision", async () => {
    const org = await setupOrg(env, { mode: "enforce" });
    const session = (await openSession(org.key.raw)).body.session_id;
    const body = act("read", { request_id: "replay-me", session_id: session });
    const original = (await evaluate(org.key.raw, body)).body;
    expect(original.decision).toBe("allow");
    const manual = await console_(org.owner.cookie, "/api/console/security/quarantine", { subject_type: "session", subject_id: session, note: "Session containment test" });
    const replay = await call(env, "/v1/evaluate", { json: body, key: org.key.raw });
    const replayed = (await replay.json()) as Json;
    expect(replay.headers.get("Idempotent-Replayed")).toBe("true");
    expect(replayed).toMatchObject({ decision_id: original.decision_id, decision: "block", reason_code: "SESSION_QUARANTINED", original_decision: "allow", replayed: true });
    expect(await one(`SELECT decision, reason_code FROM decisions WHERE id = ?`, original.decision_id)).toEqual({ decision: "allow", reason_code: "POLICY_ALLOW" });
    const ev = await one(`SELECT type, reason_code, decision_id, request_id, session_id, incident_id, created_at, detail FROM runtime_events WHERE type = 'runtime.replay_blocked'`);
    expect(ev).toMatchObject({ reason_code: "SESSION_QUARANTINED", decision_id: original.decision_id, request_id: "replay-me", session_id: session, incident_id: manual.body.incident_id });
    expect(JSON.parse(ev!.detail).original_decision).toBe("allow");

    // In monitor mode the same replay is unchanged.
    const monitorOrg = await setupOrg(env, { mode: "monitor", name: "Monitor Co" });
    const b2 = act("read", { request_id: "replay-monitor" });
    await evaluate(monitorOrg.key.raw, b2);
    expect((await evaluate(monitorOrg.key.raw, b2)).body).toMatchObject({ decision: "allow", replayed: true });
  });

  it("REVIEW approval cannot override quarantine: pending cancelled by the system, approved grants invalid forever, new approvals work after clearance", async () => {
    const org = await setupOrg(env, { mode: "enforce" });
    const approved = (await evaluate(org.key.raw, act("export", { resource: "canary:a" }))).body;
    expect((await console_(org.owner.cookie, `/api/console/approvals/${approved.approval_id}/approve`, {})).status).toBe(200);
    const pending = (await evaluate(org.key.raw, act("export", { resource: "canary:b" }))).body;
    const q = await console_(org.owner.cookie, "/api/console/security/quarantine", { subject_type: "agent", subject_id: org.agentId, note: "Containment approval test" });
    const incidentId = q.body.incident_id;

    const cancelledRow = await one(`SELECT status, acted_by, acted_by_name, note, terminated_reason, terminated_incident_id FROM approvals WHERE id = ?`, pending.approval_id);
    expect(cancelledRow).toMatchObject({ status: "denied", acted_by: null, terminated_reason: "quarantine", terminated_incident_id: incidentId });
    expect(cancelledRow!.note).toContain("Not a human decision");
    const ce = await one(`SELECT actor_type, actor_id, action FROM control_events WHERE action = 'approval.cancelled_by_quarantine' AND target_id = ?`, pending.approval_id);
    expect(ce).toEqual({ actor_type: "system", actor_id: null, action: "approval.cancelled_by_quarantine" });
    const poll = (await (await call(env, `/v1/approvals/${pending.approval_id}`, { key: org.key.raw })).json()) as Json;
    expect(poll.termination).toEqual({ reason: "quarantine", incident_id: incidentId, by: "system" });
    expect(await one(`SELECT relation FROM incident_members WHERE incident_id = ? AND member_id = ?`, incidentId, approved.approval_id)).toEqual({ relation: "invalidated_grant" });

    const consume = await call(env, `/v1/approvals/${approved.approval_id}/consume`, { method: "POST", key: org.key.raw });
    expect(((await consume.json()) as Json).error.code).toBe("APPROVAL_INVALIDATED");
    await console_(org.owner.cookie, `/api/console/security/incidents/${incidentId}/clear`, { note: "Reviewed and cleared by the owner." });
    const afterClear = await call(env, `/v1/approvals/${approved.approval_id}/consume`, { method: "POST", key: org.key.raw });
    expect(((await afterClear.json()) as Json).error.code).toBe("APPROVAL_INVALIDATED");
    expect(await one(`SELECT consumed_at FROM approvals WHERE id = ?`, approved.approval_id)).toEqual({ consumed_at: null });

    const fresh = (await evaluate(org.key.raw, act("export", { resource: "canary:c" }))).body;
    expect(fresh.decision).toBe("review");
    expect((await console_(org.owner.cookie, `/api/console/approvals/${fresh.approval_id}/approve`, {})).status).toBe(200);
    expect((await call(env, `/v1/approvals/${fresh.approval_id}/consume`, { method: "POST", key: org.key.raw })).status).toBe(200);
  });

  it("approve action is refused while the scope is quarantined", async () => {
    const org = await setupOrg(env, { mode: "enforce" });
    await console_(org.owner.cookie, "/api/console/security/quarantine", { subject_type: "agent", subject_id: org.agentId, note: "Approve refusal test" });
    // A review decision for another agent in a session of the quarantined agent is inside the scope.
    const session = (await openSession(org.key.raw, { agent_id: "helper-agent" })).body.session_id;
    const review = (await evaluate(org.key.raw, { ...act("export"), agent_id: "helper-agent", session_id: session })).body;
    expect(review.decision).toBe("review");
    const approvalId = review.approval_id;
    // helper-agent is not quarantined by the agent quarantine. Quarantine the helper session and approving is refused.
    const q = await console_(org.owner.cookie, "/api/console/security/quarantine", { subject_type: "session", subject_id: session, note: "Session scope approve test" });
    expect(q.status).toBe(201);
    const refused = await console_(org.owner.cookie, `/api/console/approvals/${approvalId}/approve`, {});
    expect(refused).toMatchObject({ status: 409, body: { error: { code: "APPROVAL_INVALIDATED" } } }); // requested before the epoch (and already cancelled by containment)

    // Races: pending approvals inside the scope that escaped cancellation. Blocked decisions carry no approval, so
    // attach racing approvals to blocked in-scope decisions: one requested before the epoch, one after.
    const before = (await evaluate(org.key.raw, { ...act("delete"), agent_id: "helper-agent", session_id: session })).body;
    const afterDecision = (await evaluate(org.key.raw, { ...act("delete", { resource: "canary:y" }), agent_id: "helper-agent", session_id: session })).body;
    expect([before.decision, afterDecision.decision]).toEqual(["block", "block"]);
    const epoch = (await subject("session", session))!.containment_epoch_at as string;
    const future = new Date(Date.now() + 600_000).toISOString();
    await env.DB.prepare(`INSERT INTO approvals (id, organization_id, decision_id, status, requested_at, expires_at) VALUES ('apr_raceBEFOREraceBEFORE00', ?, ?, 'pending', ?, ?)`)
      .bind(org.orgId, before.decision_id, new Date(Date.parse(epoch) - 1000).toISOString(), future).run();
    await env.DB.prepare(`INSERT INTO approvals (id, organization_id, decision_id, status, requested_at, expires_at) VALUES ('apr_raceAFTERraceAFTER0000', ?, ?, 'pending', ?, ?)`)
      .bind(org.orgId, afterDecision.decision_id, new Date(Date.parse(epoch) + 1000).toISOString(), future).run();
    expect((await console_(org.owner.cookie, "/api/console/approvals/apr_raceBEFOREraceBEFORE00/approve", {})).body.error.code).toBe("APPROVAL_INVALIDATED");
    expect((await console_(org.owner.cookie, "/api/console/approvals/apr_raceAFTERraceAFTER0000/approve", {})).body.error.code).toBe("SCOPE_QUARANTINED");
    expect(await all(`SELECT id FROM approvals WHERE status = 'approved'`)).toHaveLength(0);
  });

  // ------------------------------------------------------------------ leases
  it("capability leases: exact scope, same key, revoked lease cannot be replayed, expired lease refused, policy change invalidates", async () => {
    const org = await setupOrg(env, { mode: "enforce" });
    const otherKey = await seedKey(env, org.orgId);
    const session = (await openSession(org.key.raw)).body.session_id;
    const d = (await evaluate(org.key.raw, act("read", { session_id: session, lease: { ttl_seconds: 120, max_uses: 5 } }))).body;
    const lease = d.lease.lease_id;
    const use = (body: Json, key = org.key.raw) => call(env, `/v1/leases/${lease}/use`, { json: body, key }).then(async (r) => ({ status: r.status, body: (await r.json()) as Json }));
    expect((await use({ resource: "canary:doc-1" })).status).toBe(200);
    expect((await use({ resource: "canary:doc-2" })).body.error.code).toBe("LEASE_SCOPE_MISMATCH");
    expect((await use({ resource: "canary:doc-1", destination: "external" })).body.error.code).toBe("LEASE_SCOPE_MISMATCH");
    expect((await use({ resource: "canary:doc-1" }, otherKey.raw)).body.error.code).toBe("LEASE_KEY_MISMATCH");
    await env.DB.prepare(`UPDATE capability_leases SET revoked_at = ?, revoked_reason = 'test' WHERE id = ?`).bind(new Date().toISOString(), lease).run();
    expect((await use({ resource: "canary:doc-1" })).body.error.code).toBe("LEASE_REVOKED");
    await expect(env.DB.prepare(`UPDATE capability_leases SET revoked_at = NULL WHERE id = ?`).bind(lease).run()).rejects.toThrow(/invalid lease transition/);
    await expect(env.DB.prepare(`UPDATE capability_leases SET resource = 'canary:*' WHERE id = ?`).bind(lease).run()).rejects.toThrow(/invalid lease transition/);
    expect(await all(`SELECT outcome, refusal_code FROM lease_uses WHERE lease_id = ? ORDER BY created_at`, lease)).toHaveLength(5);

    // Two stale-authority uses (revoked + expired) accumulate 40 + 40 = 80 and would quarantine one agent; use a second agent below.
    expect((await subject("agent", org.agentId))!.state).toBe("elevated");
    const helperSession = (await openSession(org.key.raw, { agent_id: "helper-agent" })).body.session_id;
    const d2 = (await evaluate(org.key.raw, { ...act("read", { resource: "canary:doc-9", lease: { ttl_seconds: 5, max_uses: 1 } }), agent_id: "helper-agent", session_id: helperSession })).body;
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 6_000);
    const expired = await call(env, `/v1/leases/${d2.lease.lease_id}/use`, { json: { resource: "canary:doc-9" }, key: org.key.raw });
    expect(((await expired.json()) as Json).error.code).toBe("LEASE_EXPIRED");
    vi.useRealTimers();

    const d3 = (await evaluate(org.key.raw, { ...act("read", { resource: "canary:doc-7", lease: { ttl_seconds: 120, max_uses: 1 } }), agent_id: "helper-agent", session_id: helperSession })).body;
    await new Promise((r) => setTimeout(r, 5));
    await env.DB.prepare(`UPDATE policies SET version = version + 1, updated_at = ? WHERE organization_id = ? AND name = 'Read records'`).bind(new Date().toISOString(), org.orgId).run();
    const changed = await call(env, `/v1/leases/${d3.lease.lease_id}/use`, { json: { resource: "canary:doc-7" }, key: org.key.raw });
    expect(((await changed.json()) as Json).error.code).toBe("LEASE_POLICY_CHANGED");
  });

  it("a lease issued before the containment epoch is refused forever, even if it escaped revocation and the quarantine was cleared", async () => {
    const org = await setupOrg(env, { mode: "enforce" });
    const session = (await openSession(org.key.raw)).body.session_id;
    const d = (await evaluate(org.key.raw, act("read", { session_id: session }))).body;
    await new Promise((r) => setTimeout(r, 5));
    const issuedBefore = new Date().toISOString();
    await new Promise((r) => setTimeout(r, 5));
    const q = await console_(org.owner.cookie, "/api/console/security/quarantine", { subject_type: "agent", subject_id: org.agentId, note: "Epoch lease test quarantine" });
    await console_(org.owner.cookie, `/api/console/security/incidents/${q.body.incident_id}/clear`, { note: "Cleared for the epoch lease test." });
    const session2 = (await openSession(org.key.raw)).body.session_id;
    // Simulate the race: a lease row written with an issue time before the epoch and never revoked.
    await env.DB.prepare(
      `INSERT INTO capability_leases (id, organization_id, agent_id, session_id, api_key_id, decision_id, principal_type, capability, operation, resource, max_uses, issued_at, expires_at)
       VALUES ('lse_raceRACErace0000000000', ?, ?, ?, ?, ?, 'user', 'canary.records', 'read', 'canary:doc-1', 3, ?, ?)`,
    ).bind(org.orgId, org.agentId, session2, org.key.id, d.decision_id, issuedBefore, new Date(Date.now() + 300_000).toISOString()).run();
    const r = await call(env, "/v1/leases/lse_raceRACErace0000000000/use", { json: { resource: "canary:doc-1" }, key: org.key.raw });
    expect(((await r.json()) as Json).error.code).toBe("LEASE_INVALIDATED");
  });

  it("leases require an allowed action in a valid session, and are never issued under review or quarantine", async () => {
    const org = await setupOrg(env, { mode: "enforce" });
    expect((await evaluate(org.key.raw, act("read", { lease: { ttl_seconds: 60 } }))).status).toBe(400);
    const session = (await openSession(org.key.raw)).body.session_id;
    expect((await evaluate(org.key.raw, act("export", { session_id: session, lease: { ttl_seconds: 60 } }))).body).not.toHaveProperty("lease");
    expect((await evaluate(org.key.raw, act("delete", { session_id: session, lease: { ttl_seconds: 60 } }))).body).not.toHaveProperty("lease");
    await console_(org.owner.cookie, "/api/console/security/quarantine", { subject_type: "session", subject_id: session, note: "No lease under quarantine" });
    expect((await evaluate(org.key.raw, act("read", { session_id: session, lease: { ttl_seconds: 60 } }))).body).not.toHaveProperty("lease");
    expect(await all(`SELECT id FROM capability_leases`)).toHaveLength(0);
    await expect(
      env.DB.prepare(
        `INSERT INTO capability_leases (id, organization_id, agent_id, session_id, api_key_id, decision_id, principal_type, capability, operation, max_uses, issued_at, expires_at)
         SELECT 'lse_forged', organization_id, agent_id, session_id, api_key_id, id, 'user', capability, operation, 1, created_at, '2999-01-01T00:00:00.000Z' FROM decisions WHERE decision = 'block' LIMIT 1`,
      ).run(),
    ).rejects.toThrow(/invalid lease/);
  });

  // ------------------------------------------------------------------ sessions, lineage, blast radius
  it("child session is in the blast radius; quarantined lineage blocks children and refuses new child sessions", async () => {
    const org = await setupOrg(env, { mode: "enforce" });
    const root = (await openSession(org.key.raw)).body;
    const child = (await openSession(org.key.raw, { agent_id: "helper-agent", parent_session_id: root.session_id, principal: { type: "agent", ref: "ops-agent" } })).body;
    expect(child).toMatchObject({ depth: 1, root_session_id: root.session_id, parent_session_id: root.session_id });
    const rootDecision = (await evaluate(org.key.raw, act("read", { session_id: root.session_id }))).body;
    const childDecision = (await evaluate(org.key.raw, { ...act("read", { resource: "canary:child-doc" }), agent_id: "helper-agent", session_id: child.session_id, parent_decision_id: rootDecision.decision_id })).body;
    expect(childDecision).toMatchObject({ decision: "allow", parent_decision_id: rootDecision.decision_id });

    const q = await console_(org.owner.cookie, "/api/console/security/quarantine", { subject_type: "session", subject_id: root.session_id, note: "Lineage containment test" });
    const members = await all(`SELECT member_type, member_id, relation FROM incident_members WHERE incident_id = ?`, q.body.incident_id);
    expect(members).toEqual(expect.arrayContaining([
      { member_type: "session", member_id: root.session_id, relation: "subject" },
      { member_type: "session", member_id: child.session_id, relation: "scope_session" },
      { member_type: "agent", member_id: org.helperId, relation: "child_agent" },
    ]));
    const detail = await console_(org.owner.cookie, `/api/console/security/incidents/${q.body.incident_id}`);
    expect(detail.status).toBe(200);
    const br = detail.body.blast_radius;
    expect(br.sessions.map((s: Json) => s.id)).toEqual(expect.arrayContaining([root.session_id, child.session_id]));
    expect(br.agents.map((a: Json) => a.value)).toEqual(expect.arrayContaining(["ops-agent", "helper-agent"]));
    expect(br.resources.map((r: Json) => r.value)).toEqual(expect.arrayContaining(["canary:doc-1", "canary:child-doc"]));
    expect(br.boundary).toMatch(/Only actions that called Mother/);

    expect((await evaluate(org.key.raw, { ...act("read"), agent_id: "helper-agent", session_id: child.session_id })).body).toMatchObject({ decision: "block", reason_code: "SESSION_QUARANTINED" });
    const refused = await openSession(org.key.raw, { agent_id: "helper-agent", parent_session_id: root.session_id });
    expect(refused).toMatchObject({ status: 409, body: { error: { code: "SESSION_REFUSED" } } });
    // Session-scoped containment does not reach the agents' other sessions.
    const elsewhere = (await openSession(org.key.raw, { agent_id: "helper-agent" })).body.session_id;
    expect((await evaluate(org.key.raw, { ...act("read"), agent_id: "helper-agent", session_id: elsewhere })).body.decision).toBe("allow");
  });

  it("spoofed session and parent ids fail closed and are recorded; the claim is never stored as correlation", async () => {
    // Integrity gate applies in every mode. monitor keeps accumulation from quarantining mid-test (covered below).
    const org = await setupOrg(env, { mode: "monitor" });
    const mine = (await openSession(org.key.raw)).body.session_id;
    const helperSession = (await openSession(org.key.raw, { agent_id: "helper-agent" })).body.session_id;
    const otherKey = await seedKey(env, org.orgId);
    const cases: Array<[Json, string, string]> = [
      [act("read", { session_id: `asn_${"Z".repeat(22)}` }), "SESSION_INVALID", org.key.raw],
      [act("read", { session_id: helperSession }), "SESSION_INVALID", org.key.raw],
      [act("read", { session_id: mine }), "SESSION_INVALID", otherKey.raw],
      [act("read", { session_id: mine, parent_decision_id: `dec_${"Q".repeat(22)}` }), "PARENT_INVALID", org.key.raw],
    ];
    for (const [body, code, key] of cases) {
      const r = (await evaluate(key, body)).body;
      expect(r).toMatchObject({ decision: "block", reason_code: code, parent_decision_id: null });
      const stored = await one(`SELECT d.session_id, d.parent_decision_id, re.claimed_session_id, re.claimed_parent_id FROM decisions d JOIN risk_evaluations re ON re.decision_id = d.id WHERE d.id = ?`, r.decision_id);
      expect(stored!.parent_decision_id).toBeNull();
      if (code === "SESSION_INVALID") {
        expect(r.session_id).toBeNull();
        expect(stored!.session_id).toBeNull();
        expect(stored!.claimed_session_id).toBe(body.session_id);
      } else {
        // The session itself is valid and stays correlated; only the invalid parent claim is rejected.
        expect(stored!.session_id).toBe(mine);
        expect(stored!.claimed_parent_id).toBe(body.parent_decision_id);
      }
    }
    const helperDecision = (await evaluate(org.key.raw, { ...act("read"), agent_id: "helper-agent", session_id: helperSession })).body;
    expect((await evaluate(org.key.raw, act("read", { session_id: mine, parent_decision_id: helperDecision.decision_id }))).body.reason_code).toBe("PARENT_INVALID");
    await call(env, `/v1/sessions/${mine}/close`, { method: "POST", key: org.key.raw });
    expect((await evaluate(org.key.raw, act("read", { session_id: mine }))).body.reason_code).toBe("SESSION_CLOSED");
    const short = (await openSession(org.key.raw, { agent_id: "ops-agent", ttl_seconds: 60 })).body.session_id;
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 61_000);
    expect((await evaluate(org.key.raw, act("read", { session_id: short }))).body.reason_code).toBe("SESSION_EXPIRED");
    vi.useRealTimers();
    const signals = await all(`SELECT signal, hard, points FROM risk_signals WHERE signal = 'SESSION_OR_PARENT_INVALID'`);
    expect(signals.length).toBeGreaterThan(0);
    expect(signals.every((x) => x.hard === 0 && x.points === 50)).toBe(true);

    // enforce: one invalid claim (50) is not enough; a second distinct one accumulates to 100 and quarantines the agent.
    const e = await setupOrg(env, { mode: "enforce", name: "Enforce Spoof Co" });
    const first = (await evaluate(e.key.raw, act("read", { session_id: `asn_${"A".repeat(22)}` }))).body;
    expect(first).toMatchObject({ decision: "block", reason_code: "SESSION_INVALID", risk: { state: "review_required" } });
    const second = (await evaluate(e.key.raw, act("read", { session_id: `asn_${"B".repeat(22)}` }))).body;
    expect(second.decision).toBe("block");
    expect(await one(`SELECT cause, score FROM security_incidents WHERE subject_id = ?`, e.agentId)).toEqual({ cause: "score_quarantine", score: 100 });
  });

  // ------------------------------------------------------------------ tenancy
  it("cross-org telemetry and references are impossible; a cross-tenant reference is a hard violation for the caller's agent", async () => {
    const a = await setupOrg(env, { mode: "enforce", name: "Org A" });
    const b = await setupOrg(env, { mode: "enforce", name: "Org B" });
    const aSession = (await openSession(a.key.raw)).body.session_id;
    const aDecision = (await evaluate(a.key.raw, act("read", { session_id: aSession, lease: { ttl_seconds: 120 } }))).body;
    const aCounts = async () => ({
      events: (await all(`SELECT id FROM runtime_events WHERE organization_id = ?`, a.orgId)).length,
      signals: (await all(`SELECT id FROM risk_signals WHERE organization_id = ?`, a.orgId)).length,
    });
    const before = await aCounts();

    expect((await call(env, "/v1/events", { json: { type: "execution.reported", decision_id: aDecision.decision_id, outcome: "succeeded" }, key: b.key.raw })).status).toBe(404);
    expect((await call(env, `/v1/leases/${aDecision.lease.lease_id}/use`, { json: { resource: "canary:doc-1" }, key: b.key.raw })).status).toBe(404);
    expect((await openSession(b.key.raw, { agent_id: "ops-agent", parent_session_id: aSession })).status).toBe(404);
    expect((await call(env, `/v1/sessions/${aSession}`, { key: b.key.raw })).status).toBe(404);
    const spoof = (await evaluate(b.key.raw, act("read", { session_id: aSession }))).body;
    expect(spoof).toMatchObject({ decision: "block", reason_code: "SESSION_INVALID" });
    expect(await aCounts()).toEqual(before);
    expect((await subject("agent", b.agentId))!.state).toMatch(/quarantined|contained/);
    expect(await subject("agent", a.agentId)).toBeNull();

    const aIncident = (await console_(a.owner.cookie, "/api/console/security/quarantine", { subject_type: "agent", subject_id: a.agentId, note: "Tenant isolation test" })).body.incident_id;
    expect((await console_(b.owner.cookie, `/api/console/security/incidents/${aIncident}`)).status).toBe(404);
    expect((await console_(b.owner.cookie, `/api/console/security/incidents/${aIncident}/clear`, { note: "Trying to clear another org" })).status).toBe(404);
    expect((await console_(b.owner.cookie, "/api/console/security/quarantine", { subject_type: "agent", subject_id: a.agentId, note: "Cross org quarantine" })).status).toBe(404);
    expect(JSON.stringify((await console_(b.owner.cookie, "/api/console/security")).body)).not.toContain(a.agentId);

    await expect(
      env.DB.prepare(`INSERT INTO runtime_events (id, organization_id, type, source, decision_id, created_at) VALUES ('rte_x', ?, 'execution.reported', 'integration', ?, ?)`).bind(b.orgId, aDecision.decision_id, new Date().toISOString()).run(),
    ).rejects.toThrow(/cross-tenant/);
    await expect(
      env.DB.prepare(
        `INSERT INTO decisions (id, organization_id, request_id, request_fingerprint, agent_key, protocol, capability, operation, decision, reason_code, reason, engine_version, created_at, session_id)
         VALUES ('dec_crosstenant', ?, 'x', 'f', 'ops-agent', 'api', 'c', 'o', 'allow', 'X', 'x', 'mpe-1.0.0', ?, ?)`,
      ).bind(b.orgId, new Date().toISOString(), aSession).run(),
    ).rejects.toThrow(/cross-tenant/);
  });

  it("a cross-tenant session reference on /v1/evaluate is a hard signal that quarantines immediately", async () => {
    const a = await setupOrg(env, { mode: "enforce", name: "Victim Org" });
    const c = await setupOrg(env, { mode: "enforce", name: "Probe Org" });
    const victimSession = (await openSession(a.key.raw)).body.session_id;
    const r = (await evaluate(c.key.raw, act("read", { session_id: victimSession }))).body;
    expect(r).toMatchObject({ decision: "block", reason_code: "SESSION_INVALID", session_id: null });
    expect(await one(`SELECT signal, hard, points FROM risk_signals WHERE organization_id = ?`, c.orgId)).toEqual({ signal: "CROSS_TENANT_REFERENCE", hard: 1, points: 100 });
    expect(await one(`SELECT cause, severity FROM security_incidents WHERE organization_id = ?`, c.orgId)).toEqual({ cause: "hard_signal_quarantine", severity: "critical" });
    expect(await all(`SELECT id FROM risk_signals WHERE organization_id = ?`, a.orgId)).toHaveLength(0);
  });

  // ------------------------------------------------------------------ evidence integrity
  it("runtime evidence and containment state cannot be altered or deleted, and quarantine cannot be escaped by editing state or mode", async () => {
    const org = await setupOrg(env, { mode: "enforce" });
    const session = (await openSession(org.key.raw)).body.session_id;
    const d = (await evaluate(org.key.raw, act("delete", { session_id: session }))).body;
    const q = await console_(org.owner.cookie, "/api/console/security/quarantine", { subject_type: "agent", subject_id: org.agentId, note: "Integrity test quarantine" });
    for (const [table, where] of [
      ["risk_evaluations", `decision_id = '${d.decision_id}'`],
      ["risk_signals", "1 = 1"],
      ["risk_transitions", "1 = 1"],
      ["runtime_events", "1 = 1"],
      ["incident_members", "1 = 1"],
      ["agent_sessions", "1 = 1"],
    ] as const) {
      await expect(env.DB.prepare(`DELETE FROM ${table} WHERE ${where}`).run()).rejects.toThrow();
    }
    await expect(env.DB.prepare(`UPDATE risk_signals SET points = 0`).run()).rejects.toThrow(/append-only/);
    await expect(env.DB.prepare(`UPDATE risk_evaluations SET effective_decision = 'allow'`).run()).rejects.toThrow(/append-only/);
    await expect(env.DB.prepare(`UPDATE decisions SET decision = 'allow' WHERE id = ?`).bind(d.decision_id).run()).rejects.toThrow(/append-only/);
    await expect(env.DB.prepare(`DELETE FROM security_incidents`).run()).rejects.toThrow(/retained/);
    await expect(env.DB.prepare(`DELETE FROM risk_subjects`).run()).rejects.toThrow(/retained/);
    await expect(env.DB.prepare(`UPDATE risk_subjects SET state = 'normal', version = version + 1 WHERE subject_id = ?`).bind(org.agentId).run()).rejects.toThrow(/invalid risk transition/);
    await expect(env.DB.prepare(`UPDATE risk_subjects SET containment_epoch_at = '2000-01-01T00:00:00.000Z', version = version + 1 WHERE subject_id = ?`).bind(org.agentId).run()).rejects.toThrow(/invalid risk transition/);
    await expect(env.DB.prepare(`UPDATE security_incidents SET status = 'cleared', cleared_at = ?, clearance_note = 'no authorized human' WHERE id = ?`).bind(new Date().toISOString(), q.body.incident_id).run()).rejects.toThrow(/invalid incident transition/);
    const approved = await env.DB.prepare(`SELECT id FROM approvals LIMIT 1`).first();
    expect(approved).toBeNull();
    const modeChange = await console_(org.owner.cookie, "/api/console/settings", { runtime_protection: "monitor" }, "PATCH");
    expect(modeChange).toMatchObject({ status: 409, body: { error: { code: "ACTIVE_QUARANTINE" } } });
    expect(await one(`SELECT runtime_protection FROM organizations WHERE id = ?`, org.orgId)).toEqual({ runtime_protection: "enforce" });
    expect((await evaluate(org.key.raw, act("read"))).body.decision).toBe("block");
  });

  // ------------------------------------------------------------------ clearance authority
  it("clearing a quarantine requires an active human security/admin/owner with a note; automation and lower roles cannot", async () => {
    const org = await setupOrg(env, { mode: "enforce" });
    const viewer = await seedSession(env, org.orgId, "viewer");
    const approver = await seedSession(env, org.orgId, "approver");
    const security = await seedSession(env, org.orgId, "security", "Sam Security");
    const automation = await seedSession(env, org.orgId, "owner", "Mother AI operator (automation)");
    await env.DB.prepare(`UPDATE users SET kind = 'automation' WHERE id = ?`).bind(automation.userId).run();
    const q = await console_(org.owner.cookie, "/api/console/security/quarantine", { subject_type: "agent", subject_id: org.agentId, note: "Clearance authority test" });
    const clear = (cookie: string, note = "Reviewed evidence and cleared.") => console_(cookie, `/api/console/security/incidents/${q.body.incident_id}/clear`, { note });

    expect((await clear(viewer.cookie)).status).toBe(403);
    expect((await clear(approver.cookie)).status).toBe(403);
    expect((await clear(automation.cookie)).body.error.code).toBe("HUMAN_REQUIRED");
    expect((await clear(security.cookie, "short")).status).toBe(400);
    await expect(env.DB.prepare(`UPDATE users SET kind = 'human' WHERE id = ?`).bind(automation.userId).run()).rejects.toThrow(/cannot become human/);
    // Direct database clearance by a non-human or a disabled member is rejected by the trigger.
    const now = new Date().toISOString();
    await expect(
      env.DB.prepare(`UPDATE risk_subjects SET state = 'cleared', cleared_by = ?, cleared_at = ?, signals_since = ?, version = version + 1 WHERE subject_id = ?`).bind(automation.userId, now, now, org.agentId).run(),
    ).rejects.toThrow(/invalid risk transition/);
    await env.DB.prepare(`UPDATE memberships SET status = 'disabled' WHERE user_id = ?`).bind(security.userId).run();
    await expect(
      env.DB.prepare(`UPDATE risk_subjects SET state = 'cleared', cleared_by = ?, cleared_at = ?, signals_since = ?, version = version + 1 WHERE subject_id = ?`).bind(security.userId, now, now, org.agentId).run(),
    ).rejects.toThrow(/invalid risk transition/);
    expect((await evaluate(org.key.raw, act("read"))).body.decision).toBe("block");

    const ok = await clear(org.owner.cookie);
    expect(ok.status).toBe(200);
    const events = await all(`SELECT actor_type, actor_id, action FROM control_events WHERE action = 'security.cleared'`);
    expect(events).toEqual([{ actor_type: "user", actor_id: org.owner.userId, action: "security.cleared" }]);
    expect(await one(`SELECT cause, actor_type, actor_id FROM risk_transitions WHERE to_state = 'cleared'`)).toEqual({ cause: "clearance", actor_type: "user", actor_id: org.owner.userId });
    expect((await evaluate(org.key.raw, act("read"))).body.decision).toBe("allow");
    expect((await clear(org.owner.cookie)).status).toBe(409);
  });

  // ------------------------------------------------------------------ alerts
  it.each(["500", "timeout"] as const)("incident notification failure (%s) never unquarantines or weakens containment", async (mode) => {
    const org = await setupOrg(env, { mode: "enforce" });
    await env.DB.prepare(`UPDATE organizations SET security_alerts_enabled = 1 WHERE id = ?`).bind(org.orgId).run();
    await console_(org.owner.cookie, "/api/console/notifications/slack", { webhook_url: WEBHOOK });
    slackMode = mode;
    const q = await console_(org.owner.cookie, "/api/console/security/quarantine", { subject_type: "agent", subject_id: org.agentId, note: "Alert failure test" });
    const subjectRow = await subject("agent", org.agentId);
    expect(subjectRow).toMatchObject({ state: "contained", incident_id: q.body.incident_id });
    const alerts = await all(`SELECT event, status, last_error FROM security_notifications`);
    expect(alerts.length).toBeGreaterThan(0);
    expect(alerts.every((a) => a.status !== "SENT_TO_PROVIDER")).toBe(true);
    expect((await evaluate(org.key.raw, act("read", { request_id: "after-alert-failure" }))).body.decision).toBe("block");
    expect((await subject("agent", org.agentId))!.containment_epoch_at).toBe(subjectRow!.containment_epoch_at);
  });

  it("a crashing alert pipeline never unquarantines", async () => {
    const org = await setupOrg(env, { mode: "enforce" });
    await env.DB.prepare(`UPDATE organizations SET security_alerts_enabled = 1 WHERE id = ?`).bind(org.orgId).run();
    await console_(org.owner.cookie, "/api/console/notifications/slack", { webhook_url: WEBHOOK });
    env.shim.sqlite.exec(`DROP TRIGGER security_notifications_no_delete; DROP TRIGGER security_notifications_terminal; ALTER TABLE security_notification_attempts RENAME TO sna_gone;`);
    const q = await console_(org.owner.cookie, "/api/console/security/quarantine", { subject_type: "agent", subject_id: org.agentId, note: "Crashing alert pipeline" });
    expect(q.status).toBe(201);
    expect((await subject("agent", org.agentId))!.state).toMatch(/quarantined|contained/);
    expect((await evaluate(org.key.raw, act("read"))).body.decision).toBe("block");
  });
});
