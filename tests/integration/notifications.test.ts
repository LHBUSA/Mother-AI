import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import worker from "../../src/worker";
import { base64UrlEncode } from "../../src/lib/crypto";
import { call, createEnv, ctx, seedAgent, seedKey, seedOrg, seedPolicy, seedSession, type TestEnv } from "../helpers/env";
import { deliverNotification, NOTIFY_TUNING, queueApprovalNotification, sweepApprovalNotifications } from "../../src/notifications/approvals";
import { buildApprovalSlackPayload } from "../../src/notifications/slack";

// Fake destinations, assembled at runtime so no webhook-shaped literal lives in the repository.
const SLACK_HOST = ["hooks", "slack", "com"].join(".");
const hook = (team: string, bot: string, token: string, { scheme = "https", host = SLACK_HOST, kind = "services" } = {}) => `${scheme}://${host}/${kind}/${team}/${bot}/${token}`;
const TOKENS = ["a", "b", "c"].map((ch) => ch.repeat(24));
const WEBHOOK_A = hook("T0AAAAAAA", "B0AAAAAAA", TOKENS[0]!);
const WEBHOOK_B = hook("T0BBBBBBB", "B0BBBBBBB", TOKENS[1]!);
const WEBHOOK_A2 = hook("T0AAAAAAA", "B0CCCCCCC", TOKENS[2]!);

function newKey(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

type Mode = "ok" | "400" | "403" | "404" | "429" | "500" | "network" | "timeout" | "hold";

interface SlackCall {
  url: string;
  body: string;
}

const refund = (amount: number, extra: Record<string, unknown> = {}) => ({
  agent_id: "billing-agent-prod",
  capability: "payments",
  operation: "refund",
  resource: "payment:pi_123",
  destination: "internal",
  data_class: "financial",
  context: { amount, currency: "USD", ticket: "SUP-CONTEXT-ONLY-7781" },
  ...extra,
});

async function setupOrg(env: TestEnv, name: string) {
  const orgId = await seedOrg(env, { name });
  const key = await seedKey(env, orgId);
  const agentId = await seedAgent(env, orgId, "billing-agent-prod");
  await seedPolicy(env, orgId, {
    name: "Refunds allowed",
    effect: "allow",
    agentIds: [agentId],
    conditions: { match: "all", conditions: [{ field: "operation", operator: "equals", value: "refund" }] },
  });
  const reviewPolicy = await seedPolicy(env, orgId, {
    name: "High value refunds",
    effect: "review",
    priority: 20,
    agentIds: [agentId],
    reasonCode: "HUMAN_APPROVAL_REQUIRED",
    conditions: { match: "all", conditions: [{ field: "context.amount", operator: "greater_than", value: 1000 }] },
  });
  await seedPolicy(env, orgId, {
    name: "Restricted egress",
    effect: "block",
    priority: 1,
    reasonCode: "RESTRICTED_DATA_EGRESS",
    conditions: { match: "all", conditions: [{ field: "data_class", operator: "equals", value: "restricted" }] },
  });
  const owner = await seedSession(env, orgId, "owner", "Olive Owner");
  return { orgId, key, agentId, reviewPolicy, owner };
}

describe("approval notifications", () => {
  const realFetch = globalThis.fetch;
  const tuning = { ...NOTIFY_TUNING };
  let env: TestEnv;
  let calls: SlackCall[];
  let mode: Mode;
  let release: () => void;
  let logs: unknown[][];

  beforeEach(() => {
    calls = [];
    mode = "ok";
    logs = [];
    release = () => {};
    Object.assign(NOTIFY_TUNING, { inlineRetryDelayMs: 0, timeoutMs: 50 });
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (!url.startsWith("https://hooks.slack.com/")) return realFetch(input, init);
      calls.push({ url, body: String(init?.body ?? "") });
      switch (mode) {
        case "ok":
          return new Response("ok", { status: 200 });
        case "network":
          throw new TypeError(`fetch failed for ${url}`);
        case "timeout":
          return new Promise<Response>((_, reject) => init?.signal?.addEventListener("abort", () => reject(init.signal!.reason)));
        case "hold":
          await new Promise<void>((r) => (release = r));
          return new Response("ok", { status: 200 });
        case "429":
          return new Response("rate_limited", { status: 429, headers: { "Retry-After": "1" } });
        default:
          return new Response("error", { status: Number(mode) });
      }
    }) as typeof fetch;
    env = createEnv({ NOTIFICATION_ENCRYPTION_KEY: newKey() });
    for (const level of ["log", "warn", "error"] as const) {
      vi.spyOn(console, level).mockImplementation((...args: unknown[]) => void logs.push(args));
    }
  });

  afterEach(() => {
    globalThis.fetch = realFetch;
    Object.assign(NOTIFY_TUNING, tuning);
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  const configure = (cookie: string, url: string) => call(env, "/api/console/notifications/slack", { json: { webhook_url: url }, cookie });
  const evaluate = (key: string, body: unknown) => call(env, "/v1/evaluate", { json: body, key });
  const rows = async (approvalId?: string) =>
    (
      await env.DB.prepare(`SELECT * FROM approval_notifications ${approvalId ? "WHERE approval_id = ?" : ""} ORDER BY queued_at`)
        .bind(...(approvalId ? [approvalId] : []))
        .all<Record<string, unknown>>()
    ).results;
  const attempts = async (notificationId: string) =>
    (await env.DB.prepare(`SELECT * FROM approval_notification_attempts WHERE notification_id = ? ORDER BY attempt`).bind(notificationId).all<Record<string, unknown>>()).results;
  const approval = async (id: string) => env.DB.prepare(`SELECT * FROM approvals WHERE id = ?`).bind(id).first<Record<string, unknown>>();

  async function reviewedOrg(name = "Acme, Inc.", url = WEBHOOK_A) {
    const org = await setupOrg(env, name);
    expect((await configure(org.owner.cookie, url)).status).toBe(201);
    return org;
  }

  // ---------------------------------------------------------------- 1-4
  it("1 + 4. one new REVIEW creates its approval and sends exactly one initial notification with the required fields", async () => {
    const org = await reviewedOrg();
    const res = await evaluate(org.key.raw, { ...refund(4200), request_id: "req-review-1" });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { decision: string; approval_id: string; decision_id: string; approval: { status: string; expires_at: string } };
    expect(body.decision).toBe("review");
    expect(body.approval.status).toBe("pending");

    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe(WEBHOOK_A);
    const stored = await rows(body.approval_id);
    expect(stored).toHaveLength(1);
    expect(stored[0]).toMatchObject({ event: "review_required", channel: "slack", status: "SENT_TO_PROVIDER", attempts: 1, last_http_status: 200 });
    const tries = await attempts(String(stored[0]!.id));
    expect(tries).toHaveLength(1);
    expect(tries[0]).toMatchObject({ attempt: 1, outcome: "SENT_TO_PROVIDER", http_status: 200 });

    const payload = JSON.parse(calls[0]!.body) as { text: string; blocks: unknown[] };
    const all = calls[0]!.body;
    expect(payload.text.startsWith("MOTHER AI · REVIEW REQUIRED")).toBe(true);
    for (const expected of ["Acme, Inc.", "billing-agent-prod", "production", "payments", "refund", "payment:pi_123", "High value refunds", "HUMAN_APPROVAL_REQUIRED", body.decision_id, body.approval_id, "https://mother.proptechusa.ai/app/approvals", "Created", "Expires"]) {
      expect(all).toContain(expected);
    }
    // Request context is never sent; neither are keys or the destination itself.
    for (const forbidden of ["SUP-CONTEXT-ONLY-7781", "4200", org.key.raw, WEBHOOK_A, ...TOKENS]) expect(all).not.toContain(forbidden);

    const approvalRow = await approval(body.approval_id);
    expect(approvalRow).toMatchObject({ status: "pending", expires_at: body.approval.expires_at, acted_at: null, consumed_at: null });
  });

  it("2 + 3. ALLOW and BLOCK never create or send approval notifications", async () => {
    const org = await reviewedOrg();
    const allow = (await (await evaluate(org.key.raw, refund(50))).json()) as { decision: string };
    const block = (await (await evaluate(org.key.raw, refund(50, { data_class: "restricted" }))).json()) as { decision: string };
    const unknownAgent = (await (await evaluate(org.key.raw, refund(5000, { agent_id: "ghost-agent" }))).json()) as { decision: string };
    expect([allow.decision, block.decision, unknownAgent.decision]).toEqual(["allow", "block", "block"]);
    await sweepApprovalNotifications(env);
    expect(calls).toHaveLength(0);
    expect(await rows()).toHaveLength(0);
  });

  it("5. duplicate evaluations, retries, polling, console reads, re-queueing and cron sweeps do not duplicate the alert", async () => {
    const org = await reviewedOrg();
    const first = (await (await evaluate(org.key.raw, { ...refund(4200), request_id: "req-dup" })).json()) as { approval_id: string };
    const replay = await evaluate(org.key.raw, { ...refund(4200), request_id: "req-dup" });
    expect(replay.headers.get("Idempotent-Replayed")).toBe("true");
    expect(((await replay.json()) as { approval_id: string }).approval_id).toBe(first.approval_id);
    await call(env, `/v1/approvals/${first.approval_id}`, { key: org.key.raw });
    await call(env, "/api/console/approvals", { cookie: org.owner.cookie });
    await queueApprovalNotification(env.DB, org.orgId, first.approval_id, "review_required", Date.now());
    await sweepApprovalNotifications(env);
    await sweepApprovalNotifications(env, () => Date.now() + 5 * 60_000);
    expect(calls).toHaveLength(1);
    expect(await rows(first.approval_id)).toHaveLength(1);
  });

  it("5. concurrent deliveries of the same queued notification send once", async () => {
    const org = await setupOrg(env, "Race Co");
    const res = (await (await evaluate(org.key.raw, refund(4200))).json()) as { approval_id: string };
    // Configure after the approval exists, then queue it by hand as if it had been configured first.
    await env.DB.prepare(`UPDATE organizations SET id = id WHERE id = ?`).bind(org.orgId).run();
    await configure(org.owner.cookie, WEBHOOK_A);
    await env.DB.prepare(`UPDATE notification_channels SET created_at = '2000-01-01T00:00:00.000Z' WHERE organization_id = ?`).bind(org.orgId).run();
    const id = (await queueApprovalNotification(env.DB, org.orgId, res.approval_id, "review_required", Date.now()))!;
    mode = "hold";
    const a = deliverNotification(env, id);
    const b = deliverNotification(env, id);
    await new Promise((r) => setTimeout(r, 20));
    const c = deliverNotification(env, id);
    release();
    await Promise.all([a, b, c]);
    expect(calls).toHaveLength(1);
    expect((await rows(res.approval_id))[0]).toMatchObject({ status: "SENT_TO_PROVIDER", attempts: 1 });
  });

  // ---------------------------------------------------------------- 6: failures never touch the approval
  it.each([
    ["400", "HTTP_400", 1],
    ["403", "HTTP_403", 1],
    ["404", "HTTP_404", 1],
  ] as const)("6. Slack %s is permanent: FAILED after one attempt, approval untouched", async (m, code, expectedCalls) => {
    const org = await reviewedOrg();
    mode = m;
    const res = await evaluate(org.key.raw, refund(4200));
    const body = (await res.json()) as { decision: string; approval_id: string; approval: { expires_at: string } };
    expect(res.status).toBe(200);
    expect(body.decision).toBe("review");
    await sweepApprovalNotifications(env, () => Date.now() + 10 * 60_000 - 1000);
    expect(calls).toHaveLength(expectedCalls);
    expect((await rows(body.approval_id))[0]).toMatchObject({ status: "FAILED", attempts: 1, last_error: code });
    expect(await approval(body.approval_id)).toMatchObject({ status: "pending", expires_at: body.approval.expires_at });
  });

  it.each(["429", "500", "network", "timeout"] as const)("6. Slack %s retries boundedly (inline, then cron) and never alters the decision", async (m) => {
    const org = await reviewedOrg();
    mode = m;
    const res = await evaluate(org.key.raw, refund(4200));
    const body = (await res.json()) as { decision: string; approval_id: string; approval: { status: string; expires_at: string } };
    expect(res.status).toBe(200);
    expect(body).toMatchObject({ decision: "review", approval: { status: "pending" } });
    // Attempt 1 plus one inline retry.
    expect(calls).toHaveLength(2);
    let [row] = await rows(body.approval_id);
    expect(row).toMatchObject({ status: "QUEUED", attempts: 2 });
    // Not due yet: a sweep does nothing.
    await sweepApprovalNotifications(env);
    expect(calls).toHaveLength(2);
    // Cron retry after backoff is the last attempt.
    await sweepApprovalNotifications(env, () => Date.now() + 2 * 60_000);
    expect(calls).toHaveLength(3);
    [row] = await rows(body.approval_id);
    const expectedError = m === "network" ? "NETWORK" : m === "timeout" ? "TIMEOUT" : `HTTP_${m}`;
    expect(row).toMatchObject({ status: "FAILED", attempts: 3, last_error: expectedError });
    expect((await attempts(String(row!.id))).map((a) => a.outcome)).toEqual(["FAILED", "FAILED", "FAILED"]);
    // No further sends, ever.
    await sweepApprovalNotifications(env, () => Date.now() + 9 * 60_000);
    expect(calls).toHaveLength(3);
    expect(await approval(body.approval_id)).toMatchObject({ status: "pending", expires_at: body.approval.expires_at, acted_at: null });
    // The approval still works end to end.
    expect((await call(env, `/api/console/approvals/${body.approval_id}/approve`, { json: {}, cookie: org.owner.cookie })).status).toBe(200);
    expect((await call(env, `/v1/approvals/${body.approval_id}/consume`, { method: "POST", key: org.key.raw })).status).toBe(200);
    // Initial alert was never sent, so no resolution alerts are invented.
    await sweepApprovalNotifications(env, () => Date.now() + 10 * 60_000);
    expect(calls).toHaveLength(3);
  });

  it("6. a notification subsystem crash cannot change the evaluate response or the approval", async () => {
    const org = await reviewedOrg();
    env.shim.sqlite.exec("ALTER TABLE approval_notifications RENAME TO approval_notifications_gone");
    const res = await evaluate(org.key.raw, refund(4200));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { decision: string; approval_id: string };
    expect(body.decision).toBe("review");
    expect(await approval(body.approval_id)).toMatchObject({ status: "pending" });
    expect(calls).toHaveLength(0);
    expect(JSON.stringify(logs)).toContain("approval notification error");
  });

  it("responds to the agent while Slack is still pending (background delivery)", async () => {
    const org = await reviewedOrg();
    mode = "hold";
    const c = ctx();
    const request = new Request("https://api.mother.proptechusa.ai/v1/evaluate", {
      method: "POST",
      headers: { Authorization: `Bearer ${org.key.raw}`, "Content-Type": "application/json", "CF-Connecting-IP": "203.0.113.7" },
      body: JSON.stringify(refund(4200)),
    });
    const res = await worker.fetch(request, env, c);
    expect(res.status).toBe(200);
    expect(((await res.json()) as { decision: string }).decision).toBe("review");
    expect(c.pending).toHaveLength(1);
    await new Promise((r) => setTimeout(r, 20));
    expect(calls).toHaveLength(1);
    release();
    await Promise.all(c.pending);
    expect((await rows())[0]).toMatchObject({ status: "SENT_TO_PROVIDER" });
  });

  // ---------------------------------------------------------------- configuration states
  it("webhook absent: REVIEW works and nothing is queued or sent", async () => {
    const org = await setupOrg(env, "Quiet Co");
    const body = (await (await evaluate(org.key.raw, refund(4200))).json()) as { decision: string };
    expect(body.decision).toBe("review");
    await sweepApprovalNotifications(env);
    expect(calls).toHaveLength(0);
    expect(await rows()).toHaveLength(0);
    const settings = (await (await call(env, "/api/console/notifications", { cookie: org.owner.cookie })).json()) as { slack: { configured: boolean; status: string } };
    expect(settings.slack).toEqual({ configured: false, status: "not_configured" });
  });

  it("encryption key missing: configuration is refused, and delivery fails closed without contacting Slack", async () => {
    const org = await reviewedOrg();
    env.NOTIFICATION_ENCRYPTION_KEY = undefined;
    const refused = await configure(org.owner.cookie, WEBHOOK_A2);
    expect(refused.status).toBe(503);
    const body = (await (await evaluate(org.key.raw, refund(4200))).json()) as { decision: string; approval_id: string };
    expect(body.decision).toBe("review");
    expect(calls).toHaveLength(0);
    expect((await rows(body.approval_id))[0]).toMatchObject({ status: "FAILED", last_error: "ENCRYPTION_KEY_UNAVAILABLE" });
  });

  it("invalid or malformed destinations are rejected and never echoed back", async () => {
    const org = await setupOrg(env, "Strict Co");
    const bad = [
      hook("T0AAAAAAA", "B0AAAAAAA", TOKENS[0]!, { scheme: "http" }),
      hook("T0AAAAAAA", "B0AAAAAAA", TOKENS[0]!, { host: `${SLACK_HOST}.evil.example` }),
      `https://evil.example/?u=${WEBHOOK_A}`,
      hook("T0AAAAAAA", "B0AAAAAAA", "../../x"),
      hook("T0AAAAAAA", "A0AAAAAAA", `123/${TOKENS[0]!}`, { kind: "workflows" }),
      hook("T0AAAAAAA", "B0AAAAAAA", TOKENS[0]!, { host: `user@${SLACK_HOST}` }),
      "javascript:alert(1)",
      "",
    ];
    for (const url of bad) {
      const res = await configure(org.owner.cookie, url);
      expect(res.status).toBe(400);
      const text = await res.text();
      if (url) expect(text).not.toContain(url);
    }
    expect((await env.DB.prepare(`SELECT COUNT(*) AS n FROM notification_channels`).first<{ n: number }>())!.n).toBe(0);

    // A corrupted stored destination fails closed.
    await configure(org.owner.cookie, WEBHOOK_A);
    await env.DB.prepare(`UPDATE notification_channels SET secret_ciphertext = 'v1.AAAA.BBBB' WHERE organization_id = ?`).bind(org.orgId).run();
    const body = (await (await evaluate(org.key.raw, refund(4200))).json()) as { decision: string; approval_id: string };
    expect(body.decision).toBe("review");
    expect(calls).toHaveLength(0);
    expect((await rows(body.approval_id))[0]).toMatchObject({ status: "FAILED", last_error: "DESTINATION_UNREADABLE" });
  });

  // ---------------------------------------------------------------- resolution events
  it("approved then consumed: two separate truthful events; approved never claims execution", async () => {
    const org = await reviewedOrg();
    const body = (await (await evaluate(org.key.raw, refund(4200))).json()) as { approval_id: string };
    expect((await call(env, `/api/console/approvals/${body.approval_id}/approve`, { json: { note: "ok" }, cookie: org.owner.cookie })).status).toBe(200);
    expect(calls).toHaveLength(2);
    const approved = JSON.parse(calls[1]!.body) as { text: string };
    expect(approved.text.startsWith("MOTHER AI · APPROVED")).toBe(true);
    expect(calls[1]!.body).toContain("Approved is not executed");
    expect(calls[1]!.body).toContain("Olive Owner");
    expect(calls[1]!.body).not.toMatch(/executed successfully|has been executed|was executed/i);

    const consumed = await call(env, `/v1/approvals/${body.approval_id}/consume`, { method: "POST", key: org.key.raw });
    expect(consumed.status).toBe(200);
    expect(calls).toHaveLength(3);
    expect(JSON.parse(calls[2]!.body).text.startsWith("MOTHER AI · CONSUMED")).toBe(true);
    expect(calls[2]!.body).toContain("does not observe the downstream action");

    // Consume semantics are unchanged: a second redemption is refused and sends nothing.
    const again = await call(env, `/v1/approvals/${body.approval_id}/consume`, { method: "POST", key: org.key.raw });
    expect(again.status).toBe(409);
    await sweepApprovalNotifications(env, () => Date.now() + 10 * 60_000);
    expect(calls).toHaveLength(3);
    expect((await rows(body.approval_id)).map((r) => [r.event, r.status])).toEqual([
      ["review_required", "SENT_TO_PROVIDER"],
      ["approved", "SENT_TO_PROVIDER"],
      ["consumed", "SENT_TO_PROVIDER"],
    ]);
  });

  it("denied: one DENIED event and the grant still cannot be consumed", async () => {
    const org = await reviewedOrg();
    const body = (await (await evaluate(org.key.raw, refund(4200))).json()) as { approval_id: string };
    await call(env, `/api/console/approvals/${body.approval_id}/deny`, { json: {}, cookie: org.owner.cookie });
    expect(calls).toHaveLength(2);
    expect(JSON.parse(calls[1]!.body).text.startsWith("MOTHER AI · DENIED")).toBe(true);
    expect((await call(env, `/v1/approvals/${body.approval_id}/consume`, { method: "POST", key: org.key.raw })).status).toBe(409);
    expect(calls).toHaveLength(2);
  });

  it("expired: the cron persists expiry, then sends one EXPIRED event; an unsent initial alert is skipped, not sent late", async () => {
    const org = await reviewedOrg();
    const sent = (await (await evaluate(org.key.raw, refund(4200))).json()) as { approval_id: string };
    mode = "500";
    const unsent = (await (await evaluate(org.key.raw, refund(4300))).json()) as { approval_id: string };
    expect(calls).toHaveLength(3);
    mode = "ok";

    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 16 * 60_000);
    const c = ctx();
    await worker.scheduled({ cron: "*/10 * * * *", scheduledTime: Date.now(), noRetry: () => {} } as ScheduledController, env, c);
    await Promise.all(c.pending);
    vi.useRealTimers();

    expect(await approval(sent.approval_id)).toMatchObject({ status: "expired" });
    expect(calls).toHaveLength(4);
    expect(JSON.parse(calls[3]!.body).text.startsWith("MOTHER AI · EXPIRED")).toBe(true);
    expect((await rows(unsent.approval_id)).map((r) => [r.event, r.status, r.last_error])).toEqual([["review_required", "SKIPPED", "APPROVAL_NOT_PENDING"]]);
  });

  it("organization suspended: queued notifications are skipped, never sent", async () => {
    const org = await reviewedOrg();
    mode = "500";
    const body = (await (await evaluate(org.key.raw, refund(4200))).json()) as { approval_id: string };
    expect(calls).toHaveLength(2);
    await env.DB.prepare(`UPDATE organizations SET status = 'suspended' WHERE id = ?`).bind(org.orgId).run();
    mode = "ok";
    await sweepApprovalNotifications(env, () => Date.now() + 2 * 60_000);
    expect(calls).toHaveLength(2);
    expect((await rows(body.approval_id))[0]).toMatchObject({ status: "SKIPPED", last_error: "ORGANIZATION_NOT_ACTIVE" });
  });

  it("an abandoned send (lease expired) is logged ABANDONED and retried within the attempt bound", async () => {
    const org = await setupOrg(env, "Lease Co");
    await configure(org.owner.cookie, WEBHOOK_A);
    const body = (await (await evaluate(org.key.raw, refund(4200))).json()) as { approval_id: string };
    const [row] = await rows(body.approval_id);
    // Simulate an invocation that claimed attempt 2 and died.
    env.shim.sqlite.exec(`DROP TRIGGER approval_notifications_terminal`);
    await env.DB.prepare(`UPDATE approval_notifications SET status = 'SENDING', attempts = 2, lease_until = ?, last_attempt_at = ? WHERE id = ?`)
      .bind(new Date(Date.now() - 1000).toISOString(), new Date(Date.now() - 61_000).toISOString(), row!.id)
      .run();
    calls = [];
    await sweepApprovalNotifications(env);
    expect(calls).toHaveLength(1);
    const tries = await attempts(String(row!.id));
    expect(tries.map((t) => t.outcome)).toEqual(["SENT_TO_PROVIDER", "ABANDONED", "SENT_TO_PROVIDER"]);
  });

  it("terminal notifications are immutable and records cannot be deleted", async () => {
    const org = await reviewedOrg();
    const body = (await (await evaluate(org.key.raw, refund(4200))).json()) as { approval_id: string };
    const [row] = await rows(body.approval_id);
    await expect(env.DB.prepare(`UPDATE approval_notifications SET status = 'QUEUED' WHERE id = ?`).bind(row!.id).run()).rejects.toThrow(/invalid notification transition/);
    await expect(env.DB.prepare(`DELETE FROM approval_notifications WHERE id = ?`).bind(row!.id).run()).rejects.toThrow(/retained/);
    await expect(env.DB.prepare(`DELETE FROM approval_notification_attempts`).run()).rejects.toThrow(/append-only/);
  });

  it("a destination configured after an approval was created does not alert on that older approval", async () => {
    const org = await setupOrg(env, "Late Co");
    const body = (await (await evaluate(org.key.raw, refund(4200))).json()) as { approval_id: string };
    await new Promise((r) => setTimeout(r, 5));
    await configure(org.owner.cookie, WEBHOOK_A);
    await sweepApprovalNotifications(env);
    expect(calls).toHaveLength(0);
    expect(await rows(body.approval_id)).toHaveLength(0);
  });

  // ---------------------------------------------------------------- content safety
  it("escapes malicious Slack markup and never forwards secrets from context or resource", async () => {
    const org = await reviewedOrg();
    await env.DB.prepare(`UPDATE policies SET name = '<!here> Refunds <https://phish.example|approve now>' WHERE id = ?`).bind(org.reviewPolicy).run();
    await env.DB.prepare(`UPDATE agents SET display_name = '<@U12345> *Billing*' WHERE id = ?`).bind(org.agentId).run();
    await evaluate(org.key.raw, refund(4200, {
      resource: "<!channel> <https://evil.example|click> `code` mai_live_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      context: { amount: 4200, api_key: "sk_live_1234567890abcdefghij", note: "Bearer abcdefghijklmnop1234", password: "hunter2hunter2" },
    }));
    expect(calls).toHaveLength(1);
    const body = calls[0]!.body;
    for (const forbidden of ["<!channel>", "<!here>", "<@U12345>", "<https://evil.example", "<https://phish.example", "mai_live_AAAA", "sk_live_1234567890", "abcdefghijklmnop1234", "hunter2"]) {
      expect(body).not.toContain(forbidden);
    }
    expect(body).toContain("&lt;!here&gt;");
    expect(body).toContain("[REDACTED]");
  });

  it("payload builder caps long values and flattens control characters", () => {
    const payload = buildApprovalSlackPayload({
      event: "review_required",
      organization: "Org\nwith breaks",
      approval_id: "apr_AAAAAAAAAAAAAAAAAAAAAA",
      decision_id: "dec_AAAAAAAAAAAAAAAAAAAAAA",
      agent_key: "agent",
      agent_display_name: null,
      environment: "production",
      protocol: "mcp",
      capability: "crm",
      operation: "x".repeat(5000),
      resource: "r".repeat(5000),
      mcp_server: "salesforce",
      mcp_tool: "contacts.delete",
      policy_id: null,
      policy_name: null,
      policy_version: null,
      reason_code: "DEFAULT_REVIEW",
      requested_at: "2026-09-14T17:00:00.000Z",
      expires_at: "2026-09-14T17:15:00.000Z",
      acted_at: null,
      acted_by_name: null,
      grant_expires_at: null,
      consumed_at: null,
    });
    const json = JSON.stringify(payload);
    expect(json.length).toBeLessThan(4000);
    expect(json).toContain("Org with breaks");
    expect(json).toContain("MCP salesforce / contacts.delete");
    expect(json).toContain("No policy (organization default)");
  });

  // ---------------------------------------------------------------- 7-8: secrets and tenancy
  it("7. the webhook never appears in API responses, control events, stored rows or logs", async () => {
    const org = await reviewedOrg();
    await evaluate(org.key.raw, refund(4200));
    mode = "500";
    await evaluate(org.key.raw, refund(4300));
    const responses = [
      await (await call(env, "/api/console/notifications", { cookie: org.owner.cookie })).text(),
      await (await call(env, "/api/console/notifications/slack/test", { json: {}, cookie: org.owner.cookie })).text(),
      await (await call(env, "/api/console/approvals?status=all", { cookie: org.owner.cookie })).text(),
      await (await call(env, "/api/console/events", { cookie: org.owner.cookie })).text(),
      await (await configure(org.owner.cookie, WEBHOOK_A2)).text(),
      await (await call(env, "/api/console/notifications/slack/remove", { json: {}, cookie: org.owner.cookie })).text(),
    ].join("\n");
    const dump = JSON.stringify({
      events: (await env.DB.prepare(`SELECT * FROM control_events`).all()).results,
      notifications: (await env.DB.prepare(`SELECT * FROM approval_notifications`).all()).results,
      attempts: (await env.DB.prepare(`SELECT * FROM approval_notification_attempts`).all()).results,
      logs,
    });
    for (const secret of [WEBHOOK_A, WEBHOOK_A2, ...TOKENS, "hooks.slack.com", env.NOTIFICATION_ENCRYPTION_KEY!]) {
      expect(responses).not.toContain(secret);
      expect(dump).not.toContain(secret);
    }
    const actions = ((await env.DB.prepare(`SELECT action FROM control_events WHERE action LIKE 'notifications.%' ORDER BY created_at`).all<{ action: string }>()).results).map((r) => r.action);
    expect(actions).toEqual(["notifications.slack_configured", "notifications.slack_test_sent", "notifications.slack_replaced", "notifications.slack_removed"]);
  });

  it("stores only ciphertext bound to the organization", async () => {
    const org = await reviewedOrg();
    const row = await env.DB.prepare(`SELECT * FROM notification_channels WHERE organization_id = ?`).bind(org.orgId).first<Record<string, string>>();
    expect(row!.secret_ciphertext).toMatch(/^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(JSON.stringify(row)).not.toContain("hooks.slack.com");
  });

  it("8. cross-org: each org alerts only its own destination, and a copied ciphertext cannot be used by another org", async () => {
    const a = await reviewedOrg("Org A", WEBHOOK_A);
    const b = await reviewedOrg("Org B", WEBHOOK_B);
    const ra = (await (await evaluate(a.key.raw, refund(4200))).json()) as { approval_id: string };
    const rb = (await (await evaluate(b.key.raw, refund(4200))).json()) as { approval_id: string };
    expect(calls.map((c) => c.url)).toEqual([WEBHOOK_A, WEBHOOK_B]);
    expect(calls[0]!.body).toContain("Org A");
    expect(calls[0]!.body).not.toContain("Org B");
    expect(calls[1]!.body).not.toContain(ra.approval_id);

    // B cannot see A's notification activity or act on A's approvals.
    const bSettings = await (await call(env, "/api/console/notifications", { cookie: b.owner.cookie })).text();
    expect(bSettings).toContain(rb.approval_id);
    expect(bSettings).not.toContain(ra.approval_id);
    expect(await queueApprovalNotification(env.DB, b.orgId, ra.approval_id, "review_required", Date.now())).toBeNull();

    // Copy A's ciphertext into B's channel: decryption is bound to B's org and channel id and fails.
    await env.DB.prepare(`UPDATE notification_channels SET secret_ciphertext = (SELECT secret_ciphertext FROM notification_channels WHERE organization_id = ?) WHERE organization_id = ?`)
      .bind(a.orgId, b.orgId)
      .run();
    calls = [];
    const rb2 = (await (await evaluate(b.key.raw, refund(4300))).json()) as { approval_id: string; decision: string };
    expect(rb2.decision).toBe("review");
    expect(calls).toHaveLength(0);
    expect((await rows(rb2.approval_id))[0]).toMatchObject({ status: "FAILED", last_error: "DESTINATION_UNREADABLE" });
  });

  it("roles: only admins and owners configure; viewers see status; suspended orgs cannot configure but can remove", async () => {
    const org = await setupOrg(env, "Roles Co");
    const viewer = await seedSession(env, org.orgId, "viewer");
    const approver = await seedSession(env, org.orgId, "approver");
    const security = await seedSession(env, org.orgId, "security");
    const admin = await seedSession(env, org.orgId, "admin");
    for (const s of [viewer, approver, security]) {
      expect((await configure(s.cookie, WEBHOOK_A)).status).toBe(403);
      expect((await call(env, "/api/console/notifications/slack/test", { json: {}, cookie: s.cookie })).status).toBe(403);
    }
    expect((await call(env, "/api/console/notifications", { cookie: viewer.cookie })).status).toBe(200);
    expect((await configure(admin.cookie, WEBHOOK_A)).status).toBe(201);
    expect((await call(env, "/api/console/notifications/slack/remove", { json: {}, cookie: viewer.cookie })).status).toBe(403);
    // CSRF: cross-origin configuration is rejected.
    expect((await call(env, "/api/console/notifications/slack", { json: { webhook_url: WEBHOOK_A2 }, cookie: admin.cookie, origin: "https://evil.example" })).status).toBe(403);

    await env.DB.prepare(`UPDATE organizations SET status = 'suspended' WHERE id = ?`).bind(org.orgId).run();
    expect((await configure(admin.cookie, WEBHOOK_A2)).status).toBe(403);
    expect((await call(env, "/api/console/notifications/slack/remove", { json: {}, cookie: admin.cookie })).status).toBe(200);
  });

  it("test send reports the provider result truthfully and creates no approval", async () => {
    const org = await reviewedOrg();
    const ok = (await (await call(env, "/api/console/notifications/slack/test", { json: {}, cookie: org.owner.cookie })).json()) as { test: { status: string } };
    expect(ok.test).toEqual({ status: "SENT_TO_PROVIDER", http_status: 200, error: null });
    expect(JSON.parse(calls[0]!.body).text).toContain("No approval was created");
    mode = "403";
    const failed = (await (await call(env, "/api/console/notifications/slack/test", { json: {}, cookie: org.owner.cookie })).json()) as { test: { status: string } };
    expect(failed.test).toEqual({ status: "FAILED", http_status: 403, error: "HTTP_403" });
    expect(await rows()).toHaveLength(0);
    expect((await env.DB.prepare(`SELECT COUNT(*) AS n FROM approvals`).first<{ n: number }>())!.n).toBe(0);
  });

  it("replacing the destination sends later alerts to the new webhook only", async () => {
    const org = await reviewedOrg();
    expect((await configure(org.owner.cookie, WEBHOOK_A2)).status).toBe(200);
    await evaluate(org.key.raw, refund(4200));
    expect(calls.map((c) => c.url)).toEqual([WEBHOOK_A2]);
  });

  it("9. the approvals API exposes notification status without changing approval fields", async () => {
    const org = await reviewedOrg();
    const body = (await (await evaluate(org.key.raw, refund(4200))).json()) as { approval_id: string; approval: Record<string, unknown> };
    const list = (await (await call(env, "/api/console/approvals", { cookie: org.owner.cookie })).json()) as { approvals: Array<Record<string, unknown>> };
    expect(list.approvals[0]).toMatchObject({ approval_id: body.approval_id, status: "pending", executable: false, notification: { channel: "slack", status: "SENT_TO_PROVIDER", error: null } });
    const poll = (await (await call(env, `/v1/approvals/${body.approval_id}`, { key: org.key.raw })).json()) as Record<string, unknown>;
    expect(Object.keys(poll).sort()).toEqual(["agent_id", "approval_id", "capability", "consumed_at", "decision_id", "executable", "expires_at", "grant_expires_at", "operation", "request_id", "requested_at", "resource", "status"]);
  });
});
