import { describe, expect, it, vi } from "vitest";
import { call, createEnv } from "../helpers/env";
import { DEMO_SCENARIOS } from "../../src/demo/workspace";

describe("demo workspace", () => {
  it("every scenario produces its documented decision and nothing is stored", async () => {
    const env = createEnv();
    const expected: Record<string, [string, string]> = {
      "research-read": ["allow", "POLICY_ALLOW"],
      "research-modify": ["block", "OPERATION_NOT_ALLOWED"],
      "refund-small": ["allow", "POLICY_ALLOW"],
      "refund-large": ["review", "HUMAN_APPROVAL_REQUIRED"],
      "restricted-egress": ["block", "RESTRICTED_DATA_EGRESS"],
      "mcp-update": ["allow", "POLICY_ALLOW"],
      "mcp-delete": ["block", "OPERATION_NOT_ALLOWED"],
      "unknown-agent": ["block", "AGENT_UNKNOWN"],
    };
    expect(DEMO_SCENARIOS.map((s) => s.id).sort()).toEqual(Object.keys(expected).sort());
    for (const scenario of DEMO_SCENARIOS) {
      const res = await call(env, "/api/demo/evaluate", { json: scenario.request });
      const body = (await res.json()) as { decision: string; reason_code: string; stored: boolean };
      expect([scenario.id, body.decision, body.reason_code]).toEqual([scenario.id, ...expected[scenario.id]!]);
      expect(body.stored).toBe(false);
    }
    const n = await env.DB.prepare(`SELECT (SELECT COUNT(*) FROM decisions) + (SELECT COUNT(*) FROM approvals) AS n`).first<{ n: number }>();
    expect(n?.n).toBe(0);
  });

  it("validates input and rate limits", async () => {
    const env = createEnv();
    expect((await call(env, "/api/demo/evaluate", { json: { agent_id: "x" } })).status).toBe(400);
    env.limiters.RL_DEMO!.blocked = true;
    expect((await call(env, "/api/demo/evaluate", { json: DEMO_SCENARIOS[0]!.request })).status).toBe(429);
    const ws = await call(env, "/api/demo/workspace");
    expect(ws.status).toBe(200);
    expect(await ws.json()).toMatchObject({ demo: true });
  });
});

describe("founding access", () => {
  const valid = { name: "Jane Doe", company: "Acme, Inc.", work_email: "Jane@Acme.com", use_case: "Govern refunds issued by our support agents.", agent_count: "6-25", uses_mcp: "yes", website: "" };

  async function token(env: ReturnType<typeof createEnv>) {
    return ((await (await call(env, "/api/founding-access/token")).json()) as { form_token: string; turnstile_site_key: string | null });
  }

  it("stores a valid submission once the form has been open long enough", async () => {
    const env = createEnv();
    const t = await token(env);
    expect(t.turnstile_site_key).toBeNull();
    const tooFast = await call(env, "/api/founding-access", { json: { ...valid, form_token: t.form_token } });
    expect(tooFast.status).toBe(400);
    expect(await tooFast.json()).toMatchObject({ error: { code: "FORM_TOO_FAST" } });

    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 10_000);
    try {
      const ok = await call(env, "/api/founding-access", { json: { ...valid, form_token: t.form_token } });
      expect(ok.status).toBe(201);
      const again = await call(env, "/api/founding-access", { json: { ...valid, form_token: t.form_token } });
      expect(again.status).toBe(201);
    } finally {
      vi.useRealTimers();
    }
    const rows = await env.DB.prepare(`SELECT work_email, agent_count, uses_mcp, turnstile, ip_hash FROM founding_access_requests`).all<Record<string, string>>();
    expect(rows.results).toHaveLength(1);
    expect(rows.results[0]).toMatchObject({ work_email: "jane@acme.com", agent_count: "6-25", uses_mcp: "yes", turnstile: "not_configured" });
    expect(rows.results[0]!.ip_hash).not.toContain("203.0.113.7");
  });

  it("rejects forged tokens, field errors, honeypot bots and bursts", async () => {
    const env = createEnv();
    const forged = await call(env, "/api/founding-access", { json: { ...valid, form_token: `${Date.now() - 60_000}.${"0".repeat(64)}` } });
    expect(await forged.json()).toMatchObject({ error: { code: "FORM_EXPIRED" } });

    const t = await token(env);
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 10_000);
    try {
      const invalid = await call(env, "/api/founding-access", { json: { ...valid, work_email: "not-an-email", use_case: "short", agent_count: "lots", form_token: t.form_token } });
      expect(invalid.status).toBe(400);
      const body = (await invalid.json()) as { error: { fields: Record<string, string> } };
      expect(Object.keys(body.error.fields).sort()).toEqual(["agent_count", "use_case", "work_email"]);

      const bot = await call(env, "/api/founding-access", { json: { ...valid, work_email: "bot@spam.example", website: "http://spam", form_token: t.form_token } });
      expect(bot.status).toBe(201);
    } finally {
      vi.useRealTimers();
    }
    expect((await env.DB.prepare(`SELECT COUNT(*) AS n FROM founding_access_requests`).first<{ n: number }>())?.n).toBe(0);
    env.limiters.RL_FORMS!.blocked = true;
    expect((await call(env, "/api/founding-access", { json: valid })).status).toBe(429);
  });

  it("fails closed without a signing key", async () => {
    const env = createEnv({ FORM_SIGNING_KEY: undefined });
    expect((await call(env, "/api/founding-access/token")).status).toBe(503);
  });
});

describe("health, headers and routing", () => {
  it("reports health without leaking configuration", async () => {
    const env = createEnv();
    const res = await call(env, "/health");
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toMatchObject({ status: "ok", service: "mother-ai", d1: "reachable", policy_engine: "mpe-1.0.0" });
    expect(JSON.stringify(body)).not.toMatch(/signing|secret|key/i);
    const ready = (await (await call(env, "/ready")).json()) as { ready: boolean };
    expect(ready.ready).toBe(true);
  });

  it("applies security headers everywhere and serves the console shell for deep links", async () => {
    const env = createEnv();
    for (const path of ["/", "/app/policies/pol_x", "/health", "/api/demo/workspace", "/nope"]) {
      const res = await call(env, path);
      expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
      expect(res.headers.get("Referrer-Policy")).toBe("strict-origin-when-cross-origin");
      expect(res.headers.get("X-Frame-Options")).toBe("DENY");
      expect(res.headers.get("Strict-Transport-Security")).toContain("max-age=");
      expect(res.headers.get("Content-Security-Policy")).toContain("default-src 'self'");
    }
    const deep = await call(env, "/app/policies/pol_x");
    expect(deep.status).toBe(200);
    expect(await deep.text()).toContain("asset /app/");
    expect((await call(env, "/nope")).status).toBe(404);
    expect((await call(env, "/api/nope")).status).toBe(404);
    const robots = await (await call(env, "/robots.txt")).text();
    expect(robots).toContain("Disallow: /app/");
  });

  it("never exposes stack traces", async () => {
    const env = createEnv();
    (env as unknown as { DB: unknown }).DB = { prepare: () => { throw new Error("secret internal detail at db.ts:42"); }, batch: () => { throw new Error("secret internal detail"); } };
    const res = await call(env, "/api/console/overview", { cookie: "__Host-mai_session=" + "a".repeat(43) });
    expect(res.status).toBe(500);
    expect(await res.text()).not.toContain("secret internal detail");
    const gw = await call(env, "/v1/evaluate", { key: `mai_live_${"a".repeat(40)}`, json: { agent_id: "a", capability: "b", operation: "c" } });
    const text = await gw.text();
    expect(text).not.toContain("secret internal detail");
    expect(JSON.parse(text)).toMatchObject({ decision: "block" });
  });
});
