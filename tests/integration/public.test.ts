import { describe, expect, it, vi } from "vitest";
import { API_ORIGIN, call, createEnv, FALLBACK_ORIGIN, ORIGIN, seedAgent, seedKey, seedOrg, seedPolicy, seedSession } from "../helpers/env";
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
    return ((await (await call(env, "/api/founding-access/token")).json()) as { form_token: string });
  }

  it("stores a valid submission once the form has been open long enough", async () => {
    const env = createEnv();
    const t = await token(env);
    expect(Object.keys(t)).toEqual(["form_token"]);
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
    // HTML must be no-transform so zone edge features never inject scripts into Mother AI pages.
    // (/nope is excluded: the mocked ASSETS binding has no 404.html, so it falls back to text/plain.)
    for (const path of ["/", "/app/policies/pol_x", `/verify/${"A".repeat(32)}`]) {
      expect((await call(env, path)).headers.get("Cache-Control")).toMatch(/no-transform/);
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

describe("canonical host and workers.dev fallback", () => {
  it("uses mother.proptechusa.ai as the canonical origin", () => {
    expect(ORIGIN).toBe("https://mother.proptechusa.ai");
    expect(FALLBACK_ORIGIN).toBe("https://mother-ai.sales-fd3.workers.dev");
  });

  it("redirects human-facing pages on the fallback host, preserving path and query", async () => {
    const env = createEnv();
    for (const path of ["/", "/app/", "/app/policies/pol_x?tab=1", "/app/accept-invite", `/verify/${"A".repeat(32)}`]) {
      const res = await call(env, path, { host: FALLBACK_ORIGIN });
      expect(res.status).toBe(308);
      expect(res.headers.get("Location")).toBe(`${ORIGIN}${path}`);
    }
    expect((await call(env, "/", {})).status).toBe(200);
    expect(await (await call(env, "/robots.txt", { host: FALLBACK_ORIGIN })).text()).toBe("User-agent: *\nDisallow: /\n");
    expect(await (await call(env, "/robots.txt", { host: API_ORIGIN })).text()).toBe("User-agent: *\nDisallow: /\n");
    expect((await call(env, "/app/login", { host: API_ORIGIN })).headers.get("Location")).toBe(`${ORIGIN}/app/login`);
    expect(await (await call(env, "/robots.txt")).text()).toContain(`Sitemap: ${ORIGIN}/sitemap.xml`);
  });

  it("keeps gateway, badge and health working on the fallback host", async () => {
    const env = createEnv();
    const orgId = await seedOrg(env);
    const key = await seedKey(env, orgId);
    await seedAgent(env, orgId, "billing-agent-prod");
    const gw = await call(env, "/v1/evaluate", { host: FALLBACK_ORIGIN, key: key.raw, json: { agent_id: "billing-agent-prod", capability: "payments", operation: "refund" } });
    expect(gw.status).toBe(200);
    expect(await gw.json()).toMatchObject({ decision: "block", reason_code: "DEFAULT_DENY" });
    expect((await call(env, "/health", { host: FALLBACK_ORIGIN })).status).toBe(200);
    const svg = await call(env, `/badge/${"A".repeat(32)}.svg`, { host: FALLBACK_ORIGIN });
    expect(svg.status).toBe(404);
    expect(svg.headers.get("Content-Type")).toContain("image/svg+xml");
  });

  it("binds passkey ceremonies to the UI origin, whichever host receives the API call", async () => {
    const env = createEnv();
    // UI origin calling the API host: allowed, RP ID is the UI hostname.
    const ok = await call(env, "/api/auth/login/options", { host: API_ORIGIN, json: {}, origin: ORIGIN, headers: { "Sec-Fetch-Site": "same-site" } });
    expect(ok.status).toBe(200);
    expect(((await ok.json()) as { rpId: string }).rpId).toBe("mother.proptechusa.ai");
    // Any other browser origin is refused before a challenge is issued.
    for (const origin of [FALLBACK_ORIGIN, API_ORIGIN, "https://www.proptechusa.ai", "https://evil.example"]) {
      const res = await call(env, "/api/auth/login/options", { host: API_ORIGIN, json: {}, origin });
      expect(res.status).toBe(403);
    }
  });
});

describe("browser API CORS matrix (UI on Vercel, API on the Worker)", () => {
  const preflightFor = (env: ReturnType<typeof createEnv>, path: string, origin: string, method = "POST") =>
    call(env, path, { host: API_ORIGIN, method: "OPTIONS", origin: null, headers: { Origin: origin, "Access-Control-Request-Method": method, "Access-Control-Request-Headers": "content-type" } });

  it("credentialed endpoints allow only the exact UI origin, with credentials", async () => {
    const env = createEnv();
    for (const path of ["/api/auth/login/options", "/api/console/agents"]) {
      const ok = await preflightFor(env, path, ORIGIN);
      expect(ok.status).toBe(204);
      expect(ok.headers.get("Access-Control-Allow-Origin")).toBe(ORIGIN);
      expect(ok.headers.get("Access-Control-Allow-Credentials")).toBe("true");
      expect(ok.headers.get("Access-Control-Allow-Headers")).toBe("Content-Type");
      expect(ok.headers.get("Vary")).toContain("Origin");
      for (const bad of ["https://evil.example", "https://www.proptechusa.ai", FALLBACK_ORIGIN, "null"]) {
        const res = await preflightFor(env, path, bad);
        expect(res.status).toBe(403);
        expect(res.headers.get("Access-Control-Allow-Origin")).toBeNull();
      }
    }
    const session = await call(env, "/api/auth/session", { host: API_ORIGIN, headers: { Origin: ORIGIN } });
    expect(session.status).toBe(401);
    expect(session.headers.get("Access-Control-Allow-Origin")).toBe(ORIGIN);
    expect(session.headers.get("Access-Control-Allow-Credentials")).toBe("true");
    const evil = await call(env, "/api/auth/session", { host: API_ORIGIN, headers: { Origin: "https://evil.example" } });
    expect(evil.headers.get("Access-Control-Allow-Origin")).toBeNull();
  });

  it("public browser endpoints allow the exact UI origin without credentials", async () => {
    const env = createEnv();
    for (const [path, method] of [["/api/demo/evaluate", "POST"], ["/api/demo/workspace", "GET"], ["/api/founding-access/token", "GET"], ["/api/founding-access", "POST"], [`/api/public/badges/${"A".repeat(32)}`, "GET"]] as const) {
      const ok = await preflightFor(env, path, ORIGIN, method);
      expect(ok.status).toBe(204);
      expect(ok.headers.get("Access-Control-Allow-Origin")).toBe(ORIGIN);
      expect(ok.headers.get("Access-Control-Allow-Credentials")).toBeNull();
      expect((await preflightFor(env, path, "https://evil.example", method)).status).toBe(403);
    }
    const ws = await call(env, "/api/demo/workspace", { host: API_ORIGIN, headers: { Origin: ORIGIN } });
    expect(ws.headers.get("Access-Control-Allow-Origin")).toBe(ORIGIN);
    expect(ws.headers.get("Access-Control-Allow-Credentials")).toBeNull();
  });

  it("server-to-server endpoints and images get no browser CORS", async () => {
    const env = createEnv();
    for (const path of ["/v1/evaluate", "/v1/mcp/evaluate", "/v1/approvals/apr_AAAAAAAAAAAAAAAAAAAAAA", "/v1/approvals/apr_AAAAAAAAAAAAAAAAAAAAAA/consume"]) {
      const res = await preflightFor(env, path, ORIGIN);
      expect(res.headers.get("Access-Control-Allow-Origin")).toBeNull();
      expect(res.status).not.toBe(204);
      const post = await call(env, path, { host: API_ORIGIN, json: {}, headers: { Origin: ORIGIN } });
      expect(post.headers.get("Access-Control-Allow-Origin")).toBeNull();
    }
    const svg = await call(env, `/badge/${"A".repeat(32)}.svg`, { host: API_ORIGIN, headers: { Origin: ORIGIN } });
    expect(svg.headers.get("Access-Control-Allow-Origin")).toBeNull();
    expect(svg.headers.get("Cross-Origin-Resource-Policy")).toBe("cross-origin");
  });
});

describe("CSRF for the split UI/API origins", () => {
  it("accepts same-site writes from the UI origin and rejects everything else", async () => {
    const env = createEnv();
    const orgId = await seedOrg(env);
    const owner = await seedSession(env, orgId, "owner");
    const body = { agent_id: "csrf-agent", display_name: "CSRF agent", environment: "staging" };
    const ok = await call(env, "/api/console/agents", { host: API_ORIGIN, cookie: owner.cookie, json: body, origin: ORIGIN, headers: { "Sec-Fetch-Site": "same-site" } });
    expect(ok.status).toBe(201);
    const cases: Array<[string | null, string | undefined]> = [
      ["https://evil.example", "cross-site"],
      ["https://www.proptechusa.ai", "same-site"],
      [API_ORIGIN, "same-origin"],
      [FALLBACK_ORIGIN, "cross-site"],
      [ORIGIN, "cross-site"],
      [ORIGIN, "none"],
      [null, undefined],
    ];
    for (const [origin, fetchSite] of cases) {
      const res = await call(env, "/api/console/agents", {
        host: API_ORIGIN,
        cookie: owner.cookie,
        json: { ...body, agent_id: `csrf-${Math.random().toString(36).slice(2, 8)}` },
        origin,
        headers: fetchSite ? { "Sec-Fetch-Site": fetchSite } : {},
      });
      expect([origin, fetchSite, res.status]).toEqual([origin, fetchSite, 403]);
    }
  });
});

describe("GET /api/public/badges/{token}", () => {
  it("returns only public verification data, never cached, and fails closed for unknown tokens", async () => {
    const env = createEnv();
    const orgId = await seedOrg(env, { name: "Acme <Inc>" });
    await seedAgent(env, orgId, "a1");
    await seedPolicy(env, orgId, { name: "p", effect: "block", conditions: { match: "all", conditions: [] } });
    await seedKey(env, orgId, "live");
    const owner = await seedSession(env, orgId, "owner");
    const created = (await (await call(env, "/api/console/badge/enable", { cookie: owner.cookie, method: "POST" })).json()) as { badge: { token: string; svg_url: string; verify_url: string } };
    const token = created.badge.token;
    expect(created.badge.svg_url).toBe(`${API_ORIGIN}/badge/${token}.svg`);
    expect(created.badge.verify_url).toBe(`${ORIGIN}/verify/${token}`);

    const res = await call(env, `/api/public/badges/${token}`, { host: API_ORIGIN, headers: { Origin: ORIGIN } });
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toMatchObject({ status: "active", organization: { display_name: "Acme <Inc>" }, badge: { svg_url: `${API_ORIGIN}/badge/${token}.svg`, verify_url: `${ORIGIN}/verify/${token}` } });
    expect((body.controls as Array<{ met: boolean }>).every((c) => c.met)).toBe(true);
    expect(String(body.disclaimer)).toContain("not a certification");
    const text = JSON.stringify(body);
    expect(text).not.toContain(orgId);
    expect(text).not.toMatch(/org_|bdg_|usr_|key_|agt_|pol_/);
    expect(Object.keys(body).sort()).toEqual(["activated_on", "badge", "checked_at", "controls", "disclaimer", "last_gateway_activity_on", "organization", "policy_engine", "service_version", "status"]);

    const missing = await call(env, `/api/public/badges/${"A".repeat(32)}`, { host: API_ORIGIN });
    expect(missing.status).toBe(404);
    expect(await missing.json()).toMatchObject({ error: { code: "BADGE_NOT_FOUND" } });
    expect((await call(env, "/api/public/badges/short", { host: API_ORIGIN })).status).toBe(404);
    expect((await call(env, `/api/public/badges/${token}`, { host: API_ORIGIN, json: {} })).status).toBe(405);

    env.limiters.RL_PUBLIC_BADGE!.blocked = true;
    expect((await call(env, `/api/public/badges/${token}`, { host: API_ORIGIN })).status).toBe(429);
  });
});
