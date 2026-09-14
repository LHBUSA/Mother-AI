import { beforeEach, describe, expect, it } from "vitest";
import { SoftwareAuthenticator } from "../../scripts/qa/authenticator.mjs";
import { API_ORIGIN, call, createEnv, ORIGIN, seedAgent, seedKey, seedOrg, seedPolicy, seedSession, type TestEnv } from "../helpers/env";
import { newId, sha256Hex, generateToken } from "../../src/lib/crypto";

function cookiesFrom(res: Response, jar: Map<string, string>) {
  for (const c of res.headers.getSetCookie()) {
    const [pair] = c.split(";");
    const [name, ...v] = pair!.split("=");
    const value = v.join("=");
    if (/Max-Age=0/.test(c)) jar.delete(name!);
    else jar.set(name!, value);
  }
}
const cookieHeader = (jar: Map<string, string>) => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");

async function createInvite(env: TestEnv, orgId: string, role = "owner", expiresInMs = 3600_000) {
  const token = generateToken(32);
  await env.DB.prepare(`INSERT INTO invites (id, organization_id, token_hash, role, display_name, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, 'ops', ?, ?)`)
    .bind(newId("inv"), orgId, await sha256Hex(token), role, "Jane Owner", new Date().toISOString(), new Date(Date.now() + expiresInMs).toISOString())
    .run();
  return token;
}

describe("passkey authentication", () => {
  let env: TestEnv;
  let orgId: string;

  beforeEach(async () => {
    env = createEnv();
    orgId = await seedOrg(env, { name: "Acme, Inc." });
  });

  it("redeems an invite with a passkey, then signs in again with the same passkey", async () => {
    const token = await createInvite(env, orgId);
    const authenticator = new SoftwareAuthenticator();
    const jar = new Map<string, string>();

    const inspect = await call(env, "/api/auth/invite/inspect", { json: { token } });
    expect(await inspect.json()).toMatchObject({ organization: "Acme, Inc.", role: "owner" });

    const optRes = await call(env, "/api/auth/register/options", { json: { token } });
    expect(optRes.status).toBe(200);
    cookiesFrom(optRes, jar);
    const options = await optRes.json();
    const credential = await authenticator.register(options, ORIGIN);
    const verify = await call(env, "/api/auth/register/verify", { json: { token, response: credential, device_name: "Test laptop" }, cookie: cookieHeader(jar) });
    expect(verify.status).toBe(200);
    cookiesFrom(verify, jar);
    expect(jar.has("__Host-mai_session")).toBe(true);

    const session = await call(env, "/api/auth/session", { cookie: cookieHeader(jar) });
    expect(await session.json()).toMatchObject({ role: "owner", organization: { display_name: "Acme, Inc." }, user: { display_name: "Jane Owner" } });

    // The invite is single-use.
    const reuse = await call(env, "/api/auth/register/options", { json: { token } });
    expect(reuse.status).toBe(410);

    // Sign out, then sign in with the passkey.
    const logout = await call(env, "/api/auth/logout", { json: {}, cookie: cookieHeader(jar) });
    cookiesFrom(logout, jar);
    expect((await call(env, "/api/auth/session", { cookie: cookieHeader(jar) })).status).toBe(401);

    const loginOpts = await call(env, "/api/auth/login/options", { json: {} });
    cookiesFrom(loginOpts, jar);
    const assertion = await authenticator.authenticate(await loginOpts.json(), ORIGIN);
    const login = await call(env, "/api/auth/login/verify", { json: { response: assertion }, cookie: cookieHeader(jar) });
    expect(login.status).toBe(200);
    cookiesFrom(login, jar);
    expect((await call(env, "/api/auth/session", { cookie: cookieHeader(jar) })).status).toBe(200);
    const stored = await env.DB.prepare(`SELECT counter, name FROM webauthn_credentials`).first<{ counter: number; name: string }>();
    expect(stored).toEqual({ counter: 1, name: "Test laptop" });
  });

  it("rejects replayed challenges, wrong origins, unknown passkeys and expired invites", async () => {
    const token = await createInvite(env, orgId);
    const authenticator = new SoftwareAuthenticator();
    const jar = new Map<string, string>();
    const optRes = await call(env, "/api/auth/register/options", { json: { token } });
    cookiesFrom(optRes, jar);
    const options = await optRes.json();

    const wrongOrigin = await authenticator.register(options, "https://evil.example");
    const bad = await call(env, "/api/auth/register/verify", { json: { token, response: wrongOrigin }, cookie: cookieHeader(jar) });
    expect(bad.status).toBe(400);
    // The challenge was consumed by the failed attempt.
    const good = await authenticator.register(options, ORIGIN);
    const replay = await call(env, "/api/auth/register/verify", { json: { token, response: good }, cookie: cookieHeader(jar) });
    expect(await replay.json()).toMatchObject({ error: { code: "CHALLENGE_EXPIRED" } });

    const stranger = new SoftwareAuthenticator();
    await stranger.register({ ...(options as Record<string, unknown>), challenge: "x" }, ORIGIN);
    const loginOpts = await call(env, "/api/auth/login/options", { json: {} });
    const loginJar = new Map<string, string>();
    cookiesFrom(loginOpts, loginJar);
    const assertion = await stranger.authenticate(await loginOpts.json(), ORIGIN);
    const unknown = await call(env, "/api/auth/login/verify", { json: { response: assertion }, cookie: cookieHeader(loginJar) });
    expect(unknown.status).toBe(401);

    const expired = await createInvite(env, orgId, "viewer", -1000);
    expect((await call(env, "/api/auth/invite/inspect", { json: { token: expired } })).status).toBe(410);
    expect((await call(env, "/api/auth/invite/inspect", { json: { token: "a".repeat(43) } })).status).toBe(404);
  });

  it("rejects cross-origin auth and console mutations (CSRF)", async () => {
    const token = await createInvite(env, orgId);
    expect((await call(env, "/api/auth/register/options", { json: { token }, origin: "https://evil.example" })).status).toBe(403);
    expect((await call(env, "/api/auth/register/options", { json: { token }, origin: null })).status).toBe(403);
    const owner = await seedSession(env, orgId, "owner");
    const res = await call(env, "/api/console/agents", { cookie: owner.cookie, json: { agent_id: "x-agent", display_name: "X", environment: "staging" }, origin: "https://evil.example" });
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: { code: "CSRF_REJECTED" } });
  });

  it("expires idle sessions and rejects disabled memberships", async () => {
    const owner = await seedSession(env, orgId, "owner");
    expect((await call(env, "/api/console/overview", { cookie: owner.cookie })).status).toBe(200);
    await env.DB.prepare(`UPDATE sessions SET last_seen_at = ?`).bind(new Date(Date.now() - 3 * 3600_000).toISOString()).run();
    expect((await call(env, "/api/console/overview", { cookie: owner.cookie })).status).toBe(401);
    const viewer = await seedSession(env, orgId, "viewer");
    await env.DB.prepare(`UPDATE memberships SET status = 'disabled' WHERE user_id = ?`).bind(viewer.userId).run();
    expect((await call(env, "/api/console/overview", { cookie: viewer.cookie })).status).toBe(401);
    expect((await call(env, "/api/console/overview")).status).toBe(401);
  });
});

describe("control plane API", () => {
  let env: TestEnv;
  let orgId: string;
  let owner: { cookie: string; userId: string };

  beforeEach(async () => {
    env = createEnv();
    orgId = await seedOrg(env, { name: "Acme, Inc." });
    owner = await seedSession(env, orgId, "owner", "Olivia Owner");
  });

  it("creates agents and policies through the API and enforces them at the gateway", async () => {
    const agent = await call(env, "/api/console/agents", { cookie: owner.cookie, json: { agent_id: "Billing-Agent-Prod", display_name: "Billing agent", environment: "production" } });
    expect(agent.status).toBe(201);
    const { agent: created } = (await agent.json()) as { agent: { id: string; agent_key: string } };
    expect(created.agent_key).toBe("billing-agent-prod");

    const dup = await call(env, "/api/console/agents", { cookie: owner.cookie, json: { agent_id: "billing-agent-prod", display_name: "Dup", environment: "production" } });
    expect(dup.status).toBe(409);
    const prodAllow = await call(env, "/api/console/agents", { cookie: owner.cookie, json: { agent_id: "p2", display_name: "P2", environment: "production", default_mode: "allow" } });
    expect(prodAllow.status).toBe(400);

    const policy = await call(env, "/api/console/policies", {
      cookie: owner.cookie,
      json: {
        name: "High value refunds",
        priority: 20,
        enabled: true,
        effect: "review",
        scope: "agents",
        agent_ids: [created.id],
        conditions: { match: "all", conditions: [{ field: "capability", operator: "equals", value: "Payments" }, { field: "context.amount", operator: "greater_than", value: 1000 }] },
      },
    });
    expect(policy.status).toBe(201);
    const { policy: p } = (await policy.json()) as { policy: { id: string; version: number; conditions: { conditions: Array<{ value: unknown }> } } };
    expect(p.conditions.conditions[0]!.value).toBe("payments");

    const badPolicy = await call(env, "/api/console/policies", {
      cookie: owner.cookie,
      json: { name: "Bad", priority: 1, enabled: true, effect: "block", scope: "organization", conditions: { match: "all", conditions: [{ field: "capability", operator: "greater_than", value: 3 }] } },
    });
    expect(badPolicy.status).toBe(400);

    const key = await call(env, "/api/console/keys", { cookie: owner.cookie, json: { name: "Production Gateway Key", environment: "live" } });
    expect(key.status).toBe(201);
    const keyBody = (await key.json()) as { secret: string; key: Record<string, unknown>; warning: string };
    expect(keyBody.secret).toMatch(/^mai_live_[0-9A-Za-z]{40}$/);
    expect(keyBody.warning).toBe("Store this securely. Mother AI cannot show this key again.");
    expect(keyBody.key).not.toHaveProperty("key_hash");
    const listed = JSON.stringify(await (await call(env, "/api/console/keys", { cookie: owner.cookie })).json());
    expect(listed).not.toContain(keyBody.secret);
    expect(listed).not.toContain("key_hash");
    const storedHash = await env.DB.prepare(`SELECT key_hash FROM api_keys`).first<{ key_hash: string }>();
    expect(storedHash?.key_hash).toBe(await sha256Hex(keyBody.secret));

    const decision = (await (await call(env, "/v1/evaluate", { key: keyBody.secret, json: { agent_id: "billing-agent-prod", capability: "payments", operation: "refund", context: { amount: 5000 } } })).json()) as Record<string, unknown>;
    expect(decision.decision).toBe("review");

    // Revoke via API; the key stops working immediately.
    const revoke = await call(env, `/api/console/keys/${keyBody.key.id}/revoke`, { cookie: owner.cookie, method: "POST" });
    expect(revoke.status).toBe(200);
    const after = await call(env, "/v1/evaluate", { key: keyBody.secret, json: { agent_id: "billing-agent-prod", capability: "payments", operation: "refund" } });
    expect(await after.json()).toMatchObject({ error: { code: "API_KEY_REVOKED" } });

    const events = (await (await call(env, "/api/console/events", { cookie: owner.cookie })).json()) as { events: Array<{ action: string }> };
    expect(events.events.map((e) => e.action)).toEqual(expect.arrayContaining(["agent.created", "policy.created", "api_key.created", "api_key.revoked"]));
  });

  it("versions policy edits with optimistic concurrency", async () => {
    const policyId = await seedPolicy(env, orgId, { name: "P", effect: "allow", conditions: { match: "all", conditions: [] } });
    const body = { name: "P v2", priority: 5, enabled: true, effect: "block", scope: "organization", conditions: { match: "all", conditions: [{ field: "operation", operator: "equals", value: "delete" }] } };
    const ok = await call(env, `/api/console/policies/${policyId}`, { cookie: owner.cookie, method: "PUT", json: { ...body, expected_version: 1 } });
    expect(ok.status).toBe(200);
    expect(await ok.json()).toMatchObject({ policy: { version: 2, name: "P v2" } });
    const stale = await call(env, `/api/console/policies/${policyId}`, { cookie: owner.cookie, method: "PUT", json: { ...body, name: "P v3", expected_version: 1 } });
    expect(stale.status).toBe(409);
    const detail = (await (await call(env, `/api/console/policies/${policyId}`, { cookie: owner.cookie })).json()) as { versions: Array<{ version: number }> };
    expect(detail.versions.map((v) => v.version)).toEqual([2]);
  });

  it("simulates a draft policy without storing anything", async () => {
    await seedAgent(env, orgId, "research-agent-prod");
    const before = await env.DB.prepare(`SELECT COUNT(*) AS n FROM decisions`).first<{ n: number }>();
    const res = await call(env, "/api/console/policies/simulate", {
      cookie: owner.cookie,
      json: {
        request: { agent_id: "research-agent-prod", capability: "records", operation: "read" },
        draft: { name: "Draft allow reads", effect: "allow", conditions: { match: "all", conditions: [{ field: "operation", operator: "equals", value: "read" }] } },
      },
    });
    expect(await res.json()).toMatchObject({ simulated: true, decision: "allow", policy: { name: "Draft allow reads" } });
    const after = await env.DB.prepare(`SELECT COUNT(*) AS n FROM decisions`).first<{ n: number }>();
    expect(after?.n).toBe(before?.n);
  });

  it("enforces roles", async () => {
    const viewer = await seedSession(env, orgId, "viewer");
    expect((await call(env, "/api/console/policies", { cookie: viewer.cookie })).status).toBe(200);
    expect((await call(env, "/api/console/policies", { cookie: viewer.cookie, json: { name: "x" } })).status).toBe(403);
    expect((await call(env, "/api/console/keys", { cookie: viewer.cookie })).status).toBe(403);
    const security = await seedSession(env, orgId, "security");
    expect((await call(env, "/api/console/keys", { cookie: security.cookie, json: { name: "k", environment: "live" } })).status).toBe(403);
    const admin = await seedSession(env, orgId, "admin");
    const invite = await call(env, "/api/console/members/invites", { cookie: admin.cookie, json: { display_name: "New Owner", role: "owner" } });
    expect(invite.status).toBe(403);
    const ok = await call(env, "/api/console/members/invites", { cookie: admin.cookie, json: { display_name: "New Approver", role: "approver" } });
    expect(ok.status).toBe(201);
    const { invite_url } = (await ok.json()) as { invite_url: string };
    expect(invite_url).toMatch(new RegExp(`^${ORIGIN}/app/accept-invite#token=[A-Za-z0-9_-]{43}$`));
  });

  it("isolates tenants in every console read and write", async () => {
    const agentA = await seedAgent(env, orgId, "billing-agent-prod");
    const policyA = await seedPolicy(env, orgId, { name: "A policy", effect: "allow", conditions: { match: "all", conditions: [] } });
    const keyA = await seedKey(env, orgId);
    const decisionA = (await (await call(env, "/v1/evaluate", { key: keyA.raw, json: { agent_id: "billing-agent-prod", capability: "payments", operation: "refund" } })).json()) as { decision_id: string };

    const orgB = await seedOrg(env, { name: "Globex" });
    const ownerB = await seedSession(env, orgB, "owner");
    expect((await call(env, `/api/console/agents/${agentA}`, { cookie: ownerB.cookie })).status).toBe(404);
    expect((await call(env, `/api/console/policies/${policyA}`, { cookie: ownerB.cookie })).status).toBe(404);
    expect((await call(env, `/api/console/decisions/${decisionA.decision_id}`, { cookie: ownerB.cookie })).status).toBe(404);
    expect((await call(env, `/api/console/keys/${keyA.id}/revoke`, { cookie: ownerB.cookie, method: "POST" })).status).toBe(404);
    expect((await call(env, `/api/console/policies/${policyA}/archive`, { cookie: ownerB.cookie, method: "POST" })).status).toBe(404);
    const policyWrite = await call(env, `/api/console/policies/${policyA}`, { cookie: ownerB.cookie, method: "PUT", json: { expected_version: 1 } });
    expect(policyWrite.status).toBe(404);
    const crossBind = await call(env, "/api/console/policies", {
      cookie: ownerB.cookie,
      json: { name: "steal", priority: 1, enabled: true, effect: "allow", scope: "agents", agent_ids: [agentA], conditions: { match: "all", conditions: [] } },
    });
    expect(crossBind.status).toBe(400);
    for (const path of ["/api/console/agents", "/api/console/policies", "/api/console/decisions", "/api/console/keys", "/api/console/events", "/api/console/overview", "/api/console/approvals"]) {
      const text = await (await call(env, path, { cookie: ownerB.cookie })).text();
      expect(text).not.toContain(agentA);
      expect(text).not.toContain(policyA);
      expect(text).not.toContain(decisionA.decision_id);
      expect(text).not.toContain(keyA.id);
    }
    // Key still usable for org A: B's revoke attempt did nothing.
    expect((await call(env, "/v1/evaluate", { key: keyA.raw, json: { agent_id: "billing-agent-prod", capability: "x", operation: "y" } })).status).toBe(200);
  });

  it("filters and paginates audit decisions", async () => {
    await seedAgent(env, orgId, "billing-agent-prod");
    await seedPolicy(env, orgId, { name: "allow payments", effect: "allow", conditions: { match: "all", conditions: [{ field: "capability", operator: "equals", value: "payments" }] } });
    const key = await seedKey(env, orgId);
    for (let i = 0; i < 55; i++) {
      await call(env, "/v1/evaluate", { key: key.raw, json: { request_id: `req_${i}`, agent_id: "billing-agent-prod", capability: i % 5 === 0 ? "email" : "payments", operation: "refund" } });
    }
    const page1 = (await (await call(env, "/api/console/decisions", { cookie: owner.cookie })).json()) as { decisions: Array<{ id: string }>; next_cursor: string };
    expect(page1.decisions).toHaveLength(50);
    const page2 = (await (await call(env, `/api/console/decisions?cursor=${encodeURIComponent(page1.next_cursor)}`, { cookie: owner.cookie })).json()) as { decisions: Array<{ id: string }>; next_cursor: string | null };
    expect(page2.decisions).toHaveLength(5);
    expect(page2.next_cursor).toBeNull();
    expect(new Set([...page1.decisions, ...page2.decisions].map((d) => d.id)).size).toBe(55);
    const blocked = (await (await call(env, "/api/console/decisions?decision=block", { cookie: owner.cookie })).json()) as { decisions: Array<{ capability: string }> };
    expect(blocked.decisions).toHaveLength(11);
    expect(blocked.decisions.every((d) => d.capability === "email")).toBe(true);
    const search = (await (await call(env, "/api/console/decisions?q=req_7", { cookie: owner.cookie })).json()) as { decisions: unknown[] };
    expect(search.decisions).toHaveLength(1);
    expect((await call(env, "/api/console/decisions?decision=maybe", { cookie: owner.cookie })).status).toBe(400);
  });

  it("reports honest zero metrics for an empty organization", async () => {
    const body = (await (await call(env, "/api/console/overview", { cookie: owner.cookie })).json()) as Record<string, unknown>;
    expect(body).toMatchObject({ decisions_24h: { total: 0, allow: 0, review: 0, block: 0 }, active_agents: 0, active_policies: 0, pending_approvals: 0, badge: { status: "setup", exists: false } });
    expect((body.hourly as unknown[]).length).toBe(24);
  });

  it("protects the last owner and self-modification", async () => {
    const members = (await (await call(env, "/api/console/members", { cookie: owner.cookie })).json()) as { members: Array<{ id: string; user_id: string }> };
    const me = members.members.find((m) => m.user_id === owner.userId)!;
    expect((await call(env, `/api/console/members/${me.id}`, { cookie: owner.cookie, method: "PATCH", json: { role: "viewer" } })).status).toBe(400);
  });
});

describe("badge", () => {
  let env: TestEnv;
  let orgId: string;
  let owner: { cookie: string };

  async function makeEligible() {
    await seedAgent(env, orgId, "billing-agent-prod");
    await seedPolicy(env, orgId, { name: "p", effect: "block", conditions: { match: "all", conditions: [{ field: "operation", operator: "equals", value: "delete" }] } });
    return seedKey(env, orgId, "live");
  }

  beforeEach(async () => {
    env = createEnv();
    orgId = await seedOrg(env, { name: "Acme <Inc> & Co" });
    owner = await seedSession(env, orgId, "owner");
  });

  it("stays in setup until every criterion is met, then goes active", async () => {
    const created = (await (await call(env, "/api/console/badge/enable", { cookie: owner.cookie, method: "POST" })).json()) as { status: string; badge: { token: string }; criteria: Array<{ met: boolean }> };
    expect(created.status).toBe("setup");
    const token = created.badge.token;
    expect(token).toMatch(/^[0-9A-Za-z]{32}$/);
    const setupSvg = await call(env, `/badge/${token}.svg`);
    expect(setupSvg.status).toBe(200);
    const setupText = await setupSvg.text();
    expect(setupText).toContain("Controls not active");
    expect(setupText).not.toContain("MOTHER AI PROTECTED");

    // test keys do not satisfy the live key criterion
    await seedAgent(env, orgId, "a1");
    await seedPolicy(env, orgId, { name: "p", effect: "allow", conditions: { match: "all", conditions: [] } });
    await seedKey(env, orgId, "test");
    expect(((await (await call(env, "/api/console/badge", { cookie: owner.cookie })).json()) as { status: string }).status).toBe("setup");

    await seedKey(env, orgId, "live");
    const active = (await (await call(env, "/api/console/badge", { cookie: owner.cookie })).json()) as { status: string; badge: { snippets: { markdown: string; html: string } } };
    expect(active.status).toBe("active");
    expect(active.badge.snippets.markdown).toBe(`[![Mother AI Protected — AI Controls Active](${API_ORIGIN}/badge/${token}.svg)](${ORIGIN}/verify/${token})`);
    expect(active.badge.snippets.html).toContain(`href="${ORIGIN}/verify/${token}"`);

    const svg = await call(env, `/badge/${token}.svg?theme=light`);
    expect(svg.headers.get("Content-Type")).toContain("image/svg+xml");
    expect(svg.headers.get("Cache-Control")).toContain("no-cache");
    expect(svg.headers.get("Cross-Origin-Resource-Policy")).toBe("cross-origin");
    expect(svg.headers.get("X-Frame-Options")).toBeNull();
    const svgText = await svg.text();
    expect(svgText).toContain("MOTHER AI PROTECTED");
    expect(svgText).toContain("AI Controls Active");
    expect(svgText).not.toContain(orgId);

    const page = await call(env, `/verify/${token}`);
    expect(page.status).toBe(200);
    expect(await page.text()).toContain("asset /verify/");
    expect(page.headers.get("Content-Security-Policy")).toContain("frame-ancestors 'none'");
    const verification = (await (await call(env, `/api/public/badges/${token}`, { host: API_ORIGIN })).json()) as Record<string, unknown>;
    expect(verification).toMatchObject({ status: "active", organization: { display_name: "Acme <Inc> & Co" } });
    expect(String(verification.disclaimer)).toContain("It is not a certification of the organization's entire cybersecurity program");
    expect(JSON.stringify(verification)).not.toContain(orgId);
  });

  it("suspends when a control is disabled after activation, and when suspended manually", async () => {
    await makeEligible();
    const { badge } = (await (await call(env, "/api/console/badge/enable", { cookie: owner.cookie, method: "POST" })).json()) as { badge: { token: string } };
    expect(await (await call(env, `/badge/${badge.token}.svg`)).text()).toContain("AI Controls Active");

    await call(env, "/api/console/settings", { cookie: owner.cookie, method: "PATCH", json: { audit_enabled: false } });
    const svg = await (await call(env, `/badge/${badge.token}.svg`)).text();
    expect(svg).toContain("Protection suspended");
    const suspended = (await (await call(env, `/api/public/badges/${badge.token}`, { host: API_ORIGIN })).json()) as { status: string; controls: Array<{ label: string; met: boolean }> };
    expect(suspended.status).toBe("suspended");
    expect(suspended.controls.find((c) => c.label === "Audit logging enabled")?.met).toBe(false);

    await call(env, "/api/console/settings", { cookie: owner.cookie, method: "PATCH", json: { audit_enabled: true } });
    expect(await (await call(env, `/badge/${badge.token}.svg`)).text()).toContain("AI Controls Active");
    await call(env, "/api/console/badge/suspend", { cookie: owner.cookie, method: "POST" });
    expect(await (await call(env, `/badge/${badge.token}.svg`)).text()).toContain("Protection suspended");
    await call(env, "/api/console/badge/resume", { cookie: owner.cookie, method: "POST" });
    expect(await (await call(env, `/badge/${badge.token}.svg`)).text()).toContain("AI Controls Active");

    // Administrative suspension of the organization suspends the badge immediately.
    await env.DB.prepare(`UPDATE organizations SET status = 'suspended' WHERE id = ?`).bind(orgId).run();
    expect(await (await call(env, `/badge/${badge.token}.svg`)).text()).toContain("Protection suspended");
  });

  it("revokes the old token on rotation and on administrative revocation", async () => {
    await makeEligible();
    const first = (await (await call(env, "/api/console/badge/enable", { cookie: owner.cookie, method: "POST" })).json()) as { badge: { token: string } };
    const rotated = (await (await call(env, "/api/console/badge/rotate", { cookie: owner.cookie, method: "POST" })).json()) as { status: string; badge: { token: string } };
    expect(rotated.badge.token).not.toBe(first.badge.token);
    expect(rotated.status).toBe("active");
    expect(await (await call(env, `/badge/${first.badge.token}.svg`)).text()).toContain("Badge revoked");
    expect(await (await call(env, `/api/public/badges/${first.badge.token}`, { host: API_ORIGIN })).json()).toMatchObject({ status: "revoked", controls: [] });

    await env.DB.prepare(`UPDATE organizations SET status = 'revoked' WHERE id = ?`).bind(orgId).run();
    expect(await (await call(env, `/badge/${rotated.badge.token}.svg`)).text()).toContain("Badge revoked");
  });

  it("renders an unverified state for unknown tokens", async () => {
    const svg = await call(env, `/badge/${"A".repeat(32)}.svg`);
    expect(svg.status).toBe(404);
    expect(await svg.text()).toContain("Unverified badge");
    const missing = await call(env, `/api/public/badges/${"A".repeat(32)}`, { host: API_ORIGIN });
    expect(missing.status).toBe(404);
    expect(await missing.json()).toMatchObject({ error: { code: "BADGE_NOT_FOUND" } });
    // The UI page itself is a static shell; it renders "Verification not found" from the 404 above.
    expect((await call(env, `/verify/${"A".repeat(32)}`)).status).toBe(200);
  });
});
