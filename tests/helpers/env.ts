import type { Env, RateLimiter } from "../../src/env";
import worker from "../../src/worker";
import site from "../../config/site.json";
import { D1Shim } from "./d1";
import { generateApiKey, generateToken, newId, randomBase62, sha256Hex } from "../../src/lib/crypto";
import { SESSION_COOKIE } from "../../src/auth/sessions";
import type { Role } from "../../src/auth/rbac";

export const ORIGIN = site.origin;
export const FALLBACK_ORIGIN = site.fallbackOrigins[0]!;
export const API_ORIGIN = site.apiOrigin;

export class ToggleLimiter implements RateLimiter {
  blocked = false;
  calls = 0;
  async limit() {
    this.calls++;
    return { success: !this.blocked };
  }
}

export interface TestEnv extends Env {
  shim: D1Shim;
  limiters: Record<string, ToggleLimiter>;
}

export function createEnv(overrides: Partial<Env> = {}): TestEnv {
  const shim = D1Shim.withMigrations();
  const limiters = {
    RL_GATEWAY_IP: new ToggleLimiter(),
    RL_GATEWAY_KEY: new ToggleLimiter(),
    RL_DEMO: new ToggleLimiter(),
    RL_FORMS: new ToggleLimiter(),
    RL_AUTH: new ToggleLimiter(),
    RL_CONSOLE: new ToggleLimiter(),
    RL_PUBLIC_BADGE: new ToggleLimiter(),
  };
  return {
    DB: shim.asD1(),
    ...limiters,
    ENVIRONMENT: "production",
    GIT_SHA: "test",
    FORM_SIGNING_KEY: "test-form-signing-key-0123456789abcdef",
    ...overrides,
    shim,
    limiters,
  };
}

export function ctx(): ExecutionContext & { pending: Promise<unknown>[] } {
  const pending: Promise<unknown>[] = [];
  return {
    pending,
    waitUntil: (p: Promise<unknown>) => void pending.push(p),
    passThroughOnException: () => {},
    props: {},
  } as unknown as ExecutionContext & { pending: Promise<unknown>[] };
}

export async function call(env: TestEnv, path: string, init: RequestInit & { json?: unknown; key?: string; cookie?: string; origin?: string | null; host?: string } = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  if (init.json !== undefined) {
    headers.set("Content-Type", "application/json");
  }
  if (init.key) headers.set("Authorization", `Bearer ${init.key}`);
  if (init.cookie) headers.set("Cookie", init.cookie);
  const method = init.method ?? (init.json !== undefined ? "POST" : "GET");
  if (method !== "GET" && init.origin !== null) headers.set("Origin", init.origin ?? ORIGIN);
  headers.set("CF-Connecting-IP", "203.0.113.7");
  // The Worker is API-only: requests default to the API host.
  const request = new Request(`${init.host ?? API_ORIGIN}${path}`, {
    method,
    headers,
    body: init.json !== undefined ? JSON.stringify(init.json) : (init.body ?? null),
  });
  const c = ctx();
  const res = await worker.fetch(request, env, c);
  await Promise.all(c.pending);
  return res;
}

const NOW = () => new Date().toISOString();

export async function seedOrg(env: TestEnv, opts: { slug?: string; name?: string; defaultDecision?: "block" | "review"; requireRegistered?: boolean } = {}) {
  const id = newId("org");
  const slug = opts.slug ?? `org-${randomBase62(6).toLowerCase()}`;
  await env.DB.prepare(
    `INSERT INTO organizations (id, slug, display_name, default_decision, require_registered_agents, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(id, slug, opts.name ?? "Acme, Inc.", opts.defaultDecision ?? "block", opts.requireRegistered === false ? 0 : 1, NOW(), NOW())
    .run();
  return id;
}

export async function seedKey(env: TestEnv, orgId: string, environment: "live" | "test" = "live") {
  const key = await generateApiKey(environment);
  const id = newId("key");
  await env.DB.prepare(`INSERT INTO api_keys (id, organization_id, name, key_prefix, key_hash, environment, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .bind(id, orgId, "Test key", key.prefix, key.hash, environment, NOW())
    .run();
  return { id, raw: key.raw };
}

export async function seedAgent(env: TestEnv, orgId: string, agentKey: string, opts: { environment?: string; status?: string; defaultMode?: string } = {}) {
  const id = newId("agt");
  await env.DB.prepare(
    `INSERT INTO agents (id, organization_id, agent_key, display_name, environment, status, default_mode, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(id, orgId, agentKey, agentKey, opts.environment ?? "production", opts.status ?? "active", opts.defaultMode ?? "inherit", NOW(), NOW())
    .run();
  return id;
}

export async function seedPolicy(
  env: TestEnv,
  orgId: string,
  p: { name: string; effect: "allow" | "review" | "block"; conditions: unknown; priority?: number; agentIds?: string[]; enabled?: boolean; reasonCode?: string; rawConditions?: string },
) {
  const id = newId("pol");
  const scope = p.agentIds?.length ? "agents" : "organization";
  await env.DB.prepare(
    `INSERT INTO policies (id, organization_id, name, priority, enabled, effect, scope, conditions, reason_code, version, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
  )
    .bind(id, orgId, p.name, p.priority ?? 100, p.enabled === false ? 0 : 1, p.effect, scope, p.rawConditions ?? JSON.stringify(p.conditions), p.reasonCode ?? null, NOW(), NOW())
    .run();
  for (const agentId of p.agentIds ?? []) {
    await env.DB.prepare(`INSERT INTO agent_policy_bindings (organization_id, agent_id, policy_id, created_at) VALUES (?, ?, ?, ?)`).bind(orgId, agentId, id, NOW()).run();
  }
  return id;
}

export async function seedSession(env: TestEnv, orgId: string, role: Role = "owner", name = "Test User") {
  const userId = newId("usr");
  const token = generateToken(32);
  await env.DB.batch([
    env.DB.prepare(`INSERT INTO users (id, display_name, created_at) VALUES (?, ?, ?)`).bind(userId, name, NOW()),
    env.DB.prepare(`INSERT INTO memberships (id, organization_id, user_id, role, created_at) VALUES (?, ?, ?, ?, ?)`).bind(newId("mem"), orgId, userId, role, NOW()),
    env.DB.prepare(`INSERT INTO sessions (id, token_hash, user_id, organization_id, created_at, last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`).bind(
      newId("ses"),
      await sha256Hex(token),
      userId,
      orgId,
      NOW(),
      NOW(),
      new Date(Date.now() + 3600_000).toISOString(),
    ),
  ]);
  return { userId, cookie: `${SESSION_COOKIE}=${token}` };
}
