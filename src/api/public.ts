// Public, unauthenticated endpoints: demo workspace, Founding Access capture, health.
// Each has its own abuse control and none of them can read or write tenant data.

import type { Env } from "../env";
import { hmacSha256Hex, newId, sha256Hex, timingSafeEqual } from "../lib/crypto";
import { ApiError, clientIp, json, readJsonObject } from "../lib/http";
import { iso } from "../lib/time";
import { evaluateSafely, ENGINE_VERSION } from "../gateway/policy-engine";
import { normalizeEvaluateRequest } from "../gateway/normalize";
import { DEMO_AGENTS, DEMO_POLICIES, DEMO_SCENARIOS } from "../demo/workspace";
import { SERVICE_NAME, SERVICE_VERSION } from "../version";
import { CANONICAL_ORIGIN } from "../lib/site";

// ---------------------------------------------------------------------------
// Demo
// ---------------------------------------------------------------------------

export function demoWorkspace(): Response {
  return json(
    {
      demo: true,
      agents: DEMO_AGENTS.map(({ agent_id, display_name, environment, description }) => ({ agent_id, display_name, environment, description })),
      policies: DEMO_POLICIES.map((p) => ({
        id: p.id,
        name: p.name,
        description: p.description,
        effect: p.effect,
        priority: p.priority,
        scope: p.scope,
        agent_ids: p.agent_ids.map((id) => DEMO_AGENTS.find((a) => a.id === id)?.agent_id ?? id),
        conditions: p.conditions,
      })),
      scenarios: DEMO_SCENARIOS,
    },
    200,
    { "Cache-Control": "public, max-age=300" },
  );
}

export async function demoEvaluate(request: Request, env: Env): Promise<Response> {
  const { success } = await env.RL_DEMO.limit({ key: clientIp(request) });
  if (!success) throw new ApiError(429, "RATE_LIMITED", "Demo rate limit reached. Try again in a minute.");
  const body = await readJsonObject(request, 16 * 1024);
  delete body.request_id;
  const { action } = normalizeEvaluateRequest(body);

  const agent = DEMO_AGENTS.find((a) => a.agent_id === action.agent) ?? null;
  const t0 = performance.now();
  let result;
  if (!agent) {
    result = {
      decision: "block" as const,
      reason_code: "AGENT_UNKNOWN",
      reason: `Agent "${action.agent}" is not registered in this workspace.`,
      policy: null,
      matched: [],
      evaluated_policies: 0,
      engine_version: ENGINE_VERSION,
    };
  } else if (action.environment && action.environment !== agent.environment) {
    result = {
      decision: "block" as const,
      reason_code: "AGENT_ENVIRONMENT_MISMATCH",
      reason: `Request declared environment "${action.environment}" but agent "${agent.agent_id}" is registered for "${agent.environment}".`,
      policy: null,
      matched: [],
      evaluated_policies: 0,
      engine_version: ENGINE_VERSION,
    };
  } else {
    result = evaluateSafely({
      action: { ...action, environment: agent.environment },
      agentId: agent.id,
      policies: DEMO_POLICIES,
      defaultDecision: "block",
    });
  }
  const evalMs = performance.now() - t0;

  return json({
    demo: true,
    stored: false,
    decision: result.decision,
    reason_code: result.reason_code,
    reason: result.reason,
    policy: result.policy ? { id: result.policy.id, name: result.policy.name, effect: result.policy.effect, priority: result.policy.priority } : null,
    matched: result.matched.map((m) => ({ policy_id: m.policy_id, name: m.name, effect: m.effect, indeterminate: m.indeterminate })),
    evaluated_policies: result.evaluated_policies,
    eval_ms: Math.round(evalMs * 1000) / 1000,
    engine_version: result.engine_version,
  });
}

// ---------------------------------------------------------------------------
// Founding Access
// ---------------------------------------------------------------------------

const FORM_MIN_AGE_MS = 3_000;
const FORM_MAX_AGE_MS = 2 * 60 * 60 * 1000;
const EMAIL = /^[^\s@<>()[\]\\,;:"]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;
const AGENT_COUNTS = ["1-5", "6-25", "26-100", "100+", "unknown"];
const MCP_USAGE = ["yes", "no", "evaluating"];

/**
 * Turnstile is enforced when both keys are configured (Worker secrets). Exactly one
 * configured is a misconfiguration and fails closed rather than silently skipping it.
 */
function turnstileMode(env: Env): "enforced" | "not_configured" {
  const site = !!env.TURNSTILE_SITE_KEY;
  const secret = !!env.TURNSTILE_SECRET_KEY;
  if (site && secret) return "enforced";
  if (!site && !secret) return "not_configured";
  throw new ApiError(503, "FORMS_UNAVAILABLE", "Founding Access is temporarily unavailable.");
}

export async function foundingAccessToken(env: Env, nowMs: number): Promise<Response> {
  if (!env.FORM_SIGNING_KEY) throw new ApiError(503, "FORMS_UNAVAILABLE", "Founding Access is temporarily unavailable.");
  turnstileMode(env);
  const issued = String(nowMs);
  const token = `${issued}.${await hmacSha256Hex(env.FORM_SIGNING_KEY, `founding-access:${issued}`)}`;
  return json({ form_token: token, turnstile_site_key: env.TURNSTILE_SITE_KEY || null });
}

async function verifyFormToken(env: Env, token: unknown, nowMs: number): Promise<void> {
  if (typeof token !== "string" || !/^\d{13}\.[0-9a-f]{64}$/.test(token)) {
    throw new ApiError(400, "FORM_EXPIRED", "This form expired. Reload the page and try again.");
  }
  const [issued, sig] = token.split(".") as [string, string];
  const expected = await hmacSha256Hex(env.FORM_SIGNING_KEY!, `founding-access:${issued}`);
  const age = nowMs - Number(issued);
  if (!timingSafeEqual(sig, expected) || age > FORM_MAX_AGE_MS || age < -60_000) {
    throw new ApiError(400, "FORM_EXPIRED", "This form expired. Reload the page and try again.");
  }
  if (age < FORM_MIN_AGE_MS) throw new ApiError(400, "FORM_TOO_FAST", "Please take a moment to complete the form.");
}

async function verifyTurnstile(env: Env, token: unknown, ip: string): Promise<"verified" | "not_configured"> {
  if (turnstileMode(env) === "not_configured") return "not_configured";
  if (typeof token !== "string" || token.length === 0 || token.length > 2048) {
    throw new ApiError(403, "VERIFICATION_FAILED", "Human verification is required.");
  }
  const form = new FormData();
  form.append("secret", env.TURNSTILE_SECRET_KEY!);
  form.append("response", token);
  form.append("remoteip", ip);
  let outcome: { success?: boolean; hostname?: string; "error-codes"?: string[] };
  try {
    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: form });
    outcome = (await res.json()) as typeof outcome;
  } catch {
    // siteverify unreachable: fail closed.
    throw new ApiError(503, "VERIFICATION_UNAVAILABLE", "Human verification is temporarily unavailable. Please try again.");
  }
  // Cloudflare rejects invalid, expired and already-redeemed tokens (e.g. timeout-or-duplicate).
  if (!outcome.success) throw new ApiError(403, "VERIFICATION_FAILED", "Human verification failed. Please try again.");
  // A valid token must have been solved on the canonical host.
  if (outcome.hostname !== new URL(CANONICAL_ORIGIN).hostname) {
    throw new ApiError(403, "VERIFICATION_FAILED", "Human verification failed. Please try again.");
  }
  return "verified";
}

function text(body: Record<string, unknown>, key: string, min: number, max: number, fields: Record<string, string>): string {
  const v = body[key];
  if (typeof v !== "string" || v.trim().length < min) {
    fields[key] = min > 1 ? `Must be at least ${min} characters.` : "Required.";
    return "";
  }
  const t = v.trim();
  if (t.length > max) fields[key] = `Must be at most ${max} characters.`;
  if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(t)) fields[key] = "Contains invalid characters.";
  return t;
}

export async function foundingAccessSubmit(request: Request, env: Env, nowMs: number): Promise<Response> {
  const ip = clientIp(request);
  const { success } = await env.RL_FORMS.limit({ key: ip });
  if (!success) throw new ApiError(429, "RATE_LIMITED", "Too many submissions. Try again in a minute.");
  if (!env.FORM_SIGNING_KEY) throw new ApiError(503, "FORMS_UNAVAILABLE", "Founding Access is temporarily unavailable.");

  const body = await readJsonObject(request, 16 * 1024);
  // Honeypot: real browsers leave this empty. Bots get a success response and nothing is stored.
  if (typeof body.website === "string" && body.website.length > 0) return json({ ok: true }, 201);

  await verifyFormToken(env, body.form_token, nowMs);

  const fields: Record<string, string> = {};
  const name = text(body, "name", 1, 120, fields);
  const company = text(body, "company", 1, 160, fields);
  const email = text(body, "work_email", 3, 254, fields).toLowerCase();
  if (email && !fields.work_email && !EMAIL.test(email)) fields.work_email = "Enter a valid work email.";
  const useCase = text(body, "use_case", 10, 2000, fields);
  const agentCount = typeof body.agent_count === "string" && AGENT_COUNTS.includes(body.agent_count) ? body.agent_count : "";
  if (!agentCount) fields.agent_count = "Choose an option.";
  const usesMcp = typeof body.uses_mcp === "string" && MCP_USAGE.includes(body.uses_mcp) ? body.uses_mcp : "";
  if (!usesMcp) fields.uses_mcp = "Choose an option.";
  if (Object.keys(fields).length) throw new ApiError(400, "INVALID_REQUEST", "Please correct the highlighted fields.", { fields });

  const turnstile = await verifyTurnstile(env, body.turnstile_token, ip);

  const now = iso(nowMs);
  const dayAgo = iso(nowMs - 24 * 60 * 60 * 1000);
  const duplicate = await env.DB.prepare(`SELECT id FROM founding_access_requests WHERE work_email = ? AND created_at > ? LIMIT 1`)
    .bind(email, dayAgo)
    .first<{ id: string }>();
  if (duplicate) return json({ ok: true }, 201);

  const ipHash = await sha256Hex(`${ip}|${now.slice(0, 10)}|${env.FORM_SIGNING_KEY}`);
  await env.DB.prepare(
    `INSERT INTO founding_access_requests (id, name, company, work_email, use_case, agent_count, uses_mcp, ip_hash, turnstile, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(newId("fa"), name, company, email, useCase, agentCount, usesMcp, ipHash, turnstile, now)
    .run();
  return json({ ok: true }, 201);
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

async function d1Reachable(env: Env): Promise<boolean> {
  try {
    const row = await env.DB.prepare("SELECT 1 AS ok").first<{ ok: number }>();
    return row?.ok === 1;
  } catch {
    return false;
  }
}

export async function health(env: Env, nowMs: number): Promise<Response> {
  const d1 = await d1Reachable(env);
  return json(
    {
      status: d1 ? "ok" : "degraded",
      service: SERVICE_NAME,
      version: SERVICE_VERSION,
      commit: env.GIT_SHA,
      policy_engine: ENGINE_VERSION,
      d1: d1 ? "reachable" : "unreachable",
      time: iso(nowMs),
    },
    d1 ? 200 : 503,
  );
}

export async function ready(env: Env): Promise<Response> {
  const d1 = await d1Reachable(env);
  let schema = false;
  if (d1) {
    try {
      await env.DB.prepare("SELECT id FROM organizations LIMIT 1").all();
      await env.DB.prepare("SELECT id FROM decisions LIMIT 1").all();
      schema = true;
    } catch {
      schema = false;
    }
  }
  const checks = { d1, schema, form_signing: !!env.FORM_SIGNING_KEY, turnstile: !!env.TURNSTILE_SECRET_KEY && !!env.TURNSTILE_SITE_KEY ? "enforced" : !env.TURNSTILE_SECRET_KEY && !env.TURNSTILE_SITE_KEY ? "not_configured" : "misconfigured" };
  const isReady = d1 && schema;
  return json({ ready: isReady, checks }, isReady ? 200 : 503);
}
