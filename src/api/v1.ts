// Gateway API (/v1/*). Server-to-server only: authenticated with Mother AI API
// keys in the Authorization header. No CORS headers are emitted, so browsers
// cannot call these endpoints cross-origin.

import type { Env } from "../env";
import { timingSafeEqual } from "../lib/crypto";
import { ApiError, clientIp, json, methodNotAllowed, readJsonObject } from "../lib/http";
import type { DecisionRow } from "../lib/db";
import { assertKeyUsable, readBearerKey } from "../gateway/identity";
import { gatewayError, handleEvaluate, type GatewayDeps } from "../gateway/evaluate";
import { approvalView, consumeApproval, getApproval } from "../gateway/approvals";
import { notifyApprovalEvent } from "../notifications/approvals";
import type { RiskMode } from "../runtime/engine";
import { approvalContainmentRefusal, closeSession, getSession, openSession, recordConsumeRefusal, reportEvent, useLease, type RuntimePrincipal } from "../runtime/api";

async function authenticate(request: Request, env: Env): Promise<RuntimePrincipal> {
  const ipLimit = await env.RL_GATEWAY_IP.limit({ key: clientIp(request) });
  if (!ipLimit.success) throw new ApiError(429, "RATE_LIMITED", "Too many gateway requests from this address.");
  const key = await readBearerKey(request);
  const row = await env.DB.prepare(
    `SELECT k.id AS key_id, k.key_prefix, k.key_hash, k.environment AS key_environment, k.revoked_at, o.id AS org_id, o.status AS org_status,
            o.gateway_enabled, o.runtime_protection, o.security_alerts_enabled
       FROM api_keys k JOIN organizations o ON o.id = k.organization_id WHERE k.key_hash = ?`,
  )
    .bind(key.hash)
    .first<{
      key_id: string;
      key_prefix: string;
      key_hash: string;
      key_environment: "live" | "test";
      revoked_at: string | null;
      org_id: string;
      org_status: string;
      gateway_enabled: number;
      runtime_protection: RiskMode;
      security_alerts_enabled: number;
    }>();
  assertKeyUsable(row, key.hash, timingSafeEqual);
  const keyLimit = await env.RL_GATEWAY_KEY.limit({ key: row!.key_id });
  if (!keyLimit.success) throw new ApiError(429, "RATE_LIMITED", "This API key exceeded its gateway rate limit.");
  return {
    key_id: row!.key_id,
    key_prefix: row!.key_prefix,
    key_environment: row!.key_environment,
    org_id: row!.org_id,
    runtime_protection: row!.runtime_protection ?? "monitor",
    security_alerts_enabled: row!.security_alerts_enabled ?? 0,
  };
}

const APPROVAL_PATH = /^\/v1\/approvals\/(apr_[0-9A-Za-z]{22})(\/consume)?$/;
const SESSION_PATH = /^\/v1\/sessions\/(asn_[0-9A-Za-z]{22})(\/close)?$/;
const LEASE_PATH = /^\/v1\/leases\/(lse_[0-9A-Za-z]{22})\/use$/;
const CONSUME_EVIDENCE_CODES = new Set(["APPROVAL_DENIED", "APPROVAL_EXPIRED", "APPROVAL_ALREADY_CONSUMED", "APPROVAL_GRANT_EXPIRED"]);

export async function routeV1(request: Request, env: Env, deps: GatewayDeps): Promise<Response> {
  const url = new URL(request.url);
  try {
    if (url.pathname === "/v1/evaluate" || url.pathname === "/v1/mcp/evaluate") {
      if (request.method !== "POST") return methodNotAllowed(["POST"]);
      return await handleEvaluate(request, env, deps, url.pathname === "/v1/mcp/evaluate" ? "mcp" : "api");
    }

    if (url.pathname === "/v1/sessions") {
      if (request.method !== "POST") return methodNotAllowed(["POST"]);
      const principal = await authenticate(request, env);
      return await openSession(env, principal, await readJsonObject(request), deps.now(), deps.waitUntil);
    }
    const sessionMatch = SESSION_PATH.exec(url.pathname);
    if (sessionMatch) {
      const close = !!sessionMatch[2];
      if (close && request.method !== "POST") return methodNotAllowed(["POST"]);
      if (!close && request.method !== "GET") return methodNotAllowed(["GET"]);
      const principal = await authenticate(request, env);
      return close ? await closeSession(env, principal, sessionMatch[1]!, deps.now()) : await getSession(env, principal, sessionMatch[1]!, deps.now());
    }
    const leaseMatch = LEASE_PATH.exec(url.pathname);
    if (leaseMatch) {
      if (request.method !== "POST") return methodNotAllowed(["POST"]);
      const principal = await authenticate(request, env);
      const body = request.headers.get("Content-Type") ? await readJsonObject(request) : {};
      return await useLease(env, principal, leaseMatch[1]!, body, deps.now(), deps.waitUntil);
    }
    if (url.pathname === "/v1/events") {
      if (request.method !== "POST") return methodNotAllowed(["POST"]);
      const principal = await authenticate(request, env);
      return await reportEvent(env, principal, await readJsonObject(request), deps.now(), deps.waitUntil);
    }

    const approvalMatch = APPROVAL_PATH.exec(url.pathname);
    if (approvalMatch) {
      const approvalId = approvalMatch[1]!;
      const consume = !!approvalMatch[2];
      if (consume && request.method !== "POST") return methodNotAllowed(["POST"]);
      if (!consume && request.method !== "GET") return methodNotAllowed(["GET"]);
      const principal = await authenticate(request, env);
      const nowMs = deps.now();
      let row;
      if (consume) {
        // Containment first: a grant issued before the containment epoch, or inside a quarantined
        // scope, is refused before the ordinary lifecycle checks run.
        const refusal = await approvalContainmentRefusal(env, principal, approvalId, nowMs, deps.waitUntil);
        if (refusal) throw refusal;
        try {
          row = await consumeApproval(env.DB, principal.org_id, approvalId, { type: "api_key", id: principal.key_id, label: principal.key_prefix }, nowMs);
        } catch (err) {
          if (err instanceof ApiError && CONSUME_EVIDENCE_CODES.has(err.code)) await recordConsumeRefusal(env, principal, approvalId, err.code, nowMs, deps.waitUntil);
          throw err;
        }
      } else {
        row = await getApproval(env.DB, principal.org_id, approvalId);
      }
      if (!row) throw new ApiError(404, "APPROVAL_NOT_FOUND", "Approval not found.");
      if (consume) deps.waitUntil(notifyApprovalEvent(env, principal.org_id, approvalId, "consumed", deps.now));
      const decision = await env.DB.prepare(
        `SELECT id, request_id, agent_key, capability, operation, resource FROM decisions WHERE id = ? AND organization_id = ?`,
      )
        .bind(row.decision_id, principal.org_id)
        .first<Pick<DecisionRow, "id" | "request_id" | "agent_key" | "capability" | "operation" | "resource">>();
      return json({
        ...approvalView(row, nowMs),
        decision_id: row.decision_id,
        request_id: decision?.request_id ?? null,
        agent_id: decision?.agent_key ?? null,
        capability: decision?.capability ?? null,
        operation: decision?.operation ?? null,
        resource: decision?.resource ?? null,
        ...(row.terminated_reason ? { termination: { reason: row.terminated_reason, incident_id: row.terminated_incident_id, by: "system" } } : {}),
      });
    }

    return gatewayError(new ApiError(404, "NOT_FOUND", "Unknown gateway endpoint."));
  } catch (err) {
    if (err instanceof ApiError) return gatewayError(err);
    console.error("v1 unhandled error", err instanceof Error ? err.name : "unknown");
    return gatewayError(new ApiError(500, "INTERNAL_ERROR", "Mother AI encountered an internal error; failing closed."));
  }
}
