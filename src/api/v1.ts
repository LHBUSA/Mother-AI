// Gateway API (/v1/*). Server-to-server only: authenticated with Mother AI API
// keys in the Authorization header. No CORS headers are emitted, so browsers
// cannot call these endpoints cross-origin.

import type { Env } from "../env";
import { timingSafeEqual } from "../lib/crypto";
import { ApiError, clientIp, json, methodNotAllowed } from "../lib/http";
import type { DecisionRow } from "../lib/db";
import { assertKeyUsable, readBearerKey } from "../gateway/identity";
import { gatewayError, handleEvaluate, type GatewayDeps } from "../gateway/evaluate";
import { approvalView, consumeApproval, getApproval } from "../gateway/approvals";
import { notifyApprovalEvent } from "../notifications/approvals";

interface GatewayPrincipal {
  key_id: string;
  key_prefix: string;
  org_id: string;
}

async function authenticate(request: Request, env: Env): Promise<GatewayPrincipal> {
  const ipLimit = await env.RL_GATEWAY_IP.limit({ key: clientIp(request) });
  if (!ipLimit.success) throw new ApiError(429, "RATE_LIMITED", "Too many gateway requests from this address.");
  const key = await readBearerKey(request);
  const row = await env.DB.prepare(
    `SELECT k.id AS key_id, k.key_prefix, k.key_hash, k.revoked_at, o.id AS org_id, o.status AS org_status, o.gateway_enabled
       FROM api_keys k JOIN organizations o ON o.id = k.organization_id WHERE k.key_hash = ?`,
  )
    .bind(key.hash)
    .first<{ key_id: string; key_prefix: string; key_hash: string; revoked_at: string | null; org_id: string; org_status: string; gateway_enabled: number }>();
  assertKeyUsable(row, key.hash, timingSafeEqual);
  const keyLimit = await env.RL_GATEWAY_KEY.limit({ key: row!.key_id });
  if (!keyLimit.success) throw new ApiError(429, "RATE_LIMITED", "This API key exceeded its gateway rate limit.");
  return { key_id: row!.key_id, key_prefix: row!.key_prefix, org_id: row!.org_id };
}

const APPROVAL_PATH = /^\/v1\/approvals\/(apr_[0-9A-Za-z]{22})(\/consume)?$/;

export async function routeV1(request: Request, env: Env, deps: GatewayDeps): Promise<Response> {
  const url = new URL(request.url);
  try {
    if (url.pathname === "/v1/evaluate" || url.pathname === "/v1/mcp/evaluate") {
      if (request.method !== "POST") return methodNotAllowed(["POST"]);
      return await handleEvaluate(request, env, deps, url.pathname === "/v1/mcp/evaluate" ? "mcp" : "api");
    }

    const approvalMatch = APPROVAL_PATH.exec(url.pathname);
    if (approvalMatch) {
      const approvalId = approvalMatch[1]!;
      const consume = !!approvalMatch[2];
      if (consume && request.method !== "POST") return methodNotAllowed(["POST"]);
      if (!consume && request.method !== "GET") return methodNotAllowed(["GET"]);
      const principal = await authenticate(request, env);
      const nowMs = deps.now();
      const row = consume
        ? await consumeApproval(env.DB, principal.org_id, approvalId, { type: "api_key", id: principal.key_id, label: principal.key_prefix }, nowMs)
        : await getApproval(env.DB, principal.org_id, approvalId);
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
      });
    }

    return gatewayError(new ApiError(404, "NOT_FOUND", "Unknown gateway endpoint."));
  } catch (err) {
    if (err instanceof ApiError) return gatewayError(err);
    console.error("v1 unhandled error", err instanceof Error ? err.name : "unknown");
    return gatewayError(new ApiError(500, "INTERNAL_ERROR", "Mother AI encountered an internal error; failing closed."));
  }
}
