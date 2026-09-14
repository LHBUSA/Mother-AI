// Control-plane API (/api/console/*): passkey session required; every mutation is
// CSRF-checked and permission-checked; every query is scoped to the session's organization.

import type { Env } from "../../env";
import { ApiError, clientIp, json, readJsonObject } from "../../lib/http";
import { assertSameOrigin, loadSession } from "../../auth/sessions";
import { requirePermission, type Permission } from "../../auth/rbac";
import type { ConsoleContext } from "./context";
import { overview } from "./overview";
import { createAgent, getAgent, listAgents, updateAgent } from "./agents";
import { archivePolicy, createPolicy, getPolicy, listPolicies, simulatePolicy, updatePolicy } from "./policies";
import { actApproval, listApprovals } from "./approvals";
import { getDecision, listControlEvents, listDecisions } from "./audit";
import { createKey, listKeys, revokeKey } from "./keys";
import { badgeAction, getBadge } from "./badge";
import { createInvite, getSecurity, getSettings, listMembers, revokeInvite, revokeOtherSessions, updateMember, updateSettings } from "./organization";

type Handler = (ctx: ConsoleContext) => Promise<Response>;
type Route = [method: string, pattern: RegExp, permission: Permission, handler: Handler];

const ID = (prefix: string) => `(${prefix}_[0-9A-Za-z]{22})`;

const ROUTES: Route[] = [
  ["GET", /^\/api\/console\/overview$/, "read", overview],

  ["GET", /^\/api\/console\/agents$/, "read", listAgents],
  ["POST", /^\/api\/console\/agents$/, "manage_agents", createAgent],
  ["GET", new RegExp(`^/api/console/agents/${ID("agt")}$`), "read", getAgent],
  ["PATCH", new RegExp(`^/api/console/agents/${ID("agt")}$`), "manage_agents", updateAgent],

  ["GET", /^\/api\/console\/policies$/, "read", listPolicies],
  ["POST", /^\/api\/console\/policies$/, "manage_policies", createPolicy],
  ["POST", /^\/api\/console\/policies\/simulate$/, "read", simulatePolicy],
  ["GET", new RegExp(`^/api/console/policies/${ID("pol")}$`), "read", getPolicy],
  ["PUT", new RegExp(`^/api/console/policies/${ID("pol")}$`), "manage_policies", updatePolicy],
  ["POST", new RegExp(`^/api/console/policies/${ID("pol")}/archive$`), "manage_policies", archivePolicy],

  ["GET", /^\/api\/console\/approvals$/, "read", listApprovals],
  ["POST", new RegExp(`^/api/console/approvals/${ID("apr")}/(approve|deny)$`), "approve", actApproval],

  ["GET", /^\/api\/console\/decisions$/, "read", listDecisions],
  ["GET", new RegExp(`^/api/console/decisions/${ID("dec")}$`), "read", getDecision],
  ["GET", /^\/api\/console\/events$/, "read", listControlEvents],

  ["GET", /^\/api\/console\/keys$/, "manage_keys", listKeys],
  ["POST", /^\/api\/console\/keys$/, "manage_keys", createKey],
  ["POST", new RegExp(`^/api/console/keys/${ID("key")}/revoke$`), "manage_keys", revokeKey],

  ["GET", /^\/api\/console\/badge$/, "read", getBadge],
  ["POST", /^\/api\/console\/badge\/(enable|suspend|resume|rotate)$/, "manage_badge", badgeAction],

  ["GET", /^\/api\/console\/settings$/, "read", getSettings],
  ["PATCH", /^\/api\/console\/settings$/, "manage_org", updateSettings],
  ["GET", /^\/api\/console\/members$/, "read", listMembers],
  ["POST", /^\/api\/console\/members\/invites$/, "manage_members", createInvite],
  ["POST", new RegExp(`^/api/console/members/invites/${ID("inv")}/revoke$`), "manage_members", revokeInvite],
  ["PATCH", new RegExp(`^/api/console/members/${ID("mem")}$`), "manage_members", updateMember],
  ["GET", /^\/api\/console\/security$/, "read", getSecurity],
  ["POST", /^\/api\/console\/security\/sessions\/revoke-others$/, "read", revokeOtherSessions],
];

export async function routeConsole(request: Request, env: Env, nowMs: number, waitUntil: (p: Promise<unknown>) => void): Promise<Response> {
  const url = new URL(request.url);
  const matches = ROUTES.filter(([, pattern]) => pattern.test(url.pathname));
  if (!matches.length) throw new ApiError(404, "NOT_FOUND", "Unknown console endpoint.");
  const route = matches.find(([method]) => method === request.method);
  if (!route) {
    const allowed = [...new Set(matches.map(([m]) => m))];
    return json({ error: { code: "METHOD_NOT_ALLOWED", message: `Allowed: ${allowed.join(", ")}` } }, 405, { Allow: allowed.join(", ") });
  }

  const mutating = request.method !== "GET";
  if (mutating) assertSameOrigin(request);

  const session = await loadSession(request, env, nowMs);
  if (!session) throw new ApiError(401, "UNAUTHENTICATED", "Sign in required.");

  const { success } = await env.RL_CONSOLE.limit({ key: session.sessionId || clientIp(request) });
  if (!success) throw new ApiError(429, "RATE_LIMITED", "Too many requests. Slow down.");

  const [, pattern, permission, handler] = route;
  requirePermission(session.role, permission);

  const body = mutating && request.headers.get("Content-Type") ? await readJsonObject(request) : {};
  const params = pattern.exec(url.pathname)!.slice(1);

  return handler({
    env,
    db: env.DB,
    session,
    orgId: session.organization.id,
    nowMs,
    actor: { type: "user", id: session.user.id, label: session.user.display_name },
    url,
    params,
    body,
    waitUntil,
  });
}
