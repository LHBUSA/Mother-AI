// Same-origin JSON client for the control-plane API.

export class ApiFailure extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly fields: Record<string, string> = {},
    readonly extra: Record<string, unknown> = {},
  ) {
    super(message);
  }
}

type Method = "GET" | "POST" | "PUT" | "PATCH";

let onUnauthenticated: (() => void) | null = null;
export function setUnauthenticatedHandler(fn: () => void) {
  onUnauthenticated = fn;
}

export async function api<T>(path: string, opts: { method?: Method; body?: unknown; allow401?: boolean } = {}): Promise<T> {
  const method = opts.method ?? (opts.body !== undefined ? "POST" : "GET");
  const init: RequestInit = { method, credentials: "same-origin", headers: { Accept: "application/json" } };
  if (method !== "GET") {
    init.headers = { ...init.headers, "Content-Type": "application/json" };
    init.body = JSON.stringify(opts.body ?? {});
  }
  let res: Response;
  try {
    res = await fetch(path, init);
  } catch {
    throw new ApiFailure(0, "NETWORK_ERROR", "Mother AI could not be reached. Check your connection and retry.");
  }
  let data: unknown = null;
  const text = await res.text();
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = null;
    }
  }
  if (!res.ok) {
    const err = (data as { error?: { code?: string; message?: string; fields?: Record<string, string> } } | null)?.error ?? {};
    const { code, message, fields, ...extra } = err as Record<string, unknown>;
    const failure = new ApiFailure(
      res.status,
      typeof code === "string" ? code : `HTTP_${res.status}`,
      typeof message === "string" ? message : friendlyStatus(res.status),
      (fields as Record<string, string>) ?? {},
      extra,
    );
    if (res.status === 401 && failure.code === "UNAUTHENTICATED" && !opts.allow401) onUnauthenticated?.();
    throw failure;
  }
  return data as T;
}

function friendlyStatus(status: number): string {
  if (status === 403) return "You don't have permission to do that.";
  if (status === 404) return "Not found.";
  if (status === 429) return "Too many requests. Wait a moment and try again.";
  if (status >= 500) return "Mother AI hit an internal error. Try again.";
  return "Request failed.";
}

export function errorMessage(err: unknown): string {
  if (err instanceof ApiFailure) {
    if (err.status === 429) return "Rate limit reached. Wait a moment and try again.";
    if (err.status === 403 && err.code === "FORBIDDEN") return err.message || "Your role can't perform this action.";
    return err.message;
  }
  return "Something went wrong.";
}

// ---------------------------------------------------------------------------
// Shared types (mirror src/api/console/*)
// ---------------------------------------------------------------------------

export type Decision = "allow" | "review" | "block";
export type Role = "owner" | "admin" | "security" | "approver" | "viewer";
export type Permission = "read" | "approve" | "manage_agents" | "manage_policies" | "manage_keys" | "manage_badge" | "manage_org" | "manage_members";

export interface SessionInfo {
  user: { id: string; display_name: string; email: string | null };
  role: Role;
  permissions: Permission[];
  organization: { id: string; display_name: string; slug: string; status: "active" | "suspended" | "revoked"; kind: string; plan: string };
  memberships: Array<{ id: string; display_name: string; slug: string; role: Role }>;
}

export interface DecisionSummary {
  id: string;
  request_id: string;
  agent_id: string | null;
  agent_key: string;
  protocol: "api" | "mcp";
  capability: string;
  operation: string;
  resource: string | null;
  destination: string | null;
  data_class: string | null;
  environment: string | null;
  mcp_server: string | null;
  mcp_tool: string | null;
  decision: Decision;
  reason_code: string;
  reason: string;
  policy_id: string | null;
  policy_version: number | null;
  created_at: string;
}

export interface Agent {
  id: string;
  agent_key: string;
  display_name: string;
  description: string;
  environment: "production" | "staging" | "development";
  status: "active" | "disabled";
  default_mode: "inherit" | "block" | "review" | "allow";
  created_at: string;
  updated_at: string;
}

export type Operator =
  | "equals"
  | "not_equals"
  | "in"
  | "not_in"
  | "starts_with"
  | "glob"
  | "greater_than"
  | "greater_than_or_equal"
  | "less_than"
  | "less_than_or_equal"
  | "exists"
  | "not_exists";

export type Scalar = string | number | boolean;
export interface Condition {
  field: string;
  operator: Operator;
  value?: Scalar | Scalar[];
}
export interface ConditionGroup {
  match: "all" | "any";
  conditions: Condition[];
}

export interface Policy {
  id: string;
  name: string;
  description: string;
  priority: number;
  enabled: boolean;
  effect: Decision;
  scope: "organization" | "agents";
  conditions: ConditionGroup | null;
  reason_code: string | null;
  reason: string | null;
  version: number;
  archived_at: string | null;
  created_at: string;
  updated_at: string;
  agents: Array<{ id: string; agent_key: string }>;
  decisions_7d?: number;
}

export type BadgeStatus = "setup" | "active" | "suspended" | "revoked";
