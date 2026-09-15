// JSON client for the control-plane API on the Mother AI API host (see web/src/shared/site.ts).
// Calls go directly to the Worker with credentials so the host-only session cookie is sent.

import { apiUrl } from "../../shared/site";

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

export const REQUEST_TIMEOUT_MS = 20_000;

let onUnauthenticated: (() => void) | null = null;
export function setUnauthenticatedHandler(fn: () => void) {
  onUnauthenticated = fn;
}

export async function api<T>(path: string, opts: { method?: Method; body?: unknown; allow401?: boolean; signal?: AbortSignal } = {}): Promise<T> {
  const method = opts.method ?? (opts.body !== undefined ? "POST" : "GET");
  const init: RequestInit = { method, credentials: "include", headers: { Accept: "application/json" } };
  if (method !== "GET") {
    init.headers = { ...init.headers, "Content-Type": "application/json" };
    init.body = JSON.stringify(opts.body ?? {});
  }
  // Bounded: a hung request surfaces as TIMEOUT instead of an endless loading state.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  // A caller-supplied signal (e.g. the user navigated to another item) cancels the request too.
  const cancel = () => controller.abort();
  if (opts.signal?.aborted) controller.abort();
  else opts.signal?.addEventListener("abort", cancel, { once: true });
  init.signal = controller.signal;
  let res: Response;
  let text: string;
  try {
    res = await fetch(apiUrl(path), init);
    text = await res.text();
  } catch {
    if (opts.signal?.aborted) throw new ApiFailure(0, "ABORTED", "The request was cancelled.");
    if (controller.signal.aborted) throw new ApiFailure(0, "TIMEOUT", "Mother AI didn't respond in time. Retry in a moment.");
    throw new ApiFailure(0, "NETWORK_ERROR", "Mother AI could not be reached. Check your connection and retry.");
  } finally {
    clearTimeout(timer);
    opts.signal?.removeEventListener("abort", cancel);
  }
  let data: unknown = null;
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

export type FailureKind = "unavailable" | "forbidden" | "suspended" | "rate_limited" | "not_found" | "unauthenticated" | "failed";

export interface FailureInfo {
  kind: FailureKind;
  title: string;
  text: string;
  /** Error code and HTTP status only — never a response body. */
  detail: string;
}

/** Classifies a failed load into one of the console's distinct, truthful states. */
export function describeFailure(err: unknown): FailureInfo {
  if (!(err instanceof ApiFailure)) {
    return { kind: "failed", title: "Couldn't load this view", text: "Something went wrong in the console. Retry, or reload the page.", detail: "CLIENT_ERROR" };
  }
  const detail = err.status ? `HTTP ${err.status} · ${err.code}` : err.code;
  if (err.status === 0 || err.status >= 500) {
    return {
      kind: "unavailable",
      title: "Mother AI API unavailable",
      text: err.code === "TIMEOUT" ? "The API didn't respond in time. Nothing is shown here rather than a guess." : "The console couldn't get an answer from the API. Nothing is shown here rather than a guess.",
      detail,
    };
  }
  if (err.status === 403 && err.code === "ORGANIZATION_SUSPENDED") return { kind: "suspended", title: "Organization suspended", text: err.message, detail };
  if (err.status === 403) return { kind: "forbidden", title: "Permission required", text: err.message || "Your role can't open this view.", detail };
  if (err.status === 429) return { kind: "rate_limited", title: "Rate limit reached", text: "Mother AI is limiting requests from this session. Wait a moment, then retry.", detail };
  if (err.status === 404) return { kind: "not_found", title: "Not found", text: err.message || "This record doesn't exist in your organization.", detail };
  if (err.status === 401) return { kind: "unauthenticated", title: "Session expired", text: "Sign in again to continue.", detail };
  return { kind: "failed", title: "Couldn't load this view", text: err.message, detail };
}

// ---------------------------------------------------------------------------
// Shared types (mirror src/api/console/*)
// ---------------------------------------------------------------------------

export type Decision = "allow" | "review" | "block";
export type Role = "owner" | "admin" | "security" | "approver" | "viewer";
export type Permission = "read" | "approve" | "manage_agents" | "manage_policies" | "manage_keys" | "manage_badge" | "manage_org" | "manage_members" | "manage_security";

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
