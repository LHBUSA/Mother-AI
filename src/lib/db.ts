// Row types and small D1 helpers. Every tenant-owned query takes organization_id
// from an authenticated principal — never from a request body or path.

export interface OrganizationRow {
  id: string;
  slug: string;
  display_name: string;
  kind: "customer" | "internal";
  status: "active" | "suspended" | "revoked";
  plan: string;
  gateway_enabled: number;
  audit_enabled: number;
  require_registered_agents: number;
  default_decision: "block" | "review";
  approval_ttl_seconds: number;
  approval_grant_ttl_seconds: number;
  created_at: string;
  updated_at: string;
}

export interface AgentRow {
  id: string;
  organization_id: string;
  agent_key: string;
  display_name: string;
  description: string;
  environment: "production" | "staging" | "development";
  status: "active" | "disabled";
  default_mode: "inherit" | "block" | "review" | "allow";
  created_at: string;
  updated_at: string;
}

export interface PolicyRow {
  id: string;
  organization_id: string;
  name: string;
  description: string;
  priority: number;
  enabled: number;
  effect: "allow" | "review" | "block";
  scope: "organization" | "agents";
  conditions: string;
  reason_code: string | null;
  reason: string | null;
  version: number;
  archived_at: string | null;
  created_by: string | null;
  updated_by: string | null;
  created_at: string;
  updated_at: string;
}

export interface ApiKeyRow {
  id: string;
  organization_id: string;
  name: string;
  key_prefix: string;
  key_hash: string;
  environment: "live" | "test";
  created_by: string | null;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
  revoked_by: string | null;
}

export interface DecisionRow {
  id: string;
  organization_id: string;
  request_id: string;
  request_fingerprint: string;
  api_key_id: string | null;
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
  decision: "allow" | "review" | "block";
  reason_code: string;
  reason: string;
  policy_id: string | null;
  policy_version: number | null;
  matched_policies: string;
  context: string | null;
  eval_ms: number | null;
  gateway_ms: number | null;
  engine_version: string;
  created_at: string;
}

export interface ApprovalRow {
  id: string;
  organization_id: string;
  decision_id: string;
  status: "pending" | "approved" | "denied" | "expired";
  requested_at: string;
  expires_at: string;
  acted_at: string | null;
  acted_by: string | null;
  acted_by_name: string | null;
  note: string | null;
  grant_expires_at: string | null;
  consumed_at: string | null;
}

export interface BadgeRow {
  id: string;
  organization_id: string;
  public_token: string;
  state: "enabled" | "suspended" | "revoked";
  activated_at: string | null;
  created_at: string;
  suspended_at: string | null;
  revoked_at: string | null;
  revoked_reason: string | null;
}

export function parseJson<T>(value: string | null | undefined, fallback: T): T {
  if (value === null || value === undefined) return fallback;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

export function isUniqueViolation(err: unknown): boolean {
  return err instanceof Error && /UNIQUE constraint failed/i.test(err.message);
}
