// Public demo policy workspace. Runs the production policy engine against a fixed,
// in-code workspace. Demo evaluations are never written to D1 and can never touch
// customer tenants.

import type { PolicyRecord } from "../gateway/policy-engine";

export interface DemoAgent {
  id: string;
  agent_id: string;
  display_name: string;
  environment: "production" | "staging" | "development";
  description: string;
}

export const DEMO_AGENTS: DemoAgent[] = [
  { id: "agt_demo_billing", agent_id: "billing-agent-prod", display_name: "Billing agent", environment: "production", description: "Issues refunds and account credits from support tickets." },
  { id: "agt_demo_research", agent_id: "research-agent-prod", display_name: "Research agent", environment: "production", description: "Reads the knowledge base and customer records to answer questions." },
  { id: "agt_demo_sales", agent_id: "sales-agent-prod", display_name: "Sales agent", environment: "production", description: "Updates CRM contacts through a Salesforce MCP server." },
];

const created = "2026-09-01T00:00:00.000Z";

export const DEMO_POLICIES: Array<PolicyRecord & { description: string }> = [
  {
    id: "pol_demo_restricted_egress",
    name: "Restricted data never leaves the company",
    description: "Blocks any agent from sending restricted data to an external destination.",
    priority: 1,
    enabled: true,
    effect: "block",
    scope: "organization",
    agent_ids: [],
    conditions: { match: "all", conditions: [{ field: "data_class", operator: "equals", value: "restricted" }, { field: "destination", operator: "equals", value: "external" }] },
    reason_code: "RESTRICTED_DATA_EGRESS",
    reason: "Restricted data cannot be sent to external destinations.",
    version: 1,
    created_at: created,
  },
  {
    id: "pol_demo_no_crm_deletes",
    name: "No agent deletes CRM records",
    description: "Blocks every delete-style tool on the Salesforce MCP server.",
    priority: 5,
    enabled: true,
    effect: "block",
    scope: "organization",
    agent_ids: [],
    conditions: { match: "all", conditions: [{ field: "capability", operator: "equals", value: "salesforce" }, { field: "operation", operator: "glob", value: "*.delete" }] },
    reason_code: "OPERATION_NOT_ALLOWED",
    reason: "Agents may not delete CRM records.",
    version: 1,
    created_at: created,
  },
  {
    id: "pol_demo_research_no_writes",
    name: "Research agent is read-only",
    description: "Blocks modifications and any finance capability for the research agent.",
    priority: 10,
    enabled: true,
    effect: "block",
    scope: "agents",
    agent_ids: ["agt_demo_research"],
    conditions: {
      match: "any",
      conditions: [
        { field: "operation", operator: "in", value: ["modify", "update", "delete", "write", "create"] },
        { field: "capability", operator: "starts_with", value: "finance" },
      ],
    },
    reason_code: "OPERATION_NOT_ALLOWED",
    reason: "The research agent may only read.",
    version: 1,
    created_at: created,
  },
  {
    id: "pol_demo_research_reads",
    name: "Research agent may read knowledge and records",
    description: "Allows read operations on the knowledge base and customer records.",
    priority: 100,
    enabled: true,
    effect: "allow",
    scope: "agents",
    agent_ids: ["agt_demo_research"],
    conditions: { match: "all", conditions: [{ field: "capability", operator: "in", value: ["knowledge", "records"] }, { field: "operation", operator: "equals", value: "read" }] },
    reason_code: null,
    reason: null,
    version: 1,
    created_at: created,
  },
  {
    id: "pol_demo_high_value_refunds",
    name: "Refunds over $1,000 need human approval",
    description: "Routes high-value refunds to an approver before execution.",
    priority: 20,
    enabled: true,
    effect: "review",
    scope: "agents",
    agent_ids: ["agt_demo_billing"],
    conditions: {
      match: "all",
      conditions: [
        { field: "capability", operator: "equals", value: "payments" },
        { field: "operation", operator: "equals", value: "refund" },
        { field: "context.amount", operator: "greater_than", value: 1000 },
      ],
    },
    reason_code: null,
    reason: "Refunds over $1,000 require human approval.",
    version: 1,
    created_at: created,
  },
  {
    id: "pol_demo_billing_refunds",
    name: "Billing agent may issue refunds and credits",
    description: "Allows refunds and credits on the payments capability.",
    priority: 100,
    enabled: true,
    effect: "allow",
    scope: "agents",
    agent_ids: ["agt_demo_billing"],
    conditions: { match: "all", conditions: [{ field: "capability", operator: "equals", value: "payments" }, { field: "operation", operator: "in", value: ["refund", "credit"] }] },
    reason_code: null,
    reason: null,
    version: 1,
    created_at: created,
  },
  {
    id: "pol_demo_sales_crm_mcp",
    name: "Sales agent may read and update contacts over MCP",
    description: "Allows two specific Salesforce MCP tools for the sales agent.",
    priority: 100,
    enabled: true,
    effect: "allow",
    scope: "agents",
    agent_ids: ["agt_demo_sales"],
    conditions: {
      match: "all",
      conditions: [
        { field: "protocol", operator: "equals", value: "mcp" },
        { field: "mcp.server", operator: "equals", value: "salesforce" },
        { field: "mcp.tool", operator: "in", value: ["contacts.read", "contacts.update"] },
      ],
    },
    reason_code: null,
    reason: null,
    version: 1,
    created_at: created,
  },
];

export const DEMO_SCENARIOS = [
  {
    id: "research-read",
    label: "Research agent reads a customer record",
    description: "A read the agent is explicitly allowed to perform.",
    request: { agent_id: "research-agent-prod", capability: "records", operation: "read", resource: "customer:8812", destination: "internal", data_class: "internal" },
  },
  {
    id: "research-modify",
    label: "Research agent tries to modify a record",
    description: "A write from an agent that is only allowed to read.",
    request: { agent_id: "research-agent-prod", capability: "records", operation: "modify", resource: "customer:8812", destination: "internal", data_class: "internal" },
  },
  {
    id: "refund-small",
    label: "Billing agent refunds $420",
    description: "Under the approval threshold.",
    request: { agent_id: "billing-agent-prod", capability: "payments", operation: "refund", resource: "payment:pi_3Q8x", destination: "internal", data_class: "financial", context: { amount: 420, currency: "USD" } },
  },
  {
    id: "refund-large",
    label: "Billing agent refunds $4,200",
    description: "Over the threshold — a human must approve.",
    request: { agent_id: "billing-agent-prod", capability: "payments", operation: "refund", resource: "payment:pi_9Lk2", destination: "internal", data_class: "financial", context: { amount: 4200, currency: "USD" } },
  },
  {
    id: "restricted-egress",
    label: "Agent sends restricted data externally",
    description: "Restricted data to an external destination.",
    request: { agent_id: "research-agent-prod", capability: "email", operation: "send", resource: "mailbox:outbound", destination: "external", data_class: "restricted" },
  },
  {
    id: "mcp-update",
    label: "Sales agent updates a contact over MCP",
    description: "An allowed MCP tool call.",
    request: { agent_id: "sales-agent-prod", protocol: "mcp", capability: "salesforce", operation: "contacts.update", mcp: { server: "salesforce", tool: "contacts.update" }, resource: "contact:003Hs00", destination: "internal", data_class: "confidential", context: { fields: ["title", "phone"] } },
  },
  {
    id: "mcp-delete",
    label: "Sales agent deletes a contact over MCP",
    description: "A destructive MCP tool no agent may call.",
    request: { agent_id: "sales-agent-prod", protocol: "mcp", capability: "salesforce", operation: "contacts.delete", mcp: { server: "salesforce", tool: "contacts.delete" }, resource: "contact:003Hs00", destination: "internal", data_class: "confidential" },
  },
  {
    id: "unknown-agent",
    label: "Unregistered agent attempts an action",
    description: "Mother fails closed on unknown identities.",
    request: { agent_id: "shadow-agent", capability: "database", operation: "query", resource: "db:customers", destination: "internal", data_class: "confidential" },
  },
];
