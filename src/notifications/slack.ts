// Slack messages for approval notifications.
//
// Every value that came from an integration or a console user is escaped (Slack
// control sequences need <, > and &) and length-capped. Request context is never
// included: approvers open the console for the evidence. Resource values were
// already redacted when the decision was stored.

import site from "../../config/site.json";
import { slackEscape } from "../leads/slack";

export type NotificationEvent = "review_required" | "approved" | "denied" | "expired" | "consumed";

export interface ApprovalNotificationData {
  event: NotificationEvent;
  organization: string;
  approval_id: string;
  decision_id: string;
  agent_key: string;
  agent_display_name: string | null;
  environment: string | null;
  protocol: string;
  capability: string;
  operation: string;
  resource: string | null;
  mcp_server: string | null;
  mcp_tool: string | null;
  policy_id: string | null;
  policy_name: string | null;
  policy_version: number | null;
  reason_code: string;
  requested_at: string;
  expires_at: string;
  acted_at: string | null;
  acted_by_name: string | null;
  grant_expires_at: string | null;
  consumed_at: string | null;
}

/** The approvals queue. The console has no per-approval route, so this is the deepest safe link. */
export const APPROVALS_URL = `${site.origin}/app/approvals`;

const TITLE: Record<NotificationEvent, string> = {
  review_required: "MOTHER AI · REVIEW REQUIRED",
  approved: "MOTHER AI · APPROVED",
  denied: "MOTHER AI · DENIED",
  expired: "MOTHER AI · EXPIRED",
  consumed: "MOTHER AI · CONSUMED",
};

function clean(value: string | null | undefined, max: number): string {
  if (value === null || value === undefined || value === "") return "—";
  // Control characters and line breaks collapse to spaces; backticks cannot close a code span.
  const flat = value.replace(/[\u0000-\u001f\u007f\u2028\u2029]+/g, " ").replace(/`/g, "'").trim();
  return slackEscape(flat.length > max ? `${flat.slice(0, max - 1)}…` : flat);
}

function when(value: string | null): string {
  if (!value) return "—";
  const ms = Date.parse(value);
  if (Number.isNaN(ms)) return "—";
  const isoText = new Date(ms).toISOString().replace("T", " ").replace(/\.\d{3}Z$/, " UTC");
  return `<!date^${Math.floor(ms / 1000)}^{date_short_pretty} {time_secs}|${isoText}>`;
}

function plainWhen(value: string | null): string {
  if (!value) return "—";
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? "—" : new Date(ms).toISOString();
}

function agentLabel(d: ApprovalNotificationData): string {
  const key = clean(d.agent_key, 120);
  return d.agent_display_name && d.agent_display_name !== d.agent_key ? `${clean(d.agent_display_name, 120)} (\`${key}\`)` : `\`${key}\``;
}

function actionLabel(d: ApprovalNotificationData): string {
  const base = `${clean(d.capability, 120)} · ${clean(d.operation, 120)}`;
  return d.protocol === "mcp" && (d.mcp_server || d.mcp_tool) ? `${base} (MCP ${clean(d.mcp_server, 80)} / ${clean(d.mcp_tool, 80)})` : base;
}

function policyLabel(d: ApprovalNotificationData): string {
  if (!d.policy_id) return "No policy (organization default)";
  const version = d.policy_version ? ` v${d.policy_version}` : "";
  return `${clean(d.policy_name ?? d.policy_id, 160)}${version}`;
}

function summaryLine(d: ApprovalNotificationData): string {
  switch (d.event) {
    case "review_required":
      return `An agent action is paused for human approval. Nothing executes until an approver decides. The request expires ${when(d.expires_at)}.`;
    case "approved":
      return `Approved by ${clean(d.acted_by_name, 120)} ${when(d.acted_at)}. The integration may redeem the one-time grant until ${when(d.grant_expires_at)}. Approved is not executed: Mother AI reports CONSUMED only when the grant is redeemed.`;
    case "denied":
      return `Denied by ${clean(d.acted_by_name, 120)} ${when(d.acted_at)}. The grant cannot be consumed.`;
    case "expired":
      return `No approver acted before ${when(d.expires_at)}. This request can no longer be approved or consumed.`;
    case "consumed":
      return `The integration redeemed the one-time grant ${when(d.consumed_at)}. Mother AI records the redemption; it does not observe the downstream action itself.`;
  }
}

function plainSummary(d: ApprovalNotificationData): string {
  switch (d.event) {
    case "review_required":
      return `Human approval required. Expires ${plainWhen(d.expires_at)}.`;
    case "approved":
      return `Approved ${plainWhen(d.acted_at)}; grant redeemable until ${plainWhen(d.grant_expires_at)}. Not executed until consumed.`;
    case "denied":
      return `Denied ${plainWhen(d.acted_at)}.`;
    case "expired":
      return `Expired ${plainWhen(d.expires_at)} without a decision.`;
    case "consumed":
      return `Grant consumed ${plainWhen(d.consumed_at)}.`;
  }
}

export function buildApprovalSlackPayload(d: ApprovalNotificationData): Record<string, unknown> {
  const title = TITLE[d.event];
  const fields =
    d.event === "review_required"
      ? [
          ["Organization", clean(d.organization, 120)],
          ["Agent", agentLabel(d)],
          ["Environment", clean(d.environment, 40)],
          ["Action", actionLabel(d)],
          ["Resource", `\`${clean(d.resource, 300)}\``],
          ["Policy", policyLabel(d)],
          ["Reason code", `\`${clean(d.reason_code, 80)}\``],
          ["Created", when(d.requested_at)],
          ["Expires", when(d.expires_at)],
        ]
      : [
          ["Organization", clean(d.organization, 120)],
          ["Agent", agentLabel(d)],
          ["Action", actionLabel(d)],
          ["Resource", `\`${clean(d.resource, 300)}\``],
        ];

  const text = [
    title,
    `Organization: ${clean(d.organization, 120)}`,
    `Agent: ${clean(d.agent_key, 120)} · ${clean(d.capability, 120)} · ${clean(d.operation, 120)}`,
    plainSummary(d),
    `Approval ${d.approval_id} · Decision ${d.decision_id}`,
  ].join("\n");

  return {
    text,
    unfurl_links: false,
    unfurl_media: false,
    blocks: [
      { type: "header", text: { type: "plain_text", text: title, emoji: false } },
      { type: "section", text: { type: "mrkdwn", text: summaryLine(d) } },
      { type: "section", fields: fields.map(([label, value]) => ({ type: "mrkdwn", text: `*${label}*\n${value}` })) },
      ...(d.event === "review_required"
        ? [{ type: "actions", elements: [{ type: "button", text: { type: "plain_text", text: "Open approvals queue", emoji: false }, url: APPROVALS_URL }] }]
        : []),
      {
        type: "context",
        elements: [{ type: "mrkdwn", text: `Approval \`${d.approval_id}\` · Decision \`${d.decision_id}\`${d.event === "review_required" ? "" : ` · <${APPROVALS_URL}|Approvals queue>`}` }],
      },
    ],
  };
}

export function buildTestSlackPayload(organization: string, actor: string): Record<string, unknown> {
  const org = clean(organization, 120);
  const who = clean(actor, 120);
  return {
    text: `MOTHER AI · TEST NOTIFICATION\nApproval notifications are connected for ${org}. Sent by ${who}. No approval was created.`,
    unfurl_links: false,
    unfurl_media: false,
    blocks: [
      { type: "header", text: { type: "plain_text", text: "MOTHER AI · TEST NOTIFICATION", emoji: false } },
      { type: "section", text: { type: "mrkdwn", text: `Approval notifications are connected for *${org}*. Sent by ${who} from the Mother AI console. No approval was created.` } },
    ],
  };
}

// ---------------------------------------------------------------------------
// Security incident alerts (runtime containment)
// ---------------------------------------------------------------------------

export interface SecurityAlertData {
  event: "risk_elevated" | "review_required" | "quarantined" | "containment_completed" | "cleared";
  organization: string;
  subjectType: string;
  subjectLabel: string;
  fromState: string;
  toState: string;
  score: number;
  signals: string;
  incidentId: string | null;
  scope: { sessions: number; childAgents: number; revokedLeases: number; cancelledApprovals: number; invalidatedGrants: number };
  clearedBy: string | null;
}

export const SECURITY_URL = `${site.origin}/app/security`;

const SECURITY_TITLE: Record<SecurityAlertData["event"], string> = {
  risk_elevated: "MOTHER AI · RISK ELEVATED",
  review_required: "MOTHER AI · RUNTIME REVIEW REQUIRED",
  quarantined: "MOTHER AI · QUARANTINED",
  containment_completed: "MOTHER AI · CONTAINMENT COMPLETED",
  cleared: "MOTHER AI · QUARANTINE CLEARED",
};

function securitySummary(d: SecurityAlertData): string {
  const subject = `${d.subjectType} ${clean(d.subjectLabel, 160)}`;
  switch (d.event) {
    case "risk_elevated":
      return `Deterministic runtime risk for ${subject} rose to elevated (score ${d.score}). No enforcement change yet.`;
    case "review_required":
      return `Runtime risk for ${subject} requires human review (score ${d.score}). Allowed actions in this scope now need approval.`;
    case "quarantined":
      return `${subject} is quarantined. Every new action in scope is blocked, live leases are revoked, pending approvals are cancelled and older grants can never be used.`;
    case "containment_completed":
      return `Containment for ${subject} is complete: no live lease and no pending approval remains in scope. It stays blocked until an authorized human clears it.`;
    case "cleared":
      return `${subject} was cleared by ${clean(d.clearedBy, 120)}. Grants and leases issued before the quarantine remain invalid; new authority must be issued.`;
  }
}

export function buildSecuritySlackPayload(d: SecurityAlertData): Record<string, unknown> {
  const title = SECURITY_TITLE[d.event];
  const fields: Array<[string, string]> = [
    ["Organization", clean(d.organization, 120)],
    ["Subject", `${clean(d.subjectType, 20)} \`${clean(d.subjectLabel, 160)}\``],
    ["State", `${clean(d.fromState, 20)} → ${clean(d.toState, 20)}`],
    ["Score", String(d.score)],
    ["Signals", clean(d.signals, 300)],
  ];
  if (d.incidentId) fields.push(["Incident", `\`${clean(d.incidentId, 40)}\``]);
  if (d.event === "quarantined" || d.event === "containment_completed") {
    fields.push([
      "Scope",
      `${d.scope.sessions} sessions · ${d.scope.childAgents} child agents · ${d.scope.revokedLeases} leases revoked · ${d.scope.cancelledApprovals} approvals cancelled · ${d.scope.invalidatedGrants} grants invalidated`,
    ]);
  }
  return {
    text: [title, `Organization: ${clean(d.organization, 120)}`, securitySummary(d), d.incidentId ? `Incident ${d.incidentId}` : ""].filter(Boolean).join("\n"),
    unfurl_links: false,
    unfurl_media: false,
    blocks: [
      { type: "header", text: { type: "plain_text", text: title, emoji: false } },
      { type: "section", text: { type: "mrkdwn", text: securitySummary(d) } },
      { type: "section", fields: fields.map(([label, value]) => ({ type: "mrkdwn", text: `*${label}*\n${value}` })) },
      { type: "actions", elements: [{ type: "button", text: { type: "plain_text", text: "Open Security", emoji: false }, url: SECURITY_URL }] },
      { type: "context", elements: [{ type: "mrkdwn", text: "Deterministic rules (mre-1.0.0). Mother only sees actions routed through Mother." }] },
    ],
  };
}
