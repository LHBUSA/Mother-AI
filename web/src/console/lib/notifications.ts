// Approval notification settings as reported by /api/console/notifications.
// The webhook URL is write-only on the server; nothing here can ever hold it after save.

export type NotificationStatus = "QUEUED" | "SENDING" | "SENT_TO_PROVIDER" | "FAILED" | "SKIPPED";
export type NotificationEvent = "review_required" | "approved" | "denied" | "expired" | "consumed";

export interface NotificationRecord {
  id: string;
  approval_id: string;
  event: NotificationEvent;
  channel: "slack";
  status: NotificationStatus;
  attempts: number;
  max_attempts: number;
  queued_at: string;
  last_attempt_at: string | null;
  completed_at: string | null;
  last_http_status: number | null;
  last_error: string | null;
}

export interface NotificationSettings {
  available: boolean;
  slack: { configured: true; status: "enabled"; configured_at: string; updated_at: string; configured_by_name: string | null } | { configured: false; status: "not_configured" };
  events: NotificationEvent[];
  recent: NotificationRecord[];
}

export const EVENT_LABEL: Record<NotificationEvent, string> = {
  review_required: "Review required",
  approved: "Approved",
  denied: "Denied",
  expired: "Expired",
  consumed: "Grant consumed",
};

/** Literal labels: "Sent to Slack" means Slack accepted the message, not that someone read it. */
export const STATUS_LABEL: Record<NotificationStatus, string> = {
  QUEUED: "Queued",
  SENDING: "Sending",
  SENT_TO_PROVIDER: "Sent to Slack",
  FAILED: "Failed",
  SKIPPED: "Skipped",
};

export const STATUS_TONE: Record<NotificationStatus, "ok" | "warn" | "bad" | "muted"> = {
  QUEUED: "warn",
  SENDING: "warn",
  SENT_TO_PROVIDER: "ok",
  FAILED: "bad",
  SKIPPED: "muted",
};

const ERROR_LABEL: Record<string, string> = {
  APPROVAL_NOT_PENDING: "approval was no longer pending",
  ORGANIZATION_NOT_ACTIVE: "organization not active",
  CHANNEL_NOT_CONFIGURED: "Slack was disconnected",
  ENCRYPTION_KEY_UNAVAILABLE: "notifications unavailable on this deployment",
  DESTINATION_UNREADABLE: "stored webhook could not be read — reconnect Slack",
  INVALID_DESTINATION: "webhook is not a Slack incoming webhook",
  LEASE_EXPIRED: "delivery interrupted",
  TIMEOUT: "Slack timed out",
  NETWORK: "network error",
  HTTP_400: "Slack rejected the message (400)",
  HTTP_403: "Slack rejected the webhook (403)",
  HTTP_404: "webhook not found — it may have been removed in Slack (404)",
  HTTP_410: "Slack channel archived (410)",
  HTTP_429: "Slack rate limited (429)",
};

export function describeNotificationError(code: string | null): string | null {
  if (!code) return null;
  return ERROR_LABEL[code] ?? (code.startsWith("HTTP_") ? `Slack answered ${code.slice(5)}` : code);
}
