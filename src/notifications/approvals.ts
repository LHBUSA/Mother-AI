// Approval notifications: queue, deliver, retry, sweep.
//
//   approval written ──(waitUntil)──> queue row (INSERT OR IGNORE on approval+event+channel)
//        QUEUED ──claim──> SENDING ──> SENT_TO_PROVIDER | QUEUED (retry) | FAILED
//        QUEUED ──precondition no longer true──> SKIPPED
//
// Invariants:
//   * Notification code runs only after the approval (and decision) are durably written,
//     and never writes to approvals or decisions. A failure here cannot change a
//     decision, delete an approval or extend its expiry.
//   * One (approval, event, channel) row, enforced by a UNIQUE constraint, is the
//     idempotency marker. Replays, retries, polling, console reads and cron sweeps
//     all funnel into that single row.
//   * A row is sent only by the invocation that claims it with a conditional UPDATE.
//     Terminal rows are immutable (schema trigger), so a sent notification is never re-sent.
//     The one unavoidable at-least-once window: an invocation that dies after Slack
//     accepted the request but before recording it; its lease expires, the attempt is
//     logged ABANDONED and the row may be retried.
//   * Attempts are bounded (max_attempts). Only 429, 5xx, timeouts and network errors retry.
//   * The destination URL is decrypted in memory for the request only. Logs carry ids,
//     HTTP statuses and error codes — never the URL.

import type { Env } from "../env";
import { newId } from "../lib/crypto";
import { iso } from "../lib/time";
import { decryptSecret, SecretUnavailableError } from "./secret";
import { buildApprovalSlackPayload, type ApprovalNotificationData, type NotificationEvent } from "./slack";

export const NOTIFY_TUNING = {
  /** Per-request timeout for the provider call. */
  timeoutMs: 5000,
  /** One in-invocation retry after this delay for retryable failures (cron handles later retries). */
  inlineRetryDelayMs: 1500,
  /** Longest Retry-After honoured inline; longer waits are left to the cron sweep. */
  inlineRetryAfterCapMs: 5000,
  /** Minimum delay before a cron retry. */
  retryBackoffMs: 60_000,
  maxAttempts: 3,
  leaseMs: 60_000,
  /** Sweep windows. */
  initialBackfillWindowMs: 60 * 60 * 1000,
  resolutionBackfillWindowMs: 24 * 60 * 60 * 1000,
};

/** Slack incoming webhooks only: fixed host and path shape, so a destination can never point anywhere else. */
export const SLACK_WEBHOOK_PATTERN = /^https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{6,15}\/B[A-Z0-9]{6,15}\/[A-Za-z0-9]{20,48}$/;

export type ProviderOutcome =
  | { kind: "sent"; httpStatus: number }
  | { kind: "retryable"; httpStatus: number | null; error: string; retryAfterMs: number | null }
  | { kind: "permanent"; httpStatus: number | null; error: string };

/** POSTs a payload to a Slack incoming webhook. Never throws and never logs the URL. */
export async function postToSlack(url: string, payload: Record<string, unknown>): Promise<ProviderOutcome> {
  if (!SLACK_WEBHOOK_PATTERN.test(url)) return { kind: "permanent", httpStatus: null, error: "INVALID_DESTINATION" };
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      redirect: "manual",
      signal: AbortSignal.timeout(NOTIFY_TUNING.timeoutMs),
    });
    await res.text().catch(() => undefined);
    // Slack answers 200 "ok" when it accepts the message. That is all SENT_TO_PROVIDER claims.
    if (res.status === 200) return { kind: "sent", httpStatus: 200 };
    if (res.status === 429 || res.status >= 500) {
      const retryAfter = Number(res.headers.get("Retry-After"));
      return { kind: "retryable", httpStatus: res.status, error: `HTTP_${res.status}`, retryAfterMs: Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : null };
    }
    return { kind: "permanent", httpStatus: res.status, error: `HTTP_${res.status}` };
  } catch (err) {
    const name = err instanceof Error ? err.name : "";
    return { kind: "retryable", httpStatus: null, error: name === "TimeoutError" || name === "AbortError" ? "TIMEOUT" : "NETWORK", retryAfterMs: null };
  }
}

// ---------------------------------------------------------------------------
// Queueing
// ---------------------------------------------------------------------------

const EVENT_CONDITION: Record<NotificationEvent, string> = {
  review_required: `ap.status = 'pending' AND ap.expires_at > ?1 AND ap.requested_at >= c.created_at`,
  approved: `ap.status = 'approved' AND EXISTS (SELECT 1 FROM approval_notifications i WHERE i.approval_id = ap.id AND i.event = 'review_required' AND i.channel = 'slack' AND i.status = 'SENT_TO_PROVIDER')`,
  denied: `ap.status = 'denied' AND EXISTS (SELECT 1 FROM approval_notifications i WHERE i.approval_id = ap.id AND i.event = 'review_required' AND i.channel = 'slack' AND i.status = 'SENT_TO_PROVIDER')`,
  expired: `ap.status = 'expired' AND EXISTS (SELECT 1 FROM approval_notifications i WHERE i.approval_id = ap.id AND i.event = 'review_required' AND i.channel = 'slack' AND i.status = 'SENT_TO_PROVIDER')`,
  consumed: `ap.consumed_at IS NOT NULL AND EXISTS (SELECT 1 FROM approval_notifications i WHERE i.approval_id = ap.id AND i.event = 'review_required' AND i.channel = 'slack' AND i.status = 'SENT_TO_PROVIDER')`,
};

/**
 * Queues one notification for an approval event if — and only if — the organization is
 * active and has a Slack destination. Initial notifications require the destination to
 * predate the approval; resolution notifications require the initial one to have been
 * sent. Returns the queued row id (existing or new), or null when nothing is queued.
 */
export async function queueApprovalNotification(db: D1Database, organizationId: string, approvalId: string, event: NotificationEvent, nowMs: number): Promise<string | null> {
  const now = iso(nowMs);
  await db
    .prepare(
      `INSERT OR IGNORE INTO approval_notifications (id, organization_id, approval_id, event, channel, status, max_attempts, queued_at, next_attempt_at)
       SELECT ?2, ap.organization_id, ap.id, ?3, 'slack', 'QUEUED', ?4, ?1, ?1
         FROM approvals ap
         JOIN organizations o ON o.id = ap.organization_id AND o.status = 'active'
         JOIN notification_channels c ON c.organization_id = ap.organization_id AND c.kind = 'slack_webhook'
        WHERE ap.id = ?5 AND ap.organization_id = ?6 AND ${EVENT_CONDITION[event]}`,
    )
    .bind(now, newId("ntf"), event, NOTIFY_TUNING.maxAttempts, approvalId, organizationId)
    .run();
  const row = await db
    .prepare(`SELECT id FROM approval_notifications WHERE approval_id = ? AND organization_id = ? AND event = ? AND channel = 'slack' AND status = 'QUEUED'`)
    .bind(approvalId, organizationId, event)
    .first<{ id: string }>();
  return row?.id ?? null;
}

/** Side-effect entry point for request handlers (run inside waitUntil). Never throws. */
export async function notifyApprovalEvent(env: Env, organizationId: string, approvalId: string, event: NotificationEvent, now: () => number = Date.now): Promise<void> {
  try {
    const id = await queueApprovalNotification(env.DB, organizationId, approvalId, event, now());
    if (id) await deliverNotification(env, id, now, { inlineRetry: true });
  } catch (err) {
    console.error("approval notification error", { approval_id: approvalId, event, error: err instanceof Error ? err.name : "unknown" });
  }
}

// ---------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------

interface DeliveryRow {
  id: string;
  organization_id: string;
  approval_id: string;
  event: NotificationEvent;
  status: string;
  attempts: number;
  max_attempts: number;
  ap_status: string;
  decision_id: string;
  requested_at: string;
  expires_at: string;
  acted_at: string | null;
  acted_by_name: string | null;
  grant_expires_at: string | null;
  consumed_at: string | null;
  agent_key: string;
  environment: string | null;
  protocol: string;
  capability: string;
  operation: string;
  resource: string | null;
  mcp_server: string | null;
  mcp_tool: string | null;
  policy_id: string | null;
  policy_version: number | null;
  reason_code: string;
  policy_name: string | null;
  agent_display_name: string | null;
  org_name: string;
  org_status: string;
  channel_id: string | null;
  secret_ciphertext: string | null;
}

function loadDeliveryRow(db: D1Database, id: string): Promise<DeliveryRow | null> {
  return db
    .prepare(
      `SELECT n.id, n.organization_id, n.approval_id, n.event, n.status, n.attempts, n.max_attempts,
              ap.status AS ap_status, ap.decision_id, ap.requested_at, ap.expires_at, ap.acted_at, ap.acted_by_name,
              ap.grant_expires_at, ap.consumed_at,
              d.agent_key, d.environment, d.protocol, d.capability, d.operation, d.resource, d.mcp_server, d.mcp_tool,
              d.policy_id, d.policy_version, d.reason_code,
              p.name AS policy_name, a.display_name AS agent_display_name,
              o.display_name AS org_name, o.status AS org_status,
              c.id AS channel_id, c.secret_ciphertext
         FROM approval_notifications n
         JOIN approvals ap ON ap.id = n.approval_id AND ap.organization_id = n.organization_id
         JOIN decisions d ON d.id = ap.decision_id AND d.organization_id = ap.organization_id
         JOIN organizations o ON o.id = n.organization_id
         LEFT JOIN policies p ON p.id = d.policy_id AND p.organization_id = d.organization_id
         LEFT JOIN agents a ON a.id = d.agent_id AND a.organization_id = d.organization_id
         LEFT JOIN notification_channels c ON c.organization_id = n.organization_id AND c.kind = 'slack_webhook'
        WHERE n.id = ?`,
    )
    .bind(id)
    .first<DeliveryRow>();
}

function skipReason(row: DeliveryRow, nowMs: number): string | null {
  if (row.org_status !== "active") return "ORGANIZATION_NOT_ACTIVE";
  if (!row.channel_id || !row.secret_ciphertext) return "CHANNEL_NOT_CONFIGURED";
  if (row.event === "review_required" && (row.ap_status !== "pending" || Date.parse(row.expires_at) <= nowMs)) return "APPROVAL_NOT_PENDING";
  return null;
}

function toPayloadData(row: DeliveryRow): ApprovalNotificationData {
  return {
    event: row.event,
    organization: row.org_name,
    approval_id: row.approval_id,
    decision_id: row.decision_id,
    agent_key: row.agent_key,
    agent_display_name: row.agent_display_name,
    environment: row.environment,
    protocol: row.protocol,
    capability: row.capability,
    operation: row.operation,
    resource: row.resource,
    mcp_server: row.mcp_server,
    mcp_tool: row.mcp_tool,
    policy_id: row.policy_id,
    policy_name: row.policy_name,
    policy_version: row.policy_version,
    reason_code: row.reason_code,
    requested_at: row.requested_at,
    expires_at: row.expires_at,
    acted_at: row.acted_at,
    acted_by_name: row.acted_by_name,
    grant_expires_at: row.grant_expires_at,
    consumed_at: row.consumed_at,
  };
}

async function recordAttempt(
  db: D1Database,
  row: { id: string; organization_id: string },
  attempt: number,
  startedAt: string,
  finishedAt: string,
  update: { status: "SENT_TO_PROVIDER" | "QUEUED" | "FAILED"; nextAttemptAt?: string; httpStatus: number | null; error: string | null },
): Promise<void> {
  const terminal = update.status !== "QUEUED";
  await db.batch([
    db
      .prepare(
        `UPDATE approval_notifications
            SET status = ?, lease_until = NULL, next_attempt_at = COALESCE(?, next_attempt_at), completed_at = ?, last_http_status = ?, last_error = ?
          WHERE id = ? AND status = 'SENDING' AND attempts = ?`,
      )
      .bind(update.status, update.nextAttemptAt ?? null, terminal ? finishedAt : null, update.httpStatus, update.error, row.id, attempt),
    db
      .prepare(
        `INSERT INTO approval_notification_attempts (id, organization_id, notification_id, attempt, started_at, finished_at, outcome, http_status, error)
         SELECT ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE changes() = 1`,
      )
      .bind(newId("nta"), row.organization_id, row.id, attempt, startedAt, finishedAt, update.status === "SENT_TO_PROVIDER" ? "SENT_TO_PROVIDER" : "FAILED", update.httpStatus, update.error),
  ]);
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Delivers one queued notification if it is due and this invocation wins the claim. Never throws. */
export async function deliverNotification(env: Env, id: string, now: () => number = Date.now, opts: { inlineRetry?: boolean } = {}): Promise<void> {
  const db = env.DB;
  let inlineRetries = opts.inlineRetry ? 1 : 0;
  try {
    for (;;) {
      const row = await loadDeliveryRow(db, id);
      if (!row || row.status !== "QUEUED") return;
      const nowMs = now();

      const skip = skipReason(row, nowMs);
      if (skip) {
        await db
          .prepare(`UPDATE approval_notifications SET status = 'SKIPPED', completed_at = ?, last_error = ? WHERE id = ? AND status = 'QUEUED'`)
          .bind(iso(nowMs), skip, id)
          .run();
        console.log("approval notification skipped", { notification_id: id, approval_id: row.approval_id, event: row.event, reason: skip });
        return;
      }

      const startedAt = iso(nowMs);
      const claim = await db
        .prepare(
          `UPDATE approval_notifications SET status = 'SENDING', attempts = attempts + 1, lease_until = ?, last_attempt_at = ?
            WHERE id = ? AND status = 'QUEUED' AND next_attempt_at <= ? AND attempts < max_attempts`,
        )
        .bind(iso(nowMs + NOTIFY_TUNING.leaseMs), startedAt, id, startedAt)
        .run();
      if ((claim.meta.changes ?? 0) !== 1) return;
      const attempt = row.attempts + 1;

      let outcome: ProviderOutcome;
      try {
        const url = await decryptSecret(env.NOTIFICATION_ENCRYPTION_KEY, row.organization_id, row.channel_id!, row.secret_ciphertext!);
        outcome = await postToSlack(url, buildApprovalSlackPayload(toPayloadData(row)));
      } catch (err) {
        outcome = { kind: "permanent", httpStatus: null, error: err instanceof SecretUnavailableError ? "ENCRYPTION_KEY_UNAVAILABLE" : "DESTINATION_UNREADABLE" };
      }
      const finishedMs = now();
      const finishedAt = iso(finishedMs);
      const log = { notification_id: id, approval_id: row.approval_id, event: row.event, attempt };

      if (outcome.kind === "sent") {
        await recordAttempt(db, row, attempt, startedAt, finishedAt, { status: "SENT_TO_PROVIDER", httpStatus: outcome.httpStatus, error: null });
        console.log("approval notification sent to provider", { ...log, status: outcome.httpStatus });
        return;
      }

      const exhausted = outcome.kind === "permanent" || attempt >= row.max_attempts;
      if (exhausted) {
        await recordAttempt(db, row, attempt, startedAt, finishedAt, { status: "FAILED", httpStatus: outcome.httpStatus, error: outcome.error });
        console.error("approval notification failed", { ...log, status: outcome.httpStatus, error: outcome.error, final: true });
        return;
      }

      const retryAfterMs = outcome.kind === "retryable" ? outcome.retryAfterMs : null;
      const inline = inlineRetries > 0 && (retryAfterMs === null || retryAfterMs <= NOTIFY_TUNING.inlineRetryAfterCapMs);
      const delayMs = inline ? Math.max(NOTIFY_TUNING.inlineRetryDelayMs, retryAfterMs ?? 0) : Math.max(NOTIFY_TUNING.retryBackoffMs, retryAfterMs ?? 0);
      await recordAttempt(db, row, attempt, startedAt, finishedAt, { status: "QUEUED", nextAttemptAt: iso(finishedMs + delayMs), httpStatus: outcome.httpStatus, error: outcome.error });
      console.error("approval notification failed", { ...log, status: outcome.httpStatus, error: outcome.error, final: false });
      if (!inline) return;
      inlineRetries--;
      if (delayMs > 0) await sleep(delayMs);
    }
  } catch (err) {
    console.error("approval notification error", { notification_id: id, error: err instanceof Error ? err.name : "unknown" });
  }
}

// ---------------------------------------------------------------------------
// Cron sweep
// ---------------------------------------------------------------------------

/**
 * Recovers anything a request-time waitUntil did not finish: abandoned leases, approvals
 * whose initial notification was never queued, resolution events, and due retries.
 */
export async function sweepApprovalNotifications(env: Env, now: () => number = Date.now, limit = 50): Promise<{ abandoned: number; queued: number; delivered: number }> {
  const db = env.DB;
  const nowMs = now();
  const nowIso = iso(nowMs);

  // 1. Leases that expired mid-send: log the attempt as ABANDONED, then retry or fail.
  const stale = await db
    .prepare(`SELECT id, organization_id, attempts, last_attempt_at FROM approval_notifications WHERE status = 'SENDING' AND lease_until < ? LIMIT ?`)
    .bind(nowIso, limit)
    .all<{ id: string; organization_id: string; attempts: number; last_attempt_at: string | null }>();
  for (const s of stale.results) {
    await db.batch([
      db
        .prepare(
          `UPDATE approval_notifications
              SET status = CASE WHEN attempts >= max_attempts THEN 'FAILED' ELSE 'QUEUED' END,
                  completed_at = CASE WHEN attempts >= max_attempts THEN ?1 ELSE NULL END,
                  lease_until = NULL, next_attempt_at = ?1, last_error = 'LEASE_EXPIRED'
            WHERE id = ?2 AND status = 'SENDING' AND lease_until < ?1`,
        )
        .bind(nowIso, s.id),
      db
        .prepare(
          `INSERT INTO approval_notification_attempts (id, organization_id, notification_id, attempt, started_at, finished_at, outcome, http_status, error)
           SELECT ?, ?, ?, ?, ?, ?, 'ABANDONED', NULL, 'LEASE_EXPIRED' WHERE changes() = 1`,
        )
        .bind(newId("nta"), s.organization_id, s.id, s.attempts, s.last_attempt_at ?? nowIso, nowIso),
    ]);
  }

  // 2. Initial notifications that were never queued (e.g. the request invocation ended first).
  const initial = await db
    .prepare(
      `SELECT ap.id, ap.organization_id FROM approvals ap
         JOIN organizations o ON o.id = ap.organization_id AND o.status = 'active'
         JOIN notification_channels c ON c.organization_id = ap.organization_id AND c.kind = 'slack_webhook'
        WHERE ap.status = 'pending' AND ap.expires_at > ?1 AND ap.requested_at >= c.created_at AND ap.requested_at > ?2
          AND NOT EXISTS (SELECT 1 FROM approval_notifications n WHERE n.approval_id = ap.id AND n.event = 'review_required' AND n.channel = 'slack')
        LIMIT ?3`,
    )
    .bind(nowIso, iso(nowMs - NOTIFY_TUNING.initialBackfillWindowMs), limit)
    .all<{ id: string; organization_id: string }>();

  // 3. Resolution events for approvals whose initial notification was sent.
  const resolution = await db
    .prepare(
      `SELECT ap.id, ap.organization_id,
              CASE WHEN ap.consumed_at IS NOT NULL THEN 'consumed' ELSE ap.status END AS event
         FROM approval_notifications i
         JOIN approvals ap ON ap.id = i.approval_id AND ap.organization_id = i.organization_id
        WHERE i.event = 'review_required' AND i.channel = 'slack' AND i.status = 'SENT_TO_PROVIDER'
          AND ap.status IN ('approved', 'denied', 'expired')
          AND COALESCE(ap.consumed_at, ap.acted_at, ap.expires_at) > ?1
          AND NOT EXISTS (
            SELECT 1 FROM approval_notifications n WHERE n.approval_id = ap.id AND n.channel = 'slack'
               AND n.event = CASE WHEN ap.consumed_at IS NOT NULL THEN 'consumed' ELSE ap.status END)
        LIMIT ?2`,
    )
    .bind(iso(nowMs - NOTIFY_TUNING.resolutionBackfillWindowMs), limit)
    .all<{ id: string; organization_id: string; event: NotificationEvent }>();
  // A consumed approval also owes its "approved" notification if that was never queued.
  const approvedBeforeConsumed = await db
    .prepare(
      `SELECT ap.id, ap.organization_id FROM approval_notifications i
         JOIN approvals ap ON ap.id = i.approval_id AND ap.organization_id = i.organization_id
        WHERE i.event = 'review_required' AND i.channel = 'slack' AND i.status = 'SENT_TO_PROVIDER'
          AND ap.status = 'approved' AND ap.consumed_at IS NOT NULL AND ap.acted_at > ?1
          AND NOT EXISTS (SELECT 1 FROM approval_notifications n WHERE n.approval_id = ap.id AND n.channel = 'slack' AND n.event = 'approved')
        LIMIT ?2`,
    )
    .bind(iso(nowMs - NOTIFY_TUNING.resolutionBackfillWindowMs), limit)
    .all<{ id: string; organization_id: string }>();

  let queued = 0;
  for (const a of initial.results) if (await queueApprovalNotification(db, a.organization_id, a.id, "review_required", nowMs)) queued++;
  for (const a of approvedBeforeConsumed.results) if (await queueApprovalNotification(db, a.organization_id, a.id, "approved", nowMs)) queued++;
  for (const a of resolution.results) if (await queueApprovalNotification(db, a.organization_id, a.id, a.event, nowMs)) queued++;

  // 4. Deliver everything due, oldest first. Retries here are not repeated inline.
  const due = await db
    .prepare(
      `SELECT id FROM approval_notifications WHERE status = 'QUEUED' AND next_attempt_at <= ?
        ORDER BY queued_at, CASE event WHEN 'review_required' THEN 0 WHEN 'consumed' THEN 2 ELSE 1 END LIMIT ?`,
    )
    .bind(iso(now()), limit)
    .all<{ id: string }>();
  for (const d of due.results) await deliverNotification(env, d.id, now);

  return { abandoned: stale.results.length, queued, delivered: due.results.length };
}
