// Security incident alerts. Reuses the organization's encrypted Slack destination
// (notification_channels), the Worker's decryption and the existing Slack sender. Separate queue
// (security_notifications) with the same claim / lease / bounded-retry semantics as approval alerts.
//
// Invariant: nothing in this file writes risk_subjects, security_incidents, capability_leases or
// approvals. A failed or crashing alert can never change containment.

import type { Env } from "../env";
import { newId } from "../lib/crypto";
import { iso } from "../lib/time";
import { decryptSecret, SecretUnavailableError } from "../notifications/secret";
import { postToSlack, type ProviderOutcome } from "../notifications/approvals";
import { buildSecuritySlackPayload, type SecurityAlertData } from "../notifications/slack";
import { verifyContainment } from "./containment";

export const SECURITY_ALERT_TUNING = { retryBackoffMs: 60_000, leaseMs: 60_000 };

interface AlertRow {
  id: string;
  organization_id: string;
  transition_id: string;
  incident_id: string | null;
  event: SecurityAlertData["event"];
  status: string;
  attempts: number;
  max_attempts: number;
  org_name: string;
  org_status: string;
  alerts_enabled: number;
  channel_id: string | null;
  secret_ciphertext: string | null;
  subject_type: string;
  subject_id: string;
  from_state: string;
  to_state: string;
  score: number;
  cause: string;
  note: string | null;
  actor_label: string | null;
}

async function loadAlert(db: D1Database, id: string) {
  const row = await db
    .prepare(
      `SELECT n.id, n.organization_id, n.transition_id, n.incident_id, n.event, n.status, n.attempts, n.max_attempts,
              o.display_name AS org_name, o.status AS org_status, o.security_alerts_enabled AS alerts_enabled,
              c.id AS channel_id, c.secret_ciphertext,
              t.subject_type, t.subject_id, t.from_state, t.to_state, t.score, t.cause, t.note, t.actor_label
         FROM security_notifications n
         JOIN organizations o ON o.id = n.organization_id
         JOIN risk_transitions t ON t.id = n.transition_id AND t.organization_id = n.organization_id
         LEFT JOIN notification_channels c ON c.organization_id = n.organization_id AND c.kind = 'slack_webhook'
        WHERE n.id = ?`,
    )
    .bind(id)
    .first<AlertRow>();
  if (!row) return null;
  const [label, members, incident] = await db.batch([
    row.subject_type === "agent"
      ? db.prepare(`SELECT agent_key AS label FROM agents WHERE id = ? AND organization_id = ?`).bind(row.subject_id, row.organization_id)
      : row.subject_type === "session"
        ? db.prepare(`SELECT a.agent_key || ' · ' || s.id AS label FROM agent_sessions s JOIN agents a ON a.id = s.agent_id WHERE s.id = ? AND s.organization_id = ?`).bind(row.subject_id, row.organization_id)
        : db.prepare(`SELECT key_prefix || '…' AS label FROM api_keys WHERE id = ? AND organization_id = ?`).bind(row.subject_id, row.organization_id),
    db
      .prepare(`SELECT relation, COUNT(*) AS n FROM incident_members WHERE incident_id = ? AND organization_id = ? GROUP BY relation`)
      .bind(row.incident_id ?? "-", row.organization_id),
    db.prepare(`SELECT opened_reason, cleared_by_name FROM security_incidents WHERE id = ? AND organization_id = ?`).bind(row.incident_id ?? "-", row.organization_id),
  ]);
  const counts = Object.fromEntries((members!.results as Array<{ relation: string; n: number }>).map((m) => [m.relation, m.n]));
  const inc = incident!.results[0] as { opened_reason: string; cleared_by_name: string | null } | undefined;
  const data: SecurityAlertData = {
    event: row.event,
    organization: row.org_name,
    subjectType: row.subject_type,
    subjectLabel: (label!.results[0] as { label: string } | undefined)?.label ?? row.subject_id,
    fromState: row.from_state,
    toState: row.to_state,
    score: row.score,
    signals: (row.note ?? inc?.opened_reason ?? "").slice(0, 300),
    incidentId: row.incident_id,
    scope: {
      sessions: counts.scope_session ?? 0,
      childAgents: counts.child_agent ?? 0,
      revokedLeases: counts.revoked_lease ?? 0,
      cancelledApprovals: counts.cancelled_approval ?? 0,
      invalidatedGrants: counts.invalidated_grant ?? 0,
    },
    clearedBy: row.event === "cleared" ? (inc?.cleared_by_name ?? row.actor_label) : null,
  };
  return { row, data };
}

async function finish(db: D1Database, row: AlertRow, attempt: number, startedAt: string, outcome: ProviderOutcome, nowMs: number): Promise<void> {
  const finishedAt = iso(nowMs);
  const sent = outcome.kind === "sent";
  const retry = !sent && outcome.kind === "retryable" && attempt < row.max_attempts;
  const status = sent ? "SENT_TO_PROVIDER" : retry ? "QUEUED" : "FAILED";
  const error = sent ? null : outcome.error;
  const retryAfter = outcome.kind === "retryable" ? (outcome.retryAfterMs ?? 0) : 0;
  await db.batch([
    db
      .prepare(
        `UPDATE security_notifications
            SET status = ?, lease_until = NULL, next_attempt_at = ?, completed_at = ?, last_http_status = ?, last_error = ?
          WHERE id = ? AND status = 'SENDING' AND attempts = ?`,
      )
      .bind(status, iso(nowMs + Math.max(SECURITY_ALERT_TUNING.retryBackoffMs, retryAfter)), status === "QUEUED" ? null : finishedAt, outcome.httpStatus, error, row.id, attempt),
    db
      .prepare(
        `INSERT INTO security_notification_attempts (id, organization_id, notification_id, attempt, started_at, finished_at, outcome, http_status, error)
         SELECT ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE changes() = 1`,
      )
      .bind(newId("sna"), row.organization_id, row.id, attempt, startedAt, finishedAt, sent ? "SENT_TO_PROVIDER" : "FAILED", outcome.httpStatus, error),
  ]);
}

/** Delivers one queued alert if due and claimed by this invocation. Never throws. */
export async function deliverSecurityAlert(env: Env, id: string, now: () => number = Date.now): Promise<void> {
  const db = env.DB;
  try {
    const loaded = await loadAlert(db, id);
    if (!loaded || loaded.row.status !== "QUEUED") return;
    const { row, data } = loaded;
    const nowMs = now();
    const skip = row.org_status !== "active" ? "ORGANIZATION_NOT_ACTIVE" : row.alerts_enabled !== 1 ? "ALERTS_DISABLED" : !row.channel_id || !row.secret_ciphertext ? "CHANNEL_NOT_CONFIGURED" : null;
    if (skip) {
      await db.prepare(`UPDATE security_notifications SET status = 'SKIPPED', completed_at = ?, last_error = ? WHERE id = ? AND status = 'QUEUED'`).bind(iso(nowMs), skip, id).run();
      return;
    }
    const startedAt = iso(nowMs);
    const claim = await db
      .prepare(
        `UPDATE security_notifications SET status = 'SENDING', attempts = attempts + 1, lease_until = ?, last_attempt_at = ?
          WHERE id = ? AND status = 'QUEUED' AND next_attempt_at <= ? AND attempts < max_attempts`,
      )
      .bind(iso(nowMs + SECURITY_ALERT_TUNING.leaseMs), startedAt, id, startedAt)
      .run();
    if ((claim.meta.changes ?? 0) !== 1) return;
    let outcome: ProviderOutcome;
    try {
      const url = await decryptSecret(env.NOTIFICATION_ENCRYPTION_KEY, row.organization_id, row.channel_id!, row.secret_ciphertext!);
      outcome = await postToSlack(url, buildSecuritySlackPayload(data));
    } catch (err) {
      outcome = { kind: "permanent", httpStatus: null, error: err instanceof SecretUnavailableError ? "ENCRYPTION_KEY_UNAVAILABLE" : "DESTINATION_UNREADABLE" };
    }
    await finish(db, row, row.attempts + 1, startedAt, outcome, now());
    if (outcome.kind === "sent") console.log("security alert sent to provider", { notification_id: id, event: row.event, incident_id: row.incident_id });
    else console.error("security alert failed", { notification_id: id, event: row.event, error: outcome.error, status: outcome.httpStatus });
  } catch (err) {
    console.error("security alert error", { notification_id: id, error: err instanceof Error ? err.name : "unknown" });
  }
}

export async function deliverDueSecurityAlerts(env: Env, organizationId: string | null, now: () => number = Date.now, limit = 25): Promise<number> {
  const db = env.DB;
  const nowIso = iso(now());
  // Leases that expired mid-send: record ABANDONED and retry within the attempt bound.
  const stale = await db
    .prepare(`SELECT id, organization_id, attempts, last_attempt_at FROM security_notifications WHERE status = 'SENDING' AND lease_until < ? LIMIT ?`)
    .bind(nowIso, limit)
    .all<{ id: string; organization_id: string; attempts: number; last_attempt_at: string | null }>();
  for (const s of stale.results) {
    await db.batch([
      db
        .prepare(
          `UPDATE security_notifications
              SET status = CASE WHEN attempts >= max_attempts THEN 'FAILED' ELSE 'QUEUED' END,
                  completed_at = CASE WHEN attempts >= max_attempts THEN ?1 ELSE NULL END,
                  lease_until = NULL, next_attempt_at = ?1, last_error = 'LEASE_EXPIRED'
            WHERE id = ?2 AND status = 'SENDING' AND lease_until < ?1`,
        )
        .bind(nowIso, s.id),
      db
        .prepare(
          `INSERT INTO security_notification_attempts (id, organization_id, notification_id, attempt, started_at, finished_at, outcome, http_status, error)
           SELECT ?, ?, ?, ?, ?, ?, 'ABANDONED', NULL, 'LEASE_EXPIRED' WHERE changes() = 1`,
        )
        .bind(newId("sna"), s.organization_id, s.id, s.attempts, s.last_attempt_at ?? nowIso, nowIso),
    ]);
  }
  const due = organizationId
    ? await db.prepare(`SELECT id FROM security_notifications WHERE organization_id = ? AND status = 'QUEUED' AND next_attempt_at <= ? ORDER BY queued_at LIMIT ?`).bind(organizationId, nowIso, limit).all<{ id: string }>()
    : await db.prepare(`SELECT id FROM security_notifications WHERE status = 'QUEUED' AND next_attempt_at <= ? ORDER BY queued_at LIMIT ?`).bind(nowIso, limit).all<{ id: string }>();
  for (const d of due.results) await deliverSecurityAlert(env, d.id, now);
  return due.results.length;
}

/** Background step after a runtime write: verify containment, then send any queued alerts. Never throws. */
export async function afterRuntimeCommit(env: Env, organizationId: string, incidentId: string | null, now: () => number = Date.now): Promise<void> {
  try {
    if (incidentId) await verifyContainment(env.DB, organizationId, incidentId, now());
  } catch (err) {
    console.error("containment verification error", { incident_id: incidentId, error: err instanceof Error ? err.name : "unknown" });
  }
  try {
    await deliverDueSecurityAlerts(env, organizationId, now);
  } catch (err) {
    console.error("security alert delivery error", err instanceof Error ? err.name : "unknown");
  }
}

/** Cron: finish containment for any quarantine older than 30 s, then deliver due alerts. */
export async function sweepRuntimeSecurity(env: Env, now: () => number = Date.now): Promise<{ verified: number; alerts: number }> {
  const db = env.DB;
  const open = await db
    .prepare(`SELECT id, organization_id FROM security_incidents WHERE status = 'open' AND opened_at < ? ORDER BY opened_at LIMIT 50`)
    .bind(iso(now() - 30_000))
    .all<{ id: string; organization_id: string }>();
  let verified = 0;
  for (const inc of open.results) {
    try {
      if ((await verifyContainment(db, inc.organization_id, inc.id, now())) === "contained") verified++;
    } catch (err) {
      console.error("containment verification error", { incident_id: inc.id, error: err instanceof Error ? err.name : "unknown" });
    }
  }
  const alerts = await deliverDueSecurityAlerts(env, null, now, 50);
  return { verified, alerts };
}
