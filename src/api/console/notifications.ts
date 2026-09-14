// Approval notification settings (/api/console/notifications*).
//
// The Slack webhook URL is write-only: it is validated, encrypted and stored, and no
// endpoint ever returns it (or any part of it). Every configuration change and test
// send is recorded as a control event without the destination.

import { ApiError, json } from "../../lib/http";
import { iso } from "../../lib/time";
import { newId } from "../../lib/crypto";
import { controlEventStatement } from "../../gateway/audit";
import { decryptSecret, encryptionAvailable, encryptSecret, KEY_VERSION, SecretUnavailableError } from "../../notifications/secret";
import { postToSlack, SLACK_WEBHOOK_PATTERN } from "../../notifications/approvals";
import { buildTestSlackPayload } from "../../notifications/slack";
import { Validator, assertOrgWritable, type ConsoleContext } from "./context";

interface ChannelRow {
  id: string;
  secret_ciphertext: string;
  configured_by_name: string | null;
  created_at: string;
  updated_at: string;
}

function loadChannel(ctx: ConsoleContext): Promise<ChannelRow | null> {
  return ctx.db
    .prepare(`SELECT id, secret_ciphertext, configured_by_name, created_at, updated_at FROM notification_channels WHERE organization_id = ? AND kind = 'slack_webhook'`)
    .bind(ctx.orgId)
    .first<ChannelRow>();
}

function presentSlack(row: ChannelRow | null) {
  return row
    ? { configured: true, status: "enabled", configured_at: row.created_at, updated_at: row.updated_at, configured_by_name: row.configured_by_name }
    : { configured: false, status: "not_configured" };
}

export async function getNotificationSettings(ctx: ConsoleContext): Promise<Response> {
  const [channel, recent] = await Promise.all([
    loadChannel(ctx),
    ctx.db
      .prepare(
        `SELECT id, approval_id, event, channel, status, attempts, max_attempts, queued_at, last_attempt_at, completed_at, last_http_status, last_error
           FROM approval_notifications WHERE organization_id = ? ORDER BY queued_at DESC LIMIT 25`,
      )
      .bind(ctx.orgId)
      .all(),
  ]);
  return json({
    available: encryptionAvailable(ctx.env.NOTIFICATION_ENCRYPTION_KEY),
    slack: presentSlack(channel),
    events: ["review_required", "approved", "denied", "expired", "consumed"],
    recent: recent.results,
  });
}

export async function configureSlack(ctx: ConsoleContext): Promise<Response> {
  assertOrgWritable(ctx);
  const v = new Validator(ctx.body);
  const url = v.string("webhook_url", { min: 1, max: 200, pattern: SLACK_WEBHOOK_PATTERN, message: "must be a Slack incoming webhook URL (https://hooks.slack.com/services/…)" });
  v.assert();
  if (!encryptionAvailable(ctx.env.NOTIFICATION_ENCRYPTION_KEY)) {
    throw new ApiError(503, "NOTIFICATIONS_UNAVAILABLE", "Approval notifications are not available on this Mother AI deployment yet.");
  }

  const existing = await loadChannel(ctx);
  const id = existing?.id ?? newId("nch");
  const now = iso(ctx.nowMs);
  const ciphertext = await encryptSecret(ctx.env.NOTIFICATION_ENCRYPTION_KEY, ctx.orgId, id, url!);
  const write = existing
    ? ctx.db
        .prepare(`UPDATE notification_channels SET secret_ciphertext = ?, key_version = ?, configured_by = ?, configured_by_name = ?, updated_at = ? WHERE id = ? AND organization_id = ?`)
        .bind(ciphertext, KEY_VERSION, ctx.actor.id, ctx.actor.label, now, id, ctx.orgId)
    : ctx.db
        .prepare(
          `INSERT INTO notification_channels (id, organization_id, kind, secret_ciphertext, key_version, configured_by, configured_by_name, created_at, updated_at)
           VALUES (?, ?, 'slack_webhook', ?, ?, ?, ?, ?, ?)`,
        )
        .bind(id, ctx.orgId, ciphertext, KEY_VERSION, ctx.actor.id, ctx.actor.label, now, now);
  await ctx.db.batch([
    write,
    controlEventStatement(ctx.db, ctx.orgId, ctx.actor, existing ? "notifications.slack_replaced" : "notifications.slack_configured", { type: "notification_channel", id }, { channel: "slack" }, now),
  ]);
  return json({ slack: presentSlack(await loadChannel(ctx)) }, existing ? 200 : 201);
}

export async function removeSlack(ctx: ConsoleContext): Promise<Response> {
  // Allowed even for a suspended organization: removing a destination only reduces exposure.
  const existing = await loadChannel(ctx);
  if (!existing) throw new ApiError(404, "NOT_FOUND", "Slack approval notifications are not configured.");
  const now = iso(ctx.nowMs);
  const results = await ctx.db.batch([
    ctx.db.prepare(`DELETE FROM notification_channels WHERE id = ? AND organization_id = ?`).bind(existing.id, ctx.orgId),
    controlEventStatement(ctx.db, ctx.orgId, ctx.actor, "notifications.slack_removed", { type: "notification_channel", id: existing.id }, { channel: "slack" }, now, { onlyIfChanged: true }),
  ]);
  if ((results[0]!.meta.changes ?? 0) !== 1) throw new ApiError(404, "NOT_FOUND", "Slack approval notifications are not configured.");
  return json({ slack: presentSlack(null) });
}

export async function testSlack(ctx: ConsoleContext): Promise<Response> {
  assertOrgWritable(ctx);
  const channel = await loadChannel(ctx);
  if (!channel) throw new ApiError(404, "NOT_FOUND", "Slack approval notifications are not configured.");
  let result: { status: "SENT_TO_PROVIDER" | "FAILED"; http_status: number | null; error: string | null };
  try {
    const url = await decryptSecret(ctx.env.NOTIFICATION_ENCRYPTION_KEY, ctx.orgId, channel.id, channel.secret_ciphertext);
    const outcome = await postToSlack(url, buildTestSlackPayload(ctx.session.organization.display_name, ctx.actor.label));
    result = outcome.kind === "sent" ? { status: "SENT_TO_PROVIDER", http_status: outcome.httpStatus, error: null } : { status: "FAILED", http_status: outcome.httpStatus, error: outcome.error };
  } catch (err) {
    result = { status: "FAILED", http_status: null, error: err instanceof SecretUnavailableError ? "ENCRYPTION_KEY_UNAVAILABLE" : "DESTINATION_UNREADABLE" };
  }
  const now = iso(ctx.nowMs);
  await ctx.db.batch([controlEventStatement(ctx.db, ctx.orgId, ctx.actor, "notifications.slack_test_sent", { type: "notification_channel", id: channel.id }, { channel: "slack", ...result }, now)]);
  return json({ test: result });
}
