#!/usr/bin/env node
// Set (or replace) an organization's Slack approval-notification destination in
// production D1, then send one test message. Operator equivalent of
// Console → Settings → Notifications, without a browser session.
//
//   node scripts/ops/set-approval-slack.mjs --org <slug> --webhook "https://hooks.slack.com/services/…"
//
// Reuses the Worker's own notification code (validation pattern, AES-GCM encryption bound
// to organization + channel id, Slack sender, test payload), bundled in memory with esbuild.
// Encrypts with the backed-up NOTIFICATION_ENCRYPTION_KEY (the same value as the Worker secret).
// The webhook is never printed, logged or written anywhere except as ciphertext. Output is
// only: configured, test, http_status.
//
// The webhook travels as a command-line argument, so it can appear in shell history.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { build } from "esbuild";
import { d1, newId, now, parseArgs, query, ROOT, sql } from "./lib.mjs";

const KEY_FILE = process.env.MOTHER_NOTIFICATION_KEY_FILE ?? "D:/Workers/secrets/mother-ai-notification-encryption-key.txt";
const OPS_LABEL = "Mother AI operator";

function fail(message, code = 1) {
  console.log("configured: false");
  console.error(message);
  process.exit(code);
}

async function loadWorkerModules() {
  const out = await build({
    stdin: {
      contents: `
        export { encryptSecret, decryptSecret, encryptionAvailable, KEY_VERSION } from "./src/notifications/secret";
        export { postToSlack, SLACK_WEBHOOK_PATTERN } from "./src/notifications/approvals";
        export { buildTestSlackPayload } from "./src/notifications/slack";
      `,
      resolveDir: ROOT,
      loader: "ts",
    },
    bundle: true,
    format: "esm",
    platform: "node",
    target: "node22",
    write: false,
    logLevel: "silent",
  });
  return import(`data:text/javascript;base64,${Buffer.from(out.outputFiles[0].text).toString("base64")}`);
}

const args = parseArgs(process.argv.slice(2));
if (typeof args.org !== "string" || typeof args.webhook !== "string") {
  fail('Usage: node scripts/ops/set-approval-slack.mjs --org <slug> --webhook "<Slack incoming webhook URL>"', 2);
}

const notify = await loadWorkerModules();

// Same rules as POST /api/console/notifications/slack (Validator.string + SLACK_WEBHOOK_PATTERN).
const webhook = args.webhook.trim();
if (webhook.length < 1 || webhook.length > 200 || /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(webhook) || !notify.SLACK_WEBHOOK_PATTERN.test(webhook)) {
  fail("webhook_url must be a Slack incoming webhook URL (https://hooks.slack.com/services/…)", 2);
}

let key;
try {
  key = readFileSync(KEY_FILE, "utf8").trim();
} catch {
  fail("NOTIFICATION_ENCRYPTION_KEY backup not found");
}
if (!notify.encryptionAvailable(key)) fail("NOTIFICATION_ENCRYPTION_KEY backup is not a 32-byte base64url key");

try {
  const [org] = query(`SELECT id, display_name, status FROM organizations WHERE slug = ${sql(args.org)}`, { remote: true });
  if (!org) fail(`No organization with slug ${args.org}`);
  // Same as the console's assertOrgWritable.
  if (org.status !== "active") fail("This organization is suspended; changes are disabled.");

  const [existing] = query(`SELECT id FROM notification_channels WHERE organization_id = ${sql(org.id)} AND kind = 'slack_webhook'`, { remote: true });
  const channelId = existing?.id ?? newId("nch");
  const ts = now();
  const ciphertext = await notify.encryptSecret(key, org.id, channelId, webhook);
  const write = existing
    ? `UPDATE notification_channels SET secret_ciphertext = ${sql(ciphertext)}, key_version = ${notify.KEY_VERSION}, configured_by = NULL, configured_by_name = ${sql(OPS_LABEL)}, updated_at = ${sql(ts)} WHERE id = ${sql(channelId)} AND organization_id = ${sql(org.id)}`
    : `INSERT INTO notification_channels (id, organization_id, kind, secret_ciphertext, key_version, configured_by, configured_by_name, created_at, updated_at) VALUES (${sql(channelId)}, ${sql(org.id)}, 'slack_webhook', ${sql(ciphertext)}, ${notify.KEY_VERSION}, NULL, ${sql(OPS_LABEL)}, ${sql(ts)}, ${sql(ts)})`;
  const event = (action, detail, at) =>
    `INSERT INTO control_events (id, organization_id, actor_type, actor_id, actor_label, action, target_type, target_id, detail, created_at) VALUES (${sql(newId("evt"))}, ${sql(org.id)}, 'ops', NULL, ${sql(OPS_LABEL)}, ${sql(action)}, 'notification_channel', ${sql(channelId)}, ${sql(JSON.stringify(detail))}, ${sql(at)})`;
  d1([write, event(existing ? "notifications.slack_replaced" : "notifications.slack_configured", { channel: "slack" }, ts)], { remote: true });

  // Read back what the Worker will read, and decrypt it the way the Worker will.
  const [stored] = query(`SELECT id, secret_ciphertext FROM notification_channels WHERE organization_id = ${sql(org.id)} AND kind = 'slack_webhook'`, { remote: true });
  if (!stored || stored.id !== channelId) fail("Slack destination was not stored");
  console.log("configured: true");

  let result;
  try {
    const url = await notify.decryptSecret(key, org.id, stored.id, stored.secret_ciphertext);
    const outcome = await notify.postToSlack(url, notify.buildTestSlackPayload(org.display_name, OPS_LABEL));
    result = outcome.kind === "sent" ? { status: "SENT_TO_PROVIDER", http_status: outcome.httpStatus, error: null } : { status: "FAILED", http_status: outcome.httpStatus, error: outcome.error };
  } catch {
    result = { status: "FAILED", http_status: null, error: "DESTINATION_UNREADABLE" };
  }
  d1([event("notifications.slack_test_sent", { channel: "slack", ...result }, now())], { remote: true });

  console.log(`test: ${result.status}`);
  console.log(`http_status: ${result.http_status ?? "none"}`);
  process.exit(result.status === "SENT_TO_PROVIDER" ? 0 : 1);
} catch (err) {
  // Wrangler/network errors: report the kind only. Nothing here contains the webhook, but stay terse.
  fail(`operation failed: ${err instanceof Error ? err.name : "unknown error"}`);
}
