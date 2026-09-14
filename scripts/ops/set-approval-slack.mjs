#!/usr/bin/env node
// Set (or replace) an organization's Slack approval-notification destination in
// production D1, then send one test message. Operator equivalent of
// Console → Settings → Notifications, without a browser session.
//
//   node scripts/ops/set-approval-slack.mjs --org <slug> --webhook-file <path>
//   node scripts/ops/set-approval-slack.mjs --org <slug>          # hidden interactive prompt
//
// The webhook is a bearer secret, so it is never accepted on the command line (shell history,
// process listings). Put it in a file outside the repository (create the file with an editor,
// not with an echo command), or type/paste it at the hidden prompt.
//
// Reuses the Worker's own notification code (validation pattern, AES-GCM encryption bound
// to organization + channel id, Slack sender, test payload), bundled in memory with esbuild,
// and encrypts with the backed-up NOTIFICATION_ENCRYPTION_KEY (the same value as the Worker
// secret). The webhook is never printed, logged, or stored except as ciphertext.
//
// Fail-closed: "configured: true" is printed only after the stored row is read back with
// exactly the ciphertext this run wrote AND its audit event exists. The audit event is inserted
// only if the destination write changed a row.
//
// Output: configured, test, http_status.

import { readFileSync } from "node:fs";
import { relative, resolve, isAbsolute } from "node:path";
import { build } from "esbuild";
import { d1, newId, now, parseArgs, query, ROOT, sql } from "./lib.mjs";

const KEY_FILE = process.env.MOTHER_NOTIFICATION_KEY_FILE ?? "D:/Workers/secrets/mother-ai-notification-encryption-key.txt";
const OPS_LABEL = "Mother AI operator";

let secretForRedaction = null;
const redact = (text) => {
  let out = String(text);
  if (secretForRedaction) {
    out = out.split(secretForRedaction).join("[REDACTED]");
    const tail = secretForRedaction.split("/").pop();
    if (tail && tail.length >= 8) out = out.split(tail).join("[REDACTED]");
  }
  return out.replace(/hooks\.slack\.com\/services\/T[A-Z0-9]+\/\S+/g, "hooks.slack.com/services/[REDACTED]");
};

function fail(message, code = 1) {
  console.log("configured: false");
  console.error(redact(message));
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

function readWebhookFile(path) {
  const full = resolve(path);
  const rel = relative(resolve(ROOT), full);
  if (!rel.startsWith("..") && !isAbsolute(rel)) fail("--webhook-file must be outside the repository", 2);
  let text;
  try {
    text = readFileSync(full, "utf8");
  } catch {
    fail("--webhook-file could not be read", 2);
  }
  const lines = text.replace(/^\uFEFF/, "").split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  if (lines.length !== 1) fail("--webhook-file must contain exactly one line: the webhook URL", 2);
  return lines[0];
}

function promptHidden(label) {
  const { stdin, stderr } = process;
  if (!stdin.isTTY) {
    // Non-interactive: accept a piped value (e.g. from a secrets manager), never an argument.
    return new Promise((resolveValue) => {
      let data = "";
      stdin.setEncoding("utf8");
      stdin.on("data", (chunk) => (data += chunk));
      stdin.on("end", () => resolveValue(data.trim()));
    });
  }
  return new Promise((resolveValue) => {
    stderr.write(label);
    stdin.setRawMode(true);
    stdin.setEncoding("utf8");
    stdin.resume();
    let value = "";
    const onData = (chunk) => {
      for (const ch of chunk) {
        if (ch === "\r" || ch === "\n") {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.off("data", onData);
          stderr.write("\n");
          resolveValue(value.trim());
          return;
        }
        if (ch === "\u0003") {
          stdin.setRawMode(false);
          stderr.write("\n");
          process.exit(130);
        }
        if (ch === "\u007f" || ch === "\b") value = value.slice(0, -1);
        else if (ch >= " ") value += ch;
      }
    };
    stdin.on("data", onData);
  });
}

const args = parseArgs(process.argv.slice(2));
if ("webhook" in args) fail("Passing the webhook on the command line is not supported. Use --webhook-file <path> or the hidden prompt.", 2);
if (typeof args.org !== "string") fail("Usage: node scripts/ops/set-approval-slack.mjs --org <slug> [--webhook-file <path>]", 2);

const raw = typeof args["webhook-file"] === "string" ? readWebhookFile(args["webhook-file"]) : await promptHidden("Slack incoming webhook URL (input hidden): ");
const webhook = raw.trim();
secretForRedaction = webhook || null;

const notify = await loadWorkerModules();

// Same rules as POST /api/console/notifications/slack (Validator.string + SLACK_WEBHOOK_PATTERN).
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
  // Round-trip before writing: the stored value must decrypt to exactly this webhook for this org + channel.
  if ((await notify.decryptSecret(key, org.id, channelId, ciphertext)) !== webhook) fail("encryption round-trip failed; nothing was written");

  const write = existing
    ? `UPDATE notification_channels SET secret_ciphertext = ${sql(ciphertext)}, key_version = ${notify.KEY_VERSION}, configured_by = NULL, configured_by_name = ${sql(OPS_LABEL)}, updated_at = ${sql(ts)} WHERE id = ${sql(channelId)} AND organization_id = ${sql(org.id)}`
    : `INSERT INTO notification_channels (id, organization_id, kind, secret_ciphertext, key_version, configured_by, configured_by_name, created_at, updated_at) VALUES (${sql(channelId)}, ${sql(org.id)}, 'slack_webhook', ${sql(ciphertext)}, ${notify.KEY_VERSION}, NULL, ${sql(OPS_LABEL)}, ${sql(ts)}, ${sql(ts)})`;
  const eventValues = (eventId, action, detail, at) =>
    `${sql(eventId)}, ${sql(org.id)}, 'ops', NULL, ${sql(OPS_LABEL)}, ${sql(action)}, 'notification_channel', ${sql(channelId)}, ${sql(JSON.stringify(detail))}, ${sql(at)}`;
  const EVENT_COLUMNS = "(id, organization_id, actor_type, actor_id, actor_label, action, target_type, target_id, detail, created_at)";

  const configEventId = newId("evt");
  const configAction = existing ? "notifications.slack_replaced" : "notifications.slack_configured";
  // Same onlyIfChanged pattern as the Worker: the audit row exists only if the destination write changed a row.
  d1([write, `INSERT INTO control_events ${EVENT_COLUMNS} SELECT ${eventValues(configEventId, configAction, { channel: "slack" }, ts)} WHERE changes() = 1`], { remote: true });

  // Read back exactly what the Worker will read.
  const [stored] = query(`SELECT id, secret_ciphertext FROM notification_channels WHERE organization_id = ${sql(org.id)} AND kind = 'slack_webhook'`, { remote: true });
  const [audited] = query(`SELECT id FROM control_events WHERE id = ${sql(configEventId)} AND organization_id = ${sql(org.id)} AND action = ${sql(configAction)}`, { remote: true });
  if (!stored || stored.id !== channelId || stored.secret_ciphertext !== ciphertext) fail("Slack destination was not stored (no change was made by this run)");
  if (!audited) fail("Slack destination stored but its audit event is missing; investigate before relying on it");
  console.log("configured: true");

  let result;
  try {
    const url = await notify.decryptSecret(key, org.id, stored.id, stored.secret_ciphertext);
    const outcome = await notify.postToSlack(url, notify.buildTestSlackPayload(org.display_name, OPS_LABEL));
    result = outcome.kind === "sent" ? { status: "SENT_TO_PROVIDER", http_status: outcome.httpStatus, error: null } : { status: "FAILED", http_status: outcome.httpStatus, error: outcome.error };
  } catch {
    result = { status: "FAILED", http_status: null, error: "DESTINATION_UNREADABLE" };
  }
  d1([`INSERT INTO control_events ${EVENT_COLUMNS} VALUES (${eventValues(newId("evt"), "notifications.slack_test_sent", { channel: "slack", ...result }, now())})`], { remote: true });

  console.log(`test: ${result.status}`);
  console.log(`http_status: ${result.http_status ?? "none"}`);
  process.exit(result.status === "SENT_TO_PROVIDER" ? 0 : 1);
} catch (err) {
  // Wrangler / network errors. Diagnostics are redacted: none of these contain the webhook, but never trust that.
  const detail = err && typeof err === "object" ? [err.name, err.message, err.stderr].filter(Boolean).join(": ").slice(0, 600) : "unknown error";
  fail(`operation failed: ${detail}`);
}
