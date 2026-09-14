#!/usr/bin/env node
// Production verification for approval notifications, against the REAL deployment.
//
//   node scripts/qa/notifications-prod.mjs
//
// Uses the internal QA organizations (see verify-prod.mjs). It connects org A to a
// well-formed Slack webhook that does not exist, so every send reaches Slack and is
// refused there: the full queue → provider → recorded-outcome path runs in production
// without posting a message to any workspace. It refuses to run if org A already has
// a real destination configured, and removes its QA destination at the end.
//
// Proves on production: ALLOW/BLOCK create no notification, one REVIEW creates exactly
// one, replays/polls/console reads/approve/consume create no duplicates or invented
// resolution events, the decision and approval are unchanged by a failed send,
// tenant B sees nothing of A, and no webhook value appears in any API response or
// stored row.

import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { SoftwareAuthenticator } from "./authenticator.mjs";
import { ROOT, SITE, query } from "../ops/lib.mjs";

const ORIGIN = SITE.origin;
const API = SITE.apiOrigin;
const SECRETS = process.env.MOTHER_QA_SECRETS ?? "D:/Workers/secrets/mother-ai-qa.json";
const OUT = join(ROOT, "qa-artifacts", `notifications-${new Date().toISOString().replace(/[:.]/g, "-")}`);
mkdirSync(OUT, { recursive: true });
const RP_ID = new URL(ORIGIN).hostname;

const results = [];
let failures = 0;
const check = (name, ok, detail = "") => {
  results.push({ name, ok: !!ok, detail });
  if (!ok) failures++;
  console.log(`${ok ? "✓" : "✗"} ${name}${detail ? ` — ${detail}` : ""}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function http(path, { method, json, key, cookie } = {}) {
  const headers = {};
  if (json !== undefined) headers["Content-Type"] = "application/json";
  if (key) headers.Authorization = `Bearer ${key}`;
  if (cookie) headers.Cookie = cookie;
  const m = method ?? (json !== undefined ? "POST" : "GET");
  if (m !== "GET") headers.Origin = ORIGIN;
  if (/^\/api\//.test(path) && m !== "GET") headers["Sec-Fetch-Site"] = "same-site";
  const started = performance.now();
  const res = await fetch(`${API}${path}`, { method: m, headers, body: json !== undefined ? JSON.stringify(json) : undefined, redirect: "manual" });
  const text = await res.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = text;
  }
  return { res, body, text, ms: Math.round(performance.now() - started), setCookies: res.headers.getSetCookie() };
}

const cookieNamed = (setCookies, name) => setCookies.find((s) => s.startsWith(`${name}=`))?.split(";")[0] ?? null;

const secrets = JSON.parse(readFileSync(SECRETS, "utf8"));
async function signIn(slug) {
  const mine = (secrets.orgs[slug]?.credentials ?? []).filter((c) => c.rpId === RP_ID);
  const auth = await SoftwareAuthenticator.import(mine);
  const opt = await http("/api/auth/login/options", { json: {} });
  const assertion = await auth.authenticate(opt.body, ORIGIN);
  const verify = await http("/api/auth/login/verify", { json: { response: assertion }, cookie: cookieNamed(opt.setCookies, "__Host-mai_chal") });
  secrets.orgs[slug].credentials = [...secrets.orgs[slug].credentials.filter((c) => c.rpId !== RP_ID), ...(await auth.export())];
  writeFileSync(SECRETS, JSON.stringify(secrets, null, 2));
  const cookie = cookieNamed(verify.setCookies, "__Host-mai_session");
  check(`${slug}: passkey sign-in`, verify.res.status === 200 && cookie, `HTTP ${verify.res.status}`);
  if (!cookie) process.exit(1);
  return cookie;
}

const sqlString = (v) => `'${String(v).replace(/'/g, "''")}'`;
const notificationRows = (approvalId) =>
  query(`SELECT event, status, attempts, last_http_status, last_error FROM approval_notifications WHERE approval_id = ${sqlString(approvalId)} ORDER BY queued_at`, { remote: true });
const orgNotificationCount = (orgId) => query(`SELECT COUNT(*) AS n FROM approval_notifications WHERE organization_id = ${sqlString(orgId)}`, { remote: true })[0].n;

async function waitForRows(approvalId, predicate, timeoutMs = 25_000) {
  const until = Date.now() + timeoutMs;
  let rows = [];
  while (Date.now() < until) {
    rows = notificationRows(approvalId);
    if (predicate(rows)) return rows;
    await sleep(2500);
  }
  return rows;
}

// ---------------------------------------------------------------------------
const run = Date.now().toString(36);
const health = await http("/health");
check("health ok", health.body.status === "ok", `commit ${health.body.commit}`);

const cookieA = await signIn("mother-ai-qa");
const cookieB = await signIn("mother-ai-qa-tenant-b");
const sessionA = await http("/api/auth/session", { cookie: cookieA });
const sessionB = await http("/api/auth/session", { cookie: cookieB });
const orgA = sessionA.body.organization;
const orgB = sessionB.body.organization;
check("QA orgs are internal", orgA?.slug === "mother-ai-qa" && orgB?.slug === "mother-ai-qa-tenant-b" && orgA.kind === "internal" && orgB.kind === "internal", `${orgA?.kind}/${orgB?.kind}`);

const initialA = await http("/api/console/notifications", { cookie: cookieA });
const initialB = await http("/api/console/notifications", { cookie: cookieB });
if (initialA.body.slack?.configured) {
  console.error("✗ org A already has a Slack destination configured; refusing to replace it with a QA destination.");
  process.exit(1);
}
check("notifications available on this deployment, disabled by default", initialA.res.status === 200 && initialA.body.available === true && initialA.body.slack.configured === false && initialB.body.slack?.configured === false);

// A well-formed webhook that does not exist in any Slack workspace. Built at runtime; never printed.
const token = randomBytes(18).toString("base64url").replace(/[-_]/g, "x").slice(0, 24);
const WEBHOOK = ["https:", "", ["hooks", "slack", "com"].join("."), "services", "T0MOTHERQA", "B0MOTHERQA", token].join("/");
const leaks = (text) => [WEBHOOK, token].some((s) => String(text).includes(s));

for (const bad of [WEBHOOK.replace("https:", "http:"), WEBHOOK.replace("slack.com", "slack.com.evil.example"), `https://evil.example/?u=${WEBHOOK}`]) {
  const r = await http("/api/console/notifications/slack", { json: { webhook_url: bad }, cookie: cookieA });
  check("malformed destination rejected without echo", r.res.status === 400 && !leaks(r.text) && !r.text.includes("evil.example"), `HTTP ${r.res.status}`);
}
const configured = await http("/api/console/notifications/slack", { json: { webhook_url: WEBHOOK }, cookie: cookieA, method: "POST" });
check("owner configures Slack; response never contains the webhook", configured.res.status === 201 && configured.body.slack?.configured === true && !leaks(configured.text));
const crossOrigin = await fetch(`${API}/api/console/notifications/slack/remove`, { method: "POST", headers: { Cookie: cookieA, Origin: "https://evil.example", "Content-Type": "application/json" }, body: "{}" });
check("cross-origin configuration change rejected (CSRF)", crossOrigin.status === 403);

const test = await http("/api/console/notifications/slack/test", { json: {}, cookie: cookieA });
check("test send reports Slack's refusal truthfully", test.res.status === 200 && test.body.test?.status === "FAILED" && typeof test.body.test.http_status === "number" && !leaks(test.text), JSON.stringify(test.body.test));

// Fresh QA key for org A.
const keyRes = await http("/api/console/keys", { json: { name: `QA notifications key ${run}`, environment: "live" }, cookie: cookieA });
const key = keyRes.body.secret;
check("QA gateway key created", /^mai_live_/.test(key ?? ""));

const before = orgNotificationCount(orgA.id);
const allow = await http("/v1/evaluate", { key, json: { request_id: `qa-notify-allow-${run}`, agent_id: "billing-agent-prod", capability: "payments", operation: "refund", resource: "payment:pi_qa_notify_small", context: { amount: 420 } } });
const block = await http("/v1/evaluate", { key, json: { request_id: `qa-notify-block-${run}`, agent_id: "research-agent-prod", capability: "records", operation: "modify", resource: "customer:qa-notify" } });
await sleep(6000);
const afterAllowBlock = orgNotificationCount(orgA.id);
check("ALLOW and BLOCK create zero notifications", allow.body.decision === "allow" && block.body.decision === "block" && afterAllowBlock === before, `count ${before} → ${afterAllowBlock}`);

const reviewBody = { request_id: `qa-notify-review-${run}`, agent_id: "billing-agent-prod", capability: "payments", operation: "refund", resource: "payment:pi_qa_notify_large", destination: "internal", data_class: "financial", context: { amount: 4200, currency: "USD", ticket: `QA-NOTIFY-${run}`, api_key: "sk_live_should_never_reach_slack_123" } };
const review = await http("/v1/evaluate", { key, json: reviewBody });
check("REVIEW decision and pending approval returned unchanged", review.res.status === 200 && review.body.decision === "review" && review.body.approval?.status === "pending" && review.body.replayed === false && !leaks(review.text), `${review.ms} ms; allow ${allow.ms} ms`);
const approvalId = review.body.approval_id;

const initialRows = await waitForRows(approvalId, (rows) => rows.length === 1 && ["FAILED", "SENT_TO_PROVIDER"].includes(rows[0].status));
check(
  "one REVIEW → exactly one initial notification, delivered to Slack and recorded truthfully",
  initialRows.length === 1 && initialRows[0].event === "review_required" && initialRows[0].status === "FAILED" && initialRows[0].attempts >= 1 && initialRows[0].attempts <= 3 && /^HTTP_4/.test(initialRows[0].last_error ?? ""),
  JSON.stringify(initialRows),
);
const attemptsLog = query(`SELECT t.attempt, t.outcome, t.http_status, t.error FROM approval_notification_attempts t JOIN approval_notifications n ON n.id = t.notification_id WHERE n.approval_id = ${sqlString(approvalId)} ORDER BY t.attempt`, { remote: true });
check("attempt log matches (4xx is not retried)", attemptsLog.length === initialRows[0]?.attempts && attemptsLog.every((a) => a.outcome === "FAILED"), JSON.stringify(attemptsLog));

// Duplicates: replay, polls, console reads.
const replay = await http("/v1/evaluate", { key, json: reviewBody });
const poll1 = await http(`/v1/approvals/${approvalId}`, { key });
const poll2 = await http(`/v1/approvals/${approvalId}`, { key });
const consoleList = await http("/api/console/approvals", { cookie: cookieA });
await sleep(6000);
const afterDupes = notificationRows(approvalId);
check("replay, polling and console reads add no notification", replay.body.replayed === true && replay.body.approval_id === approvalId && poll1.body.status === "pending" && poll2.body.status === "pending" && afterDupes.length === 1 && afterDupes[0].attempts === initialRows[0].attempts, `rows ${afterDupes.length}`);
const listed = consoleList.body.approvals?.find((a) => a.approval_id === approvalId);
check("approvals API shows the alert status without destination", listed?.notification?.status === "FAILED" && listed.notification.channel === "slack" && !leaks(consoleList.text), JSON.stringify(listed?.notification));
check("failed notification did not change the approval", poll1.body.expires_at === review.body.approval.expires_at && poll1.body.executable === false && poll1.body.consumed_at === null);

// Approve → consume semantics unchanged; no resolution events are invented for an unsent alert.
const approve = await http(`/api/console/approvals/${approvalId}/approve`, { json: { note: "QA: notifications verification" }, cookie: cookieA });
const consume = await http(`/v1/approvals/${approvalId}/consume`, { method: "POST", key });
const reconsume = await http(`/v1/approvals/${approvalId}/consume`, { method: "POST", key });
await sleep(6000);
const afterResolution = notificationRows(approvalId);
check("approve → consume once → 409 on replay (unchanged)", approve.res.status === 200 && consume.res.status === 200 && consume.body.consumed_at && reconsume.res.status === 409 && reconsume.body.error?.code === "APPROVAL_ALREADY_CONSUMED");
check("no APPROVED/CONSUMED alert invented when the initial alert was never accepted", afterResolution.length === 1, JSON.stringify(afterResolution.map((r) => r.event)));

// Tenant isolation.
const settingsB = await http("/api/console/notifications", { cookie: cookieB });
const removeB = await http("/api/console/notifications/slack/remove", { json: {}, cookie: cookieB });
const eventsB = await http("/api/console/events?limit=100", { cookie: cookieB });
check("tenant B sees none of A's notifications or configuration and cannot remove it", settingsB.body.slack?.configured === false && !settingsB.text.includes(approvalId) && removeB.res.status === 404 && !eventsB.text.includes("notifications.slack") && !leaks(settingsB.text + eventsB.text));
const settingsA = await http("/api/console/notifications", { cookie: cookieA });
check("A still configured after B's attempt", settingsA.body.slack?.configured === true && settingsA.text.includes(approvalId) && !leaks(settingsA.text));

// Secret leakage in stored data.
const leakRows = query(
  `SELECT
     (SELECT COUNT(*) FROM control_events WHERE detail LIKE ${sqlString(`%${token}%`)} OR detail LIKE '%hooks.slack%') AS events,
     (SELECT COUNT(*) FROM approval_notifications WHERE last_error LIKE '%hooks%' OR last_error LIKE ${sqlString(`%${token}%`)}) AS notifications,
     (SELECT COUNT(*) FROM approval_notification_attempts WHERE error LIKE '%hooks%') AS attempts,
     (SELECT COUNT(*) FROM notification_channels WHERE secret_ciphertext LIKE '%hooks%' OR secret_ciphertext LIKE ${sqlString(`%${token}%`)}) AS plaintext,
     (SELECT COUNT(*) FROM notification_channels WHERE organization_id = ${sqlString(orgA.id)} AND secret_ciphertext LIKE 'v1.%') AS encrypted,
     (SELECT COUNT(*) FROM decisions WHERE context LIKE '%hooks.slack%') AS decisions`,
  { remote: true },
)[0];
check("no webhook value in control events, notifications, attempts, decisions; destination stored only as ciphertext", leakRows.events === 0 && leakRows.notifications === 0 && leakRows.attempts === 0 && leakRows.plaintext === 0 && leakRows.decisions === 0 && leakRows.encrypted === 1, JSON.stringify(leakRows));

// Remove the QA destination; a REVIEW afterwards creates nothing.
const removeA = await http("/api/console/notifications/slack/remove", { json: {}, cookie: cookieA });
const afterRemove = await http("/api/console/notifications", { cookie: cookieA });
check("QA destination removed", removeA.res.status === 200 && afterRemove.body.slack?.configured === false);
const eventsA = await http("/api/console/events?limit=100", { cookie: cookieA });
const actions = (eventsA.body.events ?? []).map((e) => e.action).filter((a) => a.startsWith("notifications."));
check("configuration changes are audited", ["notifications.slack_configured", "notifications.slack_test_sent", "notifications.slack_removed"].every((a) => actions.includes(a)) && !leaks(eventsA.text), actions.slice(0, 6).join(","));
const reviewAfter = await http("/v1/evaluate", { key, json: { ...reviewBody, request_id: `qa-notify-review-after-remove-${run}`, context: { amount: 5100 } } });
await sleep(6000);
check("not configured → REVIEW still works and queues nothing", reviewAfter.body.decision === "review" && notificationRows(reviewAfter.body.approval_id).length === 0);
await http(`/api/console/approvals/${reviewAfter.body.approval_id}/deny`, { json: { note: "QA: cleanup" }, cookie: cookieA });

const revoke = await http(`/api/console/keys/${keyRes.body.key.id}/revoke`, { method: "POST", cookie: cookieA });
check("QA key revoked", revoke.res.status === 200);

writeFileSync(join(OUT, "results.json"), JSON.stringify({ commit: health.body.commit, approval_id: approvalId, results }, null, 2));
console.log(`\n${results.length - failures}/${results.length} notification checks passed. Evidence: ${OUT}`);
process.exit(failures ? 1 : 0);
