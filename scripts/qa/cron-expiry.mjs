#!/usr/bin/env node
// Natural scheduled-expiry acceptance. Two phases, no long-running process:
//
//   node scripts/qa/cron-expiry.mjs create   # creates a 60 s QA approval that expires before the next */10 cron boundary
//   node scripts/qa/cron-expiry.mjs check    # after the boundary: proves the cron (not a read) expired it
//
// Between the phases nothing may read the QA tenant's approvals through the console
// (console approval/overview reads also persist expiry). The check phase first reads
// D1 directly, read-only, before touching any API that could expire the approval.

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { SoftwareAuthenticator } from "./authenticator.mjs";
import { ROOT, SITE } from "../ops/lib.mjs";

const ORIGIN = SITE.origin;
const RP_ID = new URL(ORIGIN).hostname;
const SECRETS = process.env.MOTHER_QA_SECRETS ?? "D:/Workers/secrets/mother-ai-qa.json";
const STATE = join(ROOT, "qa-artifacts", "cron-expiry-state.json");
const SLUG = "mother-ai-qa-tenant-b";
const phase = process.argv[2];

const secrets = JSON.parse(readFileSync(SECRETS, "utf8"));

async function api(path, { method, json, key, cookie } = {}) {
  const headers = {};
  if (json !== undefined) headers["Content-Type"] = "application/json";
  if (key) headers.Authorization = `Bearer ${key}`;
  if (cookie) headers.Cookie = cookie;
  const m = method ?? (json !== undefined ? "POST" : "GET");
  if (m !== "GET") headers.Origin = ORIGIN;
  const res = await fetch(`${ORIGIN}${path}`, { method: m, headers, body: json !== undefined ? JSON.stringify(json) : undefined });
  const text = await res.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = text;
  }
  return { status: res.status, body, setCookies: res.headers.getSetCookie() };
}

async function signIn() {
  const entry = secrets.orgs[SLUG];
  const mine = entry.credentials.filter((c) => c.rpId === RP_ID);
  const auth = await SoftwareAuthenticator.import(mine);
  const opt = await api("/api/auth/login/options", { json: {} });
  const chal = opt.setCookies.find((c) => c.startsWith("__Host-mai_chal=")).split(";")[0];
  const verify = await api("/api/auth/login/verify", { json: { response: await auth.authenticate(opt.body, ORIGIN) }, cookie: chal });
  entry.credentials = [...entry.credentials.filter((c) => c.rpId !== RP_ID), ...(await auth.export())];
  writeFileSync(SECRETS, JSON.stringify(secrets, null, 2));
  if (verify.status !== 200) throw new Error(`sign-in failed ${verify.status}`);
  return verify.setCookies.find((c) => c.startsWith("__Host-mai_session=")).split(";")[0];
}

function d1Read(sql) {
  const out = execFileSync(process.execPath, [join(ROOT, "node_modules", "wrangler", "bin", "wrangler.js"), "d1", "execute", "mother-ai-prod", "--remote", "--json", "--command", sql], { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  return JSON.parse(out.slice(out.indexOf("[")))[0].results;
}

if (phase === "create") {
  const now = Date.now();
  const boundary = Math.ceil((now + 1) / 600_000) * 600_000;
  if (boundary - now < 100_000) {
    console.error(`Only ${Math.round((boundary - now) / 1000)} s until the next cron boundary; rerun after ${new Date(boundary).toISOString()}.`);
    process.exit(2);
  }
  const cookie = await signIn();
  // PATCH settings and agent/key creation do not touch approvals.
  await api("/api/console/settings", { method: "PATCH", cookie, json: { approval_ttl_seconds: 60, default_decision: "review" } });
  const agents = await api("/api/console/agents", { cookie });
  if (!agents.body.agents.some((a) => a.agent_key === "expiry-agent")) {
    await api("/api/console/agents", { cookie, json: { agent_id: "expiry-agent", display_name: "Expiry agent", environment: "staging" } });
  }
  const key = await api("/api/console/keys", { cookie, json: { name: `QA cron expiry ${new Date(now).toISOString()}`, environment: "live" } });
  const evaluate = await api("/v1/evaluate", { key: key.body.secret, json: { request_id: `qa-cron-expiry-${now}`, agent_id: "expiry-agent", capability: "payments", operation: "refund", resource: "payment:pi_cron", context: { amount: 1 } } });
  await api("/api/console/settings", { method: "PATCH", cookie, json: { approval_ttl_seconds: 900, default_decision: "block" } });
  if (evaluate.body.decision !== "review") throw new Error(`expected review, got ${JSON.stringify(evaluate.body)}`);
  const state = {
    approval_id: evaluate.body.approval_id,
    decision_id: evaluate.body.decision_id,
    request_id: evaluate.body.request_id,
    created_at: evaluate.body.evaluated_at,
    expires_at: evaluate.body.approval.expires_at,
    cron_boundary: new Date(boundary).toISOString(),
    key_id: key.body.key.id,
    key_secret: key.body.secret,
  };
  writeFileSync(STATE, JSON.stringify(state, null, 2));
  console.log(JSON.stringify({ ...state, key_secret: "(stored in qa-artifacts, gitignored; revoked by check)" }, null, 2));
  console.log(`Run "check" after ${new Date(boundary + 90_000).toISOString()}. Do not open tenant B approvals in the console before then.`);
  process.exit(0);
}

if (phase === "check") {
  if (!existsSync(STATE)) throw new Error("run create first");
  const state = JSON.parse(readFileSync(STATE, "utf8"));
  if (Date.now() < Date.parse(state.cron_boundary) + 60_000) {
    console.error(`Too early: wait until ${new Date(Date.parse(state.cron_boundary) + 60_000).toISOString()}.`);
    process.exit(2);
  }
  // 1. Read-only D1 evidence BEFORE any API call that could lazily persist expiry.
  const [approval] = d1Read(`SELECT id, status, requested_at, expires_at, acted_at, acted_by, consumed_at FROM approvals WHERE id = '${state.approval_id}'`);
  const events = d1Read(`SELECT action, actor_type, actor_label, created_at FROM control_events WHERE target_id = '${state.approval_id}' ORDER BY created_at`);
  const [decision] = d1Read(`SELECT id, decision, reason_code, request_id, created_at FROM decisions WHERE id = '${state.decision_id}'`);
  const expiredEvent = events.find((e) => e.action === "approval.expired");
  const results = [];
  const check = (name, ok, detail) => {
    results.push({ name, ok: !!ok, detail });
    console.log(`${ok ? "✓" : "✗"} ${name}${detail ? ` — ${detail}` : ""}`);
  };
  const boundaryMs = Date.parse(state.cron_boundary);
  check("pending approval became expired", approval?.status === "expired", `status=${approval?.status}, expires_at=${approval?.expires_at}`);
  check(
    "expired by the scheduled cron run (system actor, first sweep after expiry, at the cron boundary)",
    expiredEvent && expiredEvent.actor_type === "system" && Date.parse(expiredEvent.created_at) >= boundaryMs && Date.parse(expiredEvent.created_at) < boundaryMs + 60_000 && events[0]?.action === "approval.expired",
    expiredEvent ? `event at ${expiredEvent.created_at}, boundary ${state.cron_boundary}` : "no approval.expired event",
  );
  check("original decision record unchanged", decision?.decision === "review" && decision?.reason_code && decision?.created_at === state.created_at, JSON.stringify(decision));

  // 2. Behavior after expiry.
  const consume = await api(`/v1/approvals/${state.approval_id}/consume`, { method: "POST", key: state.key_secret });
  check("expired approval cannot be consumed", consume.status === 409 && consume.body.error?.code === "APPROVAL_EXPIRED", `${consume.status} ${consume.body.error?.code}`);
  const cookie = await signIn();
  const approve = await api(`/api/console/approvals/${state.approval_id}/approve`, { cookie, json: { note: "QA: must fail" } });
  check("expired approval cannot be approved", approve.status === 409 && ["APPROVAL_EXPIRED", "APPROVAL_NOT_PENDING"].includes(approve.body.error?.code), `${approve.status} ${approve.body.error?.code}`);
  const [after] = d1Read(`SELECT status FROM approvals WHERE id = '${state.approval_id}'`);
  const eventsAfter = d1Read(`SELECT action FROM control_events WHERE target_id = '${state.approval_id}'`);
  check("no approval/consume event was recorded after expiry", after.status === "expired" && eventsAfter.every((e) => e.action === "approval.expired"), eventsAfter.map((e) => e.action).join(","));

  await api(`/api/console/keys/${state.key_id}/revoke`, { cookie, method: "POST" });
  writeFileSync(join(ROOT, "qa-artifacts", "cron-expiry-result.json"), JSON.stringify({ state: { ...state, key_secret: undefined }, approval, events, decision, results }, null, 2));
  writeFileSync(STATE, JSON.stringify({ ...state, key_secret: "(revoked)" }, null, 2));
  const failed = results.filter((r) => !r.ok).length;
  console.log(`\n${results.length - failed}/${results.length} cron expiry checks passed.`);
  process.exit(failed ? 1 : 0);
}

console.error("usage: cron-expiry.mjs create|check");
process.exit(2);
