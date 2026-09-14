#!/usr/bin/env node
// Production verification for Mother AI. Exercises the REAL deployment:
// passkey sign-in, console API, gateway decisions, approvals, badge and tenant
// isolation, and writes request/response evidence to qa-artifacts/.
//
//   node scripts/qa/verify-prod.mjs [--origin https://…] [--with-expiry]
//
// Uses two internal QA organizations (kind=internal). Their passkey identities and
// gateway keys are stored OUTSIDE Git in D:\Workers\secrets\mother-ai-qa.json
// (override with MOTHER_QA_SECRETS). The first run bootstraps them with
// scripts/ops/create-org.mjs --remote.

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { SoftwareAuthenticator } from "./authenticator.mjs";
import { ROOT, SITE, parseArgs, query } from "../ops/lib.mjs";

const args = parseArgs(process.argv.slice(2));
const ORIGIN = args.origin && args.origin !== true ? args.origin : SITE.origin; // UI origin (WebAuthn RP, browser Origin)
const API = args.api && args.api !== true ? args.api : SITE.apiOrigin; // Worker API host
const isApiPath = (path) => /^\/(v1|api|badge|health|ready)(\/|$)/.test(path);
const SECRETS = process.env.MOTHER_QA_SECRETS ?? "D:/Workers/secrets/mother-ai-qa.json";
const OUT = join(ROOT, "qa-artifacts", new Date().toISOString().replace(/[:.]/g, "-"));
mkdirSync(OUT, { recursive: true });

const evidence = [];
const results = [];
let failures = 0;

function redactSecrets(text) {
  return String(text).replace(/mai_(live|test)_[0-9A-Za-z]{32}([0-9A-Za-z]{8})/g, "mai_$1_…$2").replace(/(__Host-mai_session=)[^;\s"]+/g, "$1…");
}

async function http(label, path, { method, json, key, cookie, headers = {}, host } = {}) {
  const h = { ...headers };
  const base = host ?? (isApiPath(path) ? API : ORIGIN);
  if (json !== undefined) h["Content-Type"] = "application/json";
  if (key) h.Authorization = `Bearer ${key}`;
  if (cookie) h.Cookie = cookie;
  const m = method ?? (json !== undefined ? "POST" : "GET");
  if (m !== "GET" && !("Origin" in h)) h.Origin = ORIGIN;
  // Mirror what a browser on the UI origin sends to the API host.
  if (h.Origin === ORIGIN && base === API && !("Sec-Fetch-Site" in h) && /^\/api\//.test(path)) h["Sec-Fetch-Site"] = "same-site";
  const started = performance.now();
  let res;
  for (let attempt = 1; ; attempt++) {
    try {
      res = await fetch(`${base}${path}`, { method: m, headers: h, body: json !== undefined ? JSON.stringify(json) : undefined, redirect: "manual" });
      break;
    } catch (err) {
      // Transport errors only (e.g. ECONNRESET on the local network). HTTP responses are never retried.
      if (attempt >= 3) throw err;
      console.log(`  ↻ network error on ${label} (${err.cause?.code ?? err.message}); retrying`);
      await new Promise((r) => setTimeout(r, 1000 * attempt));
    }
  }
  const ms = Math.round(performance.now() - started);
  const text = await res.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = text;
  }
  const record = {
    label,
    request: { method: m, url: `${base}${path}`, headers: Object.fromEntries(Object.entries(h).map(([k, v]) => [k, k === "Authorization" ? redactSecrets(v) : k === "Cookie" ? "__Host-mai_session=…" : v])), body: json },
    response: { status: res.status, ms, headers: Object.fromEntries([...res.headers].filter(([k]) => /^(content-type|cache-control|idempotent-replayed|server-timing|x-frame-options|content-security-policy|strict-transport-security|x-content-type-options|referrer-policy|cross-origin-resource-policy|access-control-allow-origin|etag|set-cookie|permissions-policy|cross-origin-opener-policy)$/i.test(k)).map(([k, v]) => [k, k === "set-cookie" ? redactSecrets(v) : v])), body: typeof body === "string" && body.length > 600 ? `${body.slice(0, 600)}…` : body },
  };
  evidence.push(record);
  return { res, body, text, ms, setCookies: res.headers.getSetCookie() };
}

function check(name, ok, detail = "") {
  results.push({ name, ok: !!ok, detail });
  if (!ok) failures++;
  console.log(`${ok ? "✓" : "✗"} ${name}${detail ? ` — ${detail}` : ""}`);
}

function sessionCookie(setCookies) {
  const c = setCookies.find((s) => s.startsWith("__Host-mai_session="));
  return c ? c.split(";")[0] : null;
}
function challengeCookie(setCookies) {
  const c = setCookies.find((s) => s.startsWith("__Host-mai_chal="));
  return c ? c.split(";")[0] : null;
}

// ---------------------------------------------------------------------------
// Identities
// ---------------------------------------------------------------------------

function loadSecrets() {
  return existsSync(SECRETS) ? JSON.parse(readFileSync(SECRETS, "utf8")) : { orgs: {} };
}
function saveSecrets(s) {
  writeFileSync(SECRETS, JSON.stringify(s, null, 2));
}

// Passkeys are bound to a hostname (WebAuthn RP ID), so QA identities are kept per host.
const RP_ID = new URL(ORIGIN).hostname;
const hostCredentials = (entry) => (entry?.credentials ?? []).filter((c) => c.rpId === RP_ID);

async function bootstrapOrg(secrets, slug, name) {
  if (hostCredentials(secrets.orgs[slug]).length) return;
  const exists = !!secrets.orgs[slug];
  console.log(`… ${exists ? "issuing a new QA owner invite for" : "bootstrapping internal QA org"} ${slug} on ${RP_ID}`);
  const script = exists ? "invite.mjs" : "create-org.mjs";
  const scriptArgs = exists
    ? ["--slug", slug, "--name", "Mother AI QA", "--role", "owner", "--remote"]
    : ["--slug", slug, "--name", name, "--owner", "Mother AI QA", "--kind", "internal", "--remote"];
  const out = execFileSync(process.execPath, [join(ROOT, "scripts", "ops", script), ...scriptArgs], { cwd: ROOT, encoding: "utf8" });
  const { invite_url } = JSON.parse(out.slice(out.indexOf("{")));
  const token = new URL(invite_url).hash.replace("#token=", "");
  const auth = new SoftwareAuthenticator();
  const opt = await http(`bootstrap ${slug}: register options`, "/api/auth/register/options", { json: { token } });
  const credential = await auth.register(opt.body, ORIGIN);
  const verify = await http(`bootstrap ${slug}: register verify`, "/api/auth/register/verify", { json: { token, response: credential, device_name: "QA software authenticator" }, cookie: challengeCookie(opt.setCookies) });
  if (verify.res.status !== 200) throw new Error(`bootstrap failed for ${slug}: ${JSON.stringify(verify.body)}`);
  secrets.orgs[slug] = { ...(secrets.orgs[slug] ?? {}), credentials: [...(secrets.orgs[slug]?.credentials ?? []), ...(await auth.export())] };
  delete secrets.orgs[slug].live_key;
  delete secrets.orgs[slug].live_key_id;
  saveSecrets(secrets);
}

async function signIn(secrets, slug) {
  const mine = hostCredentials(secrets.orgs[slug]);
  const auth = await SoftwareAuthenticator.import(mine);
  const opt = await http(`${slug}: login options`, "/api/auth/login/options", { json: {} });
  const assertion = await auth.authenticate(opt.body, ORIGIN);
  const verify = await http(`${slug}: login verify (passkey)`, "/api/auth/login/verify", { json: { response: assertion }, cookie: challengeCookie(opt.setCookies) });
  const refreshed = await auth.export(); // persist signature counter
  secrets.orgs[slug].credentials = [...secrets.orgs[slug].credentials.filter((c) => c.rpId !== RP_ID), ...refreshed];
  saveSecrets(secrets);
  const cookie = sessionCookie(verify.setCookies);
  check(`${slug}: passkey sign-in`, verify.res.status === 200 && cookie, `HTTP ${verify.res.status}`);
  return cookie;
}

// ---------------------------------------------------------------------------
// Setup helpers (idempotent)
// ---------------------------------------------------------------------------

async function ensureAgent(cookie, agent) {
  const list = await http("list agents", "/api/console/agents", { cookie });
  const found = list.body.agents?.find((a) => a.agent_key === agent.agent_id);
  if (found) return found;
  const created = await http(`register agent ${agent.agent_id}`, "/api/console/agents", { cookie, json: agent });
  return created.body.agent;
}

async function ensurePolicy(cookie, policy) {
  const list = await http("list policies", "/api/console/policies", { cookie });
  const found = list.body.policies?.find((p) => p.name === policy.name);
  if (found) return found;
  const created = await http(`create policy ${policy.name}`, "/api/console/policies", { cookie, json: policy });
  if (created.res.status !== 201) throw new Error(`policy create failed: ${JSON.stringify(created.body)}`);
  return created.body.policy;
}

async function freshKey(cookie, name, environment) {
  const created = await http(`create ${environment} key`, "/api/console/keys", { cookie, json: { name, environment } });
  return { id: created.body.key.id, secret: created.body.secret, body: created.body };
}

// ---------------------------------------------------------------------------

const runId = Date.now().toString(36);
const secrets = loadSecrets();
await bootstrapOrg(secrets, "mother-ai-qa", "Mother AI QA (internal)");
await bootstrapOrg(secrets, "mother-ai-qa-tenant-b", "Mother AI QA Tenant B (internal)");

// Health
const health = await http("GET /health", "/health");
check("health ok + D1 reachable", health.body.status === "ok" && health.body.d1 === "reachable", `commit ${health.body.commit}, engine ${health.body.policy_engine}`);

const cookieA = await signIn(secrets, "mother-ai-qa");
const cookieB = await signIn(secrets, "mother-ai-qa-tenant-b");
if (!cookieA || !cookieB) {
  writeFileSync(join(OUT, "evidence.json"), JSON.stringify(evidence, null, 2));
  process.exit(1);
}

const session = await http("GET /api/auth/session", "/api/auth/session", { cookie: cookieA });
check("session resolves org + role", session.body.organization?.slug === "mother-ai-qa" && session.body.role === "owner");
const sessionAgain = await http("GET /api/auth/session (persisted)", "/api/auth/session", { cookie: cookieA });
check("session persists across requests", sessionAgain.res.status === 200 && sessionAgain.body.user?.id === session.body.user?.id);

// Auth responses expose no secret material; the session cookie is host-only and locked down.
{
  const probe = await SoftwareAuthenticator.import(hostCredentials(secrets.orgs["mother-ai-qa-tenant-b"]));
  const opt = await http("auth probe: login options", "/api/auth/login/options", { json: {} });
  const assertion = await probe.authenticate(opt.body, ORIGIN);
  const verify = await http("auth probe: login verify", "/api/auth/login/verify", { json: { response: assertion }, cookie: challengeCookie(opt.setCookies) });
  secrets.orgs["mother-ai-qa-tenant-b"].credentials = [...secrets.orgs["mother-ai-qa-tenant-b"].credentials.filter((c) => c.rpId !== RP_ID), ...(await probe.export())];
  saveSecrets(secrets);
  const sessionSetCookie = verify.setCookies.find((c) => c.startsWith("__Host-mai_session=")) ?? "";
  const optKeys = Object.keys(opt.body).sort().join(",");
  check(
    "auth responses expose no secret material",
    optKeys === "challenge,rpId,timeout,userVerification" &&
      opt.body.rpId === RP_ID &&
      JSON.stringify(verify.body) === '{"ok":true}' &&
      /HttpOnly/.test(sessionSetCookie) && /Secure/.test(sessionSetCookie) && /SameSite=Strict/.test(sessionSetCookie) && !/Domain=/i.test(sessionSetCookie) &&
      !JSON.stringify(sessionAgain.body).match(/token|hash|public_key|challenge/i),
    `options keys ${optKeys}`,
  );
  const probeCookie = sessionCookie(verify.setCookies);
  const logout = await http("auth probe: logout", "/api/auth/logout", { json: {}, cookie: probeCookie });
  const afterLogout = await http("auth probe: session after logout", "/api/auth/session", { cookie: probeCookie });
  check("sign-out revokes the session", logout.res.status === 200 && logout.setCookies.some((c) => /__Host-mai_session=;.*Max-Age=0/.test(c)) && afterLogout.res.status === 401);
}

// Agents and policies (org A)
const billing = await ensureAgent(cookieA, { agent_id: "billing-agent-prod", display_name: "Billing agent", description: "Issues refunds and credits.", environment: "production" });
const research = await ensureAgent(cookieA, { agent_id: "research-agent-prod", display_name: "Research agent", description: "Read-only research.", environment: "production" });
const sales = await ensureAgent(cookieA, { agent_id: "sales-agent-prod", display_name: "Sales agent", description: "Updates CRM contacts over MCP.", environment: "production" });
await ensurePolicy(cookieA, { name: "Restricted data never leaves the company", description: "Blocks restricted data to external destinations.", priority: 1, enabled: true, effect: "block", scope: "organization", reason_code: "RESTRICTED_DATA_EGRESS", reason: "Restricted data cannot be sent to external destinations.", conditions: { match: "all", conditions: [{ field: "data_class", operator: "equals", value: "restricted" }, { field: "destination", operator: "equals", value: "external" }] } });
await ensurePolicy(cookieA, { name: "Research agent is read-only", priority: 10, enabled: true, effect: "block", scope: "agents", agent_ids: [research.id], reason_code: "OPERATION_NOT_ALLOWED", conditions: { match: "any", conditions: [{ field: "operation", operator: "in", value: ["modify", "update", "delete", "write"] }, { field: "capability", operator: "starts_with", value: "finance" }] } });
await ensurePolicy(cookieA, { name: "Research agent may read knowledge and records", priority: 100, enabled: true, effect: "allow", scope: "agents", agent_ids: [research.id], conditions: { match: "all", conditions: [{ field: "capability", operator: "in", value: ["knowledge", "records"] }, { field: "operation", operator: "equals", value: "read" }] } });
await ensurePolicy(cookieA, { name: "Refunds over $1,000 need human approval", priority: 20, enabled: true, effect: "review", scope: "agents", agent_ids: [billing.id], reason: "Refunds over $1,000 require human approval.", conditions: { match: "all", conditions: [{ field: "capability", operator: "equals", value: "payments" }, { field: "operation", operator: "equals", value: "refund" }, { field: "context.amount", operator: "greater_than", value: 1000 }] } });
await ensurePolicy(cookieA, { name: "Billing agent may issue refunds", priority: 100, enabled: true, effect: "allow", scope: "agents", agent_ids: [billing.id], conditions: { match: "all", conditions: [{ field: "capability", operator: "equals", value: "payments" }, { field: "operation", operator: "in", value: ["refund", "credit"] }] } });
await ensurePolicy(cookieA, { name: "Sales agent may update contacts over MCP", priority: 100, enabled: true, effect: "allow", scope: "agents", agent_ids: [sales.id], conditions: { match: "all", conditions: [{ field: "protocol", operator: "equals", value: "mcp" }, { field: "mcp.server", operator: "equals", value: "salesforce" }, { field: "mcp.tool", operator: "in", value: ["contacts.read", "contacts.update"] }] } });
await ensurePolicy(cookieA, { name: "No agent deletes CRM records", priority: 5, enabled: true, effect: "block", scope: "organization", reason_code: "OPERATION_NOT_ALLOWED", conditions: { match: "all", conditions: [{ field: "capability", operator: "equals", value: "salesforce" }, { field: "operation", operator: "glob", value: "*.delete" }] } });

// Keys
const live = await freshKey(cookieA, `QA live key ${runId}`, "live");
check("API key shown once with warning, hash never returned", /^mai_live_[0-9A-Za-z]{40}$/.test(live.secret) && live.body.warning === "Store this securely. Mother AI cannot show this key again." && !JSON.stringify(live.body.key).includes("hash"));
if (secrets.orgs["mother-ai-qa"].live_key_id) {
  await http("REVOKE previous run's QA key", `/api/console/keys/${secrets.orgs["mother-ai-qa"].live_key_id}/revoke`, { cookie: cookieA, method: "POST" });
}
const keysList = await http("GET /api/console/keys", "/api/console/keys", { cookie: cookieA });
check("key list shows prefix only", !keysList.text.includes(live.secret) && !keysList.text.includes("key_hash") && keysList.text.includes(live.secret.slice(0, 17)));

// Gateway decisions
const allow = await http("EVALUATE allow", "/v1/evaluate", { key: live.secret, json: { request_id: `qa-allow-${runId}`, agent_id: "billing-agent-prod", capability: "payments", operation: "refund", resource: "payment:pi_qa_small", destination: "internal", data_class: "financial", context: { amount: 420, currency: "USD" } } });
check("gateway ALLOW", allow.body.decision === "allow" && allow.body.reason_code === "POLICY_ALLOW", `${allow.ms} ms round trip`);

const block = await http("EVALUATE block", "/v1/evaluate", { key: live.secret, json: { request_id: `qa-block-${runId}`, agent_id: "research-agent-prod", capability: "records", operation: "modify", resource: "customer:8812" } });
check("gateway BLOCK (unauthorized modify)", block.body.decision === "block" && block.body.reason_code === "OPERATION_NOT_ALLOWED", `${block.ms} ms`);

const egress = await http("EVALUATE block egress", "/v1/evaluate", { key: live.secret, json: { request_id: `qa-egress-${runId}`, agent_id: "research-agent-prod", capability: "records", operation: "read", destination: "external", data_class: "restricted" } });
check("gateway BLOCK (restricted egress beats allow)", egress.body.decision === "block" && egress.body.reason_code === "RESTRICTED_DATA_EGRESS");

const review = await http("EVALUATE review", "/v1/evaluate", { key: live.secret, json: { request_id: `qa-review-${runId}`, agent_id: "billing-agent-prod", capability: "payments", operation: "refund", resource: "payment:pi_qa_large", destination: "internal", data_class: "financial", context: { amount: 4200, currency: "USD", api_key: "sk_live_should_be_redacted_123" } } });
check("gateway REVIEW with pending approval", review.body.decision === "review" && review.body.reason_code === "HUMAN_APPROVAL_REQUIRED" && review.body.approval?.status === "pending", review.body.approval_id);

const review2 = await http("EVALUATE review (to deny)", "/v1/evaluate", { key: live.secret, json: { request_id: `qa-review-deny-${runId}`, agent_id: "billing-agent-prod", capability: "payments", operation: "refund", resource: "payment:pi_qa_deny", context: { amount: 9800 } } });

const mcp = await http("MCP EVALUATE allow", "/v1/mcp/evaluate", { key: live.secret, json: { request_id: `qa-mcp-${runId}`, agent_id: "sales-agent-prod", server: "salesforce", tool: "contacts.update", arguments: { id: "003QA", title: "VP Sales" }, resource: "contact:003QA", destination: "internal", data_class: "confidential" } });
check("MCP tool call ALLOW", mcp.body.decision === "allow");
const mcpDel = await http("MCP EVALUATE block", "/v1/mcp/evaluate", { key: live.secret, json: { agent_id: "sales-agent-prod", server: "salesforce", tool: "contacts.delete", arguments: { id: "003QA" } } });
check("MCP destructive tool BLOCK", mcpDel.body.decision === "block" && mcpDel.body.reason_code === "OPERATION_NOT_ALLOWED");

const unknownAgent = await http("EVALUATE unknown agent", "/v1/evaluate", { key: live.secret, json: { agent_id: "shadow-agent", capability: "database", operation: "query" } });
check("unknown agent fails closed", unknownAgent.body.decision === "block" && unknownAgent.body.reason_code === "AGENT_UNKNOWN");

// Idempotency
const retry = await http("EVALUATE idempotent retry", "/v1/evaluate", { key: live.secret, json: { request_id: `qa-review-${runId}`, agent_id: "billing-agent-prod", capability: "payments", operation: "refund", resource: "payment:pi_qa_large", destination: "internal", data_class: "financial", context: { amount: 4200, currency: "USD", api_key: "sk_live_should_be_redacted_123" } } });
check("idempotent retry returns same decision", retry.body.replayed === true && retry.body.decision_id === review.body.decision_id && retry.body.approval_id === review.body.approval_id && retry.res.headers.get("idempotent-replayed") === "true");
const conflict = await http("EVALUATE idempotency conflict", "/v1/evaluate", { key: live.secret, json: { request_id: `qa-review-${runId}`, agent_id: "billing-agent-prod", capability: "payments", operation: "refund", context: { amount: 1 } } });
check("request_id reuse for different action → 409", conflict.res.status === 409 && conflict.body.error?.code === "IDEMPOTENCY_CONFLICT" && conflict.body.decision === "block");

// Errors
const missingKey = await http("EVALUATE missing key", "/v1/evaluate", { json: { agent_id: "billing-agent-prod", capability: "payments", operation: "refund" } });
check("missing key → 401 block", missingKey.res.status === 401 && missingKey.body.decision === "block" && missingKey.body.error.code === "MISSING_API_KEY");
const invalidKey = await http("EVALUATE invalid key", "/v1/evaluate", { key: `mai_live_${"Z".repeat(40)}`, json: { agent_id: "billing-agent-prod", capability: "payments", operation: "refund" } });
check("invalid key → 401 block", invalidKey.res.status === 401 && invalidKey.body.error.code === "INVALID_API_KEY" && invalidKey.body.decision === "block");
const malformed = await http("EVALUATE malformed", "/v1/evaluate", { key: live.secret, json: { agent_id: "Billing Agent!", operation: 42, surprise: true } });
check("malformed request → 400 with field errors", malformed.res.status === 400 && malformed.body.error.code === "INVALID_REQUEST" && malformed.body.decision === "block", Object.keys(malformed.body.error?.fields ?? {}).join(","));

const temp = await freshKey(cookieA, `QA revocation key ${runId}`, "live");
const beforeRevoke = await http("EVALUATE before revoke", "/v1/evaluate", { key: temp.secret, json: { agent_id: "research-agent-prod", capability: "records", operation: "read" } });
await http("REVOKE key", `/api/console/keys/${temp.id}/revoke`, { cookie: cookieA, method: "POST" });
const revoked = await http("EVALUATE revoked key", "/v1/evaluate", { key: temp.secret, json: { agent_id: "research-agent-prod", capability: "records", operation: "read" } });
check("revoked key → 401 API_KEY_REVOKED", beforeRevoke.body.decision === "allow" && revoked.res.status === 401 && revoked.body.error.code === "API_KEY_REVOKED");

// Approvals
const pendingView = await http("GET approval (pending)", `/v1/approvals/${review.body.approval_id}`, { key: live.secret });
const earlyConsume = await http("CONSUME pending approval", `/v1/approvals/${review.body.approval_id}/consume`, { key: live.secret, method: "POST" });
check("pending approval not executable", pendingView.body.executable === false && earlyConsume.res.status === 409 && earlyConsume.body.error.code === "APPROVAL_PENDING");
const approve = await http("APPROVE via console", `/api/console/approvals/${review.body.approval_id}/approve`, { cookie: cookieA, json: { note: "QA: verified refund with customer" } });
const approvedView = await http("GET approval (approved)", `/v1/approvals/${review.body.approval_id}`, { key: live.secret });
const consume = await http("CONSUME approval", `/v1/approvals/${review.body.approval_id}/consume`, { key: live.secret, method: "POST" });
const reconsume = await http("CONSUME approval again", `/v1/approvals/${review.body.approval_id}/consume`, { key: live.secret, method: "POST" });
check("approved → executable → consumed once", approve.res.status === 200 && approvedView.body.executable === true && consume.res.status === 200 && reconsume.res.status === 409 && reconsume.body.error.code === "APPROVAL_ALREADY_CONSUMED");
const deny = await http("DENY via console", `/api/console/approvals/${review2.body.approval_id}/deny`, { cookie: cookieA, json: { note: "QA: not authorized" } });
const deniedConsume = await http("CONSUME denied approval", `/v1/approvals/${review2.body.approval_id}/consume`, { key: live.secret, method: "POST" });
check("denied approval cannot execute", deny.res.status === 200 && deniedConsume.res.status === 409 && deniedConsume.body.error.code === "APPROVAL_DENIED");

// Audit evidence
const detail = await http("GET decision detail", `/api/console/decisions/${review.body.decision_id}`, { cookie: cookieA });
check("audit: decision unchanged, approval events appended, credentials redacted", detail.body.decision?.decision === "review" && detail.body.approval_events?.map((e) => e.action).join(",") === "approval.approved,approval.consumed" && detail.body.decision?.context?.api_key === "[REDACTED]");

// Tenant isolation
const keyB = await freshKey(cookieB, `QA tenant B key ${runId}`, "live");
const isoEval = await http("TENANT B evaluate with A's request_id + agent", "/v1/evaluate", { key: keyB.secret, json: { request_id: `qa-allow-${runId}`, agent_id: "billing-agent-prod", capability: "payments", operation: "refund", resource: "payment:pi_qa_small", destination: "internal", data_class: "financial", context: { amount: 420, currency: "USD" } } });
const isoApproval = await http("TENANT B reads A's approval", `/v1/approvals/${review.body.approval_id}`, { key: keyB.secret });
const isoAgent = await http("TENANT B console reads A's agent", `/api/console/agents/${billing.id}`, { cookie: cookieB });
const isoDecision = await http("TENANT B console reads A's decision", `/api/console/decisions/${review.body.decision_id}`, { cookie: cookieB });
const isoRevoke = await http("TENANT B revokes A's key", `/api/console/keys/${live.id}/revoke`, { cookie: cookieB, method: "POST" });
const isoList = await http("TENANT B audit list", "/api/console/decisions", { cookie: cookieB });
const stillWorks = await http("A key still works after B's revoke attempt", "/v1/evaluate", { key: live.secret, json: { agent_id: "research-agent-prod", capability: "knowledge", operation: "read" } });
check(
  "tenant isolation (gateway + console)",
  isoEval.body.replayed === false && isoEval.body.reason_code === "AGENT_UNKNOWN" && isoApproval.res.status === 404 && isoAgent.res.status === 404 && isoDecision.res.status === 404 && isoRevoke.res.status === 404 && !isoList.text.includes(review.body.decision_id) && stillWorks.body.decision === "allow",
);
await http("REVOKE tenant B key", `/api/console/keys/${keyB.id}/revoke`, { cookie: cookieB, method: "POST" });

// CSRF + auth
const csrf = await http("CSRF cross-origin console mutation", "/api/console/agents", { cookie: cookieA, json: { agent_id: "csrf-agent", display_name: "x", environment: "staging" }, headers: { Origin: "https://evil.example" } });
check("CSRF rejected", csrf.res.status === 403 && csrf.body.error.code === "CSRF_REJECTED");
const unauth = await http("console without session", "/api/console/overview");
check("console requires session", unauth.res.status === 401);

// Badge
let badge = await http("GET badge", "/api/console/badge", { cookie: cookieA });
if (!badge.body.badge) badge = await http("ENABLE badge", "/api/console/badge/enable", { cookie: cookieA, method: "POST" });
if (badge.body.badge?.state === "suspended") badge = await http("RESUME badge", "/api/console/badge/resume", { cookie: cookieA, method: "POST" });
const token = badge.body.badge.token;
const svgActive = await http("BADGE svg active", `/badge/${token}.svg`);
const verifyPage = await http("VERIFY page (UI)", `/verify/${token}`);
const verifyActive = await http("PUBLIC badge API active", `/api/public/badges/${token}`, { headers: { Origin: ORIGIN } });
check(
  "badge ACTIVE + verification data",
  badge.body.status === "active" && svgActive.text.includes("AI Controls Active") && verifyPage.res.status === 200 && verifyPage.text.includes("/src/verify/") === false && verifyPage.text.includes("Mother AI verification") &&
    verifyActive.body.status === "active" && verifyActive.body.organization?.display_name === "Mother AI QA (internal)" && String(verifyActive.body.disclaimer).includes("not a certification") &&
    verifyActive.res.headers.get("access-control-allow-origin") === ORIGIN && verifyActive.res.headers.get("cache-control") === "no-store" && !/org_|bdg_|usr_|key_/.test(verifyActive.text) &&
    badge.body.badge.svg_url === `${API}/badge/${token}.svg` && badge.body.badge.verify_url === `${ORIGIN}/verify/${token}`,
  `${ORIGIN}/verify/${token}`,
);
check("badge SVG headers", svgActive.res.headers.get("content-type")?.includes("image/svg+xml") && svgActive.res.headers.get("cross-origin-resource-policy") === "cross-origin" && svgActive.res.headers.get("cache-control")?.includes("no-cache"));
await http("SUSPEND badge", "/api/console/badge/suspend", { cookie: cookieA, method: "POST" });
const svgSuspended = await http("BADGE svg suspended", `/badge/${token}.svg`);
const verifySuspended = await http("PUBLIC badge API suspended", `/api/public/badges/${token}`);
check("suspended badge renders not-active immediately", svgSuspended.text.includes("Protection suspended") && !svgSuspended.text.includes("AI Controls Active") && verifySuspended.body.status === "suspended");
await http("RESUME badge", "/api/console/badge/resume", { cookie: cookieA, method: "POST" });
const rotated = await http("ROTATE badge", "/api/console/badge/rotate", { cookie: cookieA, method: "POST" });
const oldSvg = await http("BADGE old token after rotation", `/badge/${token}.svg`);
const oldVerify = await http("PUBLIC badge API old token after rotation", `/api/public/badges/${token}`);
const newSvg = await http("BADGE new token", `/badge/${rotated.body.badge.token}.svg?theme=light`);
check("rotation revokes old token", oldSvg.text.includes("Badge revoked") && oldVerify.body.status === "revoked" && newSvg.text.includes("AI Controls Active"), `revoked ${token.slice(0, 6)}…, active ${ORIGIN}/verify/${rotated.body.badge.token}`);
const invalidSvg = await http("BADGE invalid token", `/badge/${"0".repeat(32)}.svg`);
const invalidVerify = await http("PUBLIC badge API invalid token", `/api/public/badges/${"0".repeat(32)}`);
check("invalid badge token → 404 unverified", invalidSvg.res.status === 404 && invalidSvg.text.includes("Unverified badge") && invalidVerify.res.status === 404 && invalidVerify.body.error?.code === "BADGE_NOT_FOUND");
const snippets = rotated.body.badge.snippets;

// Headers / CORS
const home = await http("GET / headers", "/");
const hdr = (r, n) => r.res.headers.get(n);
check("security headers on pages", hdr(home, "content-security-policy")?.includes("frame-ancestors 'none'") && hdr(home, "x-frame-options") === "DENY" && hdr(home, "x-content-type-options") === "nosniff" && hdr(home, "strict-transport-security") && hdr(home, "referrer-policy") === "strict-origin-when-cross-origin");
const cors = await http("CORS probe on /v1/evaluate", "/v1/evaluate", { key: live.secret, json: { agent_id: "research-agent-prod", capability: "knowledge", operation: "read" }, headers: { Origin: "https://evil.example" } });
const preflight = await http("CORS preflight", "/v1/evaluate", { method: "OPTIONS", headers: { Origin: "https://evil.example", "Access-Control-Request-Method": "POST" } });
check("no CORS on gateway", !hdr(cors, "access-control-allow-origin") && !hdr(preflight, "access-control-allow-origin"));

// Overview metrics come from real events
const overview = await http("GET overview", "/api/console/overview", { cookie: cookieA });
check("overview metrics from real events", overview.body.decisions_24h?.total > 0 && overview.body.active_agents >= 3 && overview.body.active_policies >= 7, JSON.stringify(overview.body.decisions_24h));

// Demo
const demo = await http("DEMO evaluate", "/api/demo/evaluate", { json: { agent_id: "billing-agent-prod", capability: "payments", operation: "refund", context: { amount: 4200 } } });
check("public demo is stateless and real-engine", demo.body.demo === true && demo.body.stored === false && demo.body.decision === "review");

// ---------------------------------------------------------------------------
// Split-origin acceptance (UI on mother.proptechusa.ai, API on api.mother.proptechusa.ai)
// ---------------------------------------------------------------------------

// CORS matrix
{
  const pf = (label, path, origin, method = "POST") =>
    http(`CORS preflight ${label}`, path, { method: "OPTIONS", headers: { Origin: origin, "Access-Control-Request-Method": method, "Access-Control-Request-Headers": "content-type" } });
  const matrix = [];
  for (const [path, cls, method] of [
    ["/api/auth/login/options", "credentialed", "POST"],
    ["/api/console/agents", "credentialed", "POST"],
    ["/api/demo/evaluate", "public", "POST"],
    ["/api/founding-access/token", "public", "GET"],
    ["/api/founding-access", "public", "POST"],
    ["/api/public/badges/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "public", "GET"],
    ["/v1/evaluate", "none", "POST"],
    ["/v1/mcp/evaluate", "none", "POST"],
  ]) {
    const ui = await pf(`${path} (UI)`, path, ORIGIN, method);
    const evil = await pf(`${path} (evil)`, path, "https://evil.example", method);
    const sibling = await pf(`${path} (sibling)`, path, "https://www.proptechusa.ai", method);
    const acao = ui.res.headers.get("access-control-allow-origin");
    const acac = ui.res.headers.get("access-control-allow-credentials");
    const ok =
      cls === "none"
        ? !acao && !evil.res.headers.get("access-control-allow-origin")
        : ui.res.status === 204 && acao === ORIGIN && (cls === "credentialed" ? acac === "true" : acac === null) && evil.res.status === 403 && !evil.res.headers.get("access-control-allow-origin") && sibling.res.status === 403;
    matrix.push({ path, cls, ui: `${ui.res.status} ${acao ?? "-"} ${acac ?? "-"}`, evil: evil.res.status, sibling: sibling.res.status, ok });
  }
  console.table(matrix);
  check("CORS matrix (credentialed / public / none)", matrix.every((m) => m.ok));
}

// CSRF variants on a real session
{
  const body = () => ({ agent_id: `csrf-${Math.random().toString(36).slice(2, 8)}`, display_name: "CSRF probe", environment: "staging" });
  const sibling = await http("CSRF sibling subdomain", "/api/console/agents", { cookie: cookieA, json: body(), headers: { Origin: "https://www.proptechusa.ai", "Sec-Fetch-Site": "same-site" } });
  const crossSite = await http("CSRF UI origin but cross-site fetch metadata", "/api/console/agents", { cookie: cookieA, json: body(), headers: { Origin: ORIGIN, "Sec-Fetch-Site": "cross-site" } });
  const noOrigin = await http("CSRF missing Origin", "/api/console/agents", { cookie: cookieA, json: body(), headers: { Origin: "" } });
  const apiOriginAsOrigin = await http("CSRF API host as Origin", "/api/console/agents", { cookie: cookieA, json: body(), headers: { Origin: API, "Sec-Fetch-Site": "same-origin" } });
  check("CSRF: sibling subdomain, cross-site metadata, missing Origin and API-host Origin all rejected", [sibling, crossSite, noOrigin, apiOriginAsOrigin].every((r) => r.res.status === 403));
  const legit = await http("same-site write from UI origin", "/api/console/settings", { cookie: cookieA, method: "PATCH", json: {}, headers: { Origin: ORIGIN, "Sec-Fetch-Site": "same-site" } });
  check("same-site write from the UI origin accepted", legit.res.status === 200);
}

// Session cookie contract
{
  const opt = await http("cookie probe: login options", "/api/auth/login/options", { json: {} });
  const chal = opt.setCookies.find((c) => c.startsWith("__Host-mai_chal=")) ?? "";
  check(
    "challenge + session cookies are host-only __Host-, Secure, HttpOnly, SameSite=Strict (API host)",
    /Secure/.test(chal) && /HttpOnly/.test(chal) && /SameSite=Strict/.test(chal) && /Path=\//.test(chal) && !/Domain=/i.test(chal) && opt.res.headers.get("access-control-allow-credentials") === "true",
  );
}

// Owner invite still inspects on the API (not redeemed, token never printed)
{
  const file = "D:/Workers/secrets/mother-ai-owner-invite.txt";
  if (existsSync(file)) {
    const line = readFileSync(file, "utf8").split(/\r?\n/).find((l) => l.startsWith("http"));
    const token = new URLSearchParams(new URL(line.trim()).hash.slice(1)).get("token");
    const res = await fetch(`${API}/api/auth/invite/inspect`, { method: "POST", headers: { "Content-Type": "application/json", Origin: ORIGIN, "Sec-Fetch-Site": "same-site" }, body: JSON.stringify({ token }) });
    const body = await res.json();
    evidence.push({ label: "OWNER invite inspect (token withheld)", response: { status: res.status, body } });
    check("owner invite still valid for the UI host (inspected, not redeemed)", res.status === 200 && body.role === "owner" && Date.parse(body.expires_at) > Date.now() && new URL(line.trim()).origin === ORIGIN, `expires ${body.expires_at}`);
  }
}

// Fresh QA passkey registered through the split origins (invite → register → sign in)
if (args["fresh-passkey"]) {
  const out = execFileSync(process.execPath, [join(ROOT, "scripts", "ops", "invite.mjs"), "--slug", "mother-ai-qa", "--name", "Mother AI QA", "--role", "owner", "--remote"], { cwd: ROOT, encoding: "utf8" });
  const { invite_url } = JSON.parse(out.slice(out.indexOf("{")));
  const inviteToken = new URL(invite_url).hash.replace("#token=", "");
  const fresh = new SoftwareAuthenticator();
  const opt = await http("fresh passkey: register options", "/api/auth/register/options", { json: { token: inviteToken } });
  const credential = await fresh.register(opt.body, ORIGIN);
  const verify = await http("fresh passkey: register verify", "/api/auth/register/verify", { json: { token: inviteToken, response: credential, device_name: "QA fresh passkey (split origin)" }, cookie: challengeCookie(opt.setCookies) });
  const lopt = await http("fresh passkey: login options", "/api/auth/login/options", { json: {} });
  const lverify = await http("fresh passkey: login verify", "/api/auth/login/verify", { json: { response: await fresh.authenticate(lopt.body, ORIGIN) }, cookie: challengeCookie(lopt.setCookies) });
  const freshCookie = sessionCookie(lverify.setCookies);
  const freshSession = await http("fresh passkey: session", "/api/auth/session", { cookie: freshCookie });
  check("fresh passkey: registered via invite and signed in (RP mother.proptechusa.ai via API host)", opt.body.rp?.id === RP_ID && verify.res.status === 200 && lverify.res.status === 200 && freshSession.body.organization?.slug === "mother-ai-qa");
  await http("fresh passkey: logout", "/api/auth/logout", { json: {}, cookie: freshCookie });
  secrets.orgs["mother-ai-qa"].credentials = [...secrets.orgs["mother-ai-qa"].credentials, ...(await fresh.export())];
  saveSecrets(secrets);
}

// Founding Access on the live API (real visitor IP reaches the Worker directly)
{
  const tokenRes = await http("FOUNDING token", "/api/founding-access/token", { headers: { Origin: ORIGIN } });
  const formToken = tokenRes.body.form_token;
  const valid = { name: "Mother AI QA", company: "Mother AI QA (internal)", work_email: `qa+founding-${runId}@localhomebuyersusa.com`, use_case: "Internal pre-cutover QA of Founding Access. Not a customer request.", agent_count: "1-5", uses_mcp: "evaluating", website: "", form_token: formToken };
  const post = (label, b) => http(label, "/api/founding-access", { json: b, headers: { Origin: ORIGIN } });
  const tooFast = await post("FOUNDING too fast", valid);
  await new Promise((r) => setTimeout(r, 3500));
  const invalid = await post("FOUNDING invalid fields", { ...valid, work_email: "nope", use_case: "short" });
  const forged = await post("FOUNDING forged token", { ...valid, form_token: `${Date.now() - 10_000}.${"0".repeat(64)}` });
  const honeypot = await post("FOUNDING honeypot", { ...valid, work_email: `qa+bot-${runId}@localhomebuyersusa.com`, website: "http://spam.example" });
  const ok = await post("FOUNDING valid", valid);
  const dupe = await post("FOUNDING duplicate within 24h", valid);
  const rows = query(`SELECT work_email, length(ip_hash) AS ip_hash_len, ip_hash FROM founding_access_requests WHERE work_email LIKE 'qa+%${runId}@localhomebuyersusa.com'`, { remote: true });
  const stored = rows.filter((r) => r.work_email === valid.work_email);
  check(
    "Founding Access: no Turnstile, too-fast/invalid/forged rejected, honeypot silent, valid stored once with hashed IP",
    Object.keys(tokenRes.body).join(",") === "form_token" && tokenRes.res.headers.get("access-control-allow-origin") === ORIGIN &&
      tooFast.res.status === 400 && tooFast.body.error.code === "FORM_TOO_FAST" &&
      invalid.res.status === 400 && invalid.body.error.code === "INVALID_REQUEST" &&
      forged.res.status === 400 && forged.body.error.code === "FORM_EXPIRED" &&
      honeypot.res.status === 201 && ok.res.status === 201 && dupe.res.status === 201 &&
      rows.length === 1 && stored.length === 1 && stored[0].ip_hash_len === 64 && /^[0-9a-f]{64}$/.test(stored[0].ip_hash),
    `${rows.length} row(s)`,
  );
}

// Optional: approval expiry (requires ~70 s)
if (args["with-expiry"]) {
  await http("SET approval ttl 60s", "/api/console/settings", { cookie: cookieB, method: "PATCH", json: { approval_ttl_seconds: 60, default_decision: "review" } });
  await ensureAgent(cookieB, { agent_id: "expiry-agent", display_name: "Expiry agent", environment: "staging" });
  const keyE = await freshKey(cookieB, `QA expiry key ${runId}`, "live");
  const reviewE = await http("EVALUATE review for expiry", "/v1/evaluate", { key: keyE.secret, json: { request_id: `qa-expiry-${runId}`, agent_id: "expiry-agent", capability: "payments", operation: "refund" } });
  const orgB = await http("GET settings B", "/api/console/settings", { cookie: cookieB });
  console.log(`… waiting 65 s for approval ${reviewE.body.approval_id} to expire (default decision ${orgB.body.organization.default_decision})`);
  await new Promise((r) => setTimeout(r, 65_000));
  const expiredApprove = await http("APPROVE expired", `/api/console/approvals/${reviewE.body.approval_id}/approve`, { cookie: cookieB, json: {} });
  const expiredConsume = await http("CONSUME expired", `/v1/approvals/${reviewE.body.approval_id}/consume`, { key: keyE.secret, method: "POST" });
  check("expired approval cannot be approved or executed", reviewE.body.decision === "review" && expiredApprove.res.status === 409 && expiredApprove.body.error.code === "APPROVAL_EXPIRED" && expiredConsume.body.error?.code === "APPROVAL_EXPIRED");
  await http("REVOKE expiry key", `/api/console/keys/${keyE.id}/revoke`, { cookie: cookieB, method: "POST" });
  await http("RESET approval ttl", "/api/console/settings", { cookie: cookieB, method: "PATCH", json: { approval_ttl_seconds: 900, default_decision: "block" } });
}

if (args["rate-limits"]) {
  // Demo: 30/min per client IP. Sent directly to the API host, so the limiter keys on this machine's IP.
  let demo429 = 0;
  let demoOk = 0;
  for (let i = 0; i < 40; i++) {
    const r = await fetch(`${API}/api/demo/evaluate`, { method: "POST", headers: { "Content-Type": "application/json", Origin: ORIGIN }, body: JSON.stringify({ agent_id: "research-agent-prod", capability: "records", operation: "read" }) });
    if (r.status === 429) demo429++;
    else if (r.status === 200) demoOk++;
    await r.arrayBuffer();
  }
  check("demo rate limit engages per visitor IP (30/min)", demo429 > 0 && demoOk >= 25, `${demoOk} ok, ${demo429} limited of 40`);
  // Founding Access: 5/min per client IP (forged tokens: nothing is stored).
  let form429 = 0;
  for (let i = 0; i < 10; i++) {
    const r = await fetch(`${API}/api/founding-access`, { method: "POST", headers: { "Content-Type": "application/json", Origin: ORIGIN }, body: JSON.stringify({ form_token: "x" }) });
    if (r.status === 429) form429++;
    await r.arrayBuffer();
  }
  check("Founding Access rate limit engages per visitor IP (5/min)", form429 > 0, `${form429} limited of 10`);
}

// Leave org A with one active live key for dashboards; revoke the per-run key from earlier runs is left to operators.
secrets.orgs["mother-ai-qa"].live_key_id = live.id;
secrets.orgs["mother-ai-qa"].live_key = live.secret;
saveSecrets(secrets);

writeFileSync(join(OUT, "evidence.json"), redactSecrets(JSON.stringify(evidence, null, 2)));
writeFileSync(join(OUT, "results.json"), JSON.stringify({ origin: ORIGIN, api: API, commit: health.body.commit, results, badge: { verify_url: `${ORIGIN}/verify/${rotated.body.badge.token}`, revoked_verify_url: `${ORIGIN}/verify/${token}`, snippets } }, null, 2));
console.log(`\n${results.length - failures}/${results.length} checks passed. Evidence: ${OUT}`);
process.exit(failures ? 1 : 0);
