#!/usr/bin/env node
// Browser QA against the REAL deployment at 1440px and 390px.
//
//   PUPPETEER_CORE=<path to puppeteer-core> CHROME=<chrome.exe> node scripts/qa/browser-qa.mjs [--origin …]
//
// Signs in with the internal QA organization's passkey (imported into a Chrome
// virtual authenticator from D:\Workers\secrets\mother-ai-qa.json), visits every
// public and console page, checks horizontal overflow, console errors and failed
// requests, drives API key create/revoke and an approval through the UI, and saves
// screenshots + a report to qa-artifacts/.

import { createPrivateKey } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { ROOT, SITE, parseArgs } from "../ops/lib.mjs";

const args = parseArgs(process.argv.slice(2));
const ORIGIN = args.origin && args.origin !== true ? args.origin : SITE.origin;
const SECRETS = process.env.MOTHER_QA_SECRETS ?? "D:/Workers/secrets/mother-ai-qa.json";
const PUPPETEER = process.env.PUPPETEER_CORE ?? "D:/Workers/ufc-tuf-scout-2026-09-12/qa/node_modules/puppeteer-core/lib/esm/puppeteer/puppeteer-core.js";
const CHROME = process.env.CHROME ?? "C:/Program Files/Google/Chrome/Application/chrome.exe";
const OUT = join(ROOT, "qa-artifacts", `browser-${new Date().toISOString().replace(/[:.]/g, "-")}`);
mkdirSync(OUT, { recursive: true });

const puppeteer = (await import(pathToFileURL(PUPPETEER).href)).default;
const secrets = JSON.parse(readFileSync(SECRETS, "utf8"));
const qa = secrets.orgs["mother-ai-qa"];
const report = { origin: ORIGIN, pages: [], checks: [] };
let failures = 0;
const check = (name, ok, detail = "") => {
  report.checks.push({ name, ok: !!ok, detail });
  if (!ok) failures++;
  console.log(`${ok ? "✓" : "✗"} ${name}${detail ? ` — ${detail}` : ""}`);
};

async function gateway(path, body, key = qa.live_key) {
  const res = await fetch(`${ORIGIN}${path}`, { method: "POST", headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" }, body: JSON.stringify(body) });
  return { status: res.status, body: await res.json() };
}

// Real traffic so approvals/audit have fresh data.
const run = Date.now().toString(36);
await gateway("/v1/evaluate", { request_id: `ui-review-a-${run}`, agent_id: "billing-agent-prod", capability: "payments", operation: "refund", resource: "payment:pi_ui_a", destination: "internal", data_class: "financial", context: { amount: 2750, currency: "USD", ticket: "SUP-5120" } });
await gateway("/v1/evaluate", { request_id: `ui-review-b-${run}`, agent_id: "billing-agent-prod", capability: "payments", operation: "refund", resource: "payment:pi_ui_b", destination: "internal", data_class: "financial", context: { amount: 12400, currency: "USD", ticket: "SUP-5121" } });
await gateway("/v1/mcp/evaluate", { request_id: `ui-mcp-${run}`, agent_id: "sales-agent-prod", server: "salesforce", tool: "contacts.update", arguments: { id: "003UI", title: "Director" } });

const browser = await puppeteer.launch({
  executablePath: CHROME,
  headless: true,
  userDataDir: join(process.env.TEMP ?? "D:/Temp", `mother-qa-${run}`),
  args: ["--no-first-run", "--no-default-browser-check", "--disable-gpu"],
});

const page = await browser.newPage();
const consoleErrors = [];
const failedRequests = [];
let expected4xx = new Set();
page.on("console", (m) => {
  if (m.type() !== "error") return;
  // Chrome logs every intentional 4xx (invalid badge token, 404 page, logged-out session probe) as a
  // "Failed to load resource" error. Those are expected; anything else is a real console error.
  const intentional = /Failed to load resource: the server responded with a status of 4\d\d/.test(m.text()) && expected4xx.size > 0;
  if (!intentional) consoleErrors.push({ url: page.url(), text: m.text() });
});
page.on("pageerror", (e) => consoleErrors.push({ url: page.url(), text: String(e) }));
page.on("requestfailed", (r) => failedRequests.push({ url: r.url(), error: r.failure()?.errorText }));
page.on("response", (r) => {
  if (r.status() >= 400 && !expected4xx.has(new URL(r.url()).pathname)) failedRequests.push({ url: r.url(), status: r.status() });
});

// Virtual authenticator with the QA passkey.
const cdp = await page.createCDPSession();
await cdp.send("WebAuthn.enable");
const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
  options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
});
// Passkeys are hostname-bound: use the QA credential registered for this host.
const cred = qa.credentials.find((c) => c.rpId === new URL(ORIGIN).hostname);
if (!cred) throw new Error(`No QA passkey for ${new URL(ORIGIN).hostname}; run scripts/qa/verify-prod.mjs first.`);
const pkcs8 = createPrivateKey({ key: cred.jwk, format: "jwk" }).export({ type: "pkcs8", format: "der" }).toString("base64");
await cdp.send("WebAuthn.addCredential", {
  authenticatorId,
  credential: {
    credentialId: Buffer.from(cred.id, "base64url").toString("base64"),
    isResidentCredential: true,
    rpId: cred.rpId,
    privateKey: pkcs8,
    userHandle: Buffer.from(cred.userHandle, "base64url").toString("base64"),
    signCount: cred.counter,
  },
});

async function settle() {
  await page.addStyleTag({ content: "html,body{scroll-behavior:auto!important}" }).catch(() => {});
  await new Promise((r) => setTimeout(r, 900));
}

async function shot(name, width) {
  await page.bringToFront();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  const file = join(OUT, `${name}-${width}.png`);
  await page.screenshot({ path: file, fullPage: true });
  report.pages.push({ name, width, url: page.url(), overflow_px: overflow, screenshot: file });
  if (width === 390) check(`${name} @390 no horizontal overflow`, overflow <= 0, `${overflow}px`);
  return overflow;
}

const FALLBACK_HOSTS = (SITE.fallbackOrigins ?? []).map((o) => new URL(o).host);
async function visit(path, name, width, { expect4xx = [] } = {}) {
  expected4xx = new Set(expect4xx);
  await page.setViewport({ width, height: width === 390 ? 844 : 900, deviceScaleFactor: 1 });
  const res = await page.goto(`${ORIGIN}${path}`, { waitUntil: "networkidle0", timeout: 45_000 });
  await settle();
  await shot(name, width);
  if (width === 1440) {
    // Public links, snippets and embeds must use the canonical host.
    const html = await page.evaluate(() => document.documentElement.outerHTML);
    const leaked = FALLBACK_HOSTS.filter((h) => html.includes(h));
    check(`${name}: no fallback-host URLs rendered`, leaked.length === 0 && new URL(page.url()).origin === ORIGIN, leaked.join(","));
  }
  return res;
}

async function clickText(text, { selector = "button", last = false } = {}) {
  const handles = await page.$$(selector);
  const matches = [];
  for (const h of handles) {
    const t = (await h.evaluate((el) => el.textContent?.trim() ?? "")).replace(/\s+/g, " ");
    const visible = await h.evaluate((el) => !!(el.offsetWidth || el.offsetHeight));
    if (visible && (t === text || t.endsWith(` ${text}`) || t.startsWith(text))) matches.push(h);
  }
  if (!matches.length) throw new Error(`No ${selector} with text "${text}"`);
  await (last ? matches[matches.length - 1] : matches[0]).click();
  await new Promise((r) => setTimeout(r, 700));
}

// Badge tokens come from the most recent API verification run (scripts/qa/verify-prod.mjs).
const apiRuns = readdirSync(join(ROOT, "qa-artifacts")).filter((d) => !d.startsWith("browser-") && existsSync(join(ROOT, "qa-artifacts", d, "results.json"))).sort();
const results = JSON.parse(readFileSync(join(ROOT, "qa-artifacts", apiRuns[apiRuns.length - 1], "results.json"), "utf8"));

// ---- Public pages -----------------------------------------------------------
for (const width of [1440, 390]) {
  await visit("/", "home", width);
  await visit("/app/login", "login", width);
  await visit(`/verify/${results.badge.verify_url.split("/verify/")[1]}`, "verify-active", width);
  await visit(`/verify/${results.badge.revoked_verify_url.split("/verify/")[1]}`, "verify-revoked", width);
  await visit(`/verify/${"0".repeat(32)}`, "verify-invalid", width, { expect4xx: [`/verify/${"0".repeat(32)}`, "/badge/" + "0".repeat(32) + ".svg"] });
  await visit("/does-not-exist", "not-found", width, { expect4xx: ["/does-not-exist"] });
}

// Canonical metadata + Founding Access section on the home page
await visit("/#founding-access", "founding-access", 1440);
const meta = await page.evaluate(() => ({
  canonical: document.querySelector('link[rel="canonical"]')?.getAttribute("href"),
  og: document.querySelector('meta[property="og:url"]')?.getAttribute("content"),
  form: !!document.querySelector("#founding-access form"),
}));
check("canonical + OG URLs use the canonical host", meta.canonical === `${ORIGIN}/` && meta.og === `${ORIGIN}/`, JSON.stringify(meta));
check("Founding Access form renders", meta.form);
await visit("/#founding-access", "founding-access", 390);

// Interactive demo (1440)
await visit("/#demo", "demo-before", 1440);
await page.evaluate(() => document.querySelector("#demo")?.scrollIntoView());
await page.waitForSelector("[data-demo-run]:not([disabled])", { timeout: 15_000 });
await page.click("[data-demo-run]");
await new Promise((r) => setTimeout(r, 1500));
const demoText = await page.evaluate(() => document.querySelector("#demo")?.textContent ?? "");
check("interactive demo returns a live decision", /ALLOW|REVIEW|BLOCK/i.test(demoText) && /stored|not stored|demo/i.test(demoText));
await shot("demo-after", 1440);

// Unauthenticated console redirects to login
expected4xx = new Set(["/api/auth/session"]);
await page.setViewport({ width: 1440, height: 900 });
await page.goto(`${ORIGIN}/app/agents`, { waitUntil: "networkidle0" });
await settle();
check("unauthenticated console redirects to /app/login", page.url().endsWith("/app/login"), page.url());

// ---- Sign in with passkey -----------------------------------------------------
expected4xx = new Set();
await page.goto(`${ORIGIN}/app/login`, { waitUntil: "networkidle0" });
await clickText("Sign in with passkey");
await page.waitForFunction(() => location.pathname === "/app/", { timeout: 20_000 });
await settle();
check("passkey sign-in in Chrome lands on /app/", page.url() === `${ORIGIN}/app/`);

// ---- Console pages ----------------------------------------------------------------
const agents = await page.evaluate(async () => (await (await fetch("/api/console/agents")).json()).agents);
const policies = await page.evaluate(async () => (await (await fetch("/api/console/policies")).json()).policies);
const billing = agents.find((a) => a.agent_key === "billing-agent-prod");
const reviewPolicy = policies.find((p) => p.effect === "review");
const routes = [
  ["/app/", "console-overview"],
  ["/app/agents", "console-agents"],
  [`/app/agents/${billing.id}`, "console-agent-detail"],
  ["/app/policies", "console-policies"],
  [`/app/policies/${reviewPolicy.id}`, "console-policy-editor"],
  ["/app/policies/new", "console-policy-new"],
  ["/app/approvals", "console-approvals"],
  ["/app/audit", "console-audit"],
  ["/app/integrations", "console-integrations"],
  ["/app/badge", "console-badge"],
  ["/app/settings", "console-settings-org"],
  ["/app/settings?tab=keys", "console-settings-keys"],
  ["/app/settings?tab=members", "console-settings-members"],
  ["/app/settings?tab=security", "console-settings-security"],
];
for (const width of [1440, 390]) {
  for (const [path, name] of routes) await visit(path, name, width);
}

// Mobile navigation drawer
await visit("/app/", "console-mobile-nav-closed", 390);
await page.click('button[aria-label="Open navigation"]');
await new Promise((r) => setTimeout(r, 600));
await shot("console-mobile-nav-open", 390);
const drawerOpen = await page.evaluate(() => !!document.querySelector("#mobile-nav") && document.querySelector('button[aria-label="Open navigation"]')?.getAttribute("aria-expanded") === "true");
await page.keyboard.press("Escape");
await new Promise((r) => setTimeout(r, 500));
const drawerClosed = await page.evaluate(() => document.querySelector('button[aria-label="Open navigation"]')?.getAttribute("aria-expanded") === "false");
check("mobile nav opens and closes with Escape", drawerOpen && drawerClosed);

// Audit detail (opened via ?open=<decision_id>, the same URL the timeline row uses)
const decisions = await page.evaluate(async () => (await (await fetch("/api/console/decisions?decision=review")).json()).decisions);
for (const width of [1440, 390]) {
  await visit(`/app/audit?open=${decisions[0].id}`, "console-audit-detail", width);
  const detailText = await page.evaluate(() => document.querySelector('[aria-label="Decision detail"]')?.textContent ?? "");
  check(`audit decision detail shows evidence @${width}`, /fingerprint/i.test(detailText) && detailText.includes(decisions[0].reason_code));
}

// Approve through the UI
await visit("/app/approvals", "console-approvals-before", 1440);
await clickText("Approve");
await page.keyboard.type("Browser QA approval");
await clickText("Approve", { last: true });
await new Promise((r) => setTimeout(r, 2000));
await shot("console-approvals-after", 1440);
const resolved = await page.evaluate(async () => (await (await fetch("/api/console/approvals?status=resolved")).json()).approvals);
check("approval approved through UI is recorded", resolved.some((a) => a.status === "approved" && a.note === "Browser QA approval" && a.acted_by_name === "Mother AI QA"));

// Create and revoke an API key through the UI
await visit("/app/settings?tab=keys", "console-keys-before", 1440);
await clickText("Create key");
await page.type("#create-key input[type=text], #create-key input:not([type])", `UI QA key ${run}`).catch(() => {});
await clickText("Create key", { last: true });
await page.waitForSelector(".secret-value", { timeout: 15_000 });
const secret = await page.$eval(".secret-value", (el) => el.textContent?.trim());
await shot("console-key-created", 1440);
check("UI shows the new key once with the warning", /^mai_live_[0-9A-Za-z]{40}$/.test(secret ?? "") && (await page.evaluate(() => document.body.textContent?.includes("Store this securely. Mother AI cannot show this key again."))));
const beforeRevoke = await gateway("/v1/evaluate", { agent_id: "research-agent-prod", capability: "knowledge", operation: "read" }, secret);
await page.click(".secret-reveal input[type=checkbox]");
await clickText("Done");
const secretGone = await page.evaluate((s) => !document.body.innerHTML.includes(s), secret);
check("secret removed from the DOM after closing", secretGone);
const prefix = secret.slice(0, 17);
await page.evaluate((p) => {
  const row = [...document.querySelectorAll("tr")].find((tr) => tr.textContent?.includes(p));
  const btn = [...(row?.querySelectorAll("button") ?? [])].find((b) => /Revoke/.test(b.textContent ?? ""));
  btn?.click();
}, prefix);
await new Promise((r) => setTimeout(r, 700));
await clickText("Revoke key", { last: true });
await new Promise((r) => setTimeout(r, 1500));
await shot("console-key-revoked", 1440);
const afterRevoke = await gateway("/v1/evaluate", { agent_id: "research-agent-prod", capability: "knowledge", operation: "read" }, secret);
check("UI-created key works, then UI revoke blocks it", beforeRevoke.body.decision === "allow" && afterRevoke.status === 401 && afterRevoke.body.error?.code === "API_KEY_REVOKED");

// Persist the authenticator counter so API QA keeps working.
const { credentials } = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
const updated = credentials.find((c) => Buffer.from(c.credentialId, "base64").toString("base64url") === cred.id);
if (updated) {
  cred.counter = updated.signCount;
  writeFileSync(SECRETS, JSON.stringify(secrets, null, 2));
}

check("no console errors", consoleErrors.length === 0, JSON.stringify(consoleErrors.slice(0, 5)));
check("no unexpected failed requests", failedRequests.length === 0, JSON.stringify(failedRequests.slice(0, 5)));
report.console_errors = consoleErrors;
report.failed_requests = failedRequests;
writeFileSync(join(OUT, "report.json"), JSON.stringify(report, null, 2));
await browser.close();
console.log(`\n${report.checks.length - failures}/${report.checks.length} browser checks passed. Screenshots: ${OUT}`);
process.exit(failures ? 1 : 0);
