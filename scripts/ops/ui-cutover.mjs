#!/usr/bin/env node
// Moves the public UI host (config/site.json "origin") from the Worker to Vercel.
//
//   node scripts/ops/ui-cutover.mjs status     # read-only: Worker domain/routes, DNS, UI + API health
//   node scripts/ops/ui-cutover.mjs release    # removes the Worker Custom Domain + host routes for the UI host
//   node scripts/ops/ui-cutover.mjs rollback   # re-attaches the UI host to the Worker (delete the Vercel CNAME first)
//
// `release` deletes the Worker-managed DNS record for the UI host, so the site is
// offline until the DNS-only CNAME to Vercel exists. Run it immediately before that
// DNS change. The API host (api.mother.proptechusa.ai) and workers.dev are untouched.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { SITE } from "./lib.mjs";

const ACCOUNT = "fd3a233edadd0a60916413c1199f71ee";
const ZONE = "6c4dd1dd00ceb0f72e0ea12b38f2dfb2"; // proptechusa.ai
const WORKER = "mother-ai";
const UI_HOST = new URL(SITE.origin).hostname;
const API_HOST = new URL(SITE.apiOrigin).hostname;
const UI_ROUTES = [`${UI_HOST}/*`, `${UI_HOST}/news/*`];

function token() {
  const cfg = readFileSync(join(homedir(), ".wrangler", "config", "default.toml"), "utf8");
  const t = /oauth_token\s*=\s*"([^"]+)"/.exec(cfg)?.[1];
  if (!t) throw new Error("No Wrangler OAuth token; run `npx wrangler whoami` first.");
  return t;
}

async function cf(method, path, body) {
  // Refresh the OAuth token if needed (wrangler refreshes on any authenticated command).
  execFileSync(process.execPath, [join(process.cwd(), "node_modules", "wrangler", "bin", "wrangler.js"), "whoami"], { stdio: "ignore" });
  const res = await fetch(`https://api.cloudflare.com/client/v4${path}`, {
    method,
    headers: { Authorization: `Bearer ${token()}`, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  // Some endpoints (e.g. DELETE workers/domains) answer 200 with an empty body.
  if (!text) {
    if (!res.ok) throw new Error(`${method} ${path} failed: HTTP ${res.status}`);
    return null;
  }
  const data = JSON.parse(text);
  if (!data.success) throw new Error(`${method} ${path} failed: ${JSON.stringify(data.errors)}`);
  return data.result;
}

async function state() {
  const domains = (await cf("GET", `/accounts/${ACCOUNT}/workers/domains?zone_id=${ZONE}`)).filter((d) => d.hostname === UI_HOST || d.hostname === API_HOST);
  const routes = (await cf("GET", `/zones/${ZONE}/workers/routes`)).filter((r) => r.pattern.startsWith(`${UI_HOST}/`) || r.pattern.startsWith(`${API_HOST}/`));
  return { domains, routes };
}

async function health(url) {
  try {
    const res = await fetch(url, { headers: { "Cache-Control": "no-cache" }, redirect: "manual" });
    const server = res.headers.get("server");
    const vercel = res.headers.get("x-vercel-id");
    let commit = null;
    try {
      commit = (await res.json()).commit ?? null;
    } catch {}
    return { status: res.status, server, vercel: !!vercel, commit };
  } catch (err) {
    return { error: err.cause?.code ?? err.message };
  }
}

const cmd = process.argv[2];

if (cmd === "status") {
  const s = await state();
  console.log(JSON.stringify({
    worker_custom_domains: s.domains.map((d) => ({ id: d.id, hostname: d.hostname, service: d.service })),
    worker_routes: s.routes.map((r) => ({ id: r.id, pattern: r.pattern, script: r.script })),
    ui_home: await health(`${SITE.origin}/`),
    ui_worker_health: await health(`${SITE.origin}/health`),
    api_health: await health(`${SITE.apiOrigin}/health`),
  }, null, 2));
} else if (cmd === "release") {
  const s = await state();
  const uiDomain = s.domains.find((d) => d.hostname === UI_HOST);
  const uiRoutes = s.routes.filter((r) => UI_ROUTES.includes(r.pattern));
  console.log(`Releasing ${UI_HOST} from Worker ${WORKER}: custom domain ${uiDomain?.id ?? "(none)"}, routes ${uiRoutes.map((r) => r.pattern).join(", ") || "(none)"}`);
  for (const r of uiRoutes) await cf("DELETE", `/zones/${ZONE}/workers/routes/${r.id}`);
  if (uiDomain) await cf("DELETE", `/accounts/${ACCOUNT}/workers/domains/${uiDomain.id}`);
  const after = await state();
  const leftover = after.domains.some((d) => d.hostname === UI_HOST) || after.routes.some((r) => UI_ROUTES.includes(r.pattern));
  const apiIntact = after.domains.some((d) => d.hostname === API_HOST);
  console.log(JSON.stringify({ released: !leftover, api_domain_intact: apiIntact, api_health: await health(`${SITE.apiOrigin}/health`) }, null, 2));
  if (leftover || !apiIntact) process.exit(1);
  console.log(`\nNEXT (DNS, Cloudflare zone proptechusa.ai): CNAME ${UI_HOST.split(".")[0]} -> Vercel target, Proxy status DNS only.`);
} else if (cmd === "rollback") {
  console.log(`Re-attaching ${UI_HOST} to Worker ${WORKER} (the Vercel CNAME for ${UI_HOST} must be deleted first).`);
  await cf("PUT", `/accounts/${ACCOUNT}/workers/domains`, { environment: "production", hostname: UI_HOST, service: WORKER, zone_id: ZONE });
  const existing = (await state()).routes.map((r) => r.pattern);
  for (const pattern of UI_ROUTES) {
    if (!existing.includes(pattern)) await cf("POST", `/zones/${ZONE}/workers/routes`, { pattern, script: WORKER });
  }
  console.log(JSON.stringify(await state(), null, 2));
} else {
  console.error("usage: ui-cutover.mjs status|release|rollback");
  process.exit(2);
}
