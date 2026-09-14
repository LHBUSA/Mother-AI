#!/usr/bin/env node
// Production deploy: Cloudflare Worker `mother-ai` from committed, pushed `main`.
//
//   npm run deploy            # full: tests, build, migrations, deploy, verify
//   npm run deploy -- --skip-tests
//
// The deploy is built from `git archive HEAD` into .deploy/<sha>/, never from the
// working tree, so uncommitted files cannot reach production. HEAD must equal
// origin/main. Pending committed D1 migrations are applied before the Worker deploy.
// No GitHub Actions and no other pipeline are involved.

import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const args = new Set(process.argv.slice(2));
const win = process.platform === "win32";

function git(...a) {
  return execFileSync("git", a, { cwd: ROOT, encoding: "utf8" }).trim();
}

function run(cmd, cmdArgs, cwd, opts = {}) {
  console.log(`\n$ ${cmd} ${cmdArgs.join(" ")}`);
  const res = spawnSync(cmd, cmdArgs, { cwd, stdio: opts.capture ? ["inherit", "pipe", "inherit"] : "inherit", shell: win, encoding: "utf8", env: { ...process.env, ...opts.env } });
  if (res.status !== 0) {
    console.error(`\n✗ ${cmd} ${cmdArgs.join(" ")} failed (exit ${res.status})`);
    process.exit(res.status ?? 1);
  }
  if (opts.capture) process.stdout.write(res.stdout);
  return res.stdout ?? "";
}

// 1. Source-of-truth checks
const branch = git("rev-parse", "--abbrev-ref", "HEAD");
if (branch !== "main") {
  console.error(`✗ Deploys run from main only (current: ${branch}).`);
  process.exit(1);
}
git("fetch", "origin", "main", "--quiet");
const head = git("rev-parse", "HEAD");
const remote = git("rev-parse", "origin/main");
if (head !== remote) {
  console.error(`✗ HEAD ${head.slice(0, 7)} is not origin/main ${remote.slice(0, 7)}. Commit and push main first.`);
  process.exit(1);
}
const dirty = git("status", "--porcelain");
if (dirty) console.warn("! Working tree has uncommitted changes. They are NOT deployed (export is from HEAD).");
const sha = head.slice(0, 12);
console.log(`→ Deploying main @ ${sha}`);

// 2. Clean export of HEAD. node_modules resolve from the repo root (parent directories).
const exportDir = join(ROOT, ".deploy", sha);
rmSync(exportDir, { recursive: true, force: true });
mkdirSync(exportDir, { recursive: true });
execFileSync("git", ["-c", "core.autocrlf=false", "archive", "--format=tar", "-o", join(ROOT, ".deploy", `${sha}.tar`), "HEAD"], { cwd: ROOT });
execFileSync("tar", ["-xf", join(ROOT, ".deploy", `${sha}.tar`), "-C", exportDir], { cwd: ROOT });
rmSync(join(ROOT, ".deploy", `${sha}.tar`), { force: true });

const shim = "D:/Workers/exfat-readlink.cjs";
const nodeOptions = existsSync(shim) ? { NODE_OPTIONS: `--require ${shim}` } : {};

// 3. Verify
if (!args.has("--skip-tests")) {
  run("npm", ["run", "typecheck"], exportDir);
  run("npx", ["vitest", "run"], exportDir);
}
run("npx", ["vite", "build"], exportDir, { env: nodeOptions });

// 4. Committed migrations only
run("npx", ["wrangler", "d1", "migrations", "apply", "mother-ai-prod", "--remote"], exportDir, { env: { CI: "1", ...nodeOptions } });

// 5. Deploy
const out = run("npx", ["wrangler", "deploy", "--var", `GIT_SHA:${sha}`], exportDir, { capture: true, env: nodeOptions });
const version = /Current Version ID:\s*([0-9a-f-]+)/i.exec(out)?.[1] ?? "unknown";

// 6. Verify the live Worker serves this commit
const site = JSON.parse(readFileSync(join(exportDir, "config", "site.json"), "utf8"));
// New versions can take tens of seconds to reach every edge location; allow up to ~90 s per host.
// The Worker owns the API host and fallbacks; the UI host is served by Vercel.
for (const origin of [...new Set([site.apiOrigin, ...(site.fallbackOrigins ?? [])])]) {
  let verified = false;
  for (let attempt = 0; attempt < 45 && !verified; attempt++) {
    try {
      const res = await fetch(`${origin}/health`, { headers: { "Cache-Control": "no-cache" } });
      const body = await res.json();
      if (body.commit === sha && body.status === "ok") verified = true;
      else await new Promise((r) => setTimeout(r, 2000));
    } catch {
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
  if (!verified) {
    console.error(`✗ ${origin}/health does not report commit ${sha}.`);
    process.exit(1);
  }
  console.log(`✓ ${origin}/health reports ${sha}`);
}
rmSync(exportDir, { recursive: true, force: true });
console.log(`\n✓ mother-ai deployed\n  commit:  ${sha}\n  version: ${version}\n  url:     ${site.origin}`);
