// Shared helpers for operator scripts. These run locally with Wrangler and never
// print secrets except where a one-time secret is the intended output.

import { execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
export const SITE = JSON.parse(readFileSync(join(ROOT, "config", "site.json"), "utf8"));
export const DATABASE = "mother-ai-prod";

const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

export function base62(length) {
  let out = "";
  while (out.length < length) {
    for (const b of randomBytes(length * 2)) {
      if (b < 248) out += BASE62[b % 62];
      if (out.length === length) break;
    }
  }
  return out;
}

export const newId = (prefix) => `${prefix}_${base62(22)}`;
export const token = () => randomBytes(32).toString("base64url");
export const sha256 = (value) => createHash("sha256").update(value).digest("hex");
export const now = () => new Date().toISOString();

export function sql(value) {
  if (value === null || value === undefined) return "NULL";
  if (typeof value === "number") return String(value);
  return `'${String(value).replace(/'/g, "''")}'`;
}

export function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) continue;
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith("--")) args[key] = true;
    else {
      args[key] = next;
      i++;
    }
  }
  return args;
}

/** Executes SQL against local or remote D1 through Wrangler. Returns parsed JSON results. */
export function d1(statements, { remote }) {
  const dir = mkdtempSync(join(tmpdir(), "mother-ops-"));
  const file = join(dir, "ops.sql");
  writeFileSync(file, statements.join(";\n") + ";\n");
  try {
    const out = execFileSync(
      process.platform === "win32" ? "npx.cmd" : "npx",
      ["wrangler", "d1", "execute", DATABASE, remote ? "--remote" : "--local", "--file", file, "--json", "--yes"],
      { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], shell: process.platform === "win32" },
    );
    return JSON.parse(out.slice(out.indexOf("[")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

export function query(statement, { remote }) {
  const out = execFileSync(
    process.platform === "win32" ? "npx.cmd" : "npx",
    ["wrangler", "d1", "execute", DATABASE, remote ? "--remote" : "--local", "--command", statement, "--json"],
    { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], shell: process.platform === "win32" },
  );
  return JSON.parse(out.slice(out.indexOf("[")))[0]?.results ?? [];
}

export function originFor(remote) {
  return remote ? SITE.origin : "http://localhost:8787";
}
