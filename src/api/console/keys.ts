import { generateApiKey, newId } from "../../lib/crypto";
import { ApiError, json } from "../../lib/http";
import { iso } from "../../lib/time";
import type { ApiKeyRow } from "../../lib/db";
import { controlEventStatement } from "../../gateway/audit";
import { Validator, assertOrgWritable, type ConsoleContext } from "./context";

const MAX_ACTIVE_KEYS = 25;

function present(k: ApiKeyRow) {
  // key_hash is never returned.
  return {
    id: k.id,
    name: k.name,
    key_prefix: k.key_prefix,
    environment: k.environment,
    created_at: k.created_at,
    last_used_at: k.last_used_at,
    revoked_at: k.revoked_at,
    status: k.revoked_at ? "revoked" : "active",
  };
}

export async function listKeys(ctx: ConsoleContext): Promise<Response> {
  const rows = await ctx.db
    .prepare(`SELECT * FROM api_keys WHERE organization_id = ? ORDER BY revoked_at IS NOT NULL, created_at DESC`)
    .bind(ctx.orgId)
    .all<ApiKeyRow>();
  return json({ keys: rows.results.map(present) });
}

export async function createKey(ctx: ConsoleContext): Promise<Response> {
  assertOrgWritable(ctx);
  const v = new Validator(ctx.body);
  const name = v.string("name", { min: 1, max: 80 });
  const environment = v.oneOf("environment", ["live", "test"] as const);
  v.assert();
  const active = await ctx.db
    .prepare(`SELECT COUNT(*) AS n FROM api_keys WHERE organization_id = ? AND revoked_at IS NULL`)
    .bind(ctx.orgId)
    .first<{ n: number }>();
  if ((active?.n ?? 0) >= MAX_ACTIVE_KEYS) throw new ApiError(409, "LIMIT_REACHED", `At most ${MAX_ACTIVE_KEYS} active keys. Revoke unused keys first.`);

  const key = await generateApiKey(environment!);
  const id = newId("key");
  const now = iso(ctx.nowMs);
  await ctx.db.batch([
    ctx.db
      .prepare(`INSERT INTO api_keys (id, organization_id, name, key_prefix, key_hash, environment, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
      .bind(id, ctx.orgId, name, key.prefix, key.hash, environment, ctx.actor.id, now),
    controlEventStatement(ctx.db, ctx.orgId, ctx.actor, "api_key.created", { type: "api_key", id }, { name, environment, key_prefix: key.prefix }, now),
  ]);
  const row = await ctx.db.prepare(`SELECT * FROM api_keys WHERE id = ?`).bind(id).first<ApiKeyRow>();
  return json({ key: present(row!), secret: key.raw, warning: "Store this securely. Mother AI cannot show this key again." }, 201);
}

export async function revokeKey(ctx: ConsoleContext): Promise<Response> {
  const id = ctx.params[0]!;
  const now = iso(ctx.nowMs);
  const results = await ctx.db.batch([
    ctx.db
      .prepare(`UPDATE api_keys SET revoked_at = ?, revoked_by = ? WHERE id = ? AND organization_id = ? AND revoked_at IS NULL`)
      .bind(now, ctx.actor.id, id, ctx.orgId),
    controlEventStatement(ctx.db, ctx.orgId, ctx.actor, "api_key.revoked", { type: "api_key", id }, {}, now, { onlyIfChanged: true }),
  ]);
  if ((results[0]!.meta.changes ?? 0) !== 1) throw new ApiError(404, "NOT_FOUND", "Key not found or already revoked.");
  const row = await ctx.db.prepare(`SELECT * FROM api_keys WHERE id = ? AND organization_id = ?`).bind(id, ctx.orgId).first<ApiKeyRow>();
  return json({ key: present(row!) });
}
