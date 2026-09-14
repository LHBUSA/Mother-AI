import site from "../../../config/site.json";
import { generateToken, newId, sha256Hex } from "../../lib/crypto";
import { ApiError, json } from "../../lib/http";
import { iso } from "../../lib/time";
import type { OrganizationRow } from "../../lib/db";
import { controlEventStatement } from "../../gateway/audit";
import { ROLES, canGrant, type Role } from "../../auth/rbac";
import { Validator, assertOrgWritable, type ConsoleContext } from "./context";

const INVITE_TTL_MS = 72 * 60 * 60 * 1000;

function presentOrg(o: OrganizationRow) {
  return {
    id: o.id,
    slug: o.slug,
    display_name: o.display_name,
    kind: o.kind,
    status: o.status,
    plan: o.plan,
    gateway_enabled: o.gateway_enabled === 1,
    audit_enabled: o.audit_enabled === 1,
    require_registered_agents: o.require_registered_agents === 1,
    default_decision: o.default_decision,
    approval_ttl_seconds: o.approval_ttl_seconds,
    approval_grant_ttl_seconds: o.approval_grant_ttl_seconds,
    runtime_protection: o.runtime_protection,
    security_alerts_enabled: o.security_alerts_enabled === 1,
    created_at: o.created_at,
  };
}

export async function getSettings(ctx: ConsoleContext): Promise<Response> {
  return json({ organization: presentOrg(ctx.session.organization) });
}

export async function updateSettings(ctx: ConsoleContext): Promise<Response> {
  assertOrgWritable(ctx);
  const org = ctx.session.organization;
  const v = new Validator(ctx.body);
  const displayName = v.string("display_name", { min: 1, max: 120, optional: true }) ?? org.display_name;
  const gateway = v.bool("gateway_enabled", { optional: true });
  const audit = v.bool("audit_enabled", { optional: true });
  const registered = v.bool("require_registered_agents", { optional: true });
  const defaultDecision = v.oneOf("default_decision", ["block", "review"] as const, { optional: true }) ?? org.default_decision;
  const ttl = v.int("approval_ttl_seconds", { min: 60, max: 86400, optional: true }) ?? org.approval_ttl_seconds;
  const grantTtl = v.int("approval_grant_ttl_seconds", { min: 30, max: 86400, optional: true }) ?? org.approval_grant_ttl_seconds;
  const runtimeProtection = v.oneOf("runtime_protection", ["off", "monitor", "enforce"] as const, { optional: true }) ?? org.runtime_protection;
  const alerts = v.bool("security_alerts_enabled", { optional: true });
  v.assert();

  const next = {
    display_name: displayName,
    gateway_enabled: gateway === undefined ? org.gateway_enabled : gateway ? 1 : 0,
    audit_enabled: audit === undefined ? org.audit_enabled : audit ? 1 : 0,
    require_registered_agents: registered === undefined ? org.require_registered_agents : registered ? 1 : 0,
    default_decision: defaultDecision,
    approval_ttl_seconds: ttl,
    approval_grant_ttl_seconds: grantTtl,
    runtime_protection: runtimeProtection,
    security_alerts_enabled: alerts === undefined ? org.security_alerts_enabled : alerts ? 1 : 0,
  };
  const changes: Record<string, { from: unknown; to: unknown }> = {};
  for (const [k, val] of Object.entries(next)) {
    const before = org[k as keyof OrganizationRow];
    if (before !== val) changes[k] = { from: before, to: val };
  }
  if (!Object.keys(changes).length) return json({ organization: presentOrg(org) });

  const now = iso(ctx.nowMs);
  try {
    await ctx.db.batch([
      ctx.db
        .prepare(
          `UPDATE organizations SET display_name = ?, gateway_enabled = ?, audit_enabled = ?, require_registered_agents = ?, default_decision = ?,
                  approval_ttl_seconds = ?, approval_grant_ttl_seconds = ?, runtime_protection = ?, security_alerts_enabled = ?, updated_at = ? WHERE id = ?`,
        )
        .bind(next.display_name, next.gateway_enabled, next.audit_enabled, next.require_registered_agents, next.default_decision, next.approval_ttl_seconds, next.approval_grant_ttl_seconds, next.runtime_protection, next.security_alerts_enabled, now, ctx.orgId),
      controlEventStatement(ctx.db, ctx.orgId, ctx.actor, "organization.settings_updated", { type: "organization", id: ctx.orgId }, { changes }, now),
    ]);
  } catch (err) {
    if (err instanceof Error && /active quarantine/.test(err.message)) {
      throw new ApiError(409, "ACTIVE_QUARANTINE", "Runtime protection cannot leave enforce while a quarantine is active. Clear the quarantine first.");
    }
    throw err;
  }
  const updated = await ctx.db.prepare(`SELECT * FROM organizations WHERE id = ?`).bind(ctx.orgId).first<OrganizationRow>();
  return json({ organization: presentOrg(updated!) });
}

export async function listMembers(ctx: ConsoleContext): Promise<Response> {
  const [members, invites] = await ctx.db.batch([
    ctx.db
      .prepare(
        `SELECT m.id, m.role, m.status, m.created_at, u.id AS user_id, u.display_name, u.email,
                (SELECT COUNT(*) FROM webauthn_credentials c WHERE c.user_id = u.id) AS passkeys
           FROM memberships m JOIN users u ON u.id = m.user_id
          WHERE m.organization_id = ? ORDER BY m.status, m.created_at`,
      )
      .bind(ctx.orgId),
    ctx.db
      .prepare(
        `SELECT id, role, display_name, email, created_at, expires_at, accepted_at, revoked_at FROM invites
          WHERE organization_id = ? AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > ? ORDER BY created_at DESC`,
      )
      .bind(ctx.orgId, iso(ctx.nowMs)),
  ]);
  return json({ members: members!.results, invites: invites!.results, me: ctx.session.user.id });
}

export async function createInvite(ctx: ConsoleContext): Promise<Response> {
  assertOrgWritable(ctx);
  const v = new Validator(ctx.body);
  const displayName = v.string("display_name", { min: 1, max: 120 });
  const email = v.string("email", { max: 254, optional: true, pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/, message: "enter a valid email" });
  const role = v.oneOf("role", ROLES);
  v.assert();
  if (!canGrant(ctx.session.role, role!)) throw new ApiError(403, "FORBIDDEN", `Your role (${ctx.session.role}) cannot grant ${role}.`);

  const token = generateToken(32);
  const id = newId("inv");
  const now = iso(ctx.nowMs);
  const expiresAt = iso(ctx.nowMs + INVITE_TTL_MS);
  await ctx.db.batch([
    ctx.db
      .prepare(`INSERT INTO invites (id, organization_id, token_hash, role, display_name, email, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .bind(id, ctx.orgId, await sha256Hex(token), role, displayName, email || null, ctx.actor.id, now, expiresAt),
    controlEventStatement(ctx.db, ctx.orgId, ctx.actor, "member.invited", { type: "invite", id }, { role, display_name: displayName }, now),
  ]);
  // The token travels in the URL fragment, which browsers never send to servers or logs.
  return json({ invite: { id, role, display_name: displayName, expires_at: expiresAt }, invite_url: `${site.origin}/app/accept-invite#token=${token}` }, 201);
}

export async function revokeInvite(ctx: ConsoleContext): Promise<Response> {
  const id = ctx.params[0]!;
  const now = iso(ctx.nowMs);
  const results = await ctx.db.batch([
    ctx.db.prepare(`UPDATE invites SET revoked_at = ? WHERE id = ? AND organization_id = ? AND accepted_at IS NULL AND revoked_at IS NULL`).bind(now, id, ctx.orgId),
    controlEventStatement(ctx.db, ctx.orgId, ctx.actor, "member.invite_revoked", { type: "invite", id }, {}, now, { onlyIfChanged: true }),
  ]);
  if ((results[0]!.meta.changes ?? 0) !== 1) throw new ApiError(404, "NOT_FOUND", "Invite not found.");
  return json({ ok: true });
}

export async function updateMember(ctx: ConsoleContext): Promise<Response> {
  assertOrgWritable(ctx);
  const id = ctx.params[0]!;
  const member = await ctx.db
    .prepare(`SELECT m.*, u.display_name FROM memberships m JOIN users u ON u.id = m.user_id WHERE m.id = ? AND m.organization_id = ?`)
    .bind(id, ctx.orgId)
    .first<{ id: string; user_id: string; role: Role; status: string; display_name: string }>();
  if (!member) throw new ApiError(404, "NOT_FOUND", "Member not found.");
  if (member.user_id === ctx.session.user.id) throw new ApiError(400, "CANNOT_MODIFY_SELF", "You cannot change your own role or status.");
  const v = new Validator(ctx.body);
  const role = v.oneOf("role", ROLES, { optional: true }) ?? member.role;
  const status = v.oneOf("status", ["active", "disabled"] as const, { optional: true }) ?? member.status;
  v.assert();
  if (!canGrant(ctx.session.role, member.role) || !canGrant(ctx.session.role, role)) {
    throw new ApiError(403, "FORBIDDEN", "You cannot manage a member with a higher role than yours.");
  }
  if (member.role === "owner" && (role !== "owner" || status !== "active")) {
    const owners = await ctx.db
      .prepare(`SELECT COUNT(*) AS n FROM memberships WHERE organization_id = ? AND role = 'owner' AND status = 'active'`)
      .bind(ctx.orgId)
      .first<{ n: number }>();
    if ((owners?.n ?? 0) <= 1) throw new ApiError(409, "LAST_OWNER", "An organization must keep at least one active owner.");
  }
  const now = iso(ctx.nowMs);
  await ctx.db.batch([
    ctx.db.prepare(`UPDATE memberships SET role = ?, status = ? WHERE id = ? AND organization_id = ?`).bind(role, status, id, ctx.orgId),
    ...(status === "disabled"
      ? [ctx.db.prepare(`UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND organization_id = ? AND revoked_at IS NULL`).bind(now, member.user_id, ctx.orgId)]
      : []),
    controlEventStatement(ctx.db, ctx.orgId, ctx.actor, "member.updated", { type: "user", id: member.user_id }, { display_name: member.display_name, role: { from: member.role, to: role }, status: { from: member.status, to: status } }, now),
  ]);
  return json({ ok: true });
}

export async function getSecurity(ctx: ConsoleContext): Promise<Response> {
  const [passkeys, sessions] = await ctx.db.batch([
    ctx.db.prepare(`SELECT id, name, device_type, backed_up, created_at, last_used_at FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at`).bind(ctx.session.user.id),
    ctx.db
      .prepare(`SELECT id, created_at, last_seen_at, expires_at FROM sessions WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ? ORDER BY last_seen_at DESC`)
      .bind(ctx.session.user.id, iso(ctx.nowMs)),
  ]);
  return json({
    passkeys: (passkeys!.results as Array<Record<string, unknown>>).map((p) => ({ ...p, id: `${String(p.id).slice(0, 10)}…` })),
    sessions: (sessions!.results as Array<{ id: string }>).map((s) => ({ ...s, current: s.id === ctx.session.sessionId })),
  });
}

export async function revokeOtherSessions(ctx: ConsoleContext): Promise<Response> {
  const result = await ctx.db
    .prepare(`UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND id <> ? AND revoked_at IS NULL`)
    .bind(iso(ctx.nowMs), ctx.session.user.id, ctx.session.sessionId)
    .run();
  return json({ revoked: result.meta.changes ?? 0 });
}
