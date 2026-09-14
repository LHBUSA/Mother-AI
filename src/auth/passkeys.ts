// Passkey (WebAuthn) authentication for the control plane. Mother AI stores no
// passwords. Accounts are created only by redeeming a single-use invite, which
// registers a passkey bound to this site's origin.

import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import site from "../../config/site.json";
import type { Env } from "../env";
import { base64UrlDecode, base64UrlEncode, newId, sha256Hex } from "../lib/crypto";
import { ApiError, clientIp, json, readJsonObject } from "../lib/http";
import { iso } from "../lib/time";
import { controlEventStatement } from "../gateway/audit";
import {
  CHALLENGE_COOKIE,
  SESSION_COOKIE,
  assertBrowserOrigin,
  clearCookieHeader,
  cookieHeader,
  createSession,
  loadSession,
  readCookie,
} from "./sessions";
import { permissionsFor, type Role } from "./rbac";
import { RP_ID, UI_ORIGIN, allowedBrowserOrigins } from "../lib/site";

const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const INVITE_TOKEN = /^[A-Za-z0-9_-]{43}$/;

interface RelyingParty {
  rpID: string;
  origin: string;
}

/**
 * The WebAuthn relying party is the UI origin (config/site.json "origin"), not the host
 * that receives this API request. In production the only accepted browser origin is
 * https://mother.proptechusa.ai with RP ID mother.proptechusa.ai.
 */
function relyingParty(request: Request, env: Env): RelyingParty {
  const origin = request.headers.get("Origin");
  if (!origin || !allowedBrowserOrigins(env.ENVIRONMENT).includes(origin)) {
    throw new ApiError(403, "ORIGIN_NOT_ALLOWED", "Passkey sign-in is only available on the Mother AI site.");
  }
  if (origin === UI_ORIGIN) return { rpID: RP_ID, origin: UI_ORIGIN };
  // Local development only (allowedBrowserOrigins excludes these in production).
  return { rpID: new URL(origin).hostname, origin };
}

interface InviteRow {
  id: string;
  organization_id: string;
  role: Role;
  display_name: string;
  email: string | null;
  expires_at: string;
  accepted_at: string | null;
  revoked_at: string | null;
  org_name: string;
  org_status: string;
}

async function loadInvite(db: D1Database, token: unknown, nowMs: number): Promise<InviteRow> {
  if (typeof token !== "string" || !INVITE_TOKEN.test(token)) {
    throw new ApiError(404, "INVITE_INVALID", "This invite link is not valid.");
  }
  const row = await db
    .prepare(
      `SELECT i.id, i.organization_id, i.role, i.display_name, i.email, i.expires_at, i.accepted_at, i.revoked_at,
              o.display_name AS org_name, o.status AS org_status
         FROM invites i JOIN organizations o ON o.id = i.organization_id
        WHERE i.token_hash = ?`,
    )
    .bind(await sha256Hex(token))
    .first<InviteRow>();
  if (!row || row.revoked_at || row.org_status === "revoked") throw new ApiError(404, "INVITE_INVALID", "This invite link is not valid.");
  if (row.accepted_at) throw new ApiError(410, "INVITE_USED", "This invite has already been used.");
  if (Date.parse(row.expires_at) <= nowMs) throw new ApiError(410, "INVITE_EXPIRED", "This invite has expired. Ask an administrator for a new one.");
  return row;
}

async function storeChallenge(
  db: D1Database,
  purpose: "register" | "login",
  challenge: string,
  nowMs: number,
  extra: { inviteId?: string; userId?: string } = {},
): Promise<string> {
  const id = newId("chl");
  await db
    .prepare(`INSERT INTO auth_challenges (id, purpose, challenge, invite_id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .bind(id, purpose, challenge, extra.inviteId ?? null, extra.userId ?? null, iso(nowMs), iso(nowMs + CHALLENGE_TTL_MS))
    .run();
  return id;
}

async function takeChallenge(
  request: Request,
  db: D1Database,
  purpose: "register" | "login",
  nowMs: number,
): Promise<{ id: string; challenge: string; invite_id: string | null; user_id: string | null }> {
  const id = readCookie(request, CHALLENGE_COOKIE);
  if (!id || !/^chl_[0-9A-Za-z]{22}$/.test(id)) throw new ApiError(400, "CHALLENGE_MISSING", "Sign-in challenge missing. Start again.");
  const now = iso(nowMs);
  // Atomically mark the challenge used so it can only be redeemed once.
  const row = await db
    .prepare(
      `UPDATE auth_challenges SET used_at = ? WHERE id = ? AND purpose = ? AND used_at IS NULL AND expires_at > ?
       RETURNING id, challenge, invite_id, user_id`,
    )
    .bind(now, id, purpose, now)
    .first<{ id: string; challenge: string; invite_id: string | null; user_id: string | null }>();
  if (!row) throw new ApiError(400, "CHALLENGE_EXPIRED", "Sign-in challenge expired or already used. Start again.");
  return row;
}

async function rateLimitAuth(request: Request, env: Env): Promise<void> {
  const { success } = await env.RL_AUTH.limit({ key: clientIp(request) });
  if (!success) throw new ApiError(429, "RATE_LIMITED", "Too many sign-in attempts. Wait a minute and try again.");
}

export async function routeAuth(request: Request, env: Env, nowMs: number): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === "/api/auth/session" && request.method === "GET") {
    const session = await loadSession(request, env, nowMs);
    if (!session) return json({ error: { code: "UNAUTHENTICATED", message: "Sign in required." } }, 401);
    const memberships = await env.DB.prepare(
      `SELECT o.id, o.display_name, o.slug, m.role FROM memberships m JOIN organizations o ON o.id = m.organization_id
        WHERE m.user_id = ? AND m.status = 'active' AND o.status <> 'revoked' ORDER BY o.display_name`,
    )
      .bind(session.user.id)
      .all<{ id: string; display_name: string; slug: string; role: Role }>();
    return json({
      user: session.user,
      role: session.role,
      permissions: permissionsFor(session.role),
      organization: {
        id: session.organization.id,
        display_name: session.organization.display_name,
        slug: session.organization.slug,
        status: session.organization.status,
        kind: session.organization.kind,
        plan: session.organization.plan,
      },
      memberships: memberships.results,
    });
  }

  if (request.method !== "POST") return json({ error: { code: "METHOD_NOT_ALLOWED", message: "Use POST." } }, 405);
  assertBrowserOrigin(request, env.ENVIRONMENT);
  await rateLimitAuth(request, env);

  if (path === "/api/auth/logout") {
    const session = await loadSession(request, env, nowMs);
    if (session) {
      await env.DB.batch([
        env.DB.prepare(`UPDATE sessions SET revoked_at = ? WHERE id = ?`).bind(iso(nowMs), session.sessionId),
      ]);
    }
    return json({ ok: true }, 200, { "Set-Cookie": clearCookieHeader(SESSION_COOKIE) });
  }

  const body = await readJsonObject(request);
  const db = env.DB;

  if (path === "/api/auth/invite/inspect") {
    const invite = await loadInvite(db, body.token, nowMs);
    return json({
      organization: invite.org_name,
      role: invite.role,
      display_name: invite.display_name,
      expires_at: invite.expires_at,
    });
  }

  if (path === "/api/auth/register/options") {
    const rp = relyingParty(request, env);
    const invite = await loadInvite(db, body.token, nowMs);
    const userId = newId("usr");
    const options = await generateRegistrationOptions({
      rpName: site.name,
      rpID: rp.rpID,
      userName: invite.email ?? invite.display_name,
      userDisplayName: invite.display_name,
      userID: Uint8Array.from(new TextEncoder().encode(userId)),
      attestationType: "none",
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      timeout: CHALLENGE_TTL_MS,
    });
    const challengeId = await storeChallenge(db, "register", options.challenge, nowMs, { inviteId: invite.id, userId });
    return json(options, 200, { "Set-Cookie": cookieHeader(CHALLENGE_COOKIE, challengeId, CHALLENGE_TTL_MS / 1000) });
  }

  if (path === "/api/auth/register/verify") {
    const rp = relyingParty(request, env);
    const invite = await loadInvite(db, body.token, nowMs);
    const challenge = await takeChallenge(request, db, "register", nowMs);
    if (challenge.invite_id !== invite.id || !challenge.user_id) {
      throw new ApiError(400, "CHALLENGE_MISMATCH", "This sign-up challenge does not belong to this invite.");
    }
    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: body.response as RegistrationResponseJSON,
        expectedChallenge: challenge.challenge,
        expectedOrigin: rp.origin,
        expectedRPID: rp.rpID,
        requireUserVerification: true,
      });
    } catch {
      throw new ApiError(400, "PASSKEY_VERIFICATION_FAILED", "The passkey could not be verified.");
    }
    if (!verification.verified) throw new ApiError(400, "PASSKEY_VERIFICATION_FAILED", "The passkey could not be verified.");
    const info = verification.registrationInfo;
    const userId = challenge.user_id;
    const now = iso(nowMs);
    const deviceName = typeof body.device_name === "string" && body.device_name.trim() ? body.device_name.trim().slice(0, 60) : "Passkey";
    const session = await createSession(db, userId, invite.organization_id, nowMs);

    // Claim the invite and create the account in one transaction. Every insert
    // is conditioned on this request having claimed the invite.
    const claimed = `EXISTS (SELECT 1 FROM invites WHERE id = ? AND accepted_user_id = ?)`;
    const results = await db.batch([
      db
        .prepare(
          `UPDATE invites SET accepted_at = ?, accepted_user_id = ?
            WHERE id = ? AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > ?`,
        )
        .bind(now, userId, invite.id, now),
      db
        .prepare(`INSERT INTO users (id, display_name, email, created_at) SELECT ?, ?, ?, ? WHERE ${claimed}`)
        .bind(userId, invite.display_name, invite.email, now, invite.id, userId),
      db
        .prepare(
          `INSERT INTO webauthn_credentials (id, user_id, public_key, counter, transports, device_type, backed_up, name, created_at)
           SELECT ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE ${claimed}`,
        )
        .bind(
          info.credential.id,
          userId,
          base64UrlEncode(info.credential.publicKey),
          info.credential.counter,
          JSON.stringify(info.credential.transports ?? []),
          info.credentialDeviceType,
          info.credentialBackedUp ? 1 : 0,
          deviceName,
          now,
          invite.id,
          userId,
        ),
      db
        .prepare(
          `INSERT INTO memberships (id, organization_id, user_id, role, status, created_at)
           SELECT ?, ?, ?, ?, 'active', ? WHERE ${claimed}`,
        )
        .bind(newId("mem"), invite.organization_id, userId, invite.role, now, invite.id, userId),
      controlEventStatement(
        db,
        invite.organization_id,
        { type: "user", id: userId, label: invite.display_name },
        "member.joined",
        { type: "user", id: userId },
        { role: invite.role, invite_id: invite.id },
        now,
        { onlyIfChanged: true },
      ),
    ]);
    if ((results[3]!.meta.changes ?? 0) !== 1) {
      throw new ApiError(410, "INVITE_USED", "This invite has already been used.");
    }
    await session.statement.run();
    return json({ ok: true }, 200, [
      ["Set-Cookie", session.cookie],
      ["Set-Cookie", clearCookieHeader(CHALLENGE_COOKIE)],
    ]);
  }

  if (path === "/api/auth/login/options") {
    const rp = relyingParty(request, env);
    const options = await generateAuthenticationOptions({
      rpID: rp.rpID,
      userVerification: "required",
      timeout: CHALLENGE_TTL_MS,
    });
    const challengeId = await storeChallenge(db, "login", options.challenge, nowMs);
    return json(options, 200, { "Set-Cookie": cookieHeader(CHALLENGE_COOKIE, challengeId, CHALLENGE_TTL_MS / 1000) });
  }

  if (path === "/api/auth/login/verify") {
    const rp = relyingParty(request, env);
    const challenge = await takeChallenge(request, db, "login", nowMs);
    const response = body.response as AuthenticationResponseJSON | undefined;
    if (!response || typeof response.id !== "string" || response.id.length > 1024) {
      throw new ApiError(400, "PASSKEY_VERIFICATION_FAILED", "The passkey could not be verified.");
    }
    const credential = await db
      .prepare(`SELECT id, user_id, public_key, counter, transports FROM webauthn_credentials WHERE id = ?`)
      .bind(response.id)
      .first<{ id: string; user_id: string; public_key: string; counter: number; transports: string | null }>();
    if (!credential) throw new ApiError(401, "PASSKEY_UNKNOWN", "This passkey is not registered with Mother AI.");

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response,
        expectedChallenge: challenge.challenge,
        expectedOrigin: rp.origin,
        expectedRPID: rp.rpID,
        requireUserVerification: true,
        credential: {
          id: credential.id,
          publicKey: base64UrlDecode(credential.public_key),
          counter: credential.counter,
          transports: JSON.parse(credential.transports ?? "[]") as never,
        },
      });
    } catch {
      throw new ApiError(401, "PASSKEY_VERIFICATION_FAILED", "The passkey could not be verified.");
    }
    if (!verification.verified) throw new ApiError(401, "PASSKEY_VERIFICATION_FAILED", "The passkey could not be verified.");

    const requestedOrg = typeof body.organization_id === "string" ? body.organization_id : null;
    const memberships = await db
      .prepare(
        `SELECT m.organization_id, m.role FROM memberships m JOIN organizations o ON o.id = m.organization_id
          WHERE m.user_id = ? AND m.status = 'active' AND o.status <> 'revoked' ORDER BY m.created_at`,
      )
      .bind(credential.user_id)
      .all<{ organization_id: string; role: Role }>();
    const membership = memberships.results.find((m) => m.organization_id === requestedOrg) ?? memberships.results[0];
    if (!membership) throw new ApiError(403, "NO_ACTIVE_MEMBERSHIP", "This account has no active organization membership.");

    const now = iso(nowMs);
    const session = await createSession(db, credential.user_id, membership.organization_id, nowMs);
    await db.batch([
      db
        .prepare(`UPDATE webauthn_credentials SET counter = ?, last_used_at = ? WHERE id = ?`)
        .bind(verification.authenticationInfo.newCounter, now, credential.id),
      session.statement,
    ]);
    return json({ ok: true }, 200, [
      ["Set-Cookie", session.cookie],
      ["Set-Cookie", clearCookieHeader(CHALLENGE_COOKIE)],
    ]);
  }

  if (path === "/api/auth/switch-organization") {
    const session = await loadSession(request, env, nowMs);
    if (!session) throw new ApiError(401, "UNAUTHENTICATED", "Sign in required.");
    const target = typeof body.organization_id === "string" ? body.organization_id : "";
    const membership = await db
      .prepare(
        `SELECT m.organization_id FROM memberships m JOIN organizations o ON o.id = m.organization_id
          WHERE m.user_id = ? AND m.organization_id = ? AND m.status = 'active' AND o.status <> 'revoked'`,
      )
      .bind(session.user.id, target)
      .first<{ organization_id: string }>();
    if (!membership) throw new ApiError(404, "NOT_FOUND", "Organization not found.");
    const next = await createSession(db, session.user.id, membership.organization_id, nowMs);
    await db.batch([db.prepare(`UPDATE sessions SET revoked_at = ? WHERE id = ?`).bind(iso(nowMs), session.sessionId), next.statement]);
    return json({ ok: true }, 200, { "Set-Cookie": next.cookie });
  }

  throw new ApiError(404, "NOT_FOUND", "Unknown auth endpoint.");
}
